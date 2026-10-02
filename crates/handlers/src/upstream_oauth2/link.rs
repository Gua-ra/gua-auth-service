// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::{
    net::IpAddr,
    sync::{Arc, LazyLock},
};

use axum::{
    Extension, Form,
    extract::{Path, State},
    response::{Html, IntoResponse, Response},
};
use axum_extra::typed_header::TypedHeader;
use hyper::StatusCode;
use mas_axum_utils::{
    GenericError, SessionInfoExt,
    cookies::CookieJar,
    csrf::{CsrfExt, ProtectedForm},
    record_error,
};
use mas_data_model::{
    BoxClock, BoxRng, UpstreamOAuthAuthorizationSession, UpstreamOAuthProviderOnConflict,
    UserRegistration,
};
use mas_jose::jwt::Jwt;
use mas_matrix::HomeserverConnection;
use mas_policy::Policy;
use mas_router::{PostAuthAction, UrlBuilder};
use mas_storage::{
    BoxRepository, Pagination, RepositoryAccess,
    upstream_oauth2::{
        UpstreamOAuthLinkFilter, UpstreamOAuthLinkRepository, UpstreamOAuthSessionRepository,
    },
    user::{BrowserSessionRepository, UserEmailRepository, UserRepository},
};
use mas_templates::{
    AccountInactiveContext, ErrorContext, FieldError, FormError, TemplateContext, Templates,
    ToFormState, UpstreamRegister,
};
use minijinja::Environment;
use opentelemetry::{Key, KeyValue, metrics::Counter};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use ulid::Ulid;

use super::{
    UpstreamSessionsCookie,
    template::{AttributeMappingContext, environment},
};
use crate::{
    BoundActivityTracker, METER, PreferredLanguage, SiteConfig, impl_from_error_for_route,
    views::{register::UserRegistrationSessionsCookie, shared::OptionalPostAuthAction},
};

static LOGIN_COUNTER: LazyLock<Counter<u64>> = LazyLock::new(|| {
    METER
        .u64_counter("mas.upstream_oauth2.login")
        .with_description("Successful upstream OAuth 2.0 login to existing accounts")
        .with_unit("{login}")
        .build()
});
static REGISTRATION_COUNTER: LazyLock<Counter<u64>> = LazyLock::new(|| {
    METER
        .u64_counter("mas.upstream_oauth2.registration")
        .with_description("Successful upstream OAuth 2.0 registration")
        .with_unit("{registration}")
        .build()
});
const PROVIDER: Key = Key::from_static_str("provider");

const DEFAULT_LOCALPART_TEMPLATE: &str = "{{ user.preferred_username }}";
const DEFAULT_DISPLAYNAME_TEMPLATE: &str = "{{ user.name }}";
const DEFAULT_EMAIL_TEMPLATE: &str = "{{ user.email }}";

#[derive(Debug, Error)]
pub(crate) enum RouteError {
    /// Couldn't find the link specified in the URL
    #[error("Link not found")]
    LinkNotFound,

    /// Couldn't find the session on the link
    #[error("Session {0} not found")]
    SessionNotFound(Ulid),

    /// Couldn't find the user
    #[error("User {0} not found")]
    UserNotFound(Ulid),

    /// Couldn't find upstream provider
    #[error("Upstream provider {0} not found")]
    ProviderNotFound(Ulid),

    /// Required attribute rendered to an empty string
    #[error("Template {template:?} rendered to an empty string")]
    RequiredAttributeEmpty { template: String },

    /// Required claim was missing in `id_token`
    #[error(
        "Template {template:?} could not be rendered from the upstream provider's response for required claim"
    )]
    RequiredAttributeRender {
        template: String,

        #[source]
        source: minijinja::Error,
    },

    /// Session was already consumed
    #[error("Session {0} already consumed")]
    SessionConsumed(Ulid),

    #[error("Missing session cookie")]
    MissingCookie,

    #[error("Invalid form action")]
    InvalidFormAction,

    /// GUA FORK: linking this upstream account to the signed-in user is not
    /// allowed
    #[error("Linking upstream account refused")]
    LinkRefused,

    #[error("Homeserver connection error")]
    HomeserverConnection(#[source] anyhow::Error),

    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),
}

impl_from_error_for_route!(mas_templates::TemplateError);
impl_from_error_for_route!(mas_axum_utils::csrf::CsrfError);
impl_from_error_for_route!(super::cookie::UpstreamSessionNotFound);
impl_from_error_for_route!(mas_storage::RepositoryError);
impl_from_error_for_route!(mas_policy::EvaluationError);
impl_from_error_for_route!(mas_jose::jwt::JwtDecodeError);

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        let sentry_event_id = record_error!(
            self,
            Self::Internal(_)
                | Self::RequiredAttributeEmpty { .. }
                | Self::RequiredAttributeRender { .. }
                | Self::SessionNotFound(_)
                | Self::ProviderNotFound(_)
                | Self::UserNotFound(_)
                | Self::HomeserverConnection(_)
        );

        // GUA FORK: people can reach this one, so the error page shows a
        // translated message for its code instead of the developer text.
        if matches!(self, Self::LinkRefused) {
            tracing::warn!(message = &self as &dyn std::error::Error);
            let ctx = ErrorContext::new().with_code("link_refused");
            let text = ctx.to_string();
            return (
                StatusCode::BAD_REQUEST,
                TypedHeader(headers::ContentType::text()),
                Extension(ctx),
                text,
            )
                .into_response();
        }

        let status_code = match self {
            Self::LinkNotFound => StatusCode::NOT_FOUND,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };

        let response = GenericError::new(status_code, self);
        (sentry_event_id, response).into_response()
    }
}

/// Utility function to render an attribute template.
///
/// # Parameters
///
/// * `environment` - The minijinja environment to use to render the template
/// * `template` - The template to use to render the claim
/// * `required` - Whether the attribute is required or not
///
/// # Errors
///
/// Returns an error if the attribute is required but fails to render or is
/// empty
fn render_attribute_template(
    environment: &Environment,
    template: &str,
    context: &minijinja::Value,
    required: bool,
) -> Result<Option<String>, RouteError> {
    match environment.render_str(template, context) {
        Ok(value) if value.is_empty() => {
            if required {
                return Err(RouteError::RequiredAttributeEmpty {
                    template: template.to_owned(),
                });
            }

            Ok(None)
        }

        Ok(value) => Ok(Some(value)),

        Err(source) => {
            if required {
                return Err(RouteError::RequiredAttributeRender {
                    template: template.to_owned(),
                    source,
                });
            }

            tracing::warn!(error = &source as &dyn std::error::Error, %template, "Error while rendering template");
            Ok(None)
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "lowercase", tag = "action")]
pub(crate) enum FormData {
    Register {
        #[serde(default)]
        username: Option<String>,
        #[serde(default)]
        import_email: Option<String>,
        #[serde(default)]
        import_display_name: Option<String>,
        #[serde(default)]
        accept_terms: Option<String>,
    },
    Link,
}

impl ToFormState for FormData {
    type Field = mas_templates::UpstreamRegisterFormField;
}

#[tracing::instrument(
    name = "handlers.upstream_oauth2.link.get",
    fields(upstream_oauth_link.id = %link_id),
    skip_all,
)]
pub(crate) async fn get(
    mut rng: BoxRng,
    clock: BoxClock,
    mut repo: BoxRepository,
    mut policy: Policy,
    PreferredLanguage(locale): PreferredLanguage,
    State(templates): State<Templates>,
    State(url_builder): State<UrlBuilder>,
    State(homeserver): State<Arc<dyn HomeserverConnection>>,
    cookie_jar: CookieJar,
    activity_tracker: BoundActivityTracker,
    user_agent: Option<TypedHeader<headers::UserAgent>>,
    Path(link_id): Path<Ulid>,
) -> Result<impl IntoResponse, RouteError> {
    let user_agent = user_agent.map(|ua| ua.as_str().to_owned());
    let sessions_cookie = UpstreamSessionsCookie::load(&cookie_jar);
    let (session_id, post_auth_action) = sessions_cookie
        .lookup_link(link_id)
        .map_err(|_| RouteError::MissingCookie)?;

    let link = repo
        .upstream_oauth_link()
        .lookup(link_id)
        .await?
        .ok_or(RouteError::LinkNotFound)?;

    let upstream_session = repo
        .upstream_oauth_session()
        .lookup(session_id)
        .await?
        .ok_or(RouteError::SessionNotFound(session_id))?;

    // This checks that we're in a browser session which is allowed to consume
    // this link: the upstream auth session should have been started in this
    // browser.
    if upstream_session.link_id() != Some(link.id) {
        return Err(RouteError::SessionNotFound(session_id));
    }

    if upstream_session.is_consumed() {
        return Err(RouteError::SessionConsumed(session_id));
    }

    let (user_session_info, cookie_jar) = cookie_jar.session_info();
    let (csrf_token, mut cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);
    let maybe_user_session = user_session_info.load_active_session(&mut repo).await?;

    // GUA FORK: a sign-in that completed an account recovery carries the
    // `gua_end_other_sessions` claim in its verified ID token. Only the claims
    // of this upstream session are trusted for it, never a query parameter or
    // the userinfo response.
    let end_other_sessions =
        crate::gua::sessions::claims_end_other_sessions(upstream_session.id_token_claims());

    // GUA FORK: a recovery sign-in must not keep the browser session it found,
    // even when that session belongs to the same account: it may be one the
    // recovery is meant to shut out. Dropping it here sends the flow through
    // the "linked, not logged in" arm below, which ends every session of the
    // account before creating a fresh one.
    let maybe_user_session = maybe_user_session
        .filter(|session| !(end_other_sessions && link.user_id == Some(session.user.id)));

    let response = match (maybe_user_session, link.user_id) {
        (Some(session), Some(user_id)) if session.user.id == user_id => {
            // Session already linked, and link matches the currently logged
            // user. Mark the session as consumed and renew the authentication.
            let upstream_session = repo
                .upstream_oauth_session()
                .consume(&clock, upstream_session, &session)
                .await?;

            repo.browser_session()
                .authenticate_with_upstream(&mut rng, &clock, &session, &upstream_session)
                .await?;

            cookie_jar = cookie_jar.set_session(&session);

            repo.save().await?;

            let post_auth_action = OptionalPostAuthAction {
                post_auth_action: post_auth_action.cloned(),
            };

            post_auth_action.go_next(&url_builder).into_response()
        }

        (Some(user_session), _) => {
            // GUA FORK: the browser is signed in as another account than the
            // one this upstream sign-in resolved to: the link belongs to
            // someone else, or to nobody yet.
            //
            // Upstream MAS would offer to sign out ("link mismatch") or to
            // attach this upstream account to the browser's user ("suggest
            // link"). For Gua both are wrong. The browser can share cookies
            // with an earlier sign-in, so the session found here is often a
            // leftover from a different phone number: continuing with it
            // would finish the app's sign-in as that other account, and the
            // suggest link page would let one click attach a second number's
            // subject to it. This holds for every post-auth action.
            //
            // End that session and come back to this same page. With no
            // session left, the unchanged arms below either log in the
            // account the link belongs to or start registration.
            tracing::info!(
                browser_session.id = %user_session.id,
                user.id = %user_session.user.id,
                upstream_oauth_link.id = %link.id,
                "Browser session belongs to another account than the upstream sign-in, ending it"
            );

            activity_tracker
                .record_browser_session(&clock, &user_session)
                .await;
            repo.browser_session().finish(&clock, user_session).await?;
            repo.save().await?;

            let cookie_jar =
                cookie_jar.update_session_info(&user_session_info.mark_session_ended());

            return Ok((
                cookie_jar,
                url_builder
                    .redirect(&mas_router::UpstreamOAuth2Link::new(link_id))
                    .into_response(),
            ));
        }

        (None, Some(user_id)) => {
            // Session linked, but user not logged in: do the login
            let user = repo
                .user()
                .lookup(user_id)
                .await?
                .ok_or(RouteError::UserNotFound(user_id))?;

            // Check that the user is not locked or deactivated
            if user.deactivated_at.is_some() {
                // The account is deactivated, show the 'account deactivated'
                // fallback
                let ctx = AccountInactiveContext::new(user)
                    .with_csrf(csrf_token.form_value())
                    .with_language(locale);
                let fallback = templates.render_account_deactivated(&ctx)?;
                return Ok((cookie_jar, Html(fallback).into_response()));
            }

            if user.locked_at.is_some() {
                // The account is locked, show the 'account locked' fallback
                let ctx = AccountInactiveContext::new(user)
                    .with_csrf(csrf_token.form_value())
                    .with_language(locale);
                let fallback = templates.render_account_locked(&ctx)?;
                return Ok((cookie_jar, Html(fallback).into_response()));
            }

            // GUA FORK: finishing an account recovery signs out every other
            // session of the account (apps, compatibility logins and browsers)
            // before the recovering browser gets its own. The identity service
            // cannot do this itself: the tokens the apps use are issued here.
            if end_other_sessions {
                tracing::info!(
                    user.id = %user.id,
                    upstream_oauth_provider.id = %upstream_session.provider_id,
                    upstream_oauth_link.id = %link.id,
                    "Upstream sign-in completed an account recovery, ending every other session of the account"
                );
                crate::gua::sessions::end_all_sessions_of_user(&mut repo, &mut rng, &clock, &user)
                    .await?;
            }

            let session = repo
                .browser_session()
                .add(&mut rng, &clock, &user, user_agent)
                .await?;

            let upstream_session = repo
                .upstream_oauth_session()
                .consume(&clock, upstream_session, &session)
                .await?;

            repo.browser_session()
                .authenticate_with_upstream(&mut rng, &clock, &session, &upstream_session)
                .await?;

            let post_auth_action = OptionalPostAuthAction {
                post_auth_action: post_auth_action.cloned(),
            };

            cookie_jar = sessions_cookie
                .consume_link(link_id)?
                .save(cookie_jar, &clock);
            cookie_jar = cookie_jar.set_session(&session);

            repo.save().await?;

            LOGIN_COUNTER.add(
                1,
                &[KeyValue::new(
                    PROVIDER,
                    upstream_session.provider_id.to_string(),
                )],
            );

            post_auth_action.go_next(&url_builder).into_response()
        }

        (None, None) => {
            // Session not linked and used not logged in: suggest creating an
            // account or logging in an existing user
            let id_token = upstream_session.id_token().map(Jwt::try_from).transpose()?;

            let provider = repo
                .upstream_oauth_provider()
                .lookup(link.provider_id)
                .await?
                .ok_or(RouteError::ProviderNotFound(link.provider_id))?;

            let env = environment();

            let mut context = AttributeMappingContext::new();
            if let Some(id_token) = id_token {
                let (_, payload) = id_token.into_parts();
                context = context.with_id_token_claims(payload);
            }
            if let Some(extra_callback_parameters) = upstream_session.extra_callback_parameters() {
                context = context.with_extra_callback_parameters(extra_callback_parameters.clone());
            }
            if let Some(userinfo) = upstream_session.userinfo() {
                context = context.with_userinfo_claims(userinfo.clone());
            }
            let context = context.build();

            let displayname = if provider.claims_imports.displayname.ignore() {
                None
            } else {
                let template = provider
                    .claims_imports
                    .displayname
                    .template
                    .as_deref()
                    .unwrap_or(DEFAULT_DISPLAYNAME_TEMPLATE);

                render_attribute_template(
                    &env,
                    template,
                    &context,
                    provider.claims_imports.displayname.is_required(),
                )?
            };

            let email = if provider.claims_imports.email.ignore() {
                None
            } else {
                let template = provider
                    .claims_imports
                    .email
                    .template
                    .as_deref()
                    .unwrap_or(DEFAULT_EMAIL_TEMPLATE);

                render_attribute_template(
                    &env,
                    template,
                    &context,
                    provider.claims_imports.email.is_required(),
                )?
            };

            // We do a bunch of checks for the localpart. Instead of using
            // nested ifs all the way, we use a labelled block, and
            // use `break` for 'exiting' early when needed
            let localpart = 'localpart: {
                if provider.claims_imports.localpart.ignore() {
                    break 'localpart None;
                }

                let template = provider
                    .claims_imports
                    .localpart
                    .template
                    .as_deref()
                    .unwrap_or(DEFAULT_LOCALPART_TEMPLATE);

                let Some(localpart) = render_attribute_template(
                    &env,
                    template,
                    &context,
                    provider.claims_imports.localpart.is_required(),
                )?
                else {
                    break 'localpart None;
                };

                let forced_or_required = provider.claims_imports.localpart.is_forced_or_required();

                // We got a localpart from the template. We need to check if
                // it's available, and if it's not apply the
                // conflict resolution setup in the config
                let maybe_existing_user = repo.user().find_by_username(&localpart).await?;
                if let Some(existing_user) = maybe_existing_user {
                    if !forced_or_required {
                        tracing::warn!(
                            upstream_oauth_provider.id = %provider.id,
                            upstream_oauth_link.id = %link.id,
                            user.id = %existing_user.id,
                            "Upstream provider returned a localpart {localpart:?} which is already used by another user. As the username is just a suggestion, it was ignored."
                        );
                        break 'localpart None;
                    }

                    // GUA FORK: the Gua provider must keep `on_conflict` at
                    // `fail` (the default when the key is omitted). Any other
                    // value lets a sign-in attach a new upstream subject to an
                    // existing account just because the usernames match. The
                    // provider is declared in the MAS configuration file, under
                    // `upstream_oauth2.providers[].claims_imports.localpart`,
                    // which the deployment repository ships and `mas-cli config
                    // sync` writes into the database.
                    match provider.claims_imports.localpart.on_conflict {
                        // We matched an existing user, but the server doesn't allow us to link to
                        // existing users automatically. In this case, we error out
                        UpstreamOAuthProviderOnConflict::Fail => {
                            tracing::warn!(
                                upstream_oauth_provider.id = %provider.id,
                                upstream_oauth_link.id = %link.id,
                                user.id = %existing_user.id,
                                "Upstream provider returned a localpart {localpart:?} which is already used by another user. Configuration doesn't allow for automatic linking of existing users."
                            );

                            // GUA FORK: translated by its code in `error.html`.
                            let ctx = ErrorContext::new()
                                .with_code("username_taken")
                                .with_language(&locale);

                            return Ok((
                                cookie_jar,
                                Html(templates.render_error(&ctx)?).into_response(),
                            ));
                        }

                        // We matched an existing user and the conflict resolution is to add the
                        // link to the existing user. In this case, we add the link
                        UpstreamOAuthProviderOnConflict::Add => {
                            tracing::info!(
                                user.id = %existing_user.id,
                                upstream_oauth_provider.id = %provider.id,
                                upstream_oauth_link.id = %link.id,
                                upstream_oauth_link.subject = link.subject,
                                "Upstream account mapped localpart {localpart:?} matched an existing user, linking"
                            );

                            // Add link to the user
                            repo.upstream_oauth_link()
                                .associate_to_user(&link, &existing_user)
                                .await?;
                        }

                        // We matched an existing user and the conflict resolution is to replace any
                        // link on the existing user with this one
                        UpstreamOAuthProviderOnConflict::Replace => {
                            // Find existing links for this provider and user
                            let filter = UpstreamOAuthLinkFilter::new()
                                .for_provider(&provider)
                                .for_user(&existing_user);
                            let mut cursor = Pagination::first(100);
                            let mut removed = 0;
                            loop {
                                let page = repo.upstream_oauth_link().list(filter, cursor).await?;
                                for edge in page.edges {
                                    // Remove any existing links for this
                                    // provider and user
                                    repo.upstream_oauth_link().remove(&clock, edge.node).await?;
                                    cursor = cursor.after(edge.cursor);
                                    removed += 1;
                                }

                                if !page.has_next_page {
                                    break;
                                }
                            }

                            if removed > 0 {
                                tracing::warn!(
                                    user.id = %existing_user.id,
                                    upstream_oauth_provider.id = %provider.id,
                                    upstream_oauth_link.id = %link.id,
                                    upstream_oauth_link.subject = link.subject,
                                    "Upstream account mapped localpart {localpart:?} matched an existing user, replaced {removed} links"
                                );
                            } else {
                                tracing::info!(
                                    user.id = %existing_user.id,
                                    upstream_oauth_provider.id = %provider.id,
                                    upstream_oauth_link.id = %link.id,
                                    upstream_oauth_link.subject = link.subject,
                                    "Upstream account mapped localpart {localpart:?} matched an existing user, linking"
                                );
                            }

                            // Add link to the user
                            repo.upstream_oauth_link()
                                .associate_to_user(&link, &existing_user)
                                .await?;
                        }

                        // We matched an existing user and the conflict resolution is to link to the
                        // existing user *only if* there is no existing link on that user
                        UpstreamOAuthProviderOnConflict::Set => {
                            // Find existing links for this provider and user
                            let filter = UpstreamOAuthLinkFilter::new()
                                .for_provider(&provider)
                                .for_user(&existing_user);

                            let count = repo.upstream_oauth_link().count(filter).await?;
                            if count > 0 {
                                tracing::warn!(
                                    upstream_oauth_provider.id = %provider.id,
                                    upstream_oauth_link.id = %link.id,
                                    user.id = %existing_user.id,
                                    "Upstream provider returned a localpart {localpart:?} matching an existing user who already has {count} link(s) to this provider, which isn't allowed by the conflict resolution"
                                );

                                // GUA FORK: translated by its code in
                                // `error.html`.
                                let ctx = ErrorContext::new()
                                    .with_code("username_taken")
                                    .with_language(&locale);

                                return Ok((
                                    cookie_jar,
                                    Html(templates.render_error(&ctx)?).into_response(),
                                ));
                            }

                            // Add link to the user
                            repo.upstream_oauth_link()
                                .associate_to_user(&link, &existing_user)
                                .await?;
                        }
                    }

                    // Now that we've resolved the conflict, log in that
                    // existing user

                    // Check that the user is not locked or deactivated
                    if existing_user.deactivated_at.is_some() {
                        // The account is deactivated, show the 'account
                        // deactivated' fallback
                        let ctx = AccountInactiveContext::new(existing_user)
                            .with_csrf(csrf_token.form_value())
                            .with_language(locale);
                        let fallback = templates.render_account_deactivated(&ctx)?;
                        return Ok((cookie_jar, Html(fallback).into_response()));
                    }

                    if existing_user.locked_at.is_some() {
                        // The account is locked, show the 'account locked'
                        // fallback
                        let ctx = AccountInactiveContext::new(existing_user)
                            .with_csrf(csrf_token.form_value())
                            .with_language(locale);
                        let fallback = templates.render_account_locked(&ctx)?;
                        return Ok((cookie_jar, Html(fallback).into_response()));
                    }

                    let session = repo
                        .browser_session()
                        .add(&mut rng, &clock, &existing_user, user_agent)
                        .await?;

                    let upstream_session = repo
                        .upstream_oauth_session()
                        .consume(&clock, upstream_session, &session)
                        .await?;

                    repo.browser_session()
                        .authenticate_with_upstream(&mut rng, &clock, &session, &upstream_session)
                        .await?;

                    let post_auth_action = OptionalPostAuthAction {
                        post_auth_action: post_auth_action.cloned(),
                    };

                    let cookie_jar = sessions_cookie
                        .consume_link(link_id)?
                        .save(cookie_jar, &clock)
                        .set_session(&session);

                    repo.save().await?;

                    // Count this 'on-the-fly' linking as a login
                    LOGIN_COUNTER.add(
                        1,
                        &[KeyValue::new(
                            PROVIDER,
                            upstream_session.provider_id.to_string(),
                        )],
                    );

                    return Ok((
                        cookie_jar,
                        post_auth_action.go_next(&url_builder).into_response(),
                    ));
                }

                // We've got a localpart from the template. Let's run the policy
                // engine on this registration and react early to a problem on
                // the username
                let res = policy
                    .evaluate_register(mas_policy::RegisterInput {
                        registration_method: mas_policy::RegistrationMethod::UpstreamOAuth2,
                        username: &localpart,
                        email: email.as_deref(),
                        requester: mas_policy::Requester {
                            ip_address: activity_tracker.ip(),
                            user_agent: user_agent.clone(),
                        },
                    })
                    .await?;

                // We don't do a full policy check at this point, only look for
                // violations on the username
                if res
                    .violations
                    .iter()
                    .any(|violation| violation.field.as_deref() == Some("username"))
                {
                    if !forced_or_required {
                        tracing::warn!(
                            upstream_oauth_provider.id = %provider.id,
                            upstream_oauth_link.id = %link.id,
                            "Upstream provider returned a localpart {localpart:?} which was denied by the policy ({res}). As the username is just a suggestion, it was ignored."
                        );
                        break 'localpart None;
                    }

                    // If the username policy check fails, we display an error
                    // message. GUA FORK: translated by its code in
                    // `error.html`.
                    tracing::warn!(
                        upstream_oauth_provider.id = %provider.id,
                        upstream_oauth_link.id = %link.id,
                        "Upstream provider returned a localpart {localpart:?} which was denied by the policy ({res})"
                    );
                    let ctx = ErrorContext::new()
                        .with_code("username_not_allowed")
                        .with_language(&locale);

                    return Ok((
                        cookie_jar,
                        Html(templates.render_error(&ctx)?).into_response(),
                    ));
                }

                // Now let's check if the localpart is allowed by the
                // homeserver. It's possible that it's plain
                // invalid (although that should have been caught by the
                // policy), or just reserved by an application service
                let is_available = homeserver
                    .is_localpart_available(&localpart)
                    .await
                    .map_err(RouteError::HomeserverConnection)?;

                if !is_available {
                    if !forced_or_required {
                        tracing::warn!(
                            upstream_oauth_provider.id = %provider.id,
                            upstream_oauth_link.id = %link.id,
                            "Upstream provider returned a localpart {localpart:?} which isn't available on the homeserver. As the username is just a suggestion, it was ignored."
                        );
                        break 'localpart None;
                    }

                    // GUA FORK: translated by its code in `error.html`.
                    tracing::warn!(
                        upstream_oauth_provider.id = %provider.id,
                        upstream_oauth_link.id = %link.id,
                        "Upstream provider returned a localpart {localpart:?} which isn't available on the homeserver"
                    );
                    let ctx = ErrorContext::new()
                        .with_code("username_taken")
                        .with_language(&locale);

                    return Ok((
                        cookie_jar,
                        Html(templates.render_error(&ctx)?).into_response(),
                    ));
                }

                Some(localpart)
            };

            if provider.claims_imports.skip_confirmation {
                let Some(localpart) = localpart else {
                    return Err(RouteError::Internal(
                        "No localpart available even though the provider is configured to skip confirmation, this is a bug!".into()
                    ));
                };

                // Register on the fly
                REGISTRATION_COUNTER.add(1, &[KeyValue::new(PROVIDER, provider.id.to_string())]);

                let registration = prepare_user_registration(
                    &mut rng,
                    &clock,
                    &mut repo,
                    upstream_session,
                    localpart,
                    displayname,
                    email,
                    activity_tracker.ip(),
                    user_agent,
                    post_auth_action.map(|action| serde_json::json!(action)),
                )
                .await?;

                let registrations = UserRegistrationSessionsCookie::load(&cookie_jar);

                let cookie_jar = sessions_cookie
                    .consume_link(link_id)?
                    .save(cookie_jar, &clock);

                let cookie_jar = registrations.add(&registration).save(cookie_jar, &clock);

                repo.save().await?;

                // Redirect to the user registration flow, in case we have any
                // other step to finish
                return Ok((
                    cookie_jar,
                    url_builder
                        .redirect(&mas_router::RegisterFinish::new(registration.id))
                        .into_response(),
                ));
            }

            // Else we show the upstream registration screen
            let mut ctx = UpstreamRegister::new(link.clone(), provider.clone());

            if let Some(localpart) = localpart {
                ctx = ctx.with_localpart(
                    localpart,
                    provider.claims_imports.localpart.is_forced_or_required(),
                );
            }

            if let Some(displayname) = displayname {
                ctx = ctx.with_display_name(
                    displayname,
                    provider.claims_imports.displayname.is_forced_or_required(),
                );
            }

            if let Some(email) = email {
                ctx = ctx.with_email(email, provider.claims_imports.email.is_forced_or_required());
            }

            let ctx = ctx.with_csrf(csrf_token.form_value()).with_language(locale);

            Html(templates.render_upstream_oauth2_do_register(&ctx)?).into_response()
        }
    };

    Ok((cookie_jar, response))
}

#[tracing::instrument(
    name = "handlers.upstream_oauth2.link.post",
    fields(upstream_oauth_link.id = %link_id),
    skip_all,
)]
pub(crate) async fn post(
    mut rng: BoxRng,
    clock: BoxClock,
    mut repo: BoxRepository,
    cookie_jar: CookieJar,
    user_agent: Option<TypedHeader<headers::UserAgent>>,
    mut policy: Policy,
    PreferredLanguage(locale): PreferredLanguage,
    activity_tracker: BoundActivityTracker,
    State(templates): State<Templates>,
    State(homeserver): State<Arc<dyn HomeserverConnection>>,
    State(url_builder): State<UrlBuilder>,
    State(site_config): State<SiteConfig>,
    Path(link_id): Path<Ulid>,
    Form(form): Form<ProtectedForm<FormData>>,
) -> Result<Response, RouteError> {
    let user_agent = user_agent.map(|ua| ua.as_str().to_owned());
    let form = cookie_jar.verify_form(&clock, form)?;

    let sessions_cookie = UpstreamSessionsCookie::load(&cookie_jar);
    let (session_id, post_auth_action) = sessions_cookie
        .lookup_link(link_id)
        .map_err(|_| RouteError::MissingCookie)?;

    let link = repo
        .upstream_oauth_link()
        .lookup(link_id)
        .await?
        .ok_or(RouteError::LinkNotFound)?;

    let upstream_session = repo
        .upstream_oauth_session()
        .lookup(session_id)
        .await?
        .ok_or(RouteError::SessionNotFound(session_id))?;

    // This checks that we're in a browser session which is allowed to consume
    // this link: the upstream auth session should have been started in this
    // browser.
    if upstream_session.link_id() != Some(link.id) {
        return Err(RouteError::SessionNotFound(session_id));
    }

    if upstream_session.is_consumed() {
        return Err(RouteError::SessionConsumed(session_id));
    }

    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);
    let (user_session_info, cookie_jar) = cookie_jar.session_info();
    let maybe_user_session = user_session_info.load_active_session(&mut repo).await?;
    let form_state = form.to_form_state();

    // GUA FORK: the pages offering to link are no longer rendered, but the
    // form can still be posted. Refuse it inside a sign-in (an authorization
    // grant, a device code grant or a compatibility SSO login), where the
    // browser's user is not necessarily the person signing in, and refuse it
    // for a user who already holds a link to this provider, so a second
    // subject can never be attached to an account by hand.
    if matches!(form, FormData::Link) {
        if matches!(
            post_auth_action,
            Some(
                PostAuthAction::ContinueAuthorizationGrant { .. }
                    | PostAuthAction::ContinueDeviceCodeGrant { .. }
                    | PostAuthAction::ContinueCompatSsoLogin { .. }
            )
        ) {
            tracing::warn!(
                upstream_oauth_link.id = %link.id,
                "Refusing to link an upstream account during a sign-in"
            );
            return Err(RouteError::LinkRefused);
        }

        if let Some(session) = &maybe_user_session {
            let provider = repo
                .upstream_oauth_provider()
                .lookup(link.provider_id)
                .await?
                .ok_or(RouteError::ProviderNotFound(link.provider_id))?;
            let existing_links = repo
                .upstream_oauth_link()
                .count(
                    UpstreamOAuthLinkFilter::new()
                        .for_provider(&provider)
                        .for_user(&session.user),
                )
                .await?;
            if existing_links > 0 {
                tracing::warn!(
                    upstream_oauth_provider.id = %provider.id,
                    upstream_oauth_link.id = %link.id,
                    user.id = %session.user.id,
                    "Refusing to link an upstream account to a user who already has {existing_links} link(s) to this provider"
                );
                return Err(RouteError::LinkRefused);
            }
        }
    }

    match (maybe_user_session, link.user_id, form) {
        (Some(session), None, FormData::Link) => {
            // The user is already logged in, the link is not linked to any
            // user, and the user asked to link their account.
            repo.upstream_oauth_link()
                .associate_to_user(&link, &session.user)
                .await?;

            let upstream_session = repo
                .upstream_oauth_session()
                .consume(&clock, upstream_session, &session)
                .await?;

            repo.browser_session()
                .authenticate_with_upstream(&mut rng, &clock, &session, &upstream_session)
                .await?;

            let post_auth_action = OptionalPostAuthAction {
                post_auth_action: post_auth_action.cloned(),
            };

            let cookie_jar = sessions_cookie
                .consume_link(link_id)?
                .save(cookie_jar, &clock);
            let cookie_jar = cookie_jar.set_session(&session);

            repo.save().await?;

            Ok((cookie_jar, post_auth_action.go_next(&url_builder)).into_response())
        }

        (
            None,
            None,
            FormData::Register {
                username,
                import_email,
                import_display_name,
                accept_terms,
            },
        ) => {
            // The user got the form to register a new account, and is not
            // logged in. Depending on the claims_imports, we've let
            // the user choose their username, choose whether they
            // want to import the email and display name, or not.

            // Those fields are Some("on") if the checkbox is checked
            let import_email = import_email.is_some();
            let import_display_name = import_display_name.is_some();
            let accept_terms = accept_terms.is_some();

            let id_token = upstream_session.id_token().map(Jwt::try_from).transpose()?;

            let provider = repo
                .upstream_oauth_provider()
                .lookup(link.provider_id)
                .await?
                .ok_or(RouteError::ProviderNotFound(link.provider_id))?;

            // Let's try to import the claims from the ID token
            let env = environment();

            let mut context = AttributeMappingContext::new();
            if let Some(id_token) = id_token {
                let (_, payload) = id_token.into_parts();
                context = context.with_id_token_claims(payload);
            }
            if let Some(extra_callback_parameters) = upstream_session.extra_callback_parameters() {
                context = context.with_extra_callback_parameters(extra_callback_parameters.clone());
            }
            if let Some(userinfo) = upstream_session.userinfo() {
                context = context.with_userinfo_claims(userinfo.clone());
            }
            let context = context.build();

            // Create a template context in case we need to re-render because of
            // an error
            let mut ctx = UpstreamRegister::new(link.clone(), provider.clone());

            let display_name = if provider
                .claims_imports
                .displayname
                .should_import(import_display_name)
            {
                let template = provider
                    .claims_imports
                    .displayname
                    .template
                    .as_deref()
                    .unwrap_or(DEFAULT_DISPLAYNAME_TEMPLATE);

                render_attribute_template(
                    &env,
                    template,
                    &context,
                    provider.claims_imports.displayname.is_required(),
                )?
            } else {
                None
            };

            if let Some(ref display_name) = display_name {
                ctx = ctx.with_display_name(
                    display_name.clone(),
                    provider.claims_imports.displayname.is_forced_or_required(),
                );
            }

            let email = if provider.claims_imports.email.should_import(import_email) {
                let template = provider
                    .claims_imports
                    .email
                    .template
                    .as_deref()
                    .unwrap_or(DEFAULT_EMAIL_TEMPLATE);

                render_attribute_template(
                    &env,
                    template,
                    &context,
                    provider.claims_imports.email.is_required(),
                )?
            } else {
                None
            };

            if let Some(ref email) = email {
                ctx = ctx.with_email(
                    email.clone(),
                    provider.claims_imports.email.is_forced_or_required(),
                );
            }

            let username = if provider.claims_imports.localpart.is_forced_or_required() {
                let template = provider
                    .claims_imports
                    .localpart
                    .template
                    .as_deref()
                    .unwrap_or(DEFAULT_LOCALPART_TEMPLATE);

                render_attribute_template(&env, template, &context, true)?
            } else {
                // If there is no forced username, we can use the one the user
                // entered
                username
            }
            .unwrap_or_default();

            ctx = ctx.with_localpart(
                username.clone(),
                provider.claims_imports.localpart.is_forced_or_required(),
            );

            // Validate the form
            let form_state = {
                let mut form_state = form_state;
                let mut homeserver_denied_username = false;
                if username.is_empty() {
                    form_state.add_error_on_field(
                        mas_templates::UpstreamRegisterFormField::Username,
                        FieldError::Required,
                    );
                } else if repo.user().exists(&username).await? {
                    form_state.add_error_on_field(
                        mas_templates::UpstreamRegisterFormField::Username,
                        FieldError::Exists,
                    );
                } else if !homeserver
                    .is_localpart_available(&username)
                    .await
                    .map_err(RouteError::HomeserverConnection)?
                {
                    // The user already exists on the homeserver
                    tracing::warn!(
                        %username,
                        "Homeserver denied username provided by user"
                    );

                    // We defer adding the error on the field, until we know
                    // whether we had another error from the
                    // policy, to avoid showing both
                    homeserver_denied_username = true;
                }

                // If we have a TOS in the config, make sure the user has
                // accepted it
                if site_config.tos_uri.is_some() && !accept_terms {
                    form_state.add_error_on_field(
                        mas_templates::UpstreamRegisterFormField::AcceptTerms,
                        FieldError::Required,
                    );
                }

                // Policy check
                let res = policy
                    .evaluate_register(mas_policy::RegisterInput {
                        registration_method: mas_policy::RegistrationMethod::UpstreamOAuth2,
                        username: &username,
                        email: email.as_deref(),
                        requester: mas_policy::Requester {
                            ip_address: activity_tracker.ip(),
                            user_agent: user_agent.clone(),
                        },
                    })
                    .await?;

                for violation in res.violations {
                    match violation.field.as_deref() {
                        Some("username") => {
                            // If the homeserver denied the username, but we
                            // also had an error on
                            // the policy side, we don't want to show
                            // both, so we reset the state here
                            homeserver_denied_username = false;
                            form_state.add_error_on_field(
                                mas_templates::UpstreamRegisterFormField::Username,
                                FieldError::Policy {
                                    code: violation.variant.map(|c| c.as_str()),
                                    message: violation.msg,
                                },
                            );
                        }
                        _ => form_state.add_error_on_form(FormError::Policy {
                            code: violation.variant.map(|c| c.as_str()),
                            message: violation.msg,
                        }),
                    }
                }

                if homeserver_denied_username {
                    // XXX: we may want to return different errors like "this
                    // username is reserved"
                    form_state.add_error_on_field(
                        mas_templates::UpstreamRegisterFormField::Username,
                        FieldError::Exists,
                    );
                }

                form_state
            };

            if !form_state.is_valid() {
                let ctx = ctx
                    .with_form_state(form_state)
                    .with_csrf(csrf_token.form_value())
                    .with_language(locale);

                return Ok((
                    cookie_jar,
                    Html(templates.render_upstream_oauth2_do_register(&ctx)?),
                )
                    .into_response());
            }

            REGISTRATION_COUNTER.add(1, &[KeyValue::new(PROVIDER, provider.id.to_string())]);

            let mut registration = prepare_user_registration(
                &mut rng,
                &clock,
                &mut repo,
                upstream_session,
                username,
                display_name,
                email,
                activity_tracker.ip(),
                user_agent,
                post_auth_action.map(|action| serde_json::json!(action)),
            )
            .await?;

            if let Some(terms_url) = &site_config.tos_uri {
                registration = repo
                    .user_registration()
                    .set_terms_url(registration, terms_url.clone())
                    .await?;
            }

            let registrations = UserRegistrationSessionsCookie::load(&cookie_jar);

            let cookie_jar = sessions_cookie
                .consume_link(link_id)?
                .save(cookie_jar, &clock);

            let cookie_jar = registrations.add(&registration).save(cookie_jar, &clock);

            repo.save().await?;

            // Redirect to the user registration flow, in case we have any other
            // step to finish
            Ok((
                cookie_jar,
                url_builder.redirect(&mas_router::RegisterFinish::new(registration.id)),
            )
                .into_response())
        }

        _ => Err(RouteError::InvalidFormAction),
    }
}

/// Create a user registration using attributes got from the upstream
/// authorization session
async fn prepare_user_registration(
    rng: &mut BoxRng,
    clock: &BoxClock,
    repo: &mut BoxRepository,
    upstream_session: UpstreamOAuthAuthorizationSession,
    localpart: String,
    displayname: Option<String>,
    email: Option<String>,
    ip_address: Option<IpAddr>,
    user_agent: Option<String>,
    post_auth_action: Option<serde_json::Value>,
) -> Result<UserRegistration, RouteError> {
    let mut registration = repo
        .user_registration()
        .add(
            rng,
            clock,
            localpart,
            ip_address,
            user_agent,
            post_auth_action,
        )
        .await?;

    // If we have an email, add an email authentication and complete it
    if let Some(email) = email {
        let authentication = repo
            .user_email()
            .add_authentication_for_registration(rng, clock, email, &registration)
            .await?;
        let authentication = repo
            .user_email()
            .complete_authentication_with_upstream(clock, authentication, &upstream_session)
            .await?;

        registration = repo
            .user_registration()
            .set_email_authentication(registration, &authentication)
            .await?;
    }

    // If we have a display name, add it to the registration
    if let Some(name) = displayname {
        registration = repo
            .user_registration()
            .set_display_name(registration, name)
            .await?;
    }

    let registration = repo
        .user_registration()
        .set_upstream_oauth_authorization_session(registration, &upstream_session)
        .await?;

    Ok(registration)
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode, header::CONTENT_TYPE};
    use mas_data_model::{
        UpstreamOAuthAuthorizationSession, UpstreamOAuthLink, UpstreamOAuthProviderClaimsImports,
        UpstreamOAuthProviderImportPreference, UpstreamOAuthProviderLocalpartPreference,
        UpstreamOAuthProviderTokenAuthMethod, UserEmailAuthentication, UserRegistration,
    };
    use mas_iana::jose::JsonWebSignatureAlg;
    use mas_jose::jwt::{JsonWebSignatureHeader, Jwt};
    use mas_keystore::Keystore;
    use mas_router::Route;
    use mas_storage::{Repository, RepositoryError, upstream_oauth2::UpstreamOAuthProviderParams};
    use oauth2_types::scope::{OPENID, Scope};
    use rand_chacha::ChaChaRng;
    use serde_json::Value;
    use sqlx::PgPool;
    use ulid::Ulid;

    use super::UpstreamSessionsCookie;
    use crate::test_utils::{CookieHelper, RequestBuilderExt, ResponseExt, TestState, setup};

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_register(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let mut rng = state.rng();
        let cookies = CookieHelper::new();

        let claims_imports = UpstreamOAuthProviderClaimsImports {
            localpart: UpstreamOAuthProviderLocalpartPreference {
                action: mas_data_model::UpstreamOAuthProviderImportAction::Force,
                template: None,
                on_conflict: mas_data_model::UpstreamOAuthProviderOnConflict::default(),
            },
            email: UpstreamOAuthProviderImportPreference {
                action: mas_data_model::UpstreamOAuthProviderImportAction::Force,
                template: None,
            },
            ..UpstreamOAuthProviderClaimsImports::default()
        };

        let id_token_claims = serde_json::json!({
            "preferred_username": "john",
            "email": "john@example.com",
            "email_verified": true,
        });

        // Grab a key to sign the id_token
        // We could generate a key on the fly, but because we have one available
        // here, why not use it?
        let key = state
            .key_store
            .signing_key_for_algorithm(&JsonWebSignatureAlg::Rs256)
            .unwrap();

        let signer = key
            .params()
            .signing_key_for_alg(&JsonWebSignatureAlg::Rs256)
            .unwrap();
        let header = JsonWebSignatureHeader::new(JsonWebSignatureAlg::Rs256);
        let id_token =
            Jwt::sign_with_rng(&mut rng, header, id_token_claims.clone(), &signer).unwrap();

        // Provision a provider and a link
        let mut repo = state.repository().await.unwrap();
        let provider = repo
            .upstream_oauth_provider()
            .add(
                &mut rng,
                &state.clock,
                UpstreamOAuthProviderParams {
                    issuer: Some("https://example.com/".to_owned()),
                    human_name: Some("Example Ltd.".to_owned()),
                    brand_name: None,
                    scope: Scope::from_iter([OPENID]),
                    token_endpoint_auth_method: UpstreamOAuthProviderTokenAuthMethod::None,
                    token_endpoint_signing_alg: None,
                    id_token_signed_response_alg: JsonWebSignatureAlg::Rs256,
                    client_id: "client".to_owned(),
                    encrypted_client_secret: None,
                    claims_imports,
                    authorization_endpoint_override: None,
                    token_endpoint_override: None,
                    userinfo_endpoint_override: None,
                    fetch_userinfo: false,
                    userinfo_signed_response_alg: None,
                    jwks_uri_override: None,
                    discovery_mode: mas_data_model::UpstreamOAuthProviderDiscoveryMode::Oidc,
                    pkce_mode: mas_data_model::UpstreamOAuthProviderPkceMode::Auto,
                    response_mode: None,
                    additional_authorization_parameters: Vec::new(),
                    forward_login_hint: false,
                    ui_order: 0,
                    on_backchannel_logout:
                        mas_data_model::UpstreamOAuthProviderOnBackchannelLogout::DoNothing,
                    registration_token_required: false,
                },
            )
            .await
            .unwrap();

        let session = repo
            .upstream_oauth_session()
            .add(
                &mut rng,
                &state.clock,
                &provider,
                "state".to_owned(),
                None,
                None,
            )
            .await
            .unwrap();

        let link = repo
            .upstream_oauth_link()
            .add(
                &mut rng,
                &state.clock,
                &provider,
                "subject".to_owned(),
                None,
            )
            .await
            .unwrap();

        let session = repo
            .upstream_oauth_session()
            .complete_with_link(
                &state.clock,
                session,
                &link,
                Some(id_token.into_string()),
                Some(id_token_claims),
                None,
                None,
            )
            .await
            .unwrap();

        repo.save().await.unwrap();

        let cookie_jar = state.cookie_jar();
        let upstream_sessions = UpstreamSessionsCookie::default()
            .add(session.id, provider.id, "state".to_owned(), None)
            .add_link_to_session(session.id, link.id)
            .unwrap();
        let cookie_jar = upstream_sessions.save(cookie_jar, &state.clock);
        cookies.import(cookie_jar);

        let request = Request::get(&*mas_router::UpstreamOAuth2Link::new(link.id).path()).empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");

        // Extract the CSRF token from the response body
        let csrf_token = response
            .body()
            .split("name=\"csrf\" value=\"")
            .nth(1)
            .unwrap()
            .split('\"')
            .next()
            .unwrap();

        let request = Request::post(&*mas_router::UpstreamOAuth2Link::new(link.id).path()).form(
            serde_json::json!({
                "csrf": csrf_token,
                "action": "register",
                "import_email": "on",
                "accept_terms": "on",
            }),
        );
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::SEE_OTHER);
        let location = response.headers().get(hyper::header::LOCATION).unwrap();
        // Grab the registration ID from the redirected URL:
        //   /register/steps/{id}/finish
        let registration_id: Ulid = str::from_utf8(location.as_bytes())
            .unwrap()
            .rsplit('/')
            .nth(1)
            .expect("Location to have two slashes")
            .parse()
            .expect("last segment of location to be a ULID");

        // Check that we have a registered user, with the email imported
        let mut repo = state.repository().await.unwrap();
        let registration: UserRegistration = repo
            .user_registration()
            .lookup(registration_id)
            .await
            .unwrap()
            .expect("user registration exists");

        assert_eq!(registration.password, None);
        assert_eq!(registration.completed_at, None);
        assert_eq!(registration.username, "john");

        let email_auth_id = registration
            .email_authentication_id
            .expect("registration should have an email authentication");
        let email_auth: UserEmailAuthentication = repo
            .user_email()
            .lookup_authentication(email_auth_id)
            .await
            .unwrap()
            .expect("email authentication should exist");
        assert_eq!(email_auth.email, "john@example.com");
        assert!(email_auth.completed_at.is_some());
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_register_skip_confirmation(pool: PgPool) {
        // Same test as test_register, but checks that we get straight to the
        // registration flow skipping the confirmation
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let mut rng = state.rng();
        let cookies = CookieHelper::new();

        let claims_imports = UpstreamOAuthProviderClaimsImports {
            skip_confirmation: true,
            localpart: UpstreamOAuthProviderLocalpartPreference {
                action: mas_data_model::UpstreamOAuthProviderImportAction::Require,
                template: None,
                on_conflict: mas_data_model::UpstreamOAuthProviderOnConflict::default(),
            },
            email: UpstreamOAuthProviderImportPreference {
                action: mas_data_model::UpstreamOAuthProviderImportAction::Force,
                template: None,
            },
            ..UpstreamOAuthProviderClaimsImports::default()
        };

        let id_token_claims = serde_json::json!({
            "preferred_username": "john",
            "email": "john@example.com",
            "email_verified": true,
        });

        // Grab a key to sign the id_token
        // We could generate a key on the fly, but because we have one available
        // here, why not use it?
        let key = state
            .key_store
            .signing_key_for_algorithm(&JsonWebSignatureAlg::Rs256)
            .unwrap();

        let signer = key
            .params()
            .signing_key_for_alg(&JsonWebSignatureAlg::Rs256)
            .unwrap();
        let header = JsonWebSignatureHeader::new(JsonWebSignatureAlg::Rs256);
        let id_token =
            Jwt::sign_with_rng(&mut rng, header, id_token_claims.clone(), &signer).unwrap();

        // Provision a provider and a link
        let mut repo = state.repository().await.unwrap();
        let provider = repo
            .upstream_oauth_provider()
            .add(
                &mut rng,
                &state.clock,
                UpstreamOAuthProviderParams {
                    issuer: Some("https://example.com/".to_owned()),
                    human_name: Some("Example Ltd.".to_owned()),
                    brand_name: None,
                    scope: Scope::from_iter([OPENID]),
                    token_endpoint_auth_method: UpstreamOAuthProviderTokenAuthMethod::None,
                    token_endpoint_signing_alg: None,
                    id_token_signed_response_alg: JsonWebSignatureAlg::Rs256,
                    client_id: "client".to_owned(),
                    encrypted_client_secret: None,
                    claims_imports,
                    authorization_endpoint_override: None,
                    token_endpoint_override: None,
                    userinfo_endpoint_override: None,
                    fetch_userinfo: false,
                    userinfo_signed_response_alg: None,
                    jwks_uri_override: None,
                    discovery_mode: mas_data_model::UpstreamOAuthProviderDiscoveryMode::Oidc,
                    pkce_mode: mas_data_model::UpstreamOAuthProviderPkceMode::Auto,
                    response_mode: None,
                    additional_authorization_parameters: Vec::new(),
                    forward_login_hint: false,
                    ui_order: 0,
                    on_backchannel_logout:
                        mas_data_model::UpstreamOAuthProviderOnBackchannelLogout::DoNothing,
                    registration_token_required: false,
                },
            )
            .await
            .unwrap();

        let session = repo
            .upstream_oauth_session()
            .add(
                &mut rng,
                &state.clock,
                &provider,
                "state".to_owned(),
                None,
                None,
            )
            .await
            .unwrap();

        let link = repo
            .upstream_oauth_link()
            .add(
                &mut rng,
                &state.clock,
                &provider,
                "subject".to_owned(),
                None,
            )
            .await
            .unwrap();

        let session = repo
            .upstream_oauth_session()
            .complete_with_link(
                &state.clock,
                session,
                &link,
                Some(id_token.into_string()),
                Some(id_token_claims),
                None,
                None,
            )
            .await
            .unwrap();

        repo.save().await.unwrap();

        let cookie_jar = state.cookie_jar();
        let upstream_sessions = UpstreamSessionsCookie::default()
            .add(session.id, provider.id, "state".to_owned(), None)
            .add_link_to_session(session.id, link.id)
            .unwrap();
        let cookie_jar = upstream_sessions.save(cookie_jar, &state.clock);
        cookies.import(cookie_jar);

        let request = Request::get(&*mas_router::UpstreamOAuth2Link::new(link.id).path()).empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        let location = response.headers().get(hyper::header::LOCATION).unwrap();
        // Grab the registration ID from the redirected URL:
        //   /register/steps/{id}/finish
        let registration_id: Ulid = str::from_utf8(location.as_bytes())
            .unwrap()
            .rsplit('/')
            .nth(1)
            .expect("Location to have two slashes")
            .parse()
            .expect("last segment of location to be a ULID");

        // Check that we have a registered user, with the email imported
        let mut repo = state.repository().await.unwrap();
        let registration: UserRegistration = repo
            .user_registration()
            .lookup(registration_id)
            .await
            .unwrap()
            .expect("user registration exists");

        assert_eq!(registration.password, None);
        assert_eq!(registration.completed_at, None);
        assert_eq!(registration.username, "john");

        let email_auth_id = registration
            .email_authentication_id
            .expect("registration should have an email authentication");
        let email_auth: UserEmailAuthentication = repo
            .user_email()
            .lookup_authentication(email_auth_id)
            .await
            .unwrap()
            .expect("email authentication should exist");
        assert_eq!(email_auth.email, "john@example.com");
        assert!(email_auth.completed_at.is_some());
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_link_existing_account(pool: PgPool) {
        let existing_username = "john";
        let subject = "subject";

        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let mut rng = state.rng();
        let cookies = CookieHelper::new();

        let claims_imports = UpstreamOAuthProviderClaimsImports {
            localpart: UpstreamOAuthProviderLocalpartPreference {
                action: mas_data_model::UpstreamOAuthProviderImportAction::Require,
                template: None,
                // This is the important bit: this will automatically link
                // existing accounts if the localpart matches
                on_conflict: mas_data_model::UpstreamOAuthProviderOnConflict::Add,
            },
            email: UpstreamOAuthProviderImportPreference {
                action: mas_data_model::UpstreamOAuthProviderImportAction::Require,
                template: None,
            },
            ..UpstreamOAuthProviderClaimsImports::default()
        };

        //`preferred_username` matches an existing user's username
        let id_token_claims = serde_json::json!({
            "preferred_username": existing_username,
            "email": "any@example.com",
            "email_verified": true,
        });

        let id_token = sign_token(&mut rng, &state.key_store, id_token_claims.clone()).unwrap();

        // Provision a provider and a link
        let mut repo = state.repository().await.unwrap();
        let provider = repo
            .upstream_oauth_provider()
            .add(
                &mut rng,
                &state.clock,
                UpstreamOAuthProviderParams {
                    issuer: Some("https://example.com/".to_owned()),
                    human_name: Some("Example Ltd.".to_owned()),
                    brand_name: None,
                    scope: Scope::from_iter([OPENID]),
                    token_endpoint_auth_method: UpstreamOAuthProviderTokenAuthMethod::None,
                    token_endpoint_signing_alg: None,
                    id_token_signed_response_alg: JsonWebSignatureAlg::Rs256,
                    client_id: "client".to_owned(),
                    encrypted_client_secret: None,
                    claims_imports,
                    authorization_endpoint_override: None,
                    token_endpoint_override: None,
                    userinfo_endpoint_override: None,
                    fetch_userinfo: false,
                    userinfo_signed_response_alg: None,
                    jwks_uri_override: None,
                    discovery_mode: mas_data_model::UpstreamOAuthProviderDiscoveryMode::Oidc,
                    pkce_mode: mas_data_model::UpstreamOAuthProviderPkceMode::Auto,
                    response_mode: None,
                    additional_authorization_parameters: Vec::new(),
                    forward_login_hint: false,
                    on_backchannel_logout:
                        mas_data_model::UpstreamOAuthProviderOnBackchannelLogout::DoNothing,
                    ui_order: 0,
                    registration_token_required: false,
                },
            )
            .await
            .unwrap();

        //provision upstream authorization session to setup cookies
        let (link, session) = add_linked_upstream_session(
            &mut rng,
            &state.clock,
            &mut repo,
            &provider,
            subject,
            &id_token.into_string(),
            id_token_claims,
        )
        .await
        .unwrap();

        let cookie_jar = state.cookie_jar();
        let upstream_sessions = UpstreamSessionsCookie::default()
            .add(session.id, provider.id, "state".to_owned(), None)
            .add_link_to_session(session.id, link.id)
            .unwrap();
        let cookie_jar = upstream_sessions.save(cookie_jar, &state.clock);
        cookies.import(cookie_jar);

        let user = repo
            .user()
            .add(&mut rng, &state.clock, existing_username.to_owned())
            .await
            .unwrap();

        repo.save().await.unwrap();

        let request = Request::get(&*mas_router::UpstreamOAuth2Link::new(link.id).path()).empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::SEE_OTHER);

        // Check that the existing user has the oidc link
        let mut repo = state.repository().await.unwrap();

        let link = repo
            .upstream_oauth_link()
            .find_by_subject(&provider, subject)
            .await
            .unwrap()
            .expect("link exists");

        assert_eq!(link.user_id, Some(user.id));
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_link_existing_account_when_not_allowed_by_default(pool: PgPool) {
        let existing_username = "john";

        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let mut rng = state.rng();
        let cookies = CookieHelper::new();

        let claims_imports = UpstreamOAuthProviderClaimsImports {
            localpart: UpstreamOAuthProviderLocalpartPreference {
                action: mas_data_model::UpstreamOAuthProviderImportAction::Require,
                template: None,
                on_conflict: mas_data_model::UpstreamOAuthProviderOnConflict::default(),
            },
            email: UpstreamOAuthProviderImportPreference {
                action: mas_data_model::UpstreamOAuthProviderImportAction::Require,
                template: None,
            },
            ..UpstreamOAuthProviderClaimsImports::default()
        };

        // `preferred_username` matches an existing user's username
        let id_token_claims = serde_json::json!({
            "preferred_username": existing_username,
            "email": "any@example.com",
            "email_verified": true,
        });

        let id_token = sign_token(&mut rng, &state.key_store, id_token_claims.clone()).unwrap();

        // Provision a provider and a link
        let mut repo = state.repository().await.unwrap();
        let provider = repo
            .upstream_oauth_provider()
            .add(
                &mut rng,
                &state.clock,
                UpstreamOAuthProviderParams {
                    issuer: Some("https://example.com/".to_owned()),
                    human_name: Some("Example Ltd.".to_owned()),
                    brand_name: None,
                    scope: Scope::from_iter([OPENID]),
                    token_endpoint_auth_method: UpstreamOAuthProviderTokenAuthMethod::None,
                    token_endpoint_signing_alg: None,
                    id_token_signed_response_alg: JsonWebSignatureAlg::Rs256,
                    client_id: "client".to_owned(),
                    encrypted_client_secret: None,
                    claims_imports,
                    authorization_endpoint_override: None,
                    token_endpoint_override: None,
                    userinfo_endpoint_override: None,
                    fetch_userinfo: false,
                    userinfo_signed_response_alg: None,
                    jwks_uri_override: None,
                    discovery_mode: mas_data_model::UpstreamOAuthProviderDiscoveryMode::Oidc,
                    pkce_mode: mas_data_model::UpstreamOAuthProviderPkceMode::Auto,
                    response_mode: None,
                    additional_authorization_parameters: Vec::new(),
                    forward_login_hint: false,
                    on_backchannel_logout:
                        mas_data_model::UpstreamOAuthProviderOnBackchannelLogout::DoNothing,
                    ui_order: 0,
                    registration_token_required: false,
                },
            )
            .await
            .unwrap();

        let (link, session) = add_linked_upstream_session(
            &mut rng,
            &state.clock,
            &mut repo,
            &provider,
            "subject",
            &id_token.into_string(),
            id_token_claims,
        )
        .await
        .unwrap();

        // Provision an user
        repo.user()
            .add(&mut rng, &state.clock, existing_username.to_owned())
            .await
            .unwrap();

        repo.save().await.unwrap();

        let cookie_jar = state.cookie_jar();
        let upstream_sessions = UpstreamSessionsCookie::default()
            .add(session.id, provider.id, "state".to_owned(), None)
            .add_link_to_session(session.id, link.id)
            .unwrap();
        let cookie_jar = upstream_sessions.save(cookie_jar, &state.clock);
        cookies.import(cookie_jar);

        let request = Request::get(&*mas_router::UpstreamOAuth2Link::new(link.id).path()).empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");

        assert!(response.body().contains("Unexpected error"));
    }

    fn sign_token(
        rng: &mut ChaChaRng,
        keystore: &Keystore,
        payload: Value,
    ) -> Result<Jwt<'static, Value>, mas_jose::jwt::JwtSignatureError> {
        let key = keystore
            .signing_key_for_algorithm(&JsonWebSignatureAlg::Rs256)
            .unwrap();

        let signer = key
            .params()
            .signing_key_for_alg(&JsonWebSignatureAlg::Rs256)
            .unwrap();

        let header = JsonWebSignatureHeader::new(JsonWebSignatureAlg::Rs256);

        Jwt::sign_with_rng(rng, header, payload, &signer)
    }

    async fn add_linked_upstream_session(
        rng: &mut ChaChaRng,
        clock: &impl mas_data_model::Clock,
        repo: &mut Box<dyn Repository<RepositoryError> + Send + Sync + 'static>,
        provider: &mas_data_model::UpstreamOAuthProvider,
        subject: &str,
        id_token: &str,
        id_token_claims: Value,
    ) -> Result<(UpstreamOAuthLink, UpstreamOAuthAuthorizationSession), anyhow::Error> {
        let session = repo
            .upstream_oauth_session()
            .add(
                rng,
                clock,
                provider,
                "state".to_owned(),
                None,
                Some("nonce".to_owned()),
            )
            .await?;

        let link = repo
            .upstream_oauth_link()
            .add(rng, clock, provider, subject.to_owned(), None)
            .await?;

        let session = repo
            .upstream_oauth_session()
            .complete_with_link(
                clock,
                session,
                &link,
                Some(id_token.to_owned()),
                Some(id_token_claims),
                None,
                None,
            )
            .await?;

        Ok((link, session))
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_link_existing_account_replace_conflict(pool: PgPool) {
        let existing_username = "john";
        let subject = "subject";
        let old_subject = "old_subject";

        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let mut rng = state.rng();
        let cookies = CookieHelper::new();

        let claims_imports = UpstreamOAuthProviderClaimsImports {
            localpart: UpstreamOAuthProviderLocalpartPreference {
                action: mas_data_model::UpstreamOAuthProviderImportAction::Require,
                template: None,
                // This will replace any existing links for this provider and user
                on_conflict: mas_data_model::UpstreamOAuthProviderOnConflict::Replace,
            },
            email: UpstreamOAuthProviderImportPreference {
                action: mas_data_model::UpstreamOAuthProviderImportAction::Require,
                template: None,
            },
            ..UpstreamOAuthProviderClaimsImports::default()
        };

        let id_token_claims = serde_json::json!({
            "preferred_username": existing_username,
            "email": "any@example.com",
            "email_verified": true,
        });

        let id_token = sign_token(&mut rng, &state.key_store, id_token_claims.clone()).unwrap();

        // Provision a provider and a link
        let mut repo = state.repository().await.unwrap();
        let provider = repo
            .upstream_oauth_provider()
            .add(
                &mut rng,
                &state.clock,
                UpstreamOAuthProviderParams {
                    issuer: Some("https://example.com/".to_owned()),
                    human_name: Some("Example Ltd.".to_owned()),
                    brand_name: None,
                    scope: Scope::from_iter([OPENID]),
                    token_endpoint_auth_method: UpstreamOAuthProviderTokenAuthMethod::None,
                    token_endpoint_signing_alg: None,
                    id_token_signed_response_alg: JsonWebSignatureAlg::Rs256,
                    client_id: "client".to_owned(),
                    encrypted_client_secret: None,
                    claims_imports,
                    authorization_endpoint_override: None,
                    token_endpoint_override: None,
                    userinfo_endpoint_override: None,
                    fetch_userinfo: false,
                    userinfo_signed_response_alg: None,
                    jwks_uri_override: None,
                    discovery_mode: mas_data_model::UpstreamOAuthProviderDiscoveryMode::Oidc,
                    pkce_mode: mas_data_model::UpstreamOAuthProviderPkceMode::Auto,
                    response_mode: None,
                    additional_authorization_parameters: Vec::new(),
                    forward_login_hint: false,
                    on_backchannel_logout:
                        mas_data_model::UpstreamOAuthProviderOnBackchannelLogout::DoNothing,
                    ui_order: 0,
                    registration_token_required: false,
                },
            )
            .await
            .unwrap();

        // Create an existing user
        let user = repo
            .user()
            .add(&mut rng, &state.clock, existing_username.to_owned())
            .await
            .unwrap();

        // Create an existing link for this user and provider with a different
        // subject
        let old_link = repo
            .upstream_oauth_link()
            .add(
                &mut rng,
                &state.clock,
                &provider,
                old_subject.to_owned(),
                None,
            )
            .await
            .unwrap();

        repo.upstream_oauth_link()
            .associate_to_user(&old_link, &user)
            .await
            .unwrap();

        // Provision upstream authorization session to setup cookies
        let (link, session) = add_linked_upstream_session(
            &mut rng,
            &state.clock,
            &mut repo,
            &provider,
            subject,
            &id_token.into_string(),
            id_token_claims,
        )
        .await
        .unwrap();

        repo.save().await.unwrap();

        let cookie_jar = state.cookie_jar();
        let upstream_sessions = UpstreamSessionsCookie::default()
            .add(session.id, provider.id, "state".to_owned(), None)
            .add_link_to_session(session.id, link.id)
            .unwrap();
        let cookie_jar = upstream_sessions.save(cookie_jar, &state.clock);
        cookies.import(cookie_jar);

        let request = Request::get(&*mas_router::UpstreamOAuth2Link::new(link.id).path()).empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::SEE_OTHER);

        // Check that the new link is associated with the existing user
        let mut repo = state.repository().await.unwrap();

        let new_link = repo
            .upstream_oauth_link()
            .find_by_subject(&provider, subject)
            .await
            .unwrap()
            .expect("new link exists");

        assert_eq!(new_link.user_id, Some(user.id));

        // Check that the old link was removed
        let old_link_result = repo
            .upstream_oauth_link()
            .find_by_subject(&provider, old_subject)
            .await
            .unwrap();

        assert!(
            old_link_result.is_none(),
            "Old link should have been removed"
        );
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_link_existing_account_set_conflict_success(pool: PgPool) {
        let existing_username = "john";
        let subject = "subject";

        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let mut rng = state.rng();
        let cookies = CookieHelper::new();

        let claims_imports = UpstreamOAuthProviderClaimsImports {
            localpart: UpstreamOAuthProviderLocalpartPreference {
                action: mas_data_model::UpstreamOAuthProviderImportAction::Require,
                template: None,
                // This will only link if there are no existing links for this provider and user
                on_conflict: mas_data_model::UpstreamOAuthProviderOnConflict::Set,
            },
            email: UpstreamOAuthProviderImportPreference {
                action: mas_data_model::UpstreamOAuthProviderImportAction::Require,
                template: None,
            },
            ..UpstreamOAuthProviderClaimsImports::default()
        };

        let id_token_claims = serde_json::json!({
            "preferred_username": existing_username,
            "email": "any@example.com",
            "email_verified": true,
        });

        let id_token = sign_token(&mut rng, &state.key_store, id_token_claims.clone()).unwrap();

        // Provision a provider and a link
        let mut repo = state.repository().await.unwrap();
        let provider = repo
            .upstream_oauth_provider()
            .add(
                &mut rng,
                &state.clock,
                UpstreamOAuthProviderParams {
                    issuer: Some("https://example.com/".to_owned()),
                    human_name: Some("Example Ltd.".to_owned()),
                    brand_name: None,
                    scope: Scope::from_iter([OPENID]),
                    token_endpoint_auth_method: UpstreamOAuthProviderTokenAuthMethod::None,
                    token_endpoint_signing_alg: None,
                    id_token_signed_response_alg: JsonWebSignatureAlg::Rs256,
                    client_id: "client".to_owned(),
                    encrypted_client_secret: None,
                    claims_imports,
                    authorization_endpoint_override: None,
                    token_endpoint_override: None,
                    userinfo_endpoint_override: None,
                    fetch_userinfo: false,
                    userinfo_signed_response_alg: None,
                    jwks_uri_override: None,
                    discovery_mode: mas_data_model::UpstreamOAuthProviderDiscoveryMode::Oidc,
                    pkce_mode: mas_data_model::UpstreamOAuthProviderPkceMode::Auto,
                    response_mode: None,
                    additional_authorization_parameters: Vec::new(),
                    forward_login_hint: false,
                    on_backchannel_logout:
                        mas_data_model::UpstreamOAuthProviderOnBackchannelLogout::DoNothing,
                    ui_order: 0,
                    registration_token_required: false,
                },
            )
            .await
            .unwrap();

        // Create an existing user (with no existing links for this provider)
        let user = repo
            .user()
            .add(&mut rng, &state.clock, existing_username.to_owned())
            .await
            .unwrap();

        // Provision upstream authorization session to setup cookies
        let (link, session) = add_linked_upstream_session(
            &mut rng,
            &state.clock,
            &mut repo,
            &provider,
            subject,
            &id_token.into_string(),
            id_token_claims,
        )
        .await
        .unwrap();

        repo.save().await.unwrap();

        let cookie_jar = state.cookie_jar();
        let upstream_sessions = UpstreamSessionsCookie::default()
            .add(session.id, provider.id, "state".to_owned(), None)
            .add_link_to_session(session.id, link.id)
            .unwrap();
        let cookie_jar = upstream_sessions.save(cookie_jar, &state.clock);
        cookies.import(cookie_jar);

        let request = Request::get(&*mas_router::UpstreamOAuth2Link::new(link.id).path()).empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::SEE_OTHER);

        // Check that the new link is associated with the existing user
        let mut repo = state.repository().await.unwrap();

        let new_link = repo
            .upstream_oauth_link()
            .find_by_subject(&provider, subject)
            .await
            .unwrap()
            .expect("new link exists");

        assert_eq!(new_link.user_id, Some(user.id));
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_link_existing_account_set_conflict_failure(pool: PgPool) {
        let existing_username = "john";
        let subject = "subject";
        let old_subject = "old_subject";

        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let mut rng = state.rng();
        let cookies = CookieHelper::new();

        let claims_imports = UpstreamOAuthProviderClaimsImports {
            localpart: UpstreamOAuthProviderLocalpartPreference {
                action: mas_data_model::UpstreamOAuthProviderImportAction::Require,
                template: None,
                // This will only link if there are no existing links for this provider and user
                on_conflict: mas_data_model::UpstreamOAuthProviderOnConflict::Set,
            },
            email: UpstreamOAuthProviderImportPreference {
                action: mas_data_model::UpstreamOAuthProviderImportAction::Require,
                template: None,
            },
            ..UpstreamOAuthProviderClaimsImports::default()
        };

        let id_token_claims = serde_json::json!({
            "preferred_username": existing_username,
            "email": "any@example.com",
            "email_verified": true,
        });

        let id_token = sign_token(&mut rng, &state.key_store, id_token_claims.clone()).unwrap();

        // Provision a provider and a link
        let mut repo = state.repository().await.unwrap();
        let provider = repo
            .upstream_oauth_provider()
            .add(
                &mut rng,
                &state.clock,
                UpstreamOAuthProviderParams {
                    issuer: Some("https://example.com/".to_owned()),
                    human_name: Some("Example Ltd.".to_owned()),
                    brand_name: None,
                    scope: Scope::from_iter([OPENID]),
                    token_endpoint_auth_method: UpstreamOAuthProviderTokenAuthMethod::None,
                    token_endpoint_signing_alg: None,
                    id_token_signed_response_alg: JsonWebSignatureAlg::Rs256,
                    client_id: "client".to_owned(),
                    encrypted_client_secret: None,
                    claims_imports,
                    authorization_endpoint_override: None,
                    token_endpoint_override: None,
                    userinfo_endpoint_override: None,
                    fetch_userinfo: false,
                    userinfo_signed_response_alg: None,
                    jwks_uri_override: None,
                    discovery_mode: mas_data_model::UpstreamOAuthProviderDiscoveryMode::Oidc,
                    pkce_mode: mas_data_model::UpstreamOAuthProviderPkceMode::Auto,
                    response_mode: None,
                    additional_authorization_parameters: Vec::new(),
                    forward_login_hint: false,
                    on_backchannel_logout:
                        mas_data_model::UpstreamOAuthProviderOnBackchannelLogout::DoNothing,
                    ui_order: 0,
                    registration_token_required: false,
                },
            )
            .await
            .unwrap();

        // Create an existing user
        let user = repo
            .user()
            .add(&mut rng, &state.clock, existing_username.to_owned())
            .await
            .unwrap();

        // Create an existing link for this user and provider with a different
        // subject
        let old_link = repo
            .upstream_oauth_link()
            .add(
                &mut rng,
                &state.clock,
                &provider,
                old_subject.to_owned(),
                None,
            )
            .await
            .unwrap();

        repo.upstream_oauth_link()
            .associate_to_user(&old_link, &user)
            .await
            .unwrap();

        // Provision upstream authorization session to setup cookies
        let (link, session) = add_linked_upstream_session(
            &mut rng,
            &state.clock,
            &mut repo,
            &provider,
            subject,
            &id_token.into_string(),
            id_token_claims,
        )
        .await
        .unwrap();

        repo.save().await.unwrap();

        let cookie_jar = state.cookie_jar();
        let upstream_sessions = UpstreamSessionsCookie::default()
            .add(session.id, provider.id, "state".to_owned(), None)
            .add_link_to_session(session.id, link.id)
            .unwrap();
        let cookie_jar = upstream_sessions.save(cookie_jar, &state.clock);
        cookies.import(cookie_jar);

        let request = Request::get(&*mas_router::UpstreamOAuth2Link::new(link.id).path()).empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);

        // Should return an error page because the user already has a link for
        // this provider
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");

        // Verify the error message is displayed
        assert!(response.body().contains("This username is already taken"));
        assert!(!response.body().contains("homeserver"));

        // Check that the new link was NOT associated with the existing user
        let mut repo = state.repository().await.unwrap();

        let new_link = repo
            .upstream_oauth_link()
            .find_by_subject(&provider, subject)
            .await
            .unwrap()
            .expect("new link exists");

        // The new link should still not be associated with the user
        assert_eq!(new_link.user_id, None);

        // Check that the old link is still there
        let old_link_result = repo
            .upstream_oauth_link()
            .find_by_subject(&provider, old_subject)
            .await
            .unwrap();

        assert!(old_link_result.is_some(), "Old link should still exist");
        assert_eq!(old_link_result.unwrap().user_id, Some(user.id));
    }

    /// GUA FORK: a browser session never continues an upstream sign-in as
    /// another account, and a recovery sign-in ends every other session.
    mod gua {
        use axum::response::IntoResponse;
        use hyper::{Request, StatusCode, header::LOCATION};
        use mas_axum_utils::{SessionInfoExt, csrf::CsrfExt};
        use mas_data_model::{
            BrowserSession, Device, UpstreamOAuthAuthorizationSession, UpstreamOAuthLink,
            UpstreamOAuthProvider, UpstreamOAuthProviderClaimsImports,
            UpstreamOAuthProviderLocalpartPreference, UpstreamOAuthProviderTokenAuthMethod, User,
        };
        use mas_iana::jose::JsonWebSignatureAlg;
        use mas_router::{PostAuthAction, Route, SimpleRoute};
        use mas_storage::{
            BoxRepository, upstream_oauth2::UpstreamOAuthProviderParams, user::BrowserSessionFilter,
        };
        use oauth2_types::{
            registration::ClientRegistrationResponse,
            scope::{OPENID, Scope},
        };
        use serde_json::Value;
        use sqlx::{PgPool, types::Json};
        use ulid::Ulid;

        use super::{UpstreamSessionsCookie, sign_token};
        use crate::{
            test_utils::{CookieHelper, RequestBuilderExt, ResponseExt, TestState, setup},
            views::shared::OptionalPostAuthAction,
        };

        /// Every kind of post-auth action an upstream sign-in can carry.
        fn post_auth_actions() -> Vec<Option<PostAuthAction>> {
            vec![
                None,
                Some(PostAuthAction::continue_grant(Ulid::nil())),
                Some(PostAuthAction::continue_device_code_grant(Ulid::nil())),
                Some(PostAuthAction::continue_compat_sso_login(Ulid::nil())),
                Some(PostAuthAction::ChangePassword),
                Some(PostAuthAction::link_upstream(Ulid::nil())),
                Some(PostAuthAction::manage_account(None)),
            ]
        }

        async fn add_provider(
            state: &TestState,
            repo: &mut BoxRepository,
        ) -> UpstreamOAuthProvider {
            add_provider_with(state, repo, UpstreamOAuthProviderClaimsImports::default()).await
        }

        async fn add_provider_with(
            state: &TestState,
            repo: &mut BoxRepository,
            claims_imports: UpstreamOAuthProviderClaimsImports,
        ) -> UpstreamOAuthProvider {
            repo.upstream_oauth_provider()
                .add(
                    &mut state.rng(),
                    &state.clock,
                    UpstreamOAuthProviderParams {
                        issuer: Some("https://example.com/".to_owned()),
                        human_name: Some("Example Ltd.".to_owned()),
                        brand_name: None,
                        scope: Scope::from_iter([OPENID]),
                        token_endpoint_auth_method: UpstreamOAuthProviderTokenAuthMethod::None,
                        token_endpoint_signing_alg: None,
                        id_token_signed_response_alg: JsonWebSignatureAlg::Rs256,
                        client_id: "client".to_owned(),
                        encrypted_client_secret: None,
                        claims_imports,
                        authorization_endpoint_override: None,
                        token_endpoint_override: None,
                        userinfo_endpoint_override: None,
                        fetch_userinfo: false,
                        userinfo_signed_response_alg: None,
                        jwks_uri_override: None,
                        discovery_mode: mas_data_model::UpstreamOAuthProviderDiscoveryMode::Oidc,
                        pkce_mode: mas_data_model::UpstreamOAuthProviderPkceMode::Auto,
                        response_mode: None,
                        additional_authorization_parameters: Vec::new(),
                        forward_login_hint: false,
                        on_backchannel_logout:
                            mas_data_model::UpstreamOAuthProviderOnBackchannelLogout::DoNothing,
                        ui_order: 0,
                        registration_token_required: false,
                    },
                )
                .await
                .unwrap()
        }

        /// A completed upstream sign-in for `subject`, with the given ID token
        /// claims. Each gets its own state, which must be unique.
        async fn add_upstream_sign_in(
            state: &TestState,
            repo: &mut BoxRepository,
            provider: &UpstreamOAuthProvider,
            subject: &str,
            id_token_claims: Value,
        ) -> (UpstreamOAuthLink, UpstreamOAuthAuthorizationSession) {
            let mut rng = state.rng();
            let id_token = sign_token(&mut rng, &state.key_store, id_token_claims.clone()).unwrap();
            let upstream_session = repo
                .upstream_oauth_session()
                .add(
                    &mut rng,
                    &state.clock,
                    provider,
                    format!("state-{subject}"),
                    None,
                    Some("nonce".to_owned()),
                )
                .await
                .unwrap();
            let link = repo
                .upstream_oauth_link()
                .add(&mut rng, &state.clock, provider, subject.to_owned(), None)
                .await
                .unwrap();
            let upstream_session = repo
                .upstream_oauth_session()
                .complete_with_link(
                    &state.clock,
                    upstream_session,
                    &link,
                    Some(id_token.into_string()),
                    Some(id_token_claims),
                    None,
                    None,
                )
                .await
                .unwrap();
            (link, upstream_session)
        }

        /// The cookies of a browser coming back from the upstream provider,
        /// optionally already signed in, and a CSRF token for its forms.
        fn browser(
            state: &TestState,
            upstream_session: &UpstreamOAuthAuthorizationSession,
            link: &UpstreamOAuthLink,
            post_auth_action: Option<PostAuthAction>,
            browser_session: Option<&BrowserSession>,
        ) -> (CookieHelper, String) {
            let cookie_jar = state.cookie_jar();
            let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&state.clock, state.rng());
            let cookie_jar = UpstreamSessionsCookie::default()
                .add(
                    upstream_session.id,
                    upstream_session.provider_id,
                    upstream_session.state_str.clone(),
                    post_auth_action,
                )
                .add_link_to_session(upstream_session.id, link.id)
                .unwrap()
                .save(cookie_jar, &state.clock);
            let cookie_jar = match browser_session {
                Some(browser_session) => cookie_jar.set_session(browser_session),
                None => cookie_jar,
            };

            let cookies = CookieHelper::new();
            cookies.import(cookie_jar);
            (cookies, csrf_token.form_value())
        }

        async fn get_link(
            state: &TestState,
            cookies: &CookieHelper,
            link: &UpstreamOAuthLink,
        ) -> hyper::Response<String> {
            let request =
                Request::get(&*mas_router::UpstreamOAuth2Link::new(link.id).path()).empty();
            let response = state.request(cookies.with_cookies(request)).await;
            cookies.save_cookies(&response);
            response
        }

        fn location(response: &hyper::Response<String>) -> &str {
            response.headers().get(LOCATION).unwrap().to_str().unwrap()
        }

        fn link_page(state: &TestState, link: &UpstreamOAuthLink) -> String {
            state
                .url_builder
                .relative_url_for(&mas_router::UpstreamOAuth2Link::new(link.id))
        }

        fn next_page(state: &TestState, post_auth_action: Option<PostAuthAction>) -> String {
            let response = OptionalPostAuthAction { post_auth_action }
                .go_next(&state.url_builder)
                .into_response();
            response
                .headers()
                .get(LOCATION)
                .unwrap()
                .to_str()
                .unwrap()
                .to_owned()
        }

        async fn add_user(state: &TestState, repo: &mut BoxRepository, username: &str) -> User {
            repo.user()
                .add(&mut state.rng(), &state.clock, username.to_owned())
                .await
                .unwrap()
        }

        async fn add_browser_session(
            state: &TestState,
            repo: &mut BoxRepository,
            user: &User,
        ) -> BrowserSession {
            repo.browser_session()
                .add(&mut state.rng(), &state.clock, user, None)
                .await
                .unwrap()
        }

        async fn is_finished(state: &TestState, browser_session: &BrowserSession) -> bool {
            let mut repo = state.repository().await.unwrap();
            let finished = repo
                .browser_session()
                .lookup(browser_session.id)
                .await
                .unwrap()
                .unwrap()
                .finished_at
                .is_some();
            repo.cancel().await.unwrap();
            finished
        }

        async fn active_browser_sessions(state: &TestState, user: &User) -> usize {
            let mut repo = state.repository().await.unwrap();
            let count = repo
                .browser_session()
                .count(BrowserSessionFilter::new().for_user(user).active_only())
                .await
                .unwrap();
            repo.cancel().await.unwrap();
            count
        }

        async fn link_owner(state: &TestState, link: &UpstreamOAuthLink) -> Option<Ulid> {
            let mut repo = state.repository().await.unwrap();
            let user_id = repo
                .upstream_oauth_link()
                .lookup(link.id)
                .await
                .unwrap()
                .unwrap()
                .user_id;
            repo.cancel().await.unwrap();
            user_id
        }

        #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
        async fn test_session_of_another_user_is_ended_for_every_post_auth_action(pool: PgPool) {
            setup();
            let state = TestState::from_pool(pool).await.unwrap();
            let mut repo = state.repository().await.unwrap();
            let provider = add_provider(&state, &mut repo).await;
            repo.save().await.unwrap();

            for (i, post_auth_action) in post_auth_actions().into_iter().enumerate() {
                let mut repo = state.repository().await.unwrap();
                let alice = add_user(&state, &mut repo, &format!("alice{i}")).await;
                let bob = add_user(&state, &mut repo, &format!("bob{i}")).await;
                let (link, upstream_session) = add_upstream_sign_in(
                    &state,
                    &mut repo,
                    &provider,
                    &format!("bob-subject-{i}"),
                    serde_json::json!({ "sub": "bob" }),
                )
                .await;
                repo.upstream_oauth_link()
                    .associate_to_user(&link, &bob)
                    .await
                    .unwrap();
                let alice_session = add_browser_session(&state, &mut repo, &alice).await;
                repo.save().await.unwrap();

                let (cookies, _) = browser(
                    &state,
                    &upstream_session,
                    &link,
                    post_auth_action.clone(),
                    Some(&alice_session),
                );

                // The browser is signed in as alice, the sign-in resolved to
                // bob: alice's session is ended and the page is loaded again.
                let response = get_link(&state, &cookies, &link).await;
                response.assert_status(StatusCode::SEE_OTHER);
                assert_eq!(location(&response), link_page(&state, &link));
                assert!(is_finished(&state, &alice_session).await);
                assert_eq!(active_browser_sessions(&state, &bob).await, 0);

                // With no session left, bob is signed in and the sign-in
                // carries on where it was going.
                let response = get_link(&state, &cookies, &link).await;
                response.assert_status(StatusCode::SEE_OTHER);
                assert_eq!(location(&response), next_page(&state, post_auth_action));
                assert_eq!(active_browser_sessions(&state, &bob).await, 1);
                assert_eq!(active_browser_sessions(&state, &alice).await, 0);
                assert_eq!(link_owner(&state, &link).await, Some(bob.id));
            }
        }

        #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
        async fn test_session_is_ended_when_the_link_belongs_to_nobody(pool: PgPool) {
            setup();
            let state = TestState::from_pool(pool).await.unwrap();
            let mut repo = state.repository().await.unwrap();
            let provider = add_provider(&state, &mut repo).await;
            repo.save().await.unwrap();

            for (i, post_auth_action) in post_auth_actions().into_iter().enumerate() {
                let mut repo = state.repository().await.unwrap();
                let alice = add_user(&state, &mut repo, &format!("alice{i}")).await;
                let (link, upstream_session) = add_upstream_sign_in(
                    &state,
                    &mut repo,
                    &provider,
                    &format!("new-subject-{i}"),
                    serde_json::json!({ "sub": "new" }),
                )
                .await;
                let alice_session = add_browser_session(&state, &mut repo, &alice).await;
                repo.save().await.unwrap();

                let (cookies, _) = browser(
                    &state,
                    &upstream_session,
                    &link,
                    post_auth_action,
                    Some(&alice_session),
                );

                // No "link to your account" suggestion: alice's session is
                // ended and the page is loaded again.
                let response = get_link(&state, &cookies, &link).await;
                response.assert_status(StatusCode::SEE_OTHER);
                assert_eq!(location(&response), link_page(&state, &link));
                assert!(is_finished(&state, &alice_session).await);

                // Without a session this is a new account: registration.
                let response = get_link(&state, &cookies, &link).await;
                response.assert_status(StatusCode::OK);
                assert!(!response.body().contains("action=\"link\""));
                assert!(!response.body().contains("value=\"link\""));
                assert_eq!(link_owner(&state, &link).await, None);
                assert_eq!(active_browser_sessions(&state, &alice).await, 0);
            }
        }

        #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
        async fn test_session_of_the_same_user_is_kept(pool: PgPool) {
            setup();
            let state = TestState::from_pool(pool).await.unwrap();
            let mut repo = state.repository().await.unwrap();
            let provider = add_provider(&state, &mut repo).await;
            repo.save().await.unwrap();

            for (i, post_auth_action) in post_auth_actions().into_iter().enumerate() {
                let mut repo = state.repository().await.unwrap();
                let alice = add_user(&state, &mut repo, &format!("alice{i}")).await;
                let (link, upstream_session) = add_upstream_sign_in(
                    &state,
                    &mut repo,
                    &provider,
                    &format!("alice-subject-{i}"),
                    serde_json::json!({ "sub": "alice" }),
                )
                .await;
                repo.upstream_oauth_link()
                    .associate_to_user(&link, &alice)
                    .await
                    .unwrap();
                let alice_session = add_browser_session(&state, &mut repo, &alice).await;
                repo.save().await.unwrap();

                let (cookies, _) = browser(
                    &state,
                    &upstream_session,
                    &link,
                    post_auth_action.clone(),
                    Some(&alice_session),
                );

                let response = get_link(&state, &cookies, &link).await;
                response.assert_status(StatusCode::SEE_OTHER);
                assert_eq!(location(&response), next_page(&state, post_auth_action));
                assert!(!is_finished(&state, &alice_session).await);
                assert_eq!(active_browser_sessions(&state, &alice).await, 1);
            }
        }

        async fn post_link(
            state: &TestState,
            cookies: &CookieHelper,
            csrf: &str,
            link: &UpstreamOAuthLink,
        ) -> hyper::Response<String> {
            let request = Request::post(&*mas_router::UpstreamOAuth2Link::new(link.id).path())
                .form(serde_json::json!({ "csrf": csrf, "action": "link" }));
            let response = state.request(cookies.with_cookies(request)).await;
            cookies.save_cookies(&response);
            response
        }

        #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
        async fn test_link_post_is_refused_during_a_sign_in(pool: PgPool) {
            setup();
            let state = TestState::from_pool(pool).await.unwrap();
            let mut repo = state.repository().await.unwrap();
            let provider = add_provider(&state, &mut repo).await;
            repo.save().await.unwrap();

            let sign_ins = [
                PostAuthAction::continue_grant(Ulid::nil()),
                PostAuthAction::continue_device_code_grant(Ulid::nil()),
                PostAuthAction::continue_compat_sso_login(Ulid::nil()),
            ];
            for (i, post_auth_action) in sign_ins.into_iter().enumerate() {
                let mut repo = state.repository().await.unwrap();
                // alice holds no link at all, so only the sign-in refuses it
                let alice = add_user(&state, &mut repo, &format!("alice{i}")).await;
                let (link, upstream_session) = add_upstream_sign_in(
                    &state,
                    &mut repo,
                    &provider,
                    &format!("new-subject-{i}"),
                    serde_json::json!({ "sub": "new" }),
                )
                .await;
                let alice_session = add_browser_session(&state, &mut repo, &alice).await;
                repo.save().await.unwrap();

                let (cookies, csrf) = browser(
                    &state,
                    &upstream_session,
                    &link,
                    Some(post_auth_action),
                    Some(&alice_session),
                );

                let response = post_link(&state, &cookies, &csrf, &link).await;
                response.assert_status(StatusCode::BAD_REQUEST);
                assert!(response.body().contains("finish signing you in"));
                assert!(!response.body().contains("upstream"));
                assert_eq!(link_owner(&state, &link).await, None);
            }
        }

        #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
        async fn test_link_post_is_refused_for_a_user_who_already_holds_a_link(pool: PgPool) {
            setup();
            let state = TestState::from_pool(pool).await.unwrap();
            let mut repo = state.repository().await.unwrap();
            let provider = add_provider(&state, &mut repo).await;
            let alice = add_user(&state, &mut repo, "alice").await;
            let (existing, _) = add_upstream_sign_in(
                &state,
                &mut repo,
                &provider,
                "alice-subject",
                serde_json::json!({ "sub": "alice" }),
            )
            .await;
            repo.upstream_oauth_link()
                .associate_to_user(&existing, &alice)
                .await
                .unwrap();
            let (link, upstream_session) = add_upstream_sign_in(
                &state,
                &mut repo,
                &provider,
                "second-subject",
                serde_json::json!({ "sub": "second" }),
            )
            .await;
            let alice_session = add_browser_session(&state, &mut repo, &alice).await;
            repo.save().await.unwrap();

            for post_auth_action in [None, Some(PostAuthAction::manage_account(None))] {
                let (cookies, csrf) = browser(
                    &state,
                    &upstream_session,
                    &link,
                    post_auth_action,
                    Some(&alice_session),
                );

                let response = post_link(&state, &cookies, &csrf, &link).await;
                response.assert_status(StatusCode::BAD_REQUEST);
                assert_eq!(link_owner(&state, &link).await, None);
            }
        }

        #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
        async fn test_link_post_still_links_a_user_without_a_link_outside_a_sign_in(pool: PgPool) {
            setup();
            let state = TestState::from_pool(pool).await.unwrap();
            let mut repo = state.repository().await.unwrap();
            let provider = add_provider(&state, &mut repo).await;
            let alice = add_user(&state, &mut repo, "alice").await;
            let (link, upstream_session) = add_upstream_sign_in(
                &state,
                &mut repo,
                &provider,
                "alice-subject",
                serde_json::json!({ "sub": "alice" }),
            )
            .await;
            let alice_session = add_browser_session(&state, &mut repo, &alice).await;
            repo.save().await.unwrap();

            let (cookies, csrf) = browser(
                &state,
                &upstream_session,
                &link,
                Some(PostAuthAction::manage_account(None)),
                Some(&alice_session),
            );

            let response = post_link(&state, &cookies, &csrf, &link).await;
            response.assert_status(StatusCode::SEE_OTHER);
            assert_eq!(link_owner(&state, &link).await, Some(alice.id));
        }

        /// The Gua provider imports the localpart with `on_conflict` left at
        /// its default, `fail`. This pins what that means inside a sign-in:
        /// a new upstream subject whose username matches an existing account
        /// is never attached to it, whatever post-auth action it carries.
        #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
        async fn test_default_localpart_conflict_never_attaches_a_subject_during_a_sign_in(
            pool: PgPool,
        ) {
            setup();
            let state = TestState::from_pool(pool).await.unwrap();
            let mut repo = state.repository().await.unwrap();
            let claims_imports = UpstreamOAuthProviderClaimsImports {
                localpart: UpstreamOAuthProviderLocalpartPreference {
                    action: mas_data_model::UpstreamOAuthProviderImportAction::Require,
                    template: None,
                    on_conflict: mas_data_model::UpstreamOAuthProviderOnConflict::default(),
                },
                ..UpstreamOAuthProviderClaimsImports::default()
            };
            assert_eq!(
                claims_imports.localpart.on_conflict,
                mas_data_model::UpstreamOAuthProviderOnConflict::Fail
            );
            let provider = add_provider_with(&state, &mut repo, claims_imports).await;
            let john = add_user(&state, &mut repo, "john").await;
            repo.save().await.unwrap();

            for (i, post_auth_action) in post_auth_actions().into_iter().enumerate() {
                let mut repo = state.repository().await.unwrap();
                let (link, upstream_session) = add_upstream_sign_in(
                    &state,
                    &mut repo,
                    &provider,
                    &format!("other-subject-{i}"),
                    serde_json::json!({ "sub": "other", "preferred_username": "john" }),
                )
                .await;
                repo.save().await.unwrap();

                let (cookies, _) =
                    browser(&state, &upstream_session, &link, post_auth_action, None);
                let response = get_link(&state, &cookies, &link).await;
                response.assert_status(StatusCode::OK);
                assert!(response.body().contains("This username is already taken"));
                assert_eq!(link_owner(&state, &link).await, None);
                assert_eq!(active_browser_sessions(&state, &john).await, 0);
            }
        }

        /// The sessions an account can hold: a browser session backing an app
        /// (OAuth 2.0) session and a compatibility session, and a second,
        /// unrelated browser session.
        struct Sessions {
            app_browser: BrowserSession,
            other_browser: BrowserSession,
            oauth2: Ulid,
            compat: Ulid,
        }

        async fn add_sessions(state: &TestState, user: &User) -> Sessions {
            let request = Request::post(mas_router::OAuth2RegistrationEndpoint::PATH).json(
                serde_json::json!({
                    "client_uri": "https://example.com/",
                    "redirect_uris": ["https://example.com/callback"],
                    "token_endpoint_auth_method": "client_secret_post",
                    "response_types": ["code"],
                    "grant_types": ["authorization_code", "refresh_token"],
                }),
            );
            let response = state.request(request).await;
            response.assert_status(StatusCode::CREATED);
            let registration: ClientRegistrationResponse = response.json();

            let mut rng = state.rng();
            let mut repo = state.repository().await.unwrap();
            let client = repo
                .oauth2_client()
                .find_by_client_id(&registration.client_id)
                .await
                .unwrap()
                .unwrap();
            let app_browser = add_browser_session(state, &mut repo, user).await;
            let other_browser = add_browser_session(state, &mut repo, user).await;
            let oauth2 = repo
                .oauth2_session()
                .add_from_browser_session(
                    &mut rng,
                    &state.clock,
                    &client,
                    &app_browser,
                    Scope::from_iter([OPENID]),
                )
                .await
                .unwrap();
            let device = Device::generate(&mut rng);
            let compat = repo
                .compat_session()
                .add(
                    &mut rng,
                    &state.clock,
                    user,
                    device,
                    Some(&app_browser),
                    false,
                    None,
                )
                .await
                .unwrap();
            repo.save().await.unwrap();

            Sessions {
                app_browser,
                other_browser,
                oauth2: oauth2.id,
                compat: compat.id,
            }
        }

        async fn app_sessions_valid(state: &TestState, sessions: &Sessions) -> (bool, bool) {
            let mut repo = state.repository().await.unwrap();
            let oauth2 = repo
                .oauth2_session()
                .lookup(sessions.oauth2)
                .await
                .unwrap()
                .unwrap()
                .is_valid();
            let compat = repo
                .compat_session()
                .lookup(sessions.compat)
                .await
                .unwrap()
                .unwrap()
                .is_valid();
            repo.cancel().await.unwrap();
            (oauth2, compat)
        }

        async fn sync_devices_jobs(pool: &PgPool) -> Vec<Json<Value>> {
            sqlx::query_scalar("SELECT payload FROM queue_jobs WHERE queue_name = 'sync-devices'")
                .fetch_all(pool)
                .await
                .unwrap()
        }

        #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
        async fn test_recovery_claim_ends_every_other_session(pool: PgPool) {
            setup();
            let state = TestState::from_pool(pool.clone()).await.unwrap();
            let mut repo = state.repository().await.unwrap();
            let provider = add_provider(&state, &mut repo).await;
            let bob = add_user(&state, &mut repo, "bob").await;
            let (link, upstream_session) = add_upstream_sign_in(
                &state,
                &mut repo,
                &provider,
                "bob-subject",
                serde_json::json!({ "sub": "bob", "gua_end_other_sessions": true }),
            )
            .await;
            repo.upstream_oauth_link()
                .associate_to_user(&link, &bob)
                .await
                .unwrap();
            repo.save().await.unwrap();
            let sessions = add_sessions(&state, &bob).await;
            assert!(sync_devices_jobs(&pool).await.is_empty());

            // A fresh browser completes the recovery sign-in.
            let post_auth_action = Some(PostAuthAction::continue_grant(Ulid::nil()));
            let (cookies, _) = browser(
                &state,
                &upstream_session,
                &link,
                post_auth_action.clone(),
                None,
            );
            let response = get_link(&state, &cookies, &link).await;
            response.assert_status(StatusCode::SEE_OTHER);
            assert_eq!(location(&response), next_page(&state, post_auth_action));

            assert!(is_finished(&state, &sessions.app_browser).await);
            assert!(is_finished(&state, &sessions.other_browser).await);
            assert_eq!(app_sessions_valid(&state, &sessions).await, (false, false));
            // Only the recovering browser is signed in now.
            assert_eq!(active_browser_sessions(&state, &bob).await, 1);

            let jobs = sync_devices_jobs(&pool).await;
            assert_eq!(jobs.len(), 1);
            assert_eq!(jobs[0]["user_id"], serde_json::json!(bob.id));
        }

        #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
        async fn test_recovery_claim_replaces_a_browser_session_of_the_same_user(pool: PgPool) {
            setup();
            let state = TestState::from_pool(pool).await.unwrap();
            let mut repo = state.repository().await.unwrap();
            let provider = add_provider(&state, &mut repo).await;
            let bob = add_user(&state, &mut repo, "bob").await;
            let (link, upstream_session) = add_upstream_sign_in(
                &state,
                &mut repo,
                &provider,
                "bob-subject",
                serde_json::json!({ "sub": "bob", "gua_end_other_sessions": true }),
            )
            .await;
            repo.upstream_oauth_link()
                .associate_to_user(&link, &bob)
                .await
                .unwrap();
            repo.save().await.unwrap();
            let sessions = add_sessions(&state, &bob).await;

            // The browser still holds one of bob's sessions: it is not reused.
            let (cookies, _) = browser(
                &state,
                &upstream_session,
                &link,
                None,
                Some(&sessions.other_browser),
            );
            let response = get_link(&state, &cookies, &link).await;
            response.assert_status(StatusCode::SEE_OTHER);
            assert_eq!(location(&response), next_page(&state, None));

            assert!(is_finished(&state, &sessions.app_browser).await);
            assert!(is_finished(&state, &sessions.other_browser).await);
            assert_eq!(app_sessions_valid(&state, &sessions).await, (false, false));
            assert_eq!(active_browser_sessions(&state, &bob).await, 1);
        }

        #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
        async fn test_without_the_recovery_claim_other_sessions_survive(pool: PgPool) {
            setup();
            let state = TestState::from_pool(pool.clone()).await.unwrap();
            let mut repo = state.repository().await.unwrap();
            let provider = add_provider(&state, &mut repo).await;
            let bob = add_user(&state, &mut repo, "bob").await;
            repo.save().await.unwrap();
            let sessions = add_sessions(&state, &bob).await;

            // Neither a missing claim nor anything other than a JSON `true`
            // ends sessions.
            let claims = [
                serde_json::json!({ "sub": "bob" }),
                serde_json::json!({ "sub": "bob", "gua_end_other_sessions": false }),
                serde_json::json!({ "sub": "bob", "gua_end_other_sessions": "true" }),
            ];
            for (i, id_token_claims) in claims.into_iter().enumerate() {
                let mut repo = state.repository().await.unwrap();
                let (link, upstream_session) = add_upstream_sign_in(
                    &state,
                    &mut repo,
                    &provider,
                    &format!("bob-subject-{i}"),
                    id_token_claims,
                )
                .await;
                repo.upstream_oauth_link()
                    .associate_to_user(&link, &bob)
                    .await
                    .unwrap();
                repo.save().await.unwrap();

                let (cookies, _) = browser(&state, &upstream_session, &link, None, None);
                let response = get_link(&state, &cookies, &link).await;
                response.assert_status(StatusCode::SEE_OTHER);

                assert!(!is_finished(&state, &sessions.app_browser).await);
                assert!(!is_finished(&state, &sessions.other_browser).await);
                assert_eq!(app_sessions_valid(&state, &sessions).await, (true, true));
                // The two existing browser sessions plus one per sign-in.
                assert_eq!(active_browser_sessions(&state, &bob).await, 3 + i);
            }

            assert!(sync_devices_jobs(&pool).await.is_empty());
        }
    }
}
