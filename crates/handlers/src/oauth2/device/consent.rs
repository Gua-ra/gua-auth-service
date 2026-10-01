// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::{sync::Arc, time::Duration};

use anyhow::Context;
use axum::{
    Form,
    extract::{Path, State},
    response::{Html, IntoResponse, Response},
};
use axum_extra::{TypedHeader, extract::Query};
use mas_axum_utils::{
    InternalError, SessionInfoExt,
    cookies::CookieJar,
    csrf::{CsrfExt, ProtectedForm},
};
use mas_data_model::{BoxClock, BoxRng, BrowserSession, Clock, MatrixUser};
use mas_matrix::HomeserverConnection;
use mas_policy::Policy;
use mas_router::{DeviceCodeConsentQuery, PostAuthAction, UrlBuilder};
use mas_storage::BoxRepository;
use mas_templates::{DeviceConsentContext, PolicyViolationContext, TemplateContext, Templates};
use serde::Deserialize;
use tracing::warn;
use ulid::Ulid;

use crate::{
    BoundActivityTracker, PreferredLanguage, SiteConfig,
    session::{SessionOrFallback, count_user_sessions_for_limiting, load_session_or_fallback},
};

#[derive(Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
enum Action {
    Consent,
    Reject,
}

#[derive(Deserialize, Debug)]
pub(crate) struct ConsentForm {
    action: Action,

    // HTML form checkboxes are only sent when ticked, hence the Option.
    #[serde(default)]
    confirm_device: Option<String>,
}

/// GUA FORK: the localpart the app's login hint names, when it differs from the
/// browser session's user.
fn other_account_named(
    query: &DeviceCodeConsentQuery,
    session: &BrowserSession,
    homeserver: &dyn HomeserverConnection,
) -> Option<String> {
    crate::gua::sessions::hinted_localpart(query.login_hint.as_deref(), homeserver.homeserver())
        .filter(|expected| *expected != session.user.username)
}

/// GUA FORK: call only for a grant known to exist and be unexpired, so a
/// made-up link changes nothing.
async fn end_session_and_login_as(
    mut repo: BoxRepository,
    clock: &dyn Clock,
    url_builder: &UrlBuilder,
    homeserver: &dyn HomeserverConnection,
    cookie_jar: CookieJar,
    session: BrowserSession,
    grant_id: Ulid,
    login_hint: Option<String>,
    expected: &str,
) -> Result<Response, InternalError> {
    tracing::info!(
        expected = %expected,
        browser_session.id = %session.id,
        oauth2_device_code.id = %grant_id,
        "Browser session belongs to another user than the one the app named, forcing a fresh login"
    );

    repo.browser_session().finish(clock, session).await?;
    repo.save().await?;

    let (session_info, cookie_jar) = cookie_jar.session_info();
    let cookie_jar = cookie_jar.update_session_info(&session_info.mark_session_ended());

    // The hint rides in the post-auth action, so the consent page checks the
    // account again after the login.
    let login_hint =
        login_hint.unwrap_or_else(|| format!("mxid:@{expected}:{}", homeserver.homeserver()));
    let login = mas_router::Login::and_then(PostAuthAction::continue_device_code_grant_with_hint(
        grant_id,
        Some(login_hint.clone()),
    ))
    .with_login_hint(login_hint)
    .with_force_login();

    Ok((cookie_jar, url_builder.redirect(&login)).into_response())
}

#[tracing::instrument(name = "handlers.oauth2.device.consent.get", skip_all)]
pub(crate) async fn get(
    mut rng: BoxRng,
    clock: BoxClock,
    PreferredLanguage(locale): PreferredLanguage,
    State(templates): State<Templates>,
    State(url_builder): State<UrlBuilder>,
    State(homeserver): State<Arc<dyn HomeserverConnection>>,
    State(site_config): State<SiteConfig>,
    mut repo: BoxRepository,
    mut policy: Policy,
    activity_tracker: BoundActivityTracker,
    user_agent: Option<TypedHeader<headers::UserAgent>>,
    cookie_jar: CookieJar,
    Path(grant_id): Path<Ulid>,
    Query(query): Query<DeviceCodeConsentQuery>,
) -> Result<Response, InternalError> {
    if !site_config.device_code_grant_enabled {
        return Err(InternalError::from_anyhow(anyhow::anyhow!(
            "The Device Authorization Grant is disabled"
        )));
    }
    let (cookie_jar, maybe_session) = match load_session_or_fallback(
        cookie_jar, &clock, &mut rng, &templates, &locale, &mut repo,
    )
    .await?
    {
        SessionOrFallback::MaybeSession {
            cookie_jar,
            maybe_session,
            ..
        } => (cookie_jar, maybe_session),
        SessionOrFallback::Fallback { response } => return Ok(response),
    };

    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);

    let user_agent = user_agent.map(|ua| ua.to_string());

    let Some(session) = maybe_session else {
        let login = mas_router::Login::and_then(
            PostAuthAction::continue_device_code_grant_with_hint(grant_id, query.login_hint),
        );
        return Ok((cookie_jar, url_builder.redirect(&login)).into_response());
    };

    activity_tracker
        .record_browser_session(&clock, &session)
        .await;

    // TODO: better error handling
    let grant = repo
        .oauth2_device_code_grant()
        .lookup(grant_id)
        .await?
        .context("Device grant not found")
        .map_err(InternalError::from_anyhow)?;

    if grant.expires_at < clock.now() {
        return Err(InternalError::from_anyhow(anyhow::anyhow!(
            "Grant is expired"
        )));
    }

    if let Some(expected) = other_account_named(&query, &session, &*homeserver) {
        return end_session_and_login_as(
            repo,
            &clock,
            &url_builder,
            &*homeserver,
            cookie_jar,
            session,
            grant_id,
            query.login_hint,
            &expected,
        )
        .await;
    }

    let client = repo
        .oauth2_client()
        .lookup(grant.client_id)
        .await?
        .context("Client not found")
        .map_err(InternalError::from_anyhow)?;

    let session_counts = count_user_sessions_for_limiting(&mut repo, &session.user).await?;

    // We can close the repository early, we don't need it at this point
    repo.save().await?;

    // Evaluate the policy
    let res = policy
        .evaluate_authorization_grant(mas_policy::AuthorizationGrantInput {
            grant_type: mas_policy::GrantType::DeviceCode,
            client: &client,
            session_counts: Some(session_counts),
            scope: &grant.scope,
            user: Some(&session.user),
            requester: mas_policy::Requester {
                ip_address: activity_tracker.ip(),
                user_agent,
            },
        })
        .await?;
    if !res.valid() {
        warn!(violation = ?res, "Device code grant for client {} denied by policy", client.id);

        let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);
        let ctx = PolicyViolationContext::for_device_code_grant(grant, client, res.violations)
            .with_session(session)
            .with_csrf(csrf_token.form_value())
            .with_language(locale);

        let content = templates.render_policy_violation(&ctx)?;

        return Ok((cookie_jar, Html(content)).into_response());
    }

    // Fetch informations about the user. This is purely cosmetic, so we let it
    // fail and put a 1s timeout to it in case we fail to query it
    // XXX: we're likely to need this in other places
    let localpart = &session.user.username;
    let display_name = match tokio::time::timeout(
        Duration::from_secs(1),
        homeserver.query_user(localpart),
    )
    .await
    {
        Ok(Ok(user)) => user.displayname,
        Ok(Err(err)) => {
            tracing::warn!(
                error = &*err as &dyn std::error::Error,
                localpart,
                "Failed to query user"
            );
            None
        }
        Err(_) => {
            tracing::warn!(localpart, "Timed out while querying user");
            None
        }
    };

    let matrix_user = MatrixUser {
        mxid: homeserver.mxid(localpart),
        display_name,
    };

    let ctx = DeviceConsentContext::new(grant, client, matrix_user)
        .with_session(session)
        .with_csrf(csrf_token.form_value())
        .with_language(locale);

    let rendered = templates
        .render_device_consent(&ctx)
        .context("Failed to render template")
        .map_err(InternalError::from_anyhow)?;

    Ok((cookie_jar, Html(rendered)).into_response())
}

#[tracing::instrument(name = "handlers.oauth2.device.consent.post", skip_all)]
pub(crate) async fn post(
    mut rng: BoxRng,
    clock: BoxClock,
    PreferredLanguage(locale): PreferredLanguage,
    State(templates): State<Templates>,
    State(url_builder): State<UrlBuilder>,
    State(homeserver): State<Arc<dyn HomeserverConnection>>,
    State(site_config): State<SiteConfig>,
    mut repo: BoxRepository,
    mut policy: Policy,
    activity_tracker: BoundActivityTracker,
    user_agent: Option<TypedHeader<headers::UserAgent>>,
    cookie_jar: CookieJar,
    Path(grant_id): Path<Ulid>,
    Query(query): Query<DeviceCodeConsentQuery>,
    Form(form): Form<ProtectedForm<ConsentForm>>,
) -> Result<Response, InternalError> {
    if !site_config.device_code_grant_enabled {
        return Err(InternalError::from_anyhow(anyhow::anyhow!(
            "The Device Authorization Grant is disabled"
        )));
    }
    let form = cookie_jar.verify_form(&clock, form)?;
    let (cookie_jar, maybe_session) = match load_session_or_fallback(
        cookie_jar, &clock, &mut rng, &templates, &locale, &mut repo,
    )
    .await?
    {
        SessionOrFallback::MaybeSession {
            cookie_jar,
            maybe_session,
            ..
        } => (cookie_jar, maybe_session),
        SessionOrFallback::Fallback { response } => return Ok(response),
    };
    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);

    let user_agent = user_agent.map(|TypedHeader(ua)| ua.to_string());

    let Some(session) = maybe_session else {
        let login = mas_router::Login::and_then(
            PostAuthAction::continue_device_code_grant_with_hint(grant_id, query.login_hint),
        );
        return Ok((cookie_jar, url_builder.redirect(&login)).into_response());
    };

    activity_tracker
        .record_browser_session(&clock, &session)
        .await;

    // TODO: better error handling
    let grant = repo
        .oauth2_device_code_grant()
        .lookup(grant_id)
        .await?
        .context("Device grant not found")
        .map_err(InternalError::from_anyhow)?;

    if grant.expires_at < clock.now() {
        return Err(InternalError::from_anyhow(anyhow::anyhow!(
            "Grant is expired"
        )));
    }

    if let Some(expected) = other_account_named(&query, &session, &*homeserver) {
        return end_session_and_login_as(
            repo,
            &clock,
            &url_builder,
            &*homeserver,
            cookie_jar,
            session,
            grant_id,
            query.login_hint,
            &expected,
        )
        .await;
    }

    let client = repo
        .oauth2_client()
        .lookup(grant.client_id)
        .await?
        .context("Client not found")
        .map_err(InternalError::from_anyhow)?;

    let session_counts = count_user_sessions_for_limiting(&mut repo, &session.user).await?;

    // Evaluate the policy
    let res = policy
        .evaluate_authorization_grant(mas_policy::AuthorizationGrantInput {
            grant_type: mas_policy::GrantType::DeviceCode,
            client: &client,
            session_counts: Some(session_counts),
            scope: &grant.scope,
            user: Some(&session.user),
            requester: mas_policy::Requester {
                ip_address: activity_tracker.ip(),
                user_agent,
            },
        })
        .await?;
    if !res.valid() {
        warn!(violation = ?res, "Device code grant for client {} denied by policy", client.id);

        let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);
        let ctx = PolicyViolationContext::for_device_code_grant(grant, client, res.violations)
            .with_session(session)
            .with_csrf(csrf_token.form_value())
            .with_language(locale);

        let content = templates.render_policy_violation(&ctx)?;

        return Ok((cookie_jar, Html(content)).into_response());
    }

    let grant = if grant.is_pending() {
        match form.action {
            Action::Consent => {
                // The user must explicitly tick the "confirm this is my device"
                // box. The browser enforces `required`
                // client-side; this is the server-side safety
                // net.
                if form.confirm_device.is_none() {
                    return Err(InternalError::from_anyhow(anyhow::anyhow!(
                        "The device must be confirmed before consent can be granted"
                    )));
                }

                repo.oauth2_device_code_grant()
                    .fulfill(&clock, grant, &session)
                    .await?
            }
            Action::Reject => {
                repo.oauth2_device_code_grant()
                    .reject(&clock, grant, &session)
                    .await?
            }
        }
    } else {
        // XXX: In case we're not pending, let's just return the grant as-is
        // since it might just be a form resubmission, and feedback is nice
        // enough
        warn!(
            oauth2_device_code.id = %grant.id,
            browser_session.id = %session.id,
            user.id = %session.user.id,
            "Grant is not pending",
        );
        grant
    };

    repo.save().await?;

    // Fetch informations about the user. This is purely cosmetic, so we let it
    // fail and put a 1s timeout to it in case we fail to query it
    // XXX: we're likely to need this in other places
    let localpart = &session.user.username;
    let display_name = match tokio::time::timeout(
        Duration::from_secs(1),
        homeserver.query_user(localpart),
    )
    .await
    {
        Ok(Ok(user)) => user.displayname,
        Ok(Err(err)) => {
            tracing::warn!(
                error = &*err as &dyn std::error::Error,
                localpart,
                "Failed to query user"
            );
            None
        }
        Err(_) => {
            tracing::warn!(localpart, "Timed out while querying user");
            None
        }
    };

    let matrix_user = MatrixUser {
        mxid: homeserver.mxid(localpart),
        display_name,
    };

    let ctx = DeviceConsentContext::new(grant, client, matrix_user)
        .with_session(session)
        .with_csrf(csrf_token.form_value())
        .with_language(locale);

    let rendered = templates
        .render_device_consent(&ctx)
        .context("Failed to render template")
        .map_err(InternalError::from_anyhow)?;

    Ok((cookie_jar, Html(rendered)).into_response())
}

#[cfg(test)]
mod tests {
    use axum::response::IntoResponse as _;
    use hyper::{Request, StatusCode, header::LOCATION};
    use mas_axum_utils::{SessionInfoExt, csrf::CsrfExt};
    use mas_data_model::{BrowserSession, User};
    use mas_router::{Route, SimpleRoute};
    use oauth2_types::{
        registration::ClientRegistrationResponse, requests::DeviceAuthorizationResponse,
    };
    use sqlx::PgPool;
    use ulid::Ulid;

    use crate::test_utils::{CookieHelper, RequestBuilderExt, ResponseExt, TestState, setup};

    async fn start_device_code_grant(state: &TestState) -> (Ulid, String) {
        let request =
            Request::post(mas_router::OAuth2RegistrationEndpoint::PATH).json(serde_json::json!({
                "client_uri": "https://example.com/",
                "token_endpoint_auth_method": "none",
                "grant_types": ["urn:ietf:params:oauth:grant-type:device_code", "refresh_token"],
                "response_types": [],
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);
        let ClientRegistrationResponse { client_id, .. } = response.json();

        let request = Request::post(mas_router::OAuth2DeviceAuthorizationEndpoint::PATH).form(
            serde_json::json!({
                "client_id": client_id,
                "scope": "openid",
            }),
        );
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let DeviceAuthorizationResponse { user_code, .. } = response.json();

        let mut repo = state.repository().await.unwrap();
        let grant = repo
            .oauth2_device_code_grant()
            .find_by_user_code(&user_code)
            .await
            .unwrap()
            .unwrap();
        repo.cancel().await.unwrap();
        (grant.id, user_code)
    }

    async fn signed_in_browser(
        state: &TestState,
        username: &str,
    ) -> (User, BrowserSession, CookieHelper, String) {
        let mut rng = state.rng();
        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .add(&mut rng, &state.clock, username.to_owned())
            .await
            .unwrap();
        let browser_session = repo
            .browser_session()
            .add(&mut rng, &state.clock, &user, None)
            .await
            .unwrap();
        repo.save().await.unwrap();

        let cookie_jar = state.cookie_jar();
        let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&state.clock, &mut rng);
        let cookie_jar = cookie_jar.set_session(&browser_session);
        let cookies = CookieHelper::new();
        cookies.import(cookie_jar);

        (user, browser_session, cookies, csrf_token.form_value())
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

    async fn grant_is_pending(state: &TestState, grant_id: Ulid) -> bool {
        let mut repo = state.repository().await.unwrap();
        let pending = repo
            .oauth2_device_code_grant()
            .lookup(grant_id)
            .await
            .unwrap()
            .unwrap()
            .is_pending();
        repo.cancel().await.unwrap();
        pending
    }

    fn consent_path(grant_id: Ulid, hint: Option<&str>) -> String {
        mas_router::DeviceCodeConsent::new(grant_id)
            .with_login_hint(hint.map(str::to_owned))
            .path_and_query()
            .into_owned()
    }

    fn login_as(state: &TestState, grant_id: Ulid, hint: &str) -> String {
        state.url_builder.relative_url_for(
            &mas_router::Login::and_then(
                mas_router::PostAuthAction::continue_device_code_grant_with_hint(
                    grant_id,
                    Some(hint.to_owned()),
                ),
            )
            .with_login_hint(hint.to_owned())
            .with_force_login(),
        )
    }

    fn after_login(state: &TestState, login_url: &str) -> String {
        let (_, query) = login_url.split_once('?').unwrap();
        let login: mas_router::Login = serde_urlencoded::from_str(query).unwrap();
        login
            .go_next(&state.url_builder)
            .into_response()
            .headers()
            .get(LOCATION)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned()
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_gua_consent_refuses_a_session_of_another_account(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let (grant_id, _) = start_device_code_grant(&state).await;
        let (_, alice_session, cookies, _) = signed_in_browser(&state, "alice").await;
        let hint = "mxid:@bob:example.com";

        let request = Request::get(consent_path(grant_id, Some(hint))).empty();
        let response = state.request(cookies.with_cookies(request)).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::SEE_OTHER);
        assert_eq!(
            response.headers().get(LOCATION).unwrap().to_str().unwrap(),
            login_as(&state, grant_id, hint)
        );
        assert!(is_finished(&state, &alice_session).await);
        assert!(grant_is_pending(&state, grant_id).await);

        let request = Request::get(consent_path(grant_id, None)).empty();
        let response = state.request(cookies.with_cookies(request)).await;
        response.assert_status(StatusCode::SEE_OTHER);
        assert_eq!(
            response.headers().get(LOCATION).unwrap().to_str().unwrap(),
            state
                .url_builder
                .relative_url_for(&mas_router::Login::and_continue_device_code_grant(grant_id))
        );
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_gua_consent_checks_the_account_again_after_the_login(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let mut rng = state.rng();
        let (grant_id, _) = start_device_code_grant(&state).await;
        let (alice, alice_session, cookies, _) = signed_in_browser(&state, "alice").await;
        let hint = "mxid:@bob:example.com";

        let request = Request::get(consent_path(grant_id, Some(hint))).empty();
        let response = state.request(cookies.with_cookies(request)).await;
        response.assert_status(StatusCode::SEE_OTHER);
        let login_url = response
            .headers()
            .get(LOCATION)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        assert!(is_finished(&state, &alice_session).await);

        let next = after_login(&state, &login_url);
        assert_eq!(next, consent_path(grant_id, Some(hint)));

        let mut repo = state.repository().await.unwrap();
        let again = repo
            .browser_session()
            .add(&mut rng, &state.clock, &alice, None)
            .await
            .unwrap();
        repo.save().await.unwrap();
        let cookies = CookieHelper::new();
        cookies.import(state.cookie_jar().set_session(&again));

        let request = Request::get(next).empty();
        let response = state.request(cookies.with_cookies(request)).await;
        response.assert_status(StatusCode::SEE_OTHER);
        assert_eq!(
            response.headers().get(LOCATION).unwrap().to_str().unwrap(),
            login_url
        );
        assert!(is_finished(&state, &again).await);
        assert!(grant_is_pending(&state, grant_id).await);
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_gua_consent_without_a_session_keeps_the_hint(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let (grant_id, _) = start_device_code_grant(&state).await;
        let hint = "mxid:@bob:example.com";

        let request = Request::get(consent_path(grant_id, Some(hint))).empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::SEE_OTHER);
        let login_url = response.headers().get(LOCATION).unwrap().to_str().unwrap();
        assert_eq!(
            login_url,
            state
                .url_builder
                .relative_url_for(&mas_router::Login::and_then(
                    mas_router::PostAuthAction::continue_device_code_grant_with_hint(
                        grant_id,
                        Some(hint.to_owned()),
                    ),
                ))
        );
        assert_eq!(
            after_login(&state, login_url),
            consent_path(grant_id, Some(hint))
        );
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_gua_consent_post_refuses_a_session_of_another_account(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let (grant_id, _) = start_device_code_grant(&state).await;
        let (_, alice_session, cookies, csrf) = signed_in_browser(&state, "alice").await;
        let hint = "mxid:@bob:example.com";

        let request = Request::post(consent_path(grant_id, Some(hint))).form(serde_json::json!({
            "csrf": csrf,
            "action": "consent",
            "confirm_device": "on",
        }));
        let response = state.request(cookies.with_cookies(request)).await;
        response.assert_status(StatusCode::SEE_OTHER);
        assert_eq!(
            response.headers().get(LOCATION).unwrap().to_str().unwrap(),
            login_as(&state, grant_id, hint)
        );
        assert!(is_finished(&state, &alice_session).await);
        assert!(grant_is_pending(&state, grant_id).await);
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_gua_consent_with_a_matching_or_absent_hint_is_unchanged(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let (grant_id, _) = start_device_code_grant(&state).await;
        let (_, alice_session, cookies, csrf) = signed_in_browser(&state, "alice").await;

        for hint in [
            None,
            Some("mxid:@alice:example.com"),
            Some("mxid:@bob:other.example"),
            Some("bob@example.com"),
        ] {
            let request = Request::get(consent_path(grant_id, hint)).empty();
            let response = state.request(cookies.with_cookies(request)).await;
            cookies.save_cookies(&response);
            response.assert_status(StatusCode::OK);
            assert!(!is_finished(&state, &alice_session).await);
        }

        let request = Request::post(consent_path(grant_id, Some("mxid:@alice:example.com"))).form(
            serde_json::json!({
                "csrf": csrf,
                "action": "consent",
                "confirm_device": "on",
            }),
        );
        let response = state.request(cookies.with_cookies(request)).await;
        response.assert_status(StatusCode::OK);
        assert!(!is_finished(&state, &alice_session).await);
        assert!(!grant_is_pending(&state, grant_id).await);
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_gua_link_page_passes_the_hint_to_the_consent_page(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let (grant_id, user_code) = start_device_code_grant(&state).await;

        let request = Request::get(format!(
            "{}?code={user_code}&org.matrix.msc4198.login_hint=mxid%3A%40bob%3Aexample.com",
            mas_router::DeviceCodeLink::route()
        ))
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::SEE_OTHER);
        assert_eq!(
            response.headers().get(LOCATION).unwrap().to_str().unwrap(),
            consent_path(grant_id, Some("mxid:@bob:example.com"))
        );

        let request = Request::get(format!(
            "{}?code={user_code}",
            mas_router::DeviceCodeLink::route()
        ))
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::SEE_OTHER);
        assert_eq!(
            response.headers().get(LOCATION).unwrap().to_str().unwrap(),
            format!("/device/{grant_id}")
        );
    }
}
