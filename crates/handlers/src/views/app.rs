// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::sync::Arc;

use axum::{
    extract::State,
    response::{Html, IntoResponse},
};
use axum_extra::extract::Query;
use mas_axum_utils::{InternalError, SessionInfoExt, cookies::CookieJar};
use mas_data_model::{BoxClock, BoxRng};
use mas_matrix::HomeserverConnection;
use mas_router::{AccountAction, PostAuthAction, UrlBuilder};
use mas_storage::{BoxRepository, user::BrowserSessionRepository};
use mas_templates::{AppContext, TemplateContext, Templates};
use serde::Deserialize;

use crate::{
    BoundActivityTracker, PreferredLanguage,
    session::{SessionOrFallback, load_session_or_fallback},
};

#[derive(Deserialize)]
pub struct Params {
    #[serde(default, flatten)]
    action: Option<mas_router::AccountAction>,

    #[serde(rename = "org.matrix.msc4198.login_hint")]
    unstable_login_hint: Option<String>,
}

#[tracing::instrument(name = "handlers.views.app.get", skip_all)]
pub async fn get(
    PreferredLanguage(locale): PreferredLanguage,
    State(templates): State<Templates>,
    activity_tracker: BoundActivityTracker,
    State(url_builder): State<UrlBuilder>,
    State(homeserver): State<Arc<dyn HomeserverConnection>>,
    Query(Params {
        action,
        unstable_login_hint,
    }): Query<Params>,
    mut repo: BoxRepository,
    clock: BoxClock,
    mut rng: BoxRng,
    cookie_jar: CookieJar,
) -> Result<impl IntoResponse, InternalError> {
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

    // TODO: keep the full path, not just the action
    let Some(session) = maybe_session else {
        let mut url = mas_router::Login::and_then(PostAuthAction::manage_account(action));

        if let Some(login_hint) = unstable_login_hint {
            url = url.with_login_hint(login_hint);
        }

        return Ok((cookie_jar, url_builder.redirect(&url)).into_response());
    };

    // GUA FORK: the browser session must belong to the user the app is signed in
    // as.
    //
    // The account page is opened from inside the app in a browser context that
    // shares cookies with the system browser, so the session found here can
    // belong to a completely different account than the one asking. For an
    // identity reset that is not a cosmetic mix-up: the page would approve the
    // reset for the browser's user, the app's own upload would keep being
    // refused, and the app would be left believing the reset failed while
    // another account had just been opened up for replacement.
    //
    // When the app names its user, through the MSC4198 login hint or inside the
    // action itself, and the session disagrees, treat the session as absent and
    // authenticate afresh for the named user. The name is only ever used to
    // refuse, never to grant: the action stays behind the normal owner check
    // once a matching session exists.
    let expected_user = expected_user(
        action.as_ref(),
        unstable_login_hint.as_deref(),
        homeserver.homeserver(),
    );
    if let Some(expected) = expected_user
        && expected != session.user.username
    {
        tracing::info!(
            expected = %expected,
            "Browser session belongs to another user than the one the app named, forcing a fresh login"
        );

        // End the other account's session first. Left in place, the upstream login
        // callback for the right account would find it and stop at "linked to
        // another account".
        activity_tracker
            .record_browser_session(&clock, &session)
            .await;
        repo.browser_session().finish(&clock, session).await?;
        repo.save().await?;
        let (session_info, cookie_jar) = cookie_jar.session_info();
        let cookie_jar = cookie_jar.update_session_info(&session_info.mark_session_ended());

        let login_hint = unstable_login_hint
            .unwrap_or_else(|| format!("mxid:@{expected}:{}", homeserver.homeserver()));
        let url = mas_router::Login::and_then(PostAuthAction::manage_account(action))
            .with_login_hint(login_hint)
            .with_force_login();
        return Ok((cookie_jar, url_builder.redirect(&url)).into_response());
    }

    activity_tracker
        .record_browser_session(&clock, &session)
        .await;

    let ctx = AppContext::from_url_builder(&url_builder).with_language(locale);
    let content = templates.render_app(&ctx)?;

    Ok((cookie_jar, Html(content)).into_response())
}

/// Like `get`, but allow anonymous access.
/// Used for a subset of the account management paths.
/// Needed for e.g. account recovery.
#[tracing::instrument(name = "handlers.views.app.get_anonymous", skip_all)]
pub async fn get_anonymous(
    PreferredLanguage(locale): PreferredLanguage,
    State(templates): State<Templates>,
    State(url_builder): State<UrlBuilder>,
) -> Result<impl IntoResponse, InternalError> {
    let ctx = AppContext::from_url_builder(&url_builder).with_language(locale);
    let content = templates.render_app(&ctx)?;

    Ok(Html(content).into_response())
}

/// GUA FORK: which localpart, if any, the app says it is signed in as.
///
/// Prefers the name carried inside the action, since that one survives a login
/// round trip; otherwise an `mxid:` MSC4198 hint on our own homeserver.
/// Anything else is ignored, so a foreign or malformed hint can never lock a
/// legitimate session out.
fn expected_user(
    action: Option<&AccountAction>,
    login_hint: Option<&str>,
    homeserver: &str,
) -> Option<String> {
    if let Some(AccountAction::OrgMatrixCrossSigningReset {
        gua_user: Some(user),
        ..
    }) = action
        && !user.is_empty()
    {
        return Some(user.clone());
    }
    let mxid = login_hint?.strip_prefix("mxid:")?;
    let localpart = mxid
        .strip_prefix('@')?
        .strip_suffix(&format!(":{homeserver}"))?;
    (!localpart.is_empty()).then(|| localpart.to_owned())
}

#[cfg(test)]
mod tests {
    use mas_router::AccountAction;

    use super::expected_user;

    const HS: &str = "example.com";

    #[test]
    fn prefers_the_user_carried_in_the_action() {
        let action = AccountAction::OrgMatrixCrossSigningReset {
            gua_return: None,
            gua_user: Some("alice".to_owned()),
        };
        assert_eq!(
            expected_user(Some(&action), Some("mxid:@bob:example.com"), HS).as_deref(),
            Some("alice")
        );
    }

    #[test]
    fn falls_back_to_an_mxid_hint_on_our_homeserver() {
        assert_eq!(
            expected_user(None, Some("mxid:@bob:example.com"), HS).as_deref(),
            Some("bob")
        );
    }

    #[test]
    fn ignores_hints_it_cannot_check() {
        assert_eq!(expected_user(None, Some("mxid:@bob:other.org"), HS), None);
        assert_eq!(expected_user(None, Some("bob@example.com"), HS), None);
        assert_eq!(expected_user(None, Some("mxid:@:example.com"), HS), None);
        assert_eq!(expected_user(None, None, HS), None);
        let empty = AccountAction::OrgMatrixCrossSigningReset {
            gua_return: None,
            gua_user: Some(String::new()),
        };
        assert_eq!(expected_user(Some(&empty), None, HS), None);
    }
}
