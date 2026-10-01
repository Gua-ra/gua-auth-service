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
        let mut url = mas_router::Login::and_then(PostAuthAction::manage_account_with_hint(
            action,
            unstable_login_hint.clone(),
        ));

        if let Some(login_hint) = unstable_login_hint {
            url = url.with_login_hint(login_hint);
        }

        return Ok((cookie_jar, url_builder.redirect(&url)).into_response());
    };

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

        activity_tracker
            .record_browser_session(&clock, &session)
            .await;
        repo.browser_session().finish(&clock, session).await?;
        repo.save().await?;
        let (session_info, cookie_jar) = cookie_jar.session_info();
        let cookie_jar = cookie_jar.update_session_info(&session_info.mark_session_ended());

        let login_hint = unstable_login_hint
            .unwrap_or_else(|| format!("mxid:@{expected}:{}", homeserver.homeserver()));
        let url = mas_router::Login::and_then(PostAuthAction::manage_account_with_hint(
            action,
            Some(login_hint.clone()),
        ))
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
    crate::gua::sessions::hinted_localpart(login_hint, homeserver)
}

#[cfg(test)]
mod tests {
    use axum::response::IntoResponse as _;
    use hyper::{Request, StatusCode, header::LOCATION};
    use mas_axum_utils::SessionInfoExt;
    use mas_data_model::{BrowserSession, User};
    use mas_router::{AccountAction, PostAuthAction};
    use sqlx::PgPool;

    use super::expected_user;
    use crate::test_utils::{CookieHelper, RequestBuilderExt, ResponseExt, TestState, setup};

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

    fn account_path(hint: Option<&str>) -> String {
        let mut path = "/account/?action=org.matrix.profile".to_owned();
        if let Some(hint) = hint {
            let hint =
                serde_urlencoded::to_string([("org.matrix.msc4198.login_hint", hint)]).unwrap();
            path = format!("{path}&{hint}");
        }
        path
    }

    fn login_for_account(hint: &str) -> mas_router::Login {
        mas_router::Login::and_then(PostAuthAction::manage_account_with_hint(
            Some(AccountAction::OrgMatrixProfile),
            Some(hint.to_owned()),
        ))
        .with_login_hint(hint.to_owned())
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

    async fn signed_in_browser(
        state: &TestState,
        username: &str,
    ) -> (User, BrowserSession, CookieHelper) {
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

        let cookies = CookieHelper::new();
        cookies.import(state.cookie_jar().set_session(&browser_session));

        (user, browser_session, cookies)
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

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_gua_account_page_checks_the_account_again_after_the_login(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let mut rng = state.rng();
        let (alice, alice_session, cookies) = signed_in_browser(&state, "alice").await;
        let hint = "mxid:@bob:example.com";

        let request = Request::get(account_path(Some(hint))).empty();
        let response = state.request(cookies.with_cookies(request)).await;
        response.assert_status(StatusCode::SEE_OTHER);
        let login_url = response
            .headers()
            .get(LOCATION)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        assert_eq!(
            login_url,
            state
                .url_builder
                .relative_url_for(&login_for_account(hint).with_force_login())
        );
        assert!(is_finished(&state, &alice_session).await);

        let next = after_login(&state, &login_url);
        assert_eq!(next, account_path(Some(hint)));

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
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_gua_account_page_without_a_session_keeps_the_hint(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let hint = "mxid:@bob:example.com";

        let request = Request::get(account_path(Some(hint))).empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::SEE_OTHER);
        let login_url = response.headers().get(LOCATION).unwrap().to_str().unwrap();
        assert_eq!(
            login_url,
            state.url_builder.relative_url_for(&login_for_account(hint))
        );
        assert_eq!(after_login(&state, login_url), account_path(Some(hint)));

        let request = Request::get(account_path(None)).empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::SEE_OTHER);
        let login_url = response.headers().get(LOCATION).unwrap().to_str().unwrap();
        let login = mas_router::Login::and_then(PostAuthAction::manage_account(Some(
            AccountAction::OrgMatrixProfile,
        )));
        assert_eq!(login_url, state.url_builder.relative_url_for(&login));
        assert_eq!(after_login(&state, login_url), account_path(None));
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_gua_account_page_with_a_matching_or_absent_hint_is_unchanged(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let (_, alice_session, cookies) = signed_in_browser(&state, "alice").await;

        for hint in [
            None,
            Some("mxid:@alice:example.com"),
            Some("mxid:@bob:other.example"),
            Some("bob@example.com"),
        ] {
            let request = Request::get(account_path(hint)).empty();
            let response = state.request(cookies.with_cookies(request)).await;
            cookies.save_cookies(&response);
            response.assert_status(StatusCode::OK);
            assert!(!is_finished(&state, &alice_session).await);
        }
    }

    #[test]
    fn manage_account_actions_stored_before_the_hint_still_parse() {
        let action: PostAuthAction = serde_json::from_value(serde_json::json!({
            "kind": "manage_account",
            "action": "org.matrix.cross_signing_reset",
            "gua_user": "alice",
        }))
        .unwrap();
        let PostAuthAction::ManageAccount {
            action:
                Some(AccountAction::OrgMatrixCrossSigningReset {
                    gua_user: Some(user),
                    ..
                }),
            gua_login_hint: None,
        } = &action
        else {
            panic!("unexpected post auth action: {action:?}");
        };
        assert_eq!(user, "alice");

        let action = PostAuthAction::manage_account_with_hint(
            None,
            Some("mxid:@alice:example.com".to_owned()),
        );
        let json = serde_json::to_value(&action).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "kind": "manage_account",
                "gua_login_hint": "mxid:@alice:example.com",
            })
        );
        let PostAuthAction::ManageAccount {
            action: None,
            gua_login_hint: Some(hint),
        } = serde_json::from_value(json).unwrap()
        else {
            panic!("unexpected post auth action");
        };
        assert_eq!(hint, "mxid:@alice:example.com");
    }
}
