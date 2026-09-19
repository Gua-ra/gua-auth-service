// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::{collections::BTreeSet, sync::LazyLock};

use axum::{Json, response::IntoResponse};
use axum_extra::typed_header::TypedHeader;
use headers::{Authorization, authorization::Bearer};
use hyper::StatusCode;
use mas_axum_utils::record_error;
use mas_data_model::{BoxClock, BoxRng, Clock, TokenType};
use mas_storage::{
    BoxRepository, Pagination, RepositoryAccess,
    compat::{CompatAccessTokenRepository, CompatSessionFilter, CompatSessionRepository},
    queue::{QueueJobRepositoryExt as _, SyncDevicesJob},
};
use opentelemetry::{Key, KeyValue, metrics::Counter};
use serde::Deserialize;
use thiserror::Error;
use tracing::info;
use ulid::Ulid;

use super::{MatrixError, MatrixJsonBody};
use crate::{BoundActivityTracker, METER, impl_from_error_for_route};

static LOGOUT_ALL_COUNTER: LazyLock<Counter<u64>> = LazyLock::new(|| {
    METER
        .u64_counter("mas.compat.logout_all_request")
        .with_description(
            "How many request to the /logout/all compatibility endpoint have happened",
        )
        .with_unit("{request}")
        .build()
});
const RESULT: Key = Key::from_static_str("result");

#[derive(Error, Debug)]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("Can't load session {0}")]
    CantLoadSession(Ulid),

    #[error("Can't load user {0}")]
    CantLoadUser(Ulid),

    #[error("Token {0} has expired")]
    InvalidToken(Ulid),

    #[error("Session {0} has been revoked")]
    InvalidSession(Ulid),

    #[error("User {0} is locked or deactivated")]
    InvalidUser(Ulid),

    #[error("/logout/all is not supported")]
    NotSupported,

    #[error("Missing access token")]
    MissingAuthorization,

    #[error("Invalid token format")]
    TokenFormat(#[from] mas_data_model::TokenFormatError),

    #[error("Access token is not a compatibility access token")]
    NotACompatToken,
}

impl_from_error_for_route!(mas_storage::RepositoryError);

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        let sentry_event_id = record_error!(
            self,
            Self::Internal(_) | Self::CantLoadSession(_) | Self::CantLoadUser(_)
        );

        // We track separately if the endpoint was called without the custom
        // parameter, so that we know if clients are using this endpoint in the
        // wild
        if matches!(self, Self::NotSupported) {
            LOGOUT_ALL_COUNTER.add(1, &[KeyValue::new(RESULT, "not_supported")]);
        } else {
            LOGOUT_ALL_COUNTER.add(1, &[KeyValue::new(RESULT, "error")]);
        }

        let response = match self {
            Self::Internal(_) | Self::CantLoadSession(_) | Self::CantLoadUser(_) => MatrixError {
                errcode: "M_UNKNOWN",
                error: "Internal error",
                status: StatusCode::INTERNAL_SERVER_ERROR,
            },
            Self::MissingAuthorization => MatrixError {
                errcode: "M_MISSING_TOKEN",
                error: "Missing access token",
                status: StatusCode::UNAUTHORIZED,
            },
            Self::InvalidUser(_)
            | Self::InvalidSession(_)
            | Self::InvalidToken(_)
            | Self::NotACompatToken
            | Self::TokenFormat(_) => MatrixError {
                errcode: "M_UNKNOWN_TOKEN",
                error: "Invalid access token",
                status: StatusCode::UNAUTHORIZED,
            },
            Self::NotSupported => MatrixError {
                errcode: "M_UNRECOGNIZED",
                error: "The /logout/all endpoint is not supported by this deployment",
                status: StatusCode::NOT_FOUND,
            },
        };

        (sentry_event_id, response).into_response()
    }
}

#[derive(Deserialize, Default)]
pub(crate) struct RequestBody {
    #[serde(rename = "io.element.only_compat_is_fine", default)]
    only_compat_is_fine: bool,
}

#[tracing::instrument(name = "handlers.compat.logout_all.post", skip_all)]
pub(crate) async fn post(
    clock: BoxClock,
    mut rng: BoxRng,
    mut repo: BoxRepository,
    activity_tracker: BoundActivityTracker,
    maybe_authorization: Option<TypedHeader<Authorization<Bearer>>>,
    input: Option<MatrixJsonBody<RequestBody>>,
) -> Result<impl IntoResponse, RouteError> {
    let MatrixJsonBody(input) = input.unwrap_or_default();
    let TypedHeader(authorization) = maybe_authorization.ok_or(RouteError::MissingAuthorization)?;

    let token = authorization.token();
    let token_type = TokenType::check(token)?;

    if token_type != TokenType::CompatAccessToken {
        return Err(RouteError::NotACompatToken);
    }

    let token = repo
        .compat_access_token()
        .find_by_token(token)
        .await?
        .ok_or(RouteError::NotACompatToken)?;

    if !token.is_valid(clock.now()) {
        return Err(RouteError::InvalidToken(token.id));
    }

    let session = repo
        .compat_session()
        .lookup(token.session_id)
        .await?
        .ok_or(RouteError::CantLoadSession(token.session_id))?;

    if !session.is_valid() {
        return Err(RouteError::InvalidSession(session.id));
    }

    activity_tracker
        .record_compat_session(&clock, &session)
        .await;

    let user = repo
        .user()
        .lookup(session.user_id)
        .await?
        .ok_or(RouteError::CantLoadUser(session.user_id))?;

    if !user.is_valid() {
        return Err(RouteError::InvalidUser(session.user_id));
    }

    if !input.only_compat_is_fine {
        return Err(RouteError::NotSupported);
    }

    let filter = CompatSessionFilter::new().for_user(&user).active_only();

    // GUA FORK: remember which browser sessions the sessions about to be ended
    // were started from, the calling session's included.
    let mut user_session_ids = BTreeSet::new();
    let mut cursor = Pagination::first(1000);
    loop {
        let page = repo.compat_session().list(filter, cursor).await?;
        for edge in page.edges {
            let (compat_session, _) = edge.node;
            user_session_ids.extend(compat_session.user_session_id);
            cursor = cursor.after(edge.cursor);
        }
        if !page.has_next_page {
            break;
        }
    }

    let affected_sessions = repo.compat_session().finish_bulk(&clock, filter).await?;
    info!(
        "Logged out {affected_sessions} sessions for user {user_id}",
        user_id = user.id
    );

    // GUA FORK: signing out ends the browser sessions behind the ended
    // sessions too, unless one still backs another active session. Left in
    // place, the next sign-in in any of those browsers would silently continue
    // as this account instead of the one being signed in.
    for user_session_id in user_session_ids {
        crate::gua::sessions::finish_browser_session_if_unused(
            &mut repo,
            &clock,
            Some(user_session_id),
        )
        .await?;
    }

    // Schedule a job to sync the devices of the user with the homeserver
    repo.queue_job()
        .schedule_job(&mut rng, &clock, SyncDevicesJob::new(&user))
        .await?;

    repo.save().await?;

    LOGOUT_ALL_COUNTER.add(1, &[KeyValue::new(RESULT, "success")]);

    Ok(Json(serde_json::json!({})))
}

#[cfg(test)]
mod tests {
    use hyper::Request;
    use mas_data_model::{BrowserSession, Device, TokenType};
    use mas_router::SimpleRoute;
    use oauth2_types::{
        registration::ClientRegistrationResponse,
        scope::{OPENID, Scope},
    };
    use sqlx::PgPool;

    use crate::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    async fn browser_session_finished(state: &TestState, browser_session: &BrowserSession) -> bool {
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

    /// GUA FORK: start a compatibility session from a browser session, as an
    /// SSO login does, and return its access token.
    async fn add_compat_session(state: &TestState, browser_session: &BrowserSession) -> String {
        let mut rng = state.rng();
        let mut repo = state.repository().await.unwrap();
        let device = Device::generate(&mut rng);
        let session = repo
            .compat_session()
            .add(
                &mut rng,
                &state.clock,
                &browser_session.user,
                device,
                Some(browser_session),
                false,
                None,
            )
            .await
            .unwrap();
        let token = TokenType::CompatAccessToken.generate(&mut rng);
        repo.compat_access_token()
            .add(&mut rng, &state.clock, &session, token.clone(), None)
            .await
            .unwrap();
        repo.save().await.unwrap();
        token
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_gua_logout_all_ends_the_browser_sessions_behind_the_ended_sessions(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let mut rng = state.rng();

        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();
        let lone = repo
            .browser_session()
            .add(&mut rng, &state.clock, &user, None)
            .await
            .unwrap();
        let shared = repo
            .browser_session()
            .add(&mut rng, &state.clock, &user, None)
            .await
            .unwrap();
        repo.save().await.unwrap();

        let token = add_compat_session(&state, &lone).await;
        let _other = add_compat_session(&state, &shared).await;

        let request = Request::post("/_matrix/client/v3/logout/all")
            .bearer(&token)
            .json(serde_json::json!({ "io.element.only_compat_is_fine": true }));
        let response = state.request(request).await;
        response.assert_status(hyper::StatusCode::OK);

        assert!(browser_session_finished(&state, &lone).await);
        // The other browser's session was ended too, so its browser session
        // goes with it.
        assert!(browser_session_finished(&state, &shared).await);

        // A browser session that still backs an OAuth 2.0 session is kept.
        let request =
            Request::post(mas_router::OAuth2RegistrationEndpoint::PATH).json(serde_json::json!({
                "client_uri": "https://example.com/",
                "redirect_uris": ["https://example.com/callback"],
                "token_endpoint_auth_method": "client_secret_post",
                "response_types": ["code"],
                "grant_types": ["authorization_code"],
            }));
        let response = state.request(request).await;
        response.assert_status(hyper::StatusCode::CREATED);
        let ClientRegistrationResponse { client_id, .. } = response.json();

        let mut repo = state.repository().await.unwrap();
        let user = repo.user().lookup(user.id).await.unwrap().unwrap();
        let busy = repo
            .browser_session()
            .add(&mut rng, &state.clock, &user, None)
            .await
            .unwrap();
        let client = repo
            .oauth2_client()
            .find_by_client_id(&client_id)
            .await
            .unwrap()
            .unwrap();
        repo.oauth2_session()
            .add_from_browser_session(
                &mut rng,
                &state.clock,
                &client,
                &busy,
                Scope::from_iter([OPENID]),
            )
            .await
            .unwrap();
        repo.save().await.unwrap();

        let token = add_compat_session(&state, &busy).await;
        let request = Request::post("/_matrix/client/v3/logout/all")
            .bearer(&token)
            .json(serde_json::json!({ "io.element.only_compat_is_fine": true }));
        let response = state.request(request).await;
        response.assert_status(hyper::StatusCode::OK);

        assert!(!browser_session_finished(&state, &busy).await);
    }
}
