// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::sync::LazyLock;

use axum::{Json, response::IntoResponse};
use axum_extra::typed_header::TypedHeader;
use headers::{Authorization, authorization::Bearer};
use hyper::StatusCode;
use mas_axum_utils::record_error;
use mas_data_model::{BoxClock, BoxRng, Clock, TokenType};
use mas_storage::{
    BoxRepository, RepositoryAccess,
    compat::{CompatAccessTokenRepository, CompatSessionRepository},
    queue::{QueueJobRepositoryExt as _, SyncDevicesJob},
};
use opentelemetry::{Key, KeyValue, metrics::Counter};
use thiserror::Error;

use super::MatrixError;
use crate::{BoundActivityTracker, METER, impl_from_error_for_route};

static LOGOUT_COUNTER: LazyLock<Counter<u64>> = LazyLock::new(|| {
    METER
        .u64_counter("mas.compat.logout_request")
        .with_description("How many compatibility logout request have happened")
        .with_unit("{request}")
        .build()
});
const RESULT: Key = Key::from_static_str("result");

#[derive(Error, Debug)]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("Missing access token")]
    MissingAuthorization,

    #[error("Invalid token format")]
    TokenFormat(#[from] mas_data_model::TokenFormatError),

    #[error("Invalid access token")]
    InvalidAuthorization,
}

impl_from_error_for_route!(mas_storage::RepositoryError);

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        let sentry_event_id = record_error!(self, Self::Internal(_));
        LOGOUT_COUNTER.add(1, &[KeyValue::new(RESULT, "error")]);
        let response = match self {
            Self::Internal(_) => MatrixError {
                errcode: "M_UNKNOWN",
                error: "Internal error",
                status: StatusCode::INTERNAL_SERVER_ERROR,
            },
            Self::MissingAuthorization => MatrixError {
                errcode: "M_MISSING_TOKEN",
                error: "Missing access token",
                status: StatusCode::UNAUTHORIZED,
            },
            Self::InvalidAuthorization | Self::TokenFormat(_) => MatrixError {
                errcode: "M_UNKNOWN_TOKEN",
                error: "Invalid access token",
                status: StatusCode::UNAUTHORIZED,
            },
        };

        (sentry_event_id, response).into_response()
    }
}

#[tracing::instrument(name = "handlers.compat.logout.post", skip_all)]
pub(crate) async fn post(
    clock: BoxClock,
    mut rng: BoxRng,
    mut repo: BoxRepository,
    activity_tracker: BoundActivityTracker,
    maybe_authorization: Option<TypedHeader<Authorization<Bearer>>>,
) -> Result<impl IntoResponse, RouteError> {
    let TypedHeader(authorization) = maybe_authorization.ok_or(RouteError::MissingAuthorization)?;

    let token = authorization.token();
    let token_type = TokenType::check(token)?;

    if token_type != TokenType::CompatAccessToken {
        return Err(RouteError::InvalidAuthorization);
    }

    let token = repo
        .compat_access_token()
        .find_by_token(token)
        .await?
        .filter(|t| t.is_valid(clock.now()))
        .ok_or(RouteError::InvalidAuthorization)?;

    let session = repo
        .compat_session()
        .lookup(token.session_id)
        .await?
        .filter(|s| s.is_valid())
        .ok_or(RouteError::InvalidAuthorization)?;

    activity_tracker
        .record_compat_session(&clock, &session)
        .await;

    let user = repo
        .user()
        .lookup(session.user_id)
        .await?
        // XXX: this is probably not the right error
        .ok_or(RouteError::InvalidAuthorization)?;

    let user_session_id = session.user_session_id;

    // This will make the access token invalid
    repo.compat_session().finish(&clock, session).await?;

    crate::gua::sessions::finish_browser_session_if_unused(&mut repo, &clock, user_session_id)
        .await?;

    // Schedule a job to sync the devices of the user with the homeserver
    //
    // Doing this in a background job is ok as the access token will be invalid
    // right away (from the session being finished above) and we do actually
    // want to do a full device list sync (as opposed to
    // `homeserver.delete_device(...)`), because we're not sure whether we want
    // to delete the device (if there is for example a concurrent logout and
    // login with the same device ID).
    repo.queue_job()
        .schedule_job(&mut rng, &clock, SyncDevicesJob::new(&user))
        .await?;

    repo.save().await?;

    LOGOUT_COUNTER.add(1, &[KeyValue::new(RESULT, "success")]);

    Ok(Json(serde_json::json!({})))
}

#[cfg(test)]
mod tests {
    use hyper::Request;
    use mas_data_model::{BrowserSession, Device, TokenType, User};
    use sqlx::PgPool;

    use crate::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    async fn add_compat_session(
        state: &TestState,
        user: &User,
        browser_session: &BrowserSession,
    ) -> String {
        let mut rng = state.rng();
        let mut repo = state.repository().await.unwrap();
        let device = Device::generate(&mut rng);
        let session = repo
            .compat_session()
            .add(
                &mut rng,
                &state.clock,
                user,
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

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_gua_logout_ends_the_browser_session_behind_the_last_session(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let mut rng = state.rng();

        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();
        let browser_session = repo
            .browser_session()
            .add(&mut rng, &state.clock, &user, None)
            .await
            .unwrap();
        repo.save().await.unwrap();

        let first = add_compat_session(&state, &user, &browser_session).await;
        let second = add_compat_session(&state, &user, &browser_session).await;

        let request = Request::post("/_matrix/client/v3/logout")
            .bearer(&first)
            .empty();
        let response = state.request(request).await;
        response.assert_status(hyper::StatusCode::OK);
        assert!(!browser_session_finished(&state, &browser_session).await);

        let request = Request::post("/_matrix/client/v3/logout")
            .bearer(&second)
            .empty();
        let response = state.request(request).await;
        response.assert_status(hyper::StatusCode::OK);
        assert!(browser_session_finished(&state, &browser_session).await);
    }
}
