// Copyright 2026 Gua
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! GUA FORK: lets a signed-in app approve its own cross-signing reset.
//!
//! Upstream expects the approval to happen on the account page, in a browser
//! session. For the Gua apps that meant a web sheet, and on most phones that
//! sheet holds no session at all (the app signs in through an ephemeral browser
//! context), so finishing setup demanded a whole new phone-number login. On a
//! phone whose browser held another account it silently approved the
//! reset for that account instead.
//!
//! Here the app presents the access token it is already using for the
//! homeserver. The token is checked the same way the userinfo endpoint checks
//! it (valid, unrevoked, session alive), the session must carry the Matrix
//! client API scope, and the reset is opened for that session's own user and
//! nobody else, for the homeserver's usual ten-minute window. It is
//! deliberately not reachable from a browser: there is no CSRF story here
//! because there is no cookie.

use std::sync::Arc;

use axum::{extract::State, response::IntoResponse};
use hyper::StatusCode;
use mas_axum_utils::{
    record_error,
    user_authorization::{AuthorizationVerificationError, UserAuthorization},
};
use mas_data_model::BoxClock;
use mas_matrix::HomeserverConnection;
use mas_storage::BoxRepository;
use thiserror::Error;
use ulid::Ulid;

use crate::{BoundActivityTracker, impl_from_error_for_route};

/// The scope every Gua app session carries for the homeserver API.
const MATRIX_CLIENT_API_SCOPE: &str = "urn:matrix:org.matrix.msc2967.client:api:*";

#[derive(Debug, Error)]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("failed to authenticate")]
    AuthorizationVerificationError(
        #[from] AuthorizationVerificationError<mas_storage::RepositoryError>,
    ),

    #[error("session is not allowed to approve an identity reset")]
    Unauthorized,

    #[error("failed to load user {0}")]
    NoSuchUser(Ulid),

    #[error("homeserver refused to open the reset window")]
    Homeserver(#[source] anyhow::Error),
}

impl_from_error_for_route!(mas_storage::RepositoryError);

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        let sentry_event_id = record_error!(
            self,
            Self::Internal(_) | Self::NoSuchUser(_) | Self::Homeserver(_)
        );
        let response = match self {
            Self::Internal(_) | Self::NoSuchUser(_) | Self::Homeserver(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()).into_response()
            }
            Self::AuthorizationVerificationError(_) | Self::Unauthorized => {
                StatusCode::UNAUTHORIZED.into_response()
            }
        };
        (sentry_event_id, response).into_response()
    }
}

#[tracing::instrument(name = "handlers.gua.identity_reset.post", skip_all)]
pub async fn post(
    clock: BoxClock,
    activity_tracker: BoundActivityTracker,
    mut repo: BoxRepository,
    State(homeserver): State<Arc<dyn HomeserverConnection>>,
    user_authorization: UserAuthorization,
) -> Result<StatusCode, RouteError> {
    let session = user_authorization.protected(&mut repo, &clock).await?;

    if !session.scope.contains(MATRIX_CLIENT_API_SCOPE) {
        return Err(RouteError::Unauthorized);
    }

    let Some(user_id) = session.user_id else {
        return Err(RouteError::Unauthorized);
    };

    activity_tracker
        .record_oauth2_session(&clock, &session)
        .await;

    let user = repo
        .user()
        .lookup(user_id)
        .await?
        .ok_or(RouteError::NoSuchUser(user_id))?;

    // Only ever for the session's own user: the caller does not get to name
    // anyone.
    homeserver
        .allow_cross_signing_reset(&user.username)
        .await
        .map_err(RouteError::Homeserver)?;

    tracing::info!(
        user.id = %user.id,
        session.id = %session.id,
        "Cross-signing reset approved from the app's own session"
    );

    repo.save().await?;

    Ok(StatusCode::NO_CONTENT)
}
