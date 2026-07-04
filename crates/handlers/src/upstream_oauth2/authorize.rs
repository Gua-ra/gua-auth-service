// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use axum::{
    extract::{Path, State},
    response::{IntoResponse, Redirect},
};
use axum_extra::extract::Query;
use hyper::StatusCode;
use mas_axum_utils::{GenericError, InternalError, cookies::CookieJar};
use mas_data_model::{BoxClock, BoxRng, DownstreamClientGuardConfig, UpstreamOAuthProvider};
use mas_oidc_client::requests::authorization_code::AuthorizationRequestData;
use mas_router::{PostAuthAction, UrlBuilder};
use mas_storage::{
    BoxRepository,
    upstream_oauth2::{UpstreamOAuthProviderRepository, UpstreamOAuthSessionRepository},
};
use thiserror::Error;
use ulid::Ulid;

use super::{UpstreamSessionsCookie, cache::LazyProviderInfos};
use crate::{
    impl_from_error_for_route, upstream_oauth2::cache::MetadataCache,
    views::shared::OptionalPostAuthAction,
};

#[derive(Debug, Error)]
pub(crate) enum RouteError {
    #[error("Provider not found")]
    ProviderNotFound,

    #[error(transparent)]
    Internal(Box<dyn std::error::Error>),
}

impl_from_error_for_route!(mas_oidc_client::error::DiscoveryError);
impl_from_error_for_route!(mas_oidc_client::error::AuthorizationError);
impl_from_error_for_route!(mas_storage::RepositoryError);

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        match self {
            e @ Self::ProviderNotFound => {
                GenericError::new(StatusCode::NOT_FOUND, e).into_response()
            }
            Self::Internal(e) => InternalError::new(e).into_response(),
        }
    }
}

#[tracing::instrument(
    name = "handlers.upstream_oauth2.authorize.get",
    fields(upstream_oauth_provider.id = %provider_id),
    skip_all,
)]
pub(crate) async fn get(
    mut rng: BoxRng,
    clock: BoxClock,
    State(metadata_cache): State<MetadataCache>,
    mut repo: BoxRepository,
    State(url_builder): State<UrlBuilder>,
    State(http_client): State<reqwest::Client>,
    State(downstream_guard): State<DownstreamClientGuardConfig>,
    cookie_jar: CookieJar,
    Path(provider_id): Path<Ulid>,
    Query(query): Query<OptionalPostAuthAction>,
) -> Result<impl IntoResponse, RouteError> {
    let provider = repo
        .upstream_oauth_provider()
        .lookup(provider_id)
        .await?
        .filter(UpstreamOAuthProvider::enabled)
        .ok_or(RouteError::ProviderNotFound)?;

    // First, discover the provider
    // This is done lazyly according to provider.discovery_mode and the various
    // endpoint overrides
    let mut lazy_metadata = LazyProviderInfos::new(&metadata_cache, &provider, &http_client);
    lazy_metadata.maybe_discover().await?;

    let redirect_uri = url_builder.upstream_oauth_callback(provider.id);

    let mut data = AuthorizationRequestData::new(
        provider.client_id.clone(),
        provider.scope.clone(),
        redirect_uri,
    );

    if let Some(response_mode) = provider.response_mode {
        data = data.with_response_mode(response_mode.into());
    }

    // Fetch the authorization grant once if we need it, either to forward the
    // login hint or to resolve the downstream client for the Gua marker.
    let grant = if (provider.forward_login_hint
        || downstream_guard
            .get(provider.id)
            .is_some_and(|entry| entry.forward_downstream_client))
        && let Some(PostAuthAction::ContinueAuthorizationGrant { id }) = &query.post_auth_action
    {
        repo.oauth2_authorization_grant().lookup(*id).await?
    } else {
        None
    };

    // Forward the raw login hint upstream for the provider to handle however it
    // sees fit
    if provider.forward_login_hint
        && let Some(login_hint) = grant.as_ref().and_then(|grant| grant.login_hint.clone())
    {
        data = data.with_login_hint(login_hint);
    }

    // Resolve the Gua downstream-client marker (`web` / `native`) for the
    // downstream client that initiated this flow, if the guard is enabled for
    // this provider. We look the client up now so the value can be appended to
    // the extra params below. This only touches the new-login flow (a grant is
    // present); existing-user login, re-auth, change-phone and passkey flows
    // carry no `ContinueAuthorizationGrant` grant here and are never marked.
    let guard_enabled = downstream_guard
        .get(provider.id)
        .is_some_and(|entry| entry.forward_downstream_client);
    let gua_downstream_marker = if let (true, Some(grant)) = (guard_enabled, grant.as_ref()) {
        let client = repo.oauth2_client().lookup(grant.client_id).await?;
        let client_uri = client.as_ref().and_then(|client| client.client_uri.as_ref());
        downstream_guard.marker_for(provider.id, client_uri)
    } else {
        None
    };

    let data = if let Some(methods) = lazy_metadata.pkce_methods().await? {
        data.with_code_challenge_methods_supported(methods)
    } else {
        data
    };

    // Build an authorization request for it
    let (mut url, data) = mas_oidc_client::requests::authorization_code::build_authorization_url(
        lazy_metadata.authorization_endpoint().await?.clone(),
        data,
        &mut rng,
    )?;

    // We do that in a block because params borrows url mutably
    {
        // Add any additional parameters to the query
        let mut params = url.query_pairs_mut();
        for (key, value) in &provider.additional_authorization_parameters {
            params.append_pair(key, value);
        }

        // Append the Gua downstream-client marker so the upstream provider can
        // apply the web signup allowlist only to web signups.
        if let Some(marker) = gua_downstream_marker {
            params.append_pair("gua_downstream", marker);
        }
    }

    let session = repo
        .upstream_oauth_session()
        .add(
            &mut rng,
            &clock,
            &provider,
            data.state.clone(),
            data.code_challenge_verifier,
            data.nonce,
        )
        .await?;

    let cookie_jar = UpstreamSessionsCookie::load(&cookie_jar)
        .add(session.id, provider.id, data.state, query.post_auth_action)
        .save(cookie_jar, &clock);

    repo.save().await?;

    Ok((cookie_jar, Redirect::temporary(url.as_str())))
}
