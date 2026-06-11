// Copyright 2025 Gua-ra <https://github.com/Gua-ra>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
//
// ============================================================
// GUA FORK — This file does not exist in the upstream project.
// It will never cause merge conflicts when pulling upstream
// updates. All Gua-specific handler logic lives here.
// ============================================================

//! Gua fork custom handler extensions.
//!
//! The upstream files contain only tiny hook sites that delegate to this
//! module, keeping the per-release diff minimal.

use axum::response::{IntoResponse, Response};
use mas_data_model::{AuthorizationGrant, BoxClock, BoxRng, BrowserSession, Client};
use mas_i18n::DataLocale;
use mas_keystore::Keystore;
use mas_router::UrlBuilder;
use mas_storage::BoxRepository;
use mas_templates::Templates;
use oauth2_types::requests::AuthorizationResponse;
use ulid::Ulid;

use crate::{BoundActivityTracker, oauth2::generate_id_token};
use crate::oauth2::authorization::callback::CallbackDestination;

/// Auto-fulfill an OIDC authorization grant without showing the consent screen.
///
/// Called from the consent GET handler when the requesting client is in the
/// `gua.skip_consent_client_ids` list. The OPA policy evaluation is still
/// performed by the caller before this function is invoked.
///
/// Returns the redirect [`Response`] that the browser should follow to the
/// client callback URI.
///
/// # Errors
///
/// Returns a boxed error if any repository or token-signing operation fails.
pub(crate) async fn auto_fulfill_consent(
    rng: &mut BoxRng,
    clock: &BoxClock,
    mut repo: BoxRepository,
    url_builder: &UrlBuilder,
    key_store: &Keystore,
    templates: &Templates,
    locale: &DataLocale,
    client: &Client,
    browser_session: &BrowserSession,
    grant: AuthorizationGrant,
    activity_tracker: &BoundActivityTracker,
) -> Result<Response, Box<dyn std::error::Error + Send + Sync>> {
    let callback_destination = CallbackDestination::try_from(&grant)?;

    let oauth_session = repo
        .oauth2_session()
        .add_from_browser_session(rng, clock, client, browser_session, grant.scope.clone())
        .await?;

    let grant = repo
        .oauth2_authorization_grant()
        .fulfill(clock, &oauth_session, grant)
        .await?;
    let mut params = AuthorizationResponse::default();

    if grant.response_type_id_token {
        let last_authentication = repo
            .browser_session()
            .get_last_authentication(browser_session)
            .await?;

        params.id_token = Some(generate_id_token(
            rng,
            clock,
            url_builder,
            key_store,
            client,
            Some(&grant),
            browser_session,
            None,
            last_authentication.as_ref(),
        )?);
    }

    if let Some(code) = grant.code {
        params.code = Some(code.code);
    }

    repo.save().await?;
    activity_tracker
        .record_oauth2_session(clock, &oauth_session)
        .await;

    Ok(callback_destination
        .go(templates, locale, params)?
        .into_response())
}

/// Returns `true` when the consent screen should be skipped for this client.
///
/// Inline helper used by the consent handler hook site.
pub(crate) fn should_skip_consent(client_id: Ulid, skip_ids: &[Ulid]) -> bool {
    skip_ids.contains(&client_id)
}
