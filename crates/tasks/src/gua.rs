// Copyright 2026 Gua
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! GUA FORK: tell upstream providers that an account was deleted.
//!
//! Each upstream link of a deactivated user is the record that its provider
//! still has to forget the account. The link is removed only after the
//! provider confirmed, so a failed notice is retried by the deactivation job
//! and then by the hourly sweep until it succeeds.

use std::time::Duration;

use anyhow::Context as _;
use mas_data_model::{UpstreamOAuthLink, UpstreamOAuthProvider, User};
use mas_http::RequestBuilderExt as _;
use mas_keystore::{Encrypter, Keystore};
use mas_storage::{
    Pagination, RepositoryAccess as _,
    upstream_oauth2::UpstreamOAuthLinkFilter,
    user::{UserFilter, UserRepository as _},
};
use serde::Serialize;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};
use url::Url;

use crate::{State, new_queue::JobError, upstream_oauth2::client_credentials_for_provider};

/// Path of the account deletion notice, relative to the provider's issuer.
const ACCOUNT_DELETED_PATH: &str = "oauth2/account-deleted";

const NOTICE_TIMEOUT: Duration = Duration::from_secs(10);

const PAGE_SIZE: usize = 100;

/// What the worker needs to authenticate to upstream providers.
#[derive(Clone)]
pub struct UpstreamProviderAccess {
    pub http_client: reqwest::Client,
    pub encrypter: Encrypter,
    pub keystore: Keystore,
}

#[derive(Serialize)]
struct AccountDeletedNotice<'a> {
    sub: &'a str,
}

/// Notify the provider of each of the user's upstream links, and remove every
/// link whose provider answered with a success status.
///
/// Does nothing when `account.gua_forget_upstream_on_deactivation` is off.
///
/// # Errors
///
/// Returns an error if the database fails or if any link is left.
pub(crate) async fn forget_upstream_links(state: &State, user: &User) -> anyhow::Result<()> {
    if !state.site_config().gua_forget_upstream_on_deactivation {
        return Ok(());
    }

    let mut repo = state.repository().await?;
    let mut links = Vec::new();
    let mut cursor = Pagination::first(PAGE_SIZE);
    loop {
        let page = repo
            .upstream_oauth_link()
            .list(UpstreamOAuthLinkFilter::new().for_user(user), cursor)
            .await?;
        for edge in page.edges {
            cursor = cursor.after(edge.cursor);
            let provider = repo
                .upstream_oauth_provider()
                .lookup(edge.node.provider_id)
                .await?;
            links.push((edge.node, provider));
        }
        if !page.has_next_page {
            break;
        }
    }
    repo.cancel().await?;

    let mut left = 0_usize;
    for (link, provider) in links {
        let result = match provider {
            Some(provider) => send_account_deleted(state, &provider, &link).await,
            None => Err(anyhow::anyhow!("the link's provider does not exist")),
        };

        if let Err(err) = result {
            error!(
                user.id = %user.id,
                upstream_oauth_link.id = %link.id,
                upstream_oauth_provider.id = %link.provider_id,
                error = &*err as &dyn std::error::Error,
                "Upstream provider did not confirm the account deletion, keeping the link"
            );
            left += 1;
            continue;
        }

        let mut repo = state.repository().await?;
        let removed = repo
            .upstream_oauth_link()
            .remove_and_clear_tokens(state.clock(), &link)
            .await?;
        repo.save().await?;
        info!(
            user.id = %user.id,
            upstream_oauth_link.id = %link.id,
            upstream_oauth_provider.id = %link.provider_id,
            removed,
            "Upstream provider confirmed the account deletion"
        );
    }

    anyhow::ensure!(left == 0, "{left} upstream links are left for this user");
    Ok(())
}

/// POST the account deletion notice for one link, authenticated the way the
/// provider is configured for its token endpoint.
async fn send_account_deleted(
    state: &State,
    provider: &UpstreamOAuthProvider,
    link: &UpstreamOAuthLink,
) -> anyhow::Result<()> {
    let access = state.upstream_provider_access();
    let issuer = provider
        .issuer
        .as_deref()
        .context("the provider has no issuer")?;
    let url = Url::parse(&format!(
        "{}/{ACCOUNT_DELETED_PATH}",
        issuer.trim_end_matches('/')
    ))
    .context("the provider's issuer is not a valid URL")?;

    let credentials =
        client_credentials_for_provider(provider, &url, &access.keystore, &access.encrypter)?;
    let request = access
        .http_client
        .post(url.as_str())
        .timeout(NOTICE_TIMEOUT);
    let response = credentials
        .authenticated_form(
            request,
            &AccountDeletedNotice { sub: &link.subject },
            state.clock().now(),
            &mut state.rng(),
        )?
        .send_traced()
        .await?;

    // A redirected notice is never a confirmation, whatever the final page
    // says.
    anyhow::ensure!(
        response.url() == &url,
        "the provider redirected the notice to another URL"
    );
    let status = response.status();
    anyhow::ensure!(
        status.is_success(),
        "the provider answered with status {status}"
    );

    Ok(())
}

/// Erase each deactivated user that still has upstream links on the
/// homeserver, then run [`forget_upstream_links`] for them.
///
/// This catches the deactivation jobs that gave up, and accounts deleted before
/// the notice existed. A failure is logged and left for the next run.
///
/// # Errors
///
/// Returns an error if the database fails.
pub(crate) async fn sweep_deactivated_users(
    state: &State,
    cancellation_token: &CancellationToken,
) -> Result<(), JobError> {
    if !state.site_config().gua_forget_upstream_on_deactivation {
        return Ok(());
    }

    let mut done = 0_usize;
    let mut left = 0_usize;
    let mut cursor = Pagination::first(PAGE_SIZE);
    while !cancellation_token.is_cancelled() {
        let mut repo = state.repository().await.map_err(JobError::retry)?;
        let page = repo
            .user()
            .list(UserFilter::new().deactivated_only(), cursor)
            .await
            .map_err(JobError::retry)?;
        let mut pending = Vec::new();
        for edge in page.edges {
            cursor = cursor.after(edge.cursor);
            let links = repo
                .upstream_oauth_link()
                .count(UpstreamOAuthLinkFilter::new().for_user(&edge.node))
                .await
                .map_err(JobError::retry)?;
            if links > 0 {
                pending.push(edge.node);
            }
        }
        repo.cancel().await.map_err(JobError::retry)?;

        for user in pending {
            if cancellation_token.is_cancelled() {
                break;
            }

            if let Err(err) = state
                .matrix_connection()
                .delete_user(&user.username, true)
                .await
            {
                error!(
                    user.id = %user.id,
                    error = &*err as &dyn std::error::Error,
                    "Failed to erase a deleted account on the homeserver, keeping its upstream links"
                );
                left += 1;
                continue;
            }

            match forget_upstream_links(state, &user).await {
                Ok(()) => done += 1,
                Err(err) => {
                    error!(
                        user.id = %user.id,
                        error = &*err as &dyn std::error::Error,
                        "Failed to forget the upstream links of a deleted account"
                    );
                    left += 1;
                }
            }
        }

        if !page.has_next_page {
            break;
        }
    }

    if done > 0 || left > 0 {
        info!(
            done,
            left, "Swept deleted accounts that still had upstream links"
        );
    }

    Ok(())
}
