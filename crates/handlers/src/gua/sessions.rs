// Copyright 2026 Gua
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! GUA FORK: keep browser sessions bound to the account that is signing in.
//!
//! The Gua apps open these pages in browsers that can share cookies with
//! earlier sign-ins. A browser session left behind by one account must never
//! let a later sign-in, device link or approval continue as that account.
//! These are the pieces the handlers share to enforce that.

use mas_data_model::{BrowserSession, Clock};
use mas_storage::{
    BoxRepository, RepositoryError, compat::CompatSessionFilter, oauth2::OAuth2SessionFilter,
};
use ulid::Ulid;

/// The localpart an `mxid:` MSC4198 login hint names on our own homeserver.
///
/// Anything else (a foreign homeserver, an email, an empty localpart) yields
/// `None`, so a hint we cannot check is never used to refuse a session.
pub(crate) fn hinted_localpart(login_hint: Option<&str>, homeserver: &str) -> Option<String> {
    let mxid = login_hint?.strip_prefix("mxid:")?;
    let localpart = mxid
        .strip_prefix('@')?
        .strip_suffix(&format!(":{homeserver}"))?;
    (!localpart.is_empty()).then(|| localpart.to_owned())
}

/// Finish the browser session an OAuth 2.0 or compatibility session was
/// created from, once nothing else still uses it.
///
/// Call this after finishing the app's session, in the same transaction, so
/// the counts no longer include it. Signing out of an app has to end the
/// browser session too: left in place, the next sign-in in that browser (for
/// a different phone number, say) would silently continue as this account.
/// A browser session that still backs another active session is kept, so
/// signing out of one client does not sign the user out of the others.
pub(crate) async fn finish_browser_session_if_unused(
    repo: &mut BoxRepository,
    clock: &dyn Clock,
    user_session_id: Option<Ulid>,
) -> Result<(), RepositoryError> {
    let Some(user_session_id) = user_session_id else {
        return Ok(());
    };

    let Some(browser_session) = repo
        .browser_session()
        .lookup(user_session_id)
        .await?
        .filter(BrowserSession::active)
    else {
        return Ok(());
    };

    let oauth2_sessions = repo
        .oauth2_session()
        .count(
            OAuth2SessionFilter::new()
                .for_browser_session(&browser_session)
                .active_only(),
        )
        .await?;
    let compat_sessions = repo
        .compat_session()
        .count(
            CompatSessionFilter::new()
                .for_browser_session(&browser_session)
                .active_only(),
        )
        .await?;

    if oauth2_sessions == 0 && compat_sessions == 0 {
        tracing::info!(
            browser_session.id = %browser_session.id,
            user.id = %browser_session.user.id,
            "Last session started from this browser session ended, finishing the browser session"
        );
        repo.browser_session()
            .finish(clock, browser_session)
            .await?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::hinted_localpart;

    const HS: &str = "example.com";

    #[test]
    fn reads_the_localpart_of_an_mxid_hint_on_our_homeserver() {
        assert_eq!(
            hinted_localpart(Some("mxid:@bob:example.com"), HS).as_deref(),
            Some("bob")
        );
    }

    #[test]
    fn ignores_hints_it_cannot_check() {
        assert_eq!(hinted_localpart(Some("mxid:@bob:other.org"), HS), None);
        assert_eq!(hinted_localpart(Some("bob@example.com"), HS), None);
        assert_eq!(hinted_localpart(Some("mxid:@:example.com"), HS), None);
        assert_eq!(hinted_localpart(Some("mxid:bob:example.com"), HS), None);
        assert_eq!(hinted_localpart(None, HS), None);
    }
}
