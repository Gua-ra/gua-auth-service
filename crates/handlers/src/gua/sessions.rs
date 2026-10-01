// Copyright 2026 Gua
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! GUA FORK: keep browser sessions bound to the account that is signing in.
//!
//! The Gua apps open these pages in browsers that can share cookies with
//! earlier sign-ins. A browser session left behind by one account must never
//! let a later sign-in, device link or approval continue as that account.
//! Signing out of an app therefore ends the browser session behind it, and a
//! login hint naming the app's account is only ever used to refuse a session
//! that belongs to someone else, never to grant anything. These are the
//! pieces the handlers share to enforce that.

use mas_data_model::{BrowserSession, Clock, User};
use mas_storage::{
    BoxRepository, RepositoryError,
    compat::CompatSessionFilter,
    oauth2::OAuth2SessionFilter,
    queue::{QueueJobRepositoryExt as _, SyncDevicesJob},
    user::BrowserSessionFilter,
};
use rand::RngCore;
use serde_json::Value;
use ulid::Ulid;

/// ID token claim the identity service sets, only on the sign-in that
/// completes an account recovery, to ask for every other session of the
/// account to be ended.
pub(crate) const END_OTHER_SESSIONS_CLAIM: &str = "gua_end_other_sessions";

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

/// Whether verified upstream ID token claims ask to end the account's other
/// sessions. Only a JSON `true` counts.
pub(crate) fn claims_end_other_sessions(id_token_claims: Option<&Value>) -> bool {
    id_token_claims
        .and_then(|claims| claims.get(END_OTHER_SESSIONS_CLAIM))
        .and_then(Value::as_bool)
        .unwrap_or(false)
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

/// End every active OAuth 2.0, compatibility and browser session of a user,
/// and schedule a device sync so the homeserver drops the devices too.
///
/// Used when a sign-in completes an account recovery: whoever held the
/// account's other sessions must not keep them.
pub(crate) async fn end_all_sessions_of_user(
    repo: &mut BoxRepository,
    rng: &mut (dyn RngCore + Send),
    clock: &dyn Clock,
    user: &User,
) -> Result<(), RepositoryError> {
    let oauth2_sessions = repo
        .oauth2_session()
        .finish_bulk(
            clock,
            OAuth2SessionFilter::new().for_user(user).active_only(),
        )
        .await?;
    let compat_sessions = repo
        .compat_session()
        .finish_bulk(
            clock,
            CompatSessionFilter::new().for_user(user).active_only(),
        )
        .await?;
    let browser_sessions = repo
        .browser_session()
        .finish_bulk(
            clock,
            BrowserSessionFilter::new().for_user(user).active_only(),
        )
        .await?;

    repo.queue_job()
        .schedule_job(rng, clock, SyncDevicesJob::new(user))
        .await?;

    tracing::info!(
        user.id = %user.id,
        "Account recovery sign-in: finished {oauth2_sessions} OAuth 2.0 sessions, {compat_sessions} compatibility sessions and {browser_sessions} browser sessions"
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{claims_end_other_sessions, hinted_localpart};

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

    #[test]
    fn only_a_true_claim_ends_other_sessions() {
        assert!(claims_end_other_sessions(Some(
            &json!({ "sub": "a", "gua_end_other_sessions": true })
        )));

        assert!(!claims_end_other_sessions(None));
        assert!(!claims_end_other_sessions(Some(&json!({ "sub": "a" }))));
        assert!(!claims_end_other_sessions(Some(
            &json!({ "gua_end_other_sessions": false })
        )));
        assert!(!claims_end_other_sessions(Some(
            &json!({ "gua_end_other_sessions": "true" })
        )));
        assert!(!claims_end_other_sessions(Some(
            &json!({ "gua_end_other_sessions": 1 })
        )));
    }
}
