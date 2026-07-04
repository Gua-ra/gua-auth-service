// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use chrono::{DateTime, Utc};
use mas_iana::jose::JsonWebSignatureAlg;
use oauth2_types::scope::Scope;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use ulid::Ulid;
use url::Url;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DiscoveryMode {
    /// Use OIDC discovery to fetch and verify the provider metadata
    #[default]
    Oidc,

    /// Use OIDC discovery to fetch the provider metadata, but don't verify it
    Insecure,

    /// Don't fetch the provider metadata
    Disabled,
}

impl DiscoveryMode {
    /// Returns `true` if discovery is disabled
    #[must_use]
    pub fn is_disabled(&self) -> bool {
        matches!(self, DiscoveryMode::Disabled)
    }
}

#[derive(Debug, Clone, Error)]
#[error("Invalid discovery mode {0:?}")]
pub struct InvalidDiscoveryModeError(String);

impl std::str::FromStr for DiscoveryMode {
    type Err = InvalidDiscoveryModeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "oidc" => Ok(Self::Oidc),
            "insecure" => Ok(Self::Insecure),
            "disabled" => Ok(Self::Disabled),
            s => Err(InvalidDiscoveryModeError(s.to_owned())),
        }
    }
}

impl DiscoveryMode {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Oidc => "oidc",
            Self::Insecure => "insecure",
            Self::Disabled => "disabled",
        }
    }
}

impl std::fmt::Display for DiscoveryMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum PkceMode {
    /// Use PKCE if the provider supports it
    #[default]
    Auto,

    /// Always use PKCE with the S256 method
    S256,

    /// Don't use PKCE
    Disabled,
}

#[derive(Debug, Clone, Error)]
#[error("Invalid PKCE mode {0:?}")]
pub struct InvalidPkceModeError(String);

impl std::str::FromStr for PkceMode {
    type Err = InvalidPkceModeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "auto" => Ok(Self::Auto),
            "s256" => Ok(Self::S256),
            "disabled" => Ok(Self::Disabled),
            s => Err(InvalidPkceModeError(s.to_owned())),
        }
    }
}

impl PkceMode {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::S256 => "s256",
            Self::Disabled => "disabled",
        }
    }
}

impl std::fmt::Display for PkceMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Error)]
#[error("Invalid response mode {0:?}")]
pub struct InvalidResponseModeError(String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ResponseMode {
    #[default]
    Query,
    FormPost,
}

impl From<ResponseMode> for oauth2_types::requests::ResponseMode {
    fn from(value: ResponseMode) -> Self {
        match value {
            ResponseMode::Query => oauth2_types::requests::ResponseMode::Query,
            ResponseMode::FormPost => oauth2_types::requests::ResponseMode::FormPost,
        }
    }
}

impl ResponseMode {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Query => "query",
            Self::FormPost => "form_post",
        }
    }
}

impl std::fmt::Display for ResponseMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for ResponseMode {
    type Err = InvalidResponseModeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "query" => Ok(ResponseMode::Query),
            "form_post" => Ok(ResponseMode::FormPost),
            s => Err(InvalidResponseModeError(s.to_owned())),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TokenAuthMethod {
    None,
    ClientSecretBasic,
    ClientSecretPost,
    ClientSecretJwt,
    PrivateKeyJwt,
    SignInWithApple,
}

impl TokenAuthMethod {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::ClientSecretBasic => "client_secret_basic",
            Self::ClientSecretPost => "client_secret_post",
            Self::ClientSecretJwt => "client_secret_jwt",
            Self::PrivateKeyJwt => "private_key_jwt",
            Self::SignInWithApple => "sign_in_with_apple",
        }
    }
}

impl std::fmt::Display for TokenAuthMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for TokenAuthMethod {
    type Err = InvalidUpstreamOAuth2TokenAuthMethod;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "none" => Ok(Self::None),
            "client_secret_post" => Ok(Self::ClientSecretPost),
            "client_secret_basic" => Ok(Self::ClientSecretBasic),
            "client_secret_jwt" => Ok(Self::ClientSecretJwt),
            "private_key_jwt" => Ok(Self::PrivateKeyJwt),
            "sign_in_with_apple" => Ok(Self::SignInWithApple),
            s => Err(InvalidUpstreamOAuth2TokenAuthMethod(s.to_owned())),
        }
    }
}

#[derive(Debug, Clone, Error)]
#[error("Invalid upstream OAuth 2.0 token auth method: {0}")]
pub struct InvalidUpstreamOAuth2TokenAuthMethod(String);

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OnBackchannelLogout {
    DoNothing,
    LogoutBrowserOnly,
    LogoutAll,
}

impl OnBackchannelLogout {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DoNothing => "do_nothing",
            Self::LogoutBrowserOnly => "logout_browser_only",
            Self::LogoutAll => "logout_all",
        }
    }
}

impl std::fmt::Display for OnBackchannelLogout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for OnBackchannelLogout {
    type Err = InvalidUpstreamOAuth2OnBackchannelLogout;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "do_nothing" => Ok(Self::DoNothing),
            "logout_browser_only" => Ok(Self::LogoutBrowserOnly),
            "logout_all" => Ok(Self::LogoutAll),
            s => Err(InvalidUpstreamOAuth2OnBackchannelLogout(s.to_owned())),
        }
    }
}

#[derive(Debug, Clone, Error)]
#[error("Invalid upstream OAuth 2.0 'on backchannel logout': {0}")]
pub struct InvalidUpstreamOAuth2OnBackchannelLogout(String);

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UpstreamOAuthProvider {
    pub id: Ulid,
    pub issuer: Option<String>,
    pub human_name: Option<String>,
    pub brand_name: Option<String>,
    pub discovery_mode: DiscoveryMode,
    pub pkce_mode: PkceMode,
    pub jwks_uri_override: Option<Url>,
    pub authorization_endpoint_override: Option<Url>,
    pub scope: Scope,
    pub token_endpoint_override: Option<Url>,
    pub userinfo_endpoint_override: Option<Url>,
    pub fetch_userinfo: bool,
    pub userinfo_signed_response_alg: Option<JsonWebSignatureAlg>,
    pub client_id: String,
    pub encrypted_client_secret: Option<String>,
    pub token_endpoint_signing_alg: Option<JsonWebSignatureAlg>,
    pub token_endpoint_auth_method: TokenAuthMethod,
    pub id_token_signed_response_alg: JsonWebSignatureAlg,
    pub response_mode: Option<ResponseMode>,
    pub created_at: DateTime<Utc>,
    pub disabled_at: Option<DateTime<Utc>>,
    pub claims_imports: ClaimsImports,
    pub additional_authorization_parameters: Vec<(String, String)>,
    pub forward_login_hint: bool,
    pub on_backchannel_logout: OnBackchannelLogout,
    pub registration_token_required: bool,
}

impl PartialOrd for UpstreamOAuthProvider {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for UpstreamOAuthProvider {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.id.cmp(&other.id)
    }
}

impl UpstreamOAuthProvider {
    /// Returns `true` if the provider is enabled
    #[must_use]
    pub const fn enabled(&self) -> bool {
        self.disabled_at.is_none()
    }
}

/// Per-provider settings for the Gua downstream-client marker.
///
/// This carries, per upstream provider, whether a `gua_downstream` marker
/// should be forwarded on the upstream authorization request and, if so, the
/// origin host that identifies the downstream web client. It is threaded into
/// the authorize handler out of band of the persisted provider record so that
/// no database migration is required to toggle the guard.
#[derive(Debug, Clone, Default)]
pub struct DownstreamClientGuardConfig {
    entries: std::collections::HashMap<Ulid, DownstreamClientGuardEntry>,
}

/// A single provider's downstream-client marker settings.
#[derive(Debug, Clone)]
pub struct DownstreamClientGuardEntry {
    /// Whether to forward the `gua_downstream` marker for this provider.
    pub forward_downstream_client: bool,

    /// The host that identifies the downstream web client, derived from the
    /// configured web origin. `None` means every client is treated as
    /// `native`.
    pub web_origin_host: Option<String>,
}

impl DownstreamClientGuardConfig {
    /// Build a guard config from an iterator of per-provider entries.
    #[must_use]
    pub fn new(entries: impl IntoIterator<Item = (Ulid, DownstreamClientGuardEntry)>) -> Self {
        Self {
            entries: entries.into_iter().collect(),
        }
    }

    /// Look up the entry for a provider, if any.
    #[must_use]
    pub fn get(&self, provider_id: Ulid) -> Option<&DownstreamClientGuardEntry> {
        self.entries.get(&provider_id)
    }

    /// Compute the `gua_downstream` marker value for a downstream client of
    /// the given provider.
    ///
    /// Returns `None` when the guard is disabled for this provider (the marker
    /// must not be appended at all). When enabled, returns `Some("web")` if the
    /// downstream client's `client_uri` host matches the configured web origin
    /// host, and `Some("native")` otherwise (including when the host or origin
    /// is absent). Comparison is ASCII-case-insensitive on the host only.
    #[must_use]
    pub fn marker_for(&self, provider_id: Ulid, client_uri: Option<&Url>) -> Option<&'static str> {
        let entry = self.get(provider_id)?;
        if !entry.forward_downstream_client {
            return None;
        }

        let Some(web_host) = entry.web_origin_host.as_deref() else {
            return Some("native");
        };

        let client_host = client_uri.and_then(Url::host_str);
        match client_host {
            Some(host) if host.eq_ignore_ascii_case(web_host) => Some("web"),
            _ => Some("native"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ClaimsImports {
    #[serde(default)]
    pub subject: SubjectPreference,

    #[serde(default)]
    pub skip_confirmation: bool,

    #[serde(default)]
    pub localpart: LocalpartPreference,

    #[serde(default)]
    pub displayname: ImportPreference,

    #[serde(default)]
    pub email: ImportPreference,

    #[serde(default)]
    pub account_name: SubjectPreference,
}

// XXX: this should have another name
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SubjectPreference {
    #[serde(default)]
    pub template: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct LocalpartPreference {
    #[serde(default)]
    pub action: ImportAction,

    #[serde(default)]
    pub template: Option<String>,

    #[serde(default)]
    pub on_conflict: OnConflict,
}

impl std::ops::Deref for LocalpartPreference {
    type Target = ImportAction;

    fn deref(&self) -> &Self::Target {
        &self.action
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ImportPreference {
    #[serde(default)]
    pub action: ImportAction,

    #[serde(default)]
    pub template: Option<String>,
}

impl std::ops::Deref for ImportPreference {
    type Target = ImportAction;

    fn deref(&self) -> &Self::Target {
        &self.action
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ImportAction {
    /// Ignore the claim
    #[default]
    Ignore,

    /// Suggest the claim value, but allow the user to change it
    Suggest,

    /// Force the claim value, but don't fail if it is missing
    Force,

    /// Force the claim value, and fail if it is missing
    Require,
}

impl ImportAction {
    #[must_use]
    pub fn is_forced_or_required(&self) -> bool {
        matches!(self, Self::Force | Self::Require)
    }

    #[must_use]
    pub fn ignore(&self) -> bool {
        matches!(self, Self::Ignore)
    }

    #[must_use]
    pub fn is_required(&self) -> bool {
        matches!(self, Self::Require)
    }

    #[must_use]
    pub fn should_import(&self, user_preference: bool) -> bool {
        match self {
            Self::Ignore => false,
            Self::Suggest => user_preference,
            Self::Force | Self::Require => true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum OnConflict {
    /// Fails the upstream OAuth 2.0 login on conflict
    #[default]
    Fail,

    /// Adds the upstream OAuth 2.0 identity link, regardless of whether there
    /// is an existing link or not
    Add,

    /// Replace any existing upstream OAuth 2.0 identity link
    Replace,

    /// Adds the upstream OAuth 2.0 identity link *only* if there is no existing
    /// link for this provider on the matching user
    Set,
}

#[cfg(test)]
mod tests {
    use ulid::Ulid;
    use url::Url;

    use super::{DownstreamClientGuardConfig, DownstreamClientGuardEntry};

    fn guard(
        provider_id: Ulid,
        forward: bool,
        web_origin_host: Option<&str>,
    ) -> DownstreamClientGuardConfig {
        DownstreamClientGuardConfig::new([(
            provider_id,
            DownstreamClientGuardEntry {
                forward_downstream_client: forward,
                web_origin_host: web_origin_host.map(str::to_owned),
            },
        )])
    }

    #[test]
    fn marker_web_for_matching_web_origin() {
        let provider_id = Ulid::nil();
        let guard = guard(provider_id, true, Some("app.gua.global"));
        let web_client: Url = "https://app.gua.global/".parse().unwrap();

        assert_eq!(
            guard.marker_for(provider_id, Some(&web_client)),
            Some("web")
        );
    }

    #[test]
    fn marker_native_for_non_web_origin() {
        let provider_id = Ulid::nil();
        let guard = guard(provider_id, true, Some("app.gua.global"));
        let native_client: Url = "https://elsewhere.example.com/".parse().unwrap();

        assert_eq!(
            guard.marker_for(provider_id, Some(&native_client)),
            Some("native")
        );
    }

    #[test]
    fn marker_native_when_client_uri_missing() {
        // A native client typically has no client_uri; fail closed to native so
        // the web signup allowlist never applies to it.
        let provider_id = Ulid::nil();
        let guard = guard(provider_id, true, Some("app.gua.global"));

        assert_eq!(guard.marker_for(provider_id, None), Some("native"));
    }

    #[test]
    fn marker_absent_when_flag_off() {
        // Flag off means the marker must never be appended, even for a client
        // whose host matches the web origin.
        let provider_id = Ulid::nil();
        let guard = guard(provider_id, false, Some("app.gua.global"));
        let web_client: Url = "https://app.gua.global/".parse().unwrap();

        assert_eq!(guard.marker_for(provider_id, Some(&web_client)), None);
    }

    #[test]
    fn marker_absent_when_provider_not_configured() {
        let configured = Ulid::from_parts(1, 0);
        let other = Ulid::from_parts(2, 0);
        let guard = guard(configured, true, Some("app.gua.global"));
        let web_client: Url = "https://app.gua.global/".parse().unwrap();

        assert_eq!(guard.marker_for(other, Some(&web_client)), None);
    }

    #[test]
    fn marker_host_comparison_is_case_insensitive() {
        let provider_id = Ulid::nil();
        let guard = guard(provider_id, true, Some("app.gua.global"));
        let web_client: Url = "https://APP.Gua.Global/".parse().unwrap();

        assert_eq!(
            guard.marker_for(provider_id, Some(&web_client)),
            Some("web")
        );
    }
}
