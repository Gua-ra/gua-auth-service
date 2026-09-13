// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::UrlBuilder;
pub use crate::traits::*;

#[derive(Deserialize, Serialize, Clone, Debug)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum PostAuthAction {
    ContinueAuthorizationGrant {
        id: Ulid,
    },
    ContinueDeviceCodeGrant {
        id: Ulid,
        /// GUA FORK: the MSC4198 login hint the app put on the consent page,
        /// naming the account it is signed in as.
        ///
        /// It rides inside the action so that it survives the login round
        /// trip: the consent page is reached again through this action, and
        /// must still be able to refuse a browser session for another account
        /// (one the upstream provider signed in again, say).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        gua_login_hint: Option<String>,
    },
    ContinueCompatSsoLogin {
        id: Ulid,
    },
    ChangePassword,
    LinkUpstream {
        id: Ulid,
    },
    ManageAccount {
        #[serde(flatten)]
        action: Option<AccountAction>,
        /// GUA FORK: the MSC4198 login hint the app put on the account page,
        /// naming the account it is signed in as.
        ///
        /// It rides inside the action so that it survives the login round
        /// trip: the account page is reached again through this action, and
        /// must still be able to refuse a browser session for another account
        /// (one the upstream provider signed in again, say).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        gua_login_hint: Option<String>,
    },
}

impl PostAuthAction {
    #[must_use]
    pub const fn continue_grant(id: Ulid) -> Self {
        PostAuthAction::ContinueAuthorizationGrant { id }
    }

    #[must_use]
    pub const fn continue_device_code_grant(id: Ulid) -> Self {
        PostAuthAction::ContinueDeviceCodeGrant {
            id,
            gua_login_hint: None,
        }
    }

    /// GUA FORK: continue a device code grant, carrying the app's login hint
    /// back to the consent page once the user has signed in.
    #[must_use]
    pub const fn continue_device_code_grant_with_hint(
        id: Ulid,
        login_hint: Option<String>,
    ) -> Self {
        PostAuthAction::ContinueDeviceCodeGrant {
            id,
            gua_login_hint: login_hint,
        }
    }

    #[must_use]
    pub const fn continue_compat_sso_login(id: Ulid) -> Self {
        PostAuthAction::ContinueCompatSsoLogin { id }
    }

    #[must_use]
    pub const fn link_upstream(id: Ulid) -> Self {
        PostAuthAction::LinkUpstream { id }
    }

    #[must_use]
    pub const fn manage_account(action: Option<AccountAction>) -> Self {
        PostAuthAction::ManageAccount {
            action,
            gua_login_hint: None,
        }
    }

    /// GUA FORK: manage the account, carrying the app's login hint back to the
    /// account page once the user has signed in.
    #[must_use]
    pub const fn manage_account_with_hint(
        action: Option<AccountAction>,
        login_hint: Option<String>,
    ) -> Self {
        PostAuthAction::ManageAccount {
            action,
            gua_login_hint: login_hint,
        }
    }

    pub fn go_next(&self, url_builder: &UrlBuilder) -> axum::response::Redirect {
        match self {
            Self::ContinueAuthorizationGrant { id } => url_builder.redirect(&Consent(*id)),
            Self::ContinueDeviceCodeGrant { id, gua_login_hint } => url_builder
                .redirect(&DeviceCodeConsent::new(*id).with_login_hint(gua_login_hint.clone())),
            Self::ContinueCompatSsoLogin { id } => {
                url_builder.redirect(&CompatLoginSsoComplete::new(*id, None))
            }
            Self::ChangePassword => url_builder.redirect(&AccountPasswordChange),
            Self::LinkUpstream { id } => url_builder.redirect(&UpstreamOAuth2Link::new(*id)),
            Self::ManageAccount {
                action,
                gua_login_hint,
            } => url_builder.redirect(&Account {
                action: action.clone(),
                login_hint: gua_login_hint.clone(),
            }),
        }
    }
}

/// `GET /.well-known/openid-configuration`
#[derive(Default, Debug, Clone)]
pub struct OidcConfiguration;

impl SimpleRoute for OidcConfiguration {
    const PATH: &'static str = "/.well-known/openid-configuration";
}

/// `GET /.well-known/webfinger`
#[derive(Default, Debug, Clone)]
pub struct Webfinger;

impl SimpleRoute for Webfinger {
    const PATH: &'static str = "/.well-known/webfinger";
}

/// `GET /.well-known/change-password`
pub struct ChangePasswordDiscovery;

impl SimpleRoute for ChangePasswordDiscovery {
    const PATH: &'static str = "/.well-known/change-password";
}

/// `GET /oauth2/keys.json`
#[derive(Default, Debug, Clone)]
pub struct OAuth2Keys;

impl SimpleRoute for OAuth2Keys {
    const PATH: &'static str = "/oauth2/keys.json";
}

/// `GET /oauth2/userinfo`
#[derive(Default, Debug, Clone)]
pub struct OidcUserinfo;

impl SimpleRoute for OidcUserinfo {
    const PATH: &'static str = "/oauth2/userinfo";
}

/// `POST /oauth2/introspect`
#[derive(Default, Debug, Clone)]
pub struct OAuth2Introspection;

impl SimpleRoute for OAuth2Introspection {
    const PATH: &'static str = "/oauth2/introspect";
}

/// `POST /oauth2/revoke`
#[derive(Default, Debug, Clone)]
pub struct OAuth2Revocation;

impl SimpleRoute for OAuth2Revocation {
    const PATH: &'static str = "/oauth2/revoke";
}

/// `POST /oauth2/token`
#[derive(Default, Debug, Clone)]
pub struct OAuth2TokenEndpoint;

impl SimpleRoute for OAuth2TokenEndpoint {
    const PATH: &'static str = "/oauth2/token";
}

/// `POST /oauth2/registration`
#[derive(Default, Debug, Clone)]
pub struct OAuth2RegistrationEndpoint;

impl SimpleRoute for OAuth2RegistrationEndpoint {
    const PATH: &'static str = "/oauth2/registration";
}

/// `GET /authorize`
#[derive(Default, Debug, Clone)]
pub struct OAuth2AuthorizationEndpoint;

impl SimpleRoute for OAuth2AuthorizationEndpoint {
    const PATH: &'static str = "/authorize";
}

/// `GET /`
#[derive(Default, Debug, Clone)]
pub struct Index;

impl SimpleRoute for Index {
    const PATH: &'static str = "/";
}

/// `GET /health`
#[derive(Default, Debug, Clone)]
pub struct Healthcheck;

impl SimpleRoute for Healthcheck {
    const PATH: &'static str = "/health";
}

/// `GET|POST /login`
// `login_hint` is a standard OIDC parameter and `force_login` is part of the
// login URL contract, so the field names can't change.
#[expect(clippy::struct_field_names)]
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct Login {
    #[serde(flatten)]
    post_auth_action: Option<PostAuthAction>,

    login_hint: Option<String>,

    /// Force a fresh authentication even if a browser session already exists.
    ///
    /// Used to honour an OIDC `prompt=login` (or `max_age=0`) request: when
    /// set, the login page must not reuse the current session and instead
    /// start a brand-new authentication flow.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    force_login: bool,
}

impl Route for Login {
    type Query = Self;

    fn route() -> &'static str {
        "/login"
    }

    fn query(&self) -> Option<&Self::Query> {
        Some(self)
    }
}

impl Login {
    #[must_use]
    pub const fn and_then(action: PostAuthAction) -> Self {
        Self {
            post_auth_action: Some(action),
            login_hint: None,
            force_login: false,
        }
    }

    #[must_use]
    pub const fn and_continue_grant(id: Ulid) -> Self {
        Self {
            post_auth_action: Some(PostAuthAction::continue_grant(id)),
            login_hint: None,
            force_login: false,
        }
    }

    #[must_use]
    pub const fn and_continue_device_code_grant(id: Ulid) -> Self {
        Self {
            post_auth_action: Some(PostAuthAction::continue_device_code_grant(id)),
            login_hint: None,
            force_login: false,
        }
    }

    #[must_use]
    pub const fn and_continue_compat_sso_login(id: Ulid) -> Self {
        Self {
            post_auth_action: Some(PostAuthAction::continue_compat_sso_login(id)),
            login_hint: None,
            force_login: false,
        }
    }

    #[must_use]
    pub const fn and_link_upstream(id: Ulid) -> Self {
        Self {
            post_auth_action: Some(PostAuthAction::link_upstream(id)),
            login_hint: None,
            force_login: false,
        }
    }

    #[must_use]
    pub fn with_login_hint(mut self, login_hint: String) -> Self {
        self.login_hint = Some(login_hint);
        self
    }

    /// GUA FORK: ignore any existing browser session and authenticate afresh.
    ///
    /// Used when the account page is opened with a login hint naming a
    /// different user than the one the browser is signed in as, so that the
    /// requested action (an identity reset, say) can only ever be approved
    /// by the account it belongs to.
    #[must_use]
    pub const fn with_force_login(mut self) -> Self {
        self.force_login = true;
        self
    }

    /// Force a fresh authentication, ignoring any existing browser session.
    ///
    /// This is what makes an OIDC `prompt=login` request actually
    /// re-authenticate the user instead of silently reusing the current
    /// session.
    #[must_use]
    pub fn force_login(mut self) -> Self {
        self.force_login = true;
        self
    }

    /// Get a reference to the login's post auth action.
    #[must_use]
    pub fn post_auth_action(&self) -> Option<&PostAuthAction> {
        self.post_auth_action.as_ref()
    }

    pub fn go_next(&self, url_builder: &UrlBuilder) -> axum::response::Redirect {
        match &self.post_auth_action {
            Some(action) => action.go_next(url_builder),
            None => url_builder.redirect(&Index),
        }
    }
}

impl From<Option<PostAuthAction>> for Login {
    fn from(post_auth_action: Option<PostAuthAction>) -> Self {
        Self {
            post_auth_action,
            login_hint: None,
            force_login: false,
        }
    }
}

/// `POST /logout`
#[derive(Default, Debug, Clone)]
pub struct Logout;

impl SimpleRoute for Logout {
    const PATH: &'static str = "/logout";
}

/// `POST /register`
#[derive(Default, Debug, Clone)]
pub struct Register {
    post_auth_action: Option<PostAuthAction>,
}

impl Register {
    #[must_use]
    pub fn and_then(action: PostAuthAction) -> Self {
        Self {
            post_auth_action: Some(action),
        }
    }

    #[must_use]
    pub fn and_continue_grant(data: Ulid) -> Self {
        Self {
            post_auth_action: Some(PostAuthAction::continue_grant(data)),
        }
    }

    #[must_use]
    pub fn and_continue_compat_sso_login(data: Ulid) -> Self {
        Self {
            post_auth_action: Some(PostAuthAction::continue_compat_sso_login(data)),
        }
    }

    /// Get a reference to the reauth's post auth action.
    #[must_use]
    pub fn post_auth_action(&self) -> Option<&PostAuthAction> {
        self.post_auth_action.as_ref()
    }

    pub fn go_next(&self, url_builder: &UrlBuilder) -> axum::response::Redirect {
        match &self.post_auth_action {
            Some(action) => action.go_next(url_builder),
            None => url_builder.redirect(&Index),
        }
    }
}

impl Route for Register {
    type Query = PostAuthAction;

    fn route() -> &'static str {
        "/register"
    }

    fn query(&self) -> Option<&Self::Query> {
        self.post_auth_action.as_ref()
    }
}

impl From<Option<PostAuthAction>> for Register {
    fn from(post_auth_action: Option<PostAuthAction>) -> Self {
        Self { post_auth_action }
    }
}

/// `GET|POST /register/password`
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct PasswordRegister {
    username: Option<String>,

    #[serde(flatten)]
    post_auth_action: Option<PostAuthAction>,
}

impl PasswordRegister {
    #[must_use]
    pub fn and_then(mut self, action: PostAuthAction) -> Self {
        self.post_auth_action = Some(action);
        self
    }

    #[must_use]
    pub fn and_continue_grant(mut self, data: Ulid) -> Self {
        self.post_auth_action = Some(PostAuthAction::continue_grant(data));
        self
    }

    #[must_use]
    pub fn and_continue_compat_sso_login(mut self, data: Ulid) -> Self {
        self.post_auth_action = Some(PostAuthAction::continue_compat_sso_login(data));
        self
    }

    /// Get a reference to the post auth action.
    #[must_use]
    pub fn post_auth_action(&self) -> Option<&PostAuthAction> {
        self.post_auth_action.as_ref()
    }

    /// Get a reference to the username chosen by the user.
    #[must_use]
    pub fn username(&self) -> Option<&str> {
        self.username.as_deref()
    }

    pub fn go_next(&self, url_builder: &UrlBuilder) -> axum::response::Redirect {
        match &self.post_auth_action {
            Some(action) => action.go_next(url_builder),
            None => url_builder.redirect(&Index),
        }
    }
}

impl Route for PasswordRegister {
    type Query = Self;

    fn route() -> &'static str {
        "/register/password"
    }

    fn query(&self) -> Option<&Self::Query> {
        Some(self)
    }
}

impl From<Option<PostAuthAction>> for PasswordRegister {
    fn from(post_auth_action: Option<PostAuthAction>) -> Self {
        Self {
            username: None,
            post_auth_action,
        }
    }
}

/// `GET|POST /register/steps/{id}/token`
#[derive(Debug, Clone)]
pub struct RegisterToken {
    id: Ulid,
}

impl RegisterToken {
    #[must_use]
    pub fn new(id: Ulid) -> Self {
        Self { id }
    }
}

impl Route for RegisterToken {
    type Query = ();
    fn route() -> &'static str {
        "/register/steps/{id}/token"
    }

    fn path(&self) -> std::borrow::Cow<'static, str> {
        format!("/register/steps/{}/token", self.id).into()
    }
}

/// `GET|POST /register/steps/{id}/display-name`
#[derive(Debug, Clone)]
pub struct RegisterDisplayName {
    id: Ulid,
}

impl RegisterDisplayName {
    #[must_use]
    pub fn new(id: Ulid) -> Self {
        Self { id }
    }
}

impl Route for RegisterDisplayName {
    type Query = ();
    fn route() -> &'static str {
        "/register/steps/{id}/display-name"
    }

    fn path(&self) -> std::borrow::Cow<'static, str> {
        format!("/register/steps/{}/display-name", self.id).into()
    }
}

/// `GET|POST /register/steps/{id}/verify-email`
#[derive(Debug, Clone)]
pub struct RegisterVerifyEmail {
    id: Ulid,
}

impl RegisterVerifyEmail {
    #[must_use]
    pub fn new(id: Ulid) -> Self {
        Self { id }
    }
}

impl Route for RegisterVerifyEmail {
    type Query = ();
    fn route() -> &'static str {
        "/register/steps/{id}/verify-email"
    }

    fn path(&self) -> std::borrow::Cow<'static, str> {
        format!("/register/steps/{}/verify-email", self.id).into()
    }
}

/// `GET /register/steps/{id}/finish`
#[derive(Debug, Clone)]
pub struct RegisterFinish {
    id: Ulid,
}

impl RegisterFinish {
    #[must_use]
    pub const fn new(id: Ulid) -> Self {
        Self { id }
    }
}

impl Route for RegisterFinish {
    type Query = ();
    fn route() -> &'static str {
        "/register/steps/{id}/finish"
    }

    fn path(&self) -> std::borrow::Cow<'static, str> {
        format!("/register/steps/{}/finish", self.id).into()
    }
}

/// Actions parameters as defined by MSC4191
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action")]
pub enum AccountAction {
    #[serde(rename = "org.matrix.profile")]
    OrgMatrixProfile,
    /// DEPRECATED: Use `OrgMatrixProfile` instead
    #[serde(rename = "profile")]
    Profile,

    #[serde(rename = "org.matrix.devices_list")]
    OrgMatrixDevicesList,
    /// DEPRECATED: Use `OrgMatrixDevicesList` instead
    #[serde(rename = "org.matrix.sessions_list")]
    OrgMatrixSessionsList,
    /// DEPRECATED: Use `OrgMatrixDevicesList` instead
    #[serde(rename = "sessions_list")]
    SessionsList,

    #[serde(rename = "org.matrix.device_view")]
    OrgMatrixDeviceView { device_id: String },
    /// DEPRECATED: Use `OrgMatrixDeviceView` instead
    #[serde(rename = "org.matrix.session_view")]
    OrgMatrixSessionView { device_id: String },
    /// DEPRECATED: Use `OrgMatrixDeviceView` instead
    #[serde(rename = "session_view")]
    SessionView { device_id: String },

    #[serde(rename = "org.matrix.device_delete")]
    OrgMatrixDeviceDelete { device_id: String },
    /// DEPRECATED: Use `OrgMatrixDeviceDelete` instead
    #[serde(rename = "org.matrix.session_end")]
    OrgMatrixSessionEnd { device_id: String },
    /// DEPRECATED: Use `OrgMatrixDeviceDelete` instead
    #[serde(rename = "session_end")]
    SessionEnd { device_id: String },

    #[serde(rename = "org.matrix.cross_signing_reset")]
    OrgMatrixCrossSigningReset {
        /// GUA FORK: the app scheme to hand control back to once the reset is
        /// approved.
        ///
        /// It rides inside the action so that it survives the login round trip:
        /// when the browser session does not match the app's login
        /// hint, the user is sent through login and back to this
        /// action, and the success page still needs to know where
        /// to return.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        gua_return: Option<String>,
        /// GUA FORK: the localpart of the account the app is signed in as.
        ///
        /// Carried inside the action for the same reason as `gua_return`: after
        /// a forced login the account page is reached again through the
        /// post-auth action, and the page must still be able to refuse
        /// a browser session for some other account.
        #[serde(default, rename = "gua_user", skip_serializing_if = "Option::is_none")]
        gua_user: Option<String>,
    },
}

/// `GET /account/`
#[derive(Default, Debug, Clone, Serialize)]
pub struct Account {
    #[serde(flatten)]
    action: Option<AccountAction>,

    /// GUA FORK: the MSC4198 login hint naming the account the app is signed
    /// in as, so the account page can refuse a browser session that belongs
    /// to another account.
    #[serde(
        rename = "org.matrix.msc4198.login_hint",
        skip_serializing_if = "Option::is_none"
    )]
    login_hint: Option<String>,
}

impl Route for Account {
    type Query = Self;

    fn route() -> &'static str {
        "/account/"
    }

    fn query(&self) -> Option<&Self::Query> {
        Some(self)
    }
}

/// `GET /account/*`
#[derive(Default, Debug, Clone)]
pub struct AccountWildcard;

impl SimpleRoute for AccountWildcard {
    const PATH: &'static str = "/account/{*rest}";
}

/// `GET /account/password/change`
///
/// Handled by the React frontend; this struct definition is purely for
/// redirects.
#[derive(Default, Debug, Clone)]
pub struct AccountPasswordChange;

impl SimpleRoute for AccountPasswordChange {
    const PATH: &'static str = "/account/password/change";
}

/// `GET /consent/{grant_id}`
#[derive(Debug, Clone)]
pub struct Consent(pub Ulid);

impl Route for Consent {
    type Query = ();
    fn route() -> &'static str {
        "/consent/{grant_id}"
    }

    fn path(&self) -> std::borrow::Cow<'static, str> {
        format!("/consent/{}", self.0).into()
    }
}

/// `GET|POST /_matrix/client/v3/login`
pub struct CompatLogin;

impl SimpleRoute for CompatLogin {
    const PATH: &'static str = "/_matrix/client/{version}/login";
}

/// `POST /_matrix/client/v3/logout`
pub struct CompatLogout;

impl SimpleRoute for CompatLogout {
    const PATH: &'static str = "/_matrix/client/{version}/logout";
}

/// `POST /_matrix/client/v3/logout/all`
pub struct CompatLogoutAll;

impl SimpleRoute for CompatLogoutAll {
    const PATH: &'static str = "/_matrix/client/{version}/logout/all";
}

/// `POST /_matrix/client/v3/refresh`
pub struct CompatRefresh;

impl SimpleRoute for CompatRefresh {
    const PATH: &'static str = "/_matrix/client/{version}/refresh";
}

/// `GET /_matrix/client/v3/login/sso/redirect`
pub struct CompatLoginSsoRedirect;

impl SimpleRoute for CompatLoginSsoRedirect {
    const PATH: &'static str = "/_matrix/client/{version}/login/sso/redirect";
}

/// `GET /_matrix/client/v3/login/sso/redirect/`
///
/// This is a workaround for the fact some clients (Element iOS) sends a
/// trailing slash, even though it's not in the spec.
pub struct CompatLoginSsoRedirectSlash;

impl SimpleRoute for CompatLoginSsoRedirectSlash {
    const PATH: &'static str = "/_matrix/client/{version}/login/sso/redirect/";
}

/// `GET /_matrix/client/v3/login/sso/redirect/{idp}`
pub struct CompatLoginSsoRedirectIdp;

impl SimpleRoute for CompatLoginSsoRedirectIdp {
    const PATH: &'static str = "/_matrix/client/{version}/login/sso/redirect/{idp}";
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum CompatLoginSsoAction {
    Login,
    Register,
    #[serde(other)]
    Unknown,
}

impl CompatLoginSsoAction {
    /// Returns true if the action is a known action.
    #[must_use]
    pub fn is_known(&self) -> bool {
        !matches!(self, Self::Unknown)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
pub struct CompatLoginSsoActionParams {
    action: CompatLoginSsoAction,
    /// DEPRECATED: Use `action` instead. We will remove this once enough
    /// clients support the stable name.
    #[serde(rename = "org.matrix.msc3824.action")]
    unstable_action: CompatLoginSsoAction,
}

/// `GET|POST /complete-compat-sso/{id}`
pub struct CompatLoginSsoComplete {
    id: Ulid,
    query: Option<CompatLoginSsoActionParams>,
}

impl CompatLoginSsoComplete {
    #[must_use]
    pub fn new(id: Ulid, action: Option<CompatLoginSsoAction>) -> Self {
        Self {
            id,
            query: action.map(|action| CompatLoginSsoActionParams {
                action,
                unstable_action: action,
            }),
        }
    }
}

impl Route for CompatLoginSsoComplete {
    type Query = CompatLoginSsoActionParams;

    fn query(&self) -> Option<&Self::Query> {
        self.query.as_ref()
    }

    fn route() -> &'static str {
        "/complete-compat-sso/{grant_id}"
    }

    fn path(&self) -> std::borrow::Cow<'static, str> {
        format!("/complete-compat-sso/{}", self.id).into()
    }
}

/// `GET /upstream/authorize/{id}`
pub struct UpstreamOAuth2Authorize {
    id: Ulid,
    post_auth_action: Option<PostAuthAction>,
}

impl UpstreamOAuth2Authorize {
    #[must_use]
    pub const fn new(id: Ulid) -> Self {
        Self {
            id,
            post_auth_action: None,
        }
    }

    #[must_use]
    pub fn and_then(mut self, action: PostAuthAction) -> Self {
        self.post_auth_action = Some(action);
        self
    }
}

impl Route for UpstreamOAuth2Authorize {
    type Query = PostAuthAction;
    fn route() -> &'static str {
        "/upstream/authorize/{provider_id}"
    }

    fn path(&self) -> std::borrow::Cow<'static, str> {
        format!("/upstream/authorize/{}", self.id).into()
    }

    fn query(&self) -> Option<&Self::Query> {
        self.post_auth_action.as_ref()
    }
}

/// `GET /upstream/callback/{id}`
pub struct UpstreamOAuth2Callback {
    id: Ulid,
}

impl UpstreamOAuth2Callback {
    #[must_use]
    pub const fn new(id: Ulid) -> Self {
        Self { id }
    }
}

impl Route for UpstreamOAuth2Callback {
    type Query = ();
    fn route() -> &'static str {
        "/upstream/callback/{provider_id}"
    }

    fn path(&self) -> std::borrow::Cow<'static, str> {
        format!("/upstream/callback/{}", self.id).into()
    }
}

/// `GET /upstream/link/{id}`
pub struct UpstreamOAuth2Link {
    id: Ulid,
}

impl UpstreamOAuth2Link {
    #[must_use]
    pub const fn new(id: Ulid) -> Self {
        Self { id }
    }
}

impl Route for UpstreamOAuth2Link {
    type Query = ();
    fn route() -> &'static str {
        "/upstream/link/{link_id}"
    }

    fn path(&self) -> std::borrow::Cow<'static, str> {
        format!("/upstream/link/{}", self.id).into()
    }
}

/// `POST /upstream/backchannel-logout/{id}`
pub struct UpstreamOAuth2BackchannelLogout {
    id: Ulid,
}

impl UpstreamOAuth2BackchannelLogout {
    #[must_use]
    pub const fn new(id: Ulid) -> Self {
        Self { id }
    }
}

impl Route for UpstreamOAuth2BackchannelLogout {
    type Query = ();
    fn route() -> &'static str {
        "/upstream/backchannel-logout/{provider_id}"
    }

    fn path(&self) -> std::borrow::Cow<'static, str> {
        format!("/upstream/backchannel-logout/{}", self.id).into()
    }
}

/// `GET|POST /link`
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct DeviceCodeLink {
    code: Option<String>,
}

impl DeviceCodeLink {
    #[must_use]
    pub fn with_code(code: String) -> Self {
        Self { code: Some(code) }
    }
}

impl Route for DeviceCodeLink {
    type Query = DeviceCodeLink;
    fn route() -> &'static str {
        "/link"
    }

    fn query(&self) -> Option<&Self::Query> {
        Some(self)
    }
}

/// `GET|POST /device/{device_code_id}`
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct DeviceCodeConsent {
    id: Ulid,
    query: DeviceCodeConsentQuery,
}

/// GUA FORK: query parameters of the device code consent page.
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct DeviceCodeConsentQuery {
    /// The MSC4198 login hint naming the account the app linking the new
    /// device is signed in as.
    #[serde(
        rename = "org.matrix.msc4198.login_hint",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub login_hint: Option<String>,
}

impl Route for DeviceCodeConsent {
    type Query = DeviceCodeConsentQuery;
    fn route() -> &'static str {
        "/device/{device_code_id}"
    }

    fn query(&self) -> Option<&Self::Query> {
        Some(&self.query)
    }

    fn path(&self) -> std::borrow::Cow<'static, str> {
        format!("/device/{}", self.id).into()
    }
}

impl DeviceCodeConsent {
    #[must_use]
    pub fn new(id: Ulid) -> Self {
        Self {
            id,
            query: DeviceCodeConsentQuery::default(),
        }
    }

    /// GUA FORK: carry the app's MSC4198 login hint to the consent page, so it
    /// can refuse a browser session that belongs to another account.
    #[must_use]
    pub fn with_login_hint(mut self, login_hint: Option<String>) -> Self {
        self.query.login_hint = login_hint;
        self
    }
}

/// `POST /oauth2/device`
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct OAuth2DeviceAuthorizationEndpoint;

impl SimpleRoute for OAuth2DeviceAuthorizationEndpoint {
    const PATH: &'static str = "/oauth2/device";
}

/// `GET|POST /recover`
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct AccountRecoveryStart;

impl SimpleRoute for AccountRecoveryStart {
    const PATH: &'static str = "/recover";
}

/// `GET|POST /recover/progress/{session_id}`
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct AccountRecoveryProgress {
    session_id: Ulid,
}

impl AccountRecoveryProgress {
    #[must_use]
    pub fn new(session_id: Ulid) -> Self {
        Self { session_id }
    }
}

impl Route for AccountRecoveryProgress {
    type Query = ();
    fn route() -> &'static str {
        "/recover/progress/{session_id}"
    }

    fn path(&self) -> std::borrow::Cow<'static, str> {
        format!("/recover/progress/{}", self.session_id).into()
    }
}

/// `GET /account/password/recovery?ticket=:ticket`
/// Rendered by the React frontend
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct AccountRecoveryFinish {
    ticket: String,
}

impl AccountRecoveryFinish {
    #[must_use]
    pub fn new(ticket: String) -> Self {
        Self { ticket }
    }
}

impl Route for AccountRecoveryFinish {
    type Query = AccountRecoveryFinish;

    fn route() -> &'static str {
        "/account/password/recovery"
    }

    fn query(&self) -> Option<&Self::Query> {
        Some(self)
    }
}

/// `GET /assets`
pub struct StaticAsset {
    path: String,
}

impl StaticAsset {
    #[must_use]
    pub fn new(path: String) -> Self {
        Self { path }
    }
}

impl Route for StaticAsset {
    type Query = ();
    fn route() -> &'static str {
        "/assets/"
    }

    fn path(&self) -> std::borrow::Cow<'static, str> {
        format!("/assets/{}", self.path).into()
    }
}

/// `GET|POST /graphql`
pub struct GraphQL;

impl SimpleRoute for GraphQL {
    const PATH: &'static str = "/graphql";
}

/// `GET /graphql/playground`
pub struct GraphQLPlayground;

impl SimpleRoute for GraphQLPlayground {
    const PATH: &'static str = "/graphql/playground";
}

/// `GET /api/spec.json`
pub struct ApiSpec;

impl SimpleRoute for ApiSpec {
    const PATH: &'static str = "/api/spec.json";
}

/// `GET /api/doc/`
pub struct ApiDoc;

impl SimpleRoute for ApiDoc {
    const PATH: &'static str = "/api/doc/";
}

/// `GET /api/doc/oauth2-callback`
pub struct ApiDocCallback;

impl SimpleRoute for ApiDocCallback {
    const PATH: &'static str = "/api/doc/oauth2-callback";
}

#[cfg(test)]
mod tests {
    use axum::response::IntoResponse as _;
    use ulid::Ulid;

    use super::{Account, AccountAction, DeviceCodeConsent, Login, PostAuthAction, Route};
    use crate::UrlBuilder;

    #[test]
    fn device_code_consent_carries_the_login_hint_only_when_set() {
        let id = Ulid::nil();

        assert_eq!(
            DeviceCodeConsent::new(id).path_and_query(),
            format!("/device/{id}")
        );
        assert_eq!(
            DeviceCodeConsent::new(id)
                .with_login_hint(None)
                .path_and_query(),
            format!("/device/{id}")
        );
        assert_eq!(
            DeviceCodeConsent::new(id)
                .with_login_hint(Some("mxid:@bob:example.com".to_owned()))
                .path_and_query(),
            format!("/device/{id}?org.matrix.msc4198.login_hint=mxid%3A%40bob%3Aexample.com")
        );
    }

    #[test]
    fn device_code_grant_login_brings_the_hint_back_to_the_consent_page() {
        let id = Ulid::nil();
        let hint = "mxid:@bob:example.com";
        let login = Login::and_then(PostAuthAction::continue_device_code_grant_with_hint(
            id,
            Some(hint.to_owned()),
        ))
        .with_login_hint(hint.to_owned())
        .with_force_login();

        // The action survives being carried in the login URL.
        let path_and_query = login.path_and_query();
        let (_, query) = path_and_query.split_once('?').unwrap();
        let parsed: Login = serde_urlencoded::from_str(query).unwrap();
        let Some(PostAuthAction::ContinueDeviceCodeGrant {
            id: parsed_id,
            gua_login_hint,
        }) = parsed.post_auth_action()
        else {
            panic!("unexpected post auth action: {parsed:?}");
        };
        assert_eq!(*parsed_id, id);
        assert_eq!(gua_login_hint.as_deref(), Some(hint));

        // And once signed in, the consent page gets the hint again.
        let url_builder = UrlBuilder::new("https://example.com/".parse().unwrap(), None, None);
        let response = parsed.go_next(&url_builder).into_response();
        assert_eq!(
            response.headers().get("location").unwrap(),
            &format!("/device/{id}?org.matrix.msc4198.login_hint=mxid%3A%40bob%3Aexample.com")
        );

        // Without a hint nothing new appears in either URL.
        let login = Login::and_continue_device_code_grant(id);
        assert!(!login.path_and_query().contains("gua_login_hint"));
        let response = login.go_next(&url_builder).into_response();
        assert_eq!(
            response.headers().get("location").unwrap(),
            &format!("/device/{id}")
        );
    }

    #[test]
    fn account_page_carries_the_login_hint_only_when_set() {
        assert_eq!(Account::default().path_and_query(), "/account/");
        assert_eq!(
            Account {
                action: Some(AccountAction::OrgMatrixProfile),
                login_hint: None,
            }
            .path_and_query(),
            "/account/?action=org.matrix.profile"
        );
        assert_eq!(
            Account {
                action: None,
                login_hint: Some("mxid:@bob:example.com".to_owned()),
            }
            .path_and_query(),
            "/account/?org.matrix.msc4198.login_hint=mxid%3A%40bob%3Aexample.com"
        );
        assert_eq!(
            Account {
                action: Some(AccountAction::OrgMatrixDeviceView {
                    device_id: "ABCDEF".to_owned(),
                }),
                login_hint: Some("mxid:@bob:example.com".to_owned()),
            }
            .path_and_query(),
            "/account/?action=org.matrix.device_view&device_id=ABCDEF\
             &org.matrix.msc4198.login_hint=mxid%3A%40bob%3Aexample.com"
        );
    }

    #[test]
    fn manage_account_login_brings_the_hint_back_to_the_account_page() {
        let hint = "mxid:@bob:example.com";
        let url_builder = UrlBuilder::new("https://example.com/".parse().unwrap(), None, None);

        for (action, account_query) in [
            (None, String::new()),
            (
                Some(AccountAction::OrgMatrixDeviceView {
                    device_id: "ABCDEF".to_owned(),
                }),
                "action=org.matrix.device_view&device_id=ABCDEF&".to_owned(),
            ),
            (
                Some(AccountAction::OrgMatrixCrossSigningReset {
                    gua_return: None,
                    gua_user: Some("bob".to_owned()),
                }),
                "action=org.matrix.cross_signing_reset&gua_user=bob&".to_owned(),
            ),
        ] {
            let login = Login::and_then(PostAuthAction::manage_account_with_hint(
                action,
                Some(hint.to_owned()),
            ))
            .with_login_hint(hint.to_owned())
            .with_force_login();

            // The action survives being carried in the login URL.
            let path_and_query = login.path_and_query();
            let (_, query) = path_and_query.split_once('?').unwrap();
            let parsed: Login = serde_urlencoded::from_str(query).unwrap();
            let Some(PostAuthAction::ManageAccount { gua_login_hint, .. }) =
                parsed.post_auth_action()
            else {
                panic!("unexpected post auth action: {parsed:?}");
            };
            assert_eq!(gua_login_hint.as_deref(), Some(hint));

            // And once signed in, the account page gets the hint again, next to
            // the action.
            let response = parsed.go_next(&url_builder).into_response();
            assert_eq!(
                response.headers().get("location").unwrap(),
                &format!(
                    "/account/?{account_query}\
                     org.matrix.msc4198.login_hint=mxid%3A%40bob%3Aexample.com"
                )
            );
        }

        // Without a hint nothing new appears in either URL.
        let login = Login::and_then(PostAuthAction::manage_account(Some(
            AccountAction::OrgMatrixProfile,
        )));
        assert!(!login.path_and_query().contains("login_hint"));
        let response = login.go_next(&url_builder).into_response();
        assert_eq!(
            response.headers().get("location").unwrap(),
            "/account/?action=org.matrix.profile"
        );
    }

    #[test]
    fn manage_account_login_urls_from_before_the_hint_still_parse() {
        let parsed: Login =
            serde_urlencoded::from_str("kind=manage_account&action=org.matrix.profile").unwrap();
        let Some(PostAuthAction::ManageAccount {
            action: Some(AccountAction::OrgMatrixProfile),
            gua_login_hint: None,
        }) = parsed.post_auth_action()
        else {
            panic!("unexpected post auth action: {parsed:?}");
        };

        let parsed: Login = serde_urlencoded::from_str("kind=manage_account").unwrap();
        let Some(PostAuthAction::ManageAccount {
            action: None,
            gua_login_hint: None,
        }) = parsed.post_auth_action()
        else {
            panic!("unexpected post auth action: {parsed:?}");
        };
    }
}
