// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! GUA FORK: the language a page renders in.
//!
//! The apps open these pages with `ui_locales` set to the app's language. The
//! order is:
//!
//! 1. the grant's locale, on pages tied to an authorization grant
//!    ([`grant_language`]);
//! 2. a supported `ui_locales` tag on this request;
//! 3. the language cookie that an earlier `ui_locales` set, which carries the
//!    language across the redirects of a flow that has no grant (the account
//!    page sending the browser to the login);
//! 4. `Accept-Language`.
//!
//! An unsupported `ui_locales` tag is ignored. Any Portuguese tag maps to
//! `pt-BR`, the variant the apps ship: `pt` alone would select European
//! Portuguese.

use std::{convert::Infallible, str::FromStr as _, sync::Arc};

use axum::{
    extract::{FromRef, FromRequestParts},
    http::request::Parts,
};
use headers::HeaderMapExt as _;
use http::{HeaderMap, HeaderValue, Uri};
use mas_axum_utils::language_detection::AcceptLanguage;
use mas_data_model::AuthorizationGrant;
use mas_i18n::{DataLocale, Translator, locale};

/// Name of the cookie that remembers the language a `ui_locales` asked for.
const LANGUAGE_COOKIE: &str = "mas-language";

/// The cookie only has to outlive one sign-in round trip.
const LANGUAGE_COOKIE_MAX_AGE_SECONDS: u32 = 60 * 60;

/// The language to render a page in: see the module documentation.
pub struct PreferredLanguage(pub DataLocale);

impl<S> FromRequestParts<S> for PreferredLanguage
where
    S: Send + Sync,
    Arc<Translator>: FromRef<S>,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let translator: Arc<Translator> = FromRef::from_ref(state);
        Ok(PreferredLanguage(request_language(
            &translator,
            &parts.headers,
            &parts.uri,
        )))
    }
}

/// The language the user chose through `ui_locales`, on this request or
/// remembered by the language cookie, without the `Accept-Language` fallback.
pub(crate) struct ExplicitLanguage(pub Option<DataLocale>);

impl<S> FromRequestParts<S> for ExplicitLanguage
where
    S: Send + Sync,
    Arc<Translator>: FromRef<S>,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let translator: Arc<Translator> = FromRef::from_ref(state);
        Ok(ExplicitLanguage(explicit_language(
            &translator,
            &parts.headers,
            &parts.uri,
        )))
    }
}

/// Resolve the language of a request: `ui_locales`, then the language cookie,
/// then `Accept-Language`, then the default locale.
pub(crate) fn request_language(
    translator: &Translator,
    headers: &HeaderMap,
    uri: &Uri,
) -> DataLocale {
    explicit_language(translator, headers, uri)
        .unwrap_or_else(|| accept_language(translator, headers))
}

/// The supported language of the `ui_locales` query parameter, then of the
/// language cookie.
fn explicit_language(
    translator: &Translator,
    headers: &HeaderMap,
    uri: &Uri,
) -> Option<DataLocale> {
    query_language(translator, uri).or_else(|| cookie_language(translator, headers))
}

/// The first supported tag of the `ui_locales` query parameter, if any.
pub(crate) fn query_language(translator: &Translator, uri: &Uri) -> Option<DataLocale> {
    let query = uri.query()?;
    url::form_urlencoded::parse(query.as_bytes())
        .filter(|(key, _)| key == "ui_locales")
        .flat_map(|(_, value)| {
            value
                .split_ascii_whitespace()
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .find_map(|tag| match_ui_locale(translator, &tag))
}

/// The language in the language cookie, if it is still supported.
fn cookie_language(translator: &Translator, headers: &HeaderMap) -> Option<DataLocale> {
    let cookie = headers.typed_get::<headers::Cookie>()?;
    let value = cookie.get(LANGUAGE_COOKIE)?;
    match_ui_locale(translator, value)
}

/// The `Accept-Language` choice, or the default locale.
fn accept_language(translator: &Translator, headers: &HeaderMap) -> DataLocale {
    let accept_language = headers.typed_get::<AcceptLanguage>();

    let iter = accept_language
        .iter()
        .flat_map(AcceptLanguage::iter)
        .flat_map(|lang| {
            let lang = DataLocale::from(lang);
            // XXX: this is hacky as we may want to actually maintain proper
            // language aliases at some point, but `zh-CN`
            // doesn't fallback automatically to `zh-Hans`,
            // so we insert it manually here.
            // For some reason, `zh-TW` does fallback to `zh-Hant`
            // correctly.
            if lang == locale!("zh-CN").into() {
                vec![lang, locale!("zh-Hans").into()]
            } else {
                vec![lang]
            }
        });

    translator.choose_locale(iter)
}

/// The locale stored on an authorization grant, if it is still supported.
pub(crate) fn grant_language(
    translator: &Translator,
    grant: &AuthorizationGrant,
) -> Option<DataLocale> {
    let locale = parse_tag(grant.locale.as_deref()?)?;
    translator.match_locale(locale)
}

/// Match one `ui_locales` tag against the available translations.
///
/// Accepts `_` as a separator and ignores extensions, so `pt_BR` and
/// `fr-CA-u-ca-gregory` both match.
fn match_ui_locale(translator: &Translator, tag: &str) -> Option<DataLocale> {
    let mut locale = parse_tag(tag)?;
    if locale.language().as_str() == "pt" {
        locale = locale!("pt-BR").into();
    }
    translator.match_locale(locale)
}

/// Parse a language tag, keeping only its language, script, region and
/// variants.
fn parse_tag(tag: &str) -> Option<DataLocale> {
    let tag = tag.trim().replace('_', "-");
    let base = tag
        .split('-')
        .take_while(|subtag| subtag.len() != 1)
        .collect::<Vec<_>>()
        .join("-");
    let locale = DataLocale::from_str(&base).ok()?;
    (!locale.is_und()).then_some(locale)
}

/// The `Set-Cookie` value that remembers a `ui_locales` choice.
pub(crate) fn language_cookie(locale: &DataLocale) -> Option<HeaderValue> {
    HeaderValue::from_str(&format!(
        "{LANGUAGE_COOKIE}={locale}; Path=/; Max-Age={LANGUAGE_COOKIE_MAX_AGE_SECONDS}; \
         HttpOnly; Secure; SameSite=Lax"
    ))
    .ok()
}

#[cfg(test)]
mod tests {
    use camino::Utf8PathBuf;
    use http::header::{ACCEPT_LANGUAGE, COOKIE};

    use super::*;

    fn translator() -> Translator {
        let root: Utf8PathBuf = env!("CARGO_MANIFEST_DIR").parse().unwrap();
        Translator::load_from_path(&root.join("../../translations")).unwrap()
    }

    fn headers(pairs: &[(http::HeaderName, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.insert(name, HeaderValue::from_str(value).unwrap());
        }
        headers
    }

    fn uri(query: &str) -> Uri {
        format!("https://example.com/login{query}").parse().unwrap()
    }

    #[test]
    fn test_ui_locales_tags() {
        let translator = translator();
        let lang = |tag: &str| match_ui_locale(&translator, tag).map(|l| l.to_string());

        assert_eq!(lang("pt").as_deref(), Some("pt-BR"));
        assert_eq!(lang("pt-PT").as_deref(), Some("pt-BR"));
        assert_eq!(lang("pt_BR").as_deref(), Some("pt-BR"));
        assert_eq!(lang("es-419").as_deref(), Some("es"));
        assert_eq!(lang("fr-CA-u-ca-gregory").as_deref(), Some("fr"));
        assert_eq!(lang("en-GB").as_deref(), Some("en"));
        assert_eq!(lang("xx"), None);
        assert_eq!(lang(""), None);
        assert_eq!(lang("not a tag"), None);
    }

    #[test]
    fn test_request_language_order() {
        let translator = translator();
        let lang = |headers: &HeaderMap, query: &str| {
            request_language(&translator, headers, &uri(query)).to_string()
        };

        let accept = headers(&[(ACCEPT_LANGUAGE, "fr-FR,fr;q=0.9")]);
        assert_eq!(lang(&accept, ""), "fr");
        assert_eq!(lang(&accept, "?ui_locales=pt"), "pt-BR");
        // The first supported tag wins.
        assert_eq!(lang(&accept, "?ui_locales=xx%20es"), "es");
        // An unsupported tag falls through.
        assert_eq!(lang(&accept, "?ui_locales=xx"), "fr");

        let cookie = headers(&[
            (ACCEPT_LANGUAGE, "fr-FR,fr;q=0.9"),
            (COOKIE, "mas-session=abc; mas-language=es"),
        ]);
        assert_eq!(lang(&cookie, ""), "es");
        assert_eq!(lang(&cookie, "?ui_locales=pt-BR"), "pt-BR");

        let stale = headers(&[(ACCEPT_LANGUAGE, "fr"), (COOKIE, "mas-language=xx")]);
        assert_eq!(lang(&stale, ""), "fr");

        assert_eq!(lang(&HeaderMap::new(), ""), "en");
    }
}
