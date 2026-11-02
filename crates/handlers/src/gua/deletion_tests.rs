// Copyright 2026 Gua
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! GUA FORK: deleting an account tells the upstream provider, and the link
//! goes only once the provider confirmed.

use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use headers::{Authorization, HeaderMapExt as _, authorization::Basic};
use hyper::{Request, StatusCode};
use mas_axum_utils::SessionInfoExt as _;
use mas_data_model::{
    SiteConfig, UpstreamOAuthLink, UpstreamOAuthProvider, UpstreamOAuthProviderClaimsImports,
    UpstreamOAuthProviderDiscoveryMode, UpstreamOAuthProviderOnBackchannelLogout,
    UpstreamOAuthProviderPkceMode, UpstreamOAuthProviderTokenAuthMethod, User,
};
use mas_iana::jose::JsonWebSignatureAlg;
use mas_matrix::{HomeserverConnection as _, ProvisionRequest};
use mas_storage::{
    RepositoryAccess as _,
    queue::{CleanupUpstreamOAuthLinksJob, DeactivateUserJob, QueueJobRepositoryExt as _},
    upstream_oauth2::UpstreamOAuthProviderParams,
};
use oauth2_types::scope::{OPENID, Scope};
use sqlx::{PgPool, types::Uuid};
use ulid::Ulid;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

use crate::test_utils::{
    CookieHelper, RequestBuilderExt as _, ResponseExt as _, TestState, setup, test_site_config,
};

const CLIENT_ID: &str = "mas";
const CLIENT_SECRET: &str = "provider-client-secret";
const NOTICE_PATH: &str = "/oauth2/account-deleted";

struct LinkedUser {
    user: User,
    link: UpstreamOAuthLink,
    session_id: Ulid,
}

/// The columns of an upstream authorization session that can carry the
/// provider's claims, plus the link bookkeeping.
#[derive(sqlx::FromRow)]
struct SessionPayloads {
    upstream_oauth_link_id: Option<Uuid>,
    unlinked_at: Option<DateTime<Utc>>,
    id_token: Option<String>,
    id_token_claims: Option<serde_json::Value>,
    userinfo: Option<serde_json::Value>,
    extra_callback_parameters: Option<serde_json::Value>,
}

async fn add_provider(
    state: &TestState,
    issuer: &str,
    token_endpoint_auth_method: UpstreamOAuthProviderTokenAuthMethod,
) -> UpstreamOAuthProvider {
    let mut rng = state.rng();
    let mut repo = state.repository().await.unwrap();
    let params = UpstreamOAuthProviderParams {
        issuer: Some(issuer.to_owned()),
        human_name: Some("Gua".to_owned()),
        brand_name: None,
        scope: Scope::from_iter([OPENID]),
        token_endpoint_auth_method,
        token_endpoint_signing_alg: None,
        id_token_signed_response_alg: JsonWebSignatureAlg::Rs256,
        fetch_userinfo: false,
        userinfo_signed_response_alg: None,
        client_id: CLIENT_ID.to_owned(),
        encrypted_client_secret: Some(
            state
                .encrypter
                .encrypt_to_string(CLIENT_SECRET.as_bytes())
                .unwrap(),
        ),
        claims_imports: UpstreamOAuthProviderClaimsImports::default(),
        authorization_endpoint_override: None,
        token_endpoint_override: None,
        userinfo_endpoint_override: None,
        jwks_uri_override: None,
        discovery_mode: UpstreamOAuthProviderDiscoveryMode::Disabled,
        pkce_mode: UpstreamOAuthProviderPkceMode::Auto,
        response_mode: None,
        additional_authorization_parameters: vec![],
        forward_login_hint: false,
        ui_order: 0,
        on_backchannel_logout: UpstreamOAuthProviderOnBackchannelLogout::DoNothing,
        registration_token_required: false,
    };
    let provider = repo
        .upstream_oauth_provider()
        .add(&mut rng, &state.clock, params)
        .await
        .unwrap();
    repo.save().await.unwrap();
    provider
}

/// A user known to the homeserver, linked to the provider, with one completed
/// sign-in whose stored tokens carry a phone number.
async fn add_linked_user(
    state: &TestState,
    provider: &UpstreamOAuthProvider,
    username: &str,
) -> LinkedUser {
    let mut rng = state.rng();
    let mut repo = state.repository().await.unwrap();

    let user = repo
        .user()
        .add(&mut rng, &state.clock, username.to_owned())
        .await
        .unwrap();
    state
        .homeserver_connection
        .provision_user(
            &ProvisionRequest::new(&user.username, &user.sub, false)
                .set_displayname(format!("{username} display name")),
        )
        .await
        .unwrap();

    let subject = format!("@{username}:example.com");
    let link = repo
        .upstream_oauth_link()
        .add(&mut rng, &state.clock, provider, subject.clone(), None)
        .await
        .unwrap();
    repo.upstream_oauth_link()
        .associate_to_user(&link, &user)
        .await
        .unwrap();

    let session = repo
        .upstream_oauth_session()
        .add(
            &mut rng,
            &state.clock,
            provider,
            format!("state-{username}"),
            None,
            Some("nonce".to_owned()),
        )
        .await
        .unwrap();
    let claims = serde_json::json!({ "sub": subject, "phone_number": "+15550000000" });
    let session = repo
        .upstream_oauth_session()
        .complete_with_link(
            &state.clock,
            session,
            &link,
            Some("header.payload.signature".to_owned()),
            Some(claims.clone()),
            Some(serde_json::json!({ "code": "abc" })),
            Some(claims),
        )
        .await
        .unwrap();

    repo.save().await.unwrap();

    LinkedUser {
        user,
        link,
        session_id: session.id,
    }
}

async fn deactivate(state: &TestState, user: &User) {
    let mut rng = state.rng();
    let mut repo = state.repository().await.unwrap();
    let user = repo
        .user()
        .deactivate(&state.clock, user.clone())
        .await
        .unwrap();
    repo.queue_job()
        .schedule_job(&mut rng, &state.clock, DeactivateUserJob::new(&user, true))
        .await
        .unwrap();
    repo.save().await.unwrap();
}

async fn link_exists(state: &TestState, link: &UpstreamOAuthLink) -> bool {
    let mut repo = state.repository().await.unwrap();
    repo.upstream_oauth_link()
        .lookup(link.id)
        .await
        .unwrap()
        .is_some()
}

async fn session_payloads(state: &TestState, session_id: Ulid) -> SessionPayloads {
    sqlx::query_as(
        "SELECT upstream_oauth_link_id, unlinked_at, id_token, id_token_claims, userinfo, \
         extra_callback_parameters \
         FROM upstream_oauth_authorization_sessions \
         WHERE upstream_oauth_authorization_session_id = $1",
    )
    .bind(Uuid::from(session_id))
    .fetch_one(&state.repository_factory.pool())
    .await
    .unwrap()
}

async fn notices(mock_server: &MockServer) -> Vec<wiremock::Request> {
    mock_server
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .filter(|request| request.url.path() == NOTICE_PATH)
        .collect()
}

fn form(request: &wiremock::Request) -> HashMap<String, String> {
    serde_urlencoded::from_bytes(&request.body).unwrap()
}

async fn answer_notices_with(mock_server: &MockServer, status: u16) {
    mock_server.reset().await;
    Mock::given(method("POST"))
        .and(path(NOTICE_PATH))
        .respond_with(ResponseTemplate::new(status))
        .mount(mock_server)
        .await;
}

#[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
async fn test_gua_deletion_notifies_the_provider_and_forgets_the_link(pool: PgPool) {
    setup();
    let state = TestState::from_pool(pool).await.unwrap();
    let mock_server = MockServer::start().await;
    answer_notices_with(&mock_server, 204).await;

    let provider = add_provider(
        &state,
        &mock_server.uri(),
        UpstreamOAuthProviderTokenAuthMethod::ClientSecretPost,
    )
    .await;
    let alice = add_linked_user(&state, &provider, "alice").await;

    deactivate(&state, &alice.user).await;
    state.run_jobs_in_queue().await;

    let notices = notices(&mock_server).await;
    assert_eq!(notices.len(), 1);
    assert_eq!(notices[0].method.as_str(), "POST");
    assert_eq!(
        notices[0]
            .headers
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("application/x-www-form-urlencoded")
    );
    assert_eq!(
        form(&notices[0]),
        HashMap::from([
            ("sub".to_owned(), "@alice:example.com".to_owned()),
            ("client_id".to_owned(), CLIENT_ID.to_owned()),
            ("client_secret".to_owned(), CLIENT_SECRET.to_owned()),
        ])
    );

    assert!(!link_exists(&state, &alice.link).await);
    let session = session_payloads(&state, alice.session_id).await;
    assert!(session.upstream_oauth_link_id.is_none());
    assert!(session.unlinked_at.is_some());
    assert!(session.id_token.is_none());
    assert!(session.id_token_claims.is_none());
    assert!(session.userinfo.is_none());
    assert!(session.extra_callback_parameters.is_none());

    let matrix_user = state
        .homeserver_connection
        .query_user(&alice.user.username)
        .await
        .unwrap();
    assert!(matrix_user.deactivated);
}

#[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
async fn test_gua_deletion_erases_even_when_the_job_asks_not_to(pool: PgPool) {
    setup();
    let state = TestState::from_pool(pool).await.unwrap();
    let mock_server = MockServer::start().await;
    answer_notices_with(&mock_server, 204).await;

    let provider = add_provider(
        &state,
        &mock_server.uri(),
        UpstreamOAuthProviderTokenAuthMethod::ClientSecretPost,
    )
    .await;
    let alice = add_linked_user(&state, &provider, "alice").await;

    // The job as `mas-cli manage lock --deactivate` and the admin API with
    // `skip_erase` schedule it
    let mut rng = state.rng();
    let mut repo = state.repository().await.unwrap();
    let user = repo
        .user()
        .deactivate(&state.clock, alice.user.clone())
        .await
        .unwrap();
    repo.queue_job()
        .schedule_job(&mut rng, &state.clock, DeactivateUserJob::new(&user, false))
        .await
        .unwrap();
    repo.save().await.unwrap();
    state.run_jobs_in_queue().await;

    let matrix_user = state
        .homeserver_connection
        .query_user(&alice.user.username)
        .await
        .unwrap();
    assert!(matrix_user.deactivated);
    assert!(matrix_user.displayname.is_none());
    assert_eq!(notices(&mock_server).await.len(), 1);
    assert!(!link_exists(&state, &alice.link).await);
}

#[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
async fn test_gua_deletion_notice_uses_the_providers_basic_auth(pool: PgPool) {
    setup();
    let state = TestState::from_pool(pool).await.unwrap();
    let mock_server = MockServer::start().await;
    answer_notices_with(&mock_server, 204).await;

    let provider = add_provider(
        &state,
        &mock_server.uri(),
        UpstreamOAuthProviderTokenAuthMethod::ClientSecretBasic,
    )
    .await;
    let alice = add_linked_user(&state, &provider, "alice").await;

    deactivate(&state, &alice.user).await;
    state.run_jobs_in_queue().await;

    let notices = notices(&mock_server).await;
    assert_eq!(notices.len(), 1);
    let basic = notices[0]
        .headers
        .typed_get::<Authorization<Basic>>()
        .unwrap();
    assert_eq!(basic.username(), CLIENT_ID);
    assert_eq!(basic.password(), CLIENT_SECRET);
    assert_eq!(
        form(&notices[0]),
        HashMap::from([("sub".to_owned(), "@alice:example.com".to_owned())])
    );
    assert!(!link_exists(&state, &alice.link).await);
}

#[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
async fn test_gua_deletion_keeps_the_link_until_the_provider_confirms(pool: PgPool) {
    setup();
    let state = TestState::from_pool(pool).await.unwrap();
    let mock_server = MockServer::start().await;
    answer_notices_with(&mock_server, 500).await;

    let provider = add_provider(
        &state,
        &mock_server.uri(),
        UpstreamOAuthProviderTokenAuthMethod::ClientSecretPost,
    )
    .await;
    let alice = add_linked_user(&state, &provider, "alice").await;

    deactivate(&state, &alice.user).await;
    state.run_jobs_in_queue().await;

    assert_eq!(notices(&mock_server).await.len(), 1);
    assert!(link_exists(&state, &alice.link).await);
    let session = session_payloads(&state, alice.session_id).await;
    assert!(session.upstream_oauth_link_id.is_some());
    assert!(session.id_token.is_some());
    assert!(session.id_token_claims.is_some());

    let statuses: Vec<String> = sqlx::query_scalar(
        "SELECT status::TEXT FROM queue_jobs WHERE queue_name = 'deactivate-user' \
         ORDER BY status::TEXT",
    )
    .fetch_all(&state.repository_factory.pool())
    .await
    .unwrap();
    assert_eq!(statuses, ["failed", "scheduled"]);

    // The retry runs once its delay has passed, and the provider now confirms
    answer_notices_with(&mock_server, 204).await;
    state.clock.advance(Duration::try_seconds(10).unwrap());
    state.run_jobs_in_queue().await;

    assert_eq!(notices(&mock_server).await.len(), 1);
    assert!(!link_exists(&state, &alice.link).await);
    assert!(
        session_payloads(&state, alice.session_id)
            .await
            .id_token
            .is_none()
    );
}

#[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
async fn test_gua_deletion_does_not_count_a_redirect_as_a_confirmation(pool: PgPool) {
    setup();
    let state = TestState::from_pool(pool).await.unwrap();
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(NOTICE_PATH))
        .respond_with(ResponseTemplate::new(302).insert_header("location", "/elsewhere"))
        .mount(&mock_server)
        .await;
    Mock::given(path("/elsewhere"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    let provider = add_provider(
        &state,
        &mock_server.uri(),
        UpstreamOAuthProviderTokenAuthMethod::ClientSecretPost,
    )
    .await;
    let alice = add_linked_user(&state, &provider, "alice").await;

    deactivate(&state, &alice.user).await;
    state.run_jobs_in_queue().await;

    assert_eq!(notices(&mock_server).await.len(), 1);
    assert!(link_exists(&state, &alice.link).await);
}

#[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
async fn test_gua_deletion_sends_nothing_when_the_setting_is_off(pool: PgPool) {
    setup();
    let site_config = SiteConfig {
        gua_forget_upstream_on_deactivation: false,
        ..test_site_config()
    };
    let state = TestState::from_pool_with_site_config(pool, site_config)
        .await
        .unwrap();
    let mock_server = MockServer::start().await;
    answer_notices_with(&mock_server, 204).await;

    let provider = add_provider(
        &state,
        &mock_server.uri(),
        UpstreamOAuthProviderTokenAuthMethod::ClientSecretPost,
    )
    .await;
    let alice = add_linked_user(&state, &provider, "alice").await;

    deactivate(&state, &alice.user).await;
    state.run_jobs_in_queue().await;

    // The hourly sweep is off too
    let mut rng = state.rng();
    let mut repo = state.repository().await.unwrap();
    repo.queue_job()
        .schedule_job(&mut rng, &state.clock, CleanupUpstreamOAuthLinksJob)
        .await
        .unwrap();
    repo.save().await.unwrap();
    state.run_jobs_in_queue().await;

    assert!(notices(&mock_server).await.is_empty());
    assert!(link_exists(&state, &alice.link).await);
    assert!(
        session_payloads(&state, alice.session_id)
            .await
            .id_token
            .is_some()
    );
    let matrix_user = state
        .homeserver_connection
        .query_user(&alice.user.username)
        .await
        .unwrap();
    assert!(matrix_user.deactivated);
}

#[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
async fn test_gua_deletion_without_links_completes(pool: PgPool) {
    setup();
    let state = TestState::from_pool(pool).await.unwrap();
    let mock_server = MockServer::start().await;
    answer_notices_with(&mock_server, 204).await;

    let mut rng = state.rng();
    let mut repo = state.repository().await.unwrap();
    let user = repo
        .user()
        .add(&mut rng, &state.clock, "bob".to_owned())
        .await
        .unwrap();
    repo.save().await.unwrap();
    state
        .homeserver_connection
        .provision_user(&ProvisionRequest::new(&user.username, &user.sub, false))
        .await
        .unwrap();

    deactivate(&state, &user).await;
    state.run_jobs_in_queue().await;

    assert!(notices(&mock_server).await.is_empty());
    let statuses: Vec<String> = sqlx::query_scalar(
        "SELECT status::TEXT FROM queue_jobs WHERE queue_name = 'deactivate-user'",
    )
    .fetch_all(&state.repository_factory.pool())
    .await
    .unwrap();
    assert_eq!(statuses, ["completed"]);
}

#[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
async fn test_gua_sweep_only_touches_deactivated_users(pool: PgPool) {
    setup();
    let state = TestState::from_pool(pool).await.unwrap();
    let mock_server = MockServer::start().await;
    answer_notices_with(&mock_server, 204).await;

    let provider = add_provider(
        &state,
        &mock_server.uri(),
        UpstreamOAuthProviderTokenAuthMethod::ClientSecretPost,
    )
    .await;
    let deleted = add_linked_user(&state, &provider, "deleted").await;
    let active = add_linked_user(&state, &provider, "active").await;

    // Deactivated without the job, as accounts deleted before the notice
    // existed were
    let mut rng = state.rng();
    let mut repo = state.repository().await.unwrap();
    repo.user()
        .deactivate(&state.clock, deleted.user.clone())
        .await
        .unwrap();
    repo.queue_job()
        .schedule_job(&mut rng, &state.clock, CleanupUpstreamOAuthLinksJob)
        .await
        .unwrap();
    repo.save().await.unwrap();

    state.run_jobs_in_queue().await;

    let notices = notices(&mock_server).await;
    assert_eq!(notices.len(), 1);
    assert_eq!(
        form(&notices[0]).get("sub").map(String::as_str),
        Some("@deleted:example.com")
    );
    assert!(!link_exists(&state, &deleted.link).await);
    assert!(
        session_payloads(&state, deleted.session_id)
            .await
            .id_token
            .is_none()
    );
    assert!(link_exists(&state, &active.link).await);
    assert!(
        session_payloads(&state, active.session_id)
            .await
            .id_token
            .is_some()
    );

    let erased = state
        .homeserver_connection
        .query_user(&deleted.user.username)
        .await
        .unwrap();
    assert!(erased.deactivated);
    assert!(erased.displayname.is_none());
    let untouched = state
        .homeserver_connection
        .query_user(&active.user.username)
        .await
        .unwrap();
    assert!(!untouched.deactivated);
    assert_eq!(
        untouched.displayname.as_deref(),
        Some("active display name")
    );
}

#[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
async fn test_gua_deactivate_mutation_always_erases(pool: PgPool) {
    setup();
    let state = TestState::from_pool(pool).await.unwrap();

    let mut rng = state.rng();
    let mut repo = state.repository().await.unwrap();
    let user = repo
        .user()
        .add(&mut rng, &state.clock, "carol".to_owned())
        .await
        .unwrap();
    let browser_session = repo
        .browser_session()
        .add(&mut rng, &state.clock, &user, None)
        .await
        .unwrap();
    repo.save().await.unwrap();
    state
        .homeserver_connection
        .provision_user(
            &ProvisionRequest::new(&user.username, &user.sub, false)
                .set_displayname("Carol".to_owned()),
        )
        .await
        .unwrap();

    let cookies = CookieHelper::new();
    cookies.import(state.cookie_jar().set_session(&browser_session));
    let request = cookies.with_cookies(Request::post("/graphql").json(serde_json::json!({
        "query": "mutation { deactivateUser(input: { hsErase: false }) { status } }",
    })));
    let response = state.request(request).await;
    response.assert_status(StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_eq!(
        body["data"]["deactivateUser"]["status"].as_str(),
        Some("DEACTIVATED"),
        "{body}"
    );

    state.run_jobs_in_queue().await;

    let matrix_user = state
        .homeserver_connection
        .query_user(&user.username)
        .await
        .unwrap();
    assert!(matrix_user.deactivated);
    assert!(matrix_user.displayname.is_none());
}
