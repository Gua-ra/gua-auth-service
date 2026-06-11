# Gua Fork of Matrix Authentication Service

This repository is **Gua-ra's fork** of [`element-hq/matrix-authentication-service`](https://github.com/element-hq/matrix-authentication-service) (MAS).

All Gua-specific customisations are isolated to files that **do not exist in the upstream project**, minimising merge conflicts on each upstream update:

| New file (no upstream equivalent) | Purpose |
|---|---|
| `gua/README.md` | This document |
| `crates/config/src/sections/gua.rs` | `[gua]` config section |
| `crates/handlers/src/gua/mod.rs` | Auto-fulfill consent handler logic |

Minimal hook sites added to upstream files:

| Upstream file | Change |
|---|---|
| `crates/config/src/sections/mod.rs` | `mod gua;`, `GUAConfig` re-export, `gua` field on `RootConfig` + `AppConfig` |
| `crates/data-model/src/site_config.rs` | `trusted_clients_skip_consent: Vec<Ulid>` + `skip_consent_for_all_clients: bool` fields + `ulid` import |
| `crates/cli/src/util.rs` | `gua_config` param + populate both consent-skip fields |
| `crates/cli/src/commands/server.rs` | Pass `&config.gua` |
| `crates/cli/src/commands/worker.rs` | Pass `&config.gua` |
| `crates/cli/src/commands/templates.rs` | Extract + pass `gua_config` |
| `crates/handlers/src/lib.rs` | `mod gua;` declaration |
| `crates/handlers/src/oauth2/authorization/mod.rs` | `pub(crate) mod callback` |
| `crates/handlers/src/oauth2/authorization/consent.rs` | `State<SiteConfig>` + `Keystore` params; hook site calling `crate::gua::*` |
| `crates/handlers/src/test_utils.rs` | consent-skip fields in test helper |
| `frontend/src/components/UserGreeting/UserGreeting.tsx` | Account "Your account" greeting renders the localpart (`alice`) instead of the full mxid (`@alice:dev.local`); display-only |

---

## Customisations

### Skip-consent for first-party clients

The upstream consent screen ("Continue to {client}?") is shown for every OIDC authorization. In the Gua product, users interact exclusively with first-party clients they implicitly trust, so this screen is an unwanted extra step.

The patch adds a `gua.skip_consent_client_ids` config key. For any client listed there, the consent GET handler auto-fulfills the authorization grant and redirects straight to the client callback — skipping the consent UI entirely. The OPA policy is still evaluated; only the consent *screen* is skipped.

For deployments where clients are registered dynamically (e.g. the iOS app via Dynamic Client Registration, which gets a fresh client ID per install and so can't be pinned in a static list), `gua.skip_consent_for_all_clients: true` skips consent for **every** client.

**Configuration** (`mas.conf.yaml`):

```yaml
gua:
  # Skip consent for specific first-party client IDs:
  skip_consent_client_ids:
    - 01JXTEST000000000000BCDE01   # gua-ios (OIDC client, first-party)
  # ...or skip consent for all clients (use when clients are registered dynamically):
  skip_consent_for_all_clients: true
```

### Account UI: localpart-only identity

The account management SPA's "Your account" greeting (`frontend/src/components/UserGreeting/UserGreeting.tsx`) renders only the localpart (e.g. `alice`) instead of the full Matrix ID (`@alice:dev.local`), matching Gua's frictionless design. This is display-only — the mxid is unchanged and still used for avatars and the read-only username field.

---

## Docker image

Images are published to `ghcr.io/gua-ra/gua-auth-service` via GitHub Actions on every push to the `gua/skip-consent` branch and on release tags.

```
ghcr.io/gua-ra/gua-auth-service:latest
ghcr.io/gua-ra/gua-auth-service:v1.18.0-gua.1
```

Tag convention: `v<upstream-mas-version>-gua.<patch>` (mirrors Tchap's `vX.Y.Z-<masver>` pattern).

---

## Upgrading to a new upstream MAS release

1. `git fetch upstream --tags`
2. `git merge upstream/v<new-version>` (or cherry-pick onto a new branch from the new tag)
3. Resolve conflicts — expected conflict files are only those listed in the hook-site table above
4. Re-run `cargo check` and fix any API changes in `crates/handlers/src/gua/mod.rs`
5. Bump the image tag: `v<new-version>-gua.1`
6. Open a PR, let CI build the image, then update `docker-compose.test.yml`

Expected merge-conflict rate: ~50% of MAS releases touch `consent.rs`; the diff is small (one `if` block and two extra `State<>` params in the function signature).
