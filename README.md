# Gua Authentication Service

Gua's fork of [Matrix Authentication Service](https://github.com/element-hq/matrix-authentication-service) (MAS), the OIDC authentication layer for Matrix homeservers. Gua runs one instance of it next to each homeserver. Gua clients sign in through it with the OIDC authorization code flow and PKCE.

## What the fork changes

The Gua changes are marked `GUA FORK` in the source. New modules sit under `crates/handlers/src/gua/` and `crates/tasks/src/gua.rs`:

- **Sign-in session rules.** A sign-in does not continue in a browser session that belongs to a different account. A sign-in that completes an account recovery ends every other session of the account.
- **Account pages check the account.** When an app opens the account page and names its user (`org.matrix.msc4198.login_hint`), a browser session of another account is ended and the user signs in again as the named account.
- **Sign-out ends the browser session.** Signing out of an app also ends the browser session it was started from, unless another active session still uses it.
- **Account deletion notifies the provider.** Deleting an account erases the user on the homeserver and tells each upstream provider, retrying until the provider confirms.
- **First-party endpoints** for the Gua apps, such as approving the app's own cross-signing reset with its access token.

The target design moves login authority to each homeserver's own instance of this service, including login methods verified locally. That is not implemented yet. [ADM-001](https://github.com/Gua-ra/gua-resolver/blob/main/docs/decisions/ADM-001-identifier-binding-placement-trust.md) records the decision; [Gua identity and federation](https://github.com/Gua-ra/gua-resolver/blob/main/docs/architecture/gua-identity-and-federation.md) explains it in plain language.

## Running it

It runs like upstream MAS: a single `mas-cli` binary with a YAML configuration and a PostgreSQL database. The upstream [documentation](https://element-hq.github.io/matrix-authentication-service/) covers installation, configuration and the `mas-cli` commands; the same book is in [docs/](docs/).

```bash
docker build -t gua-auth-service .
docker run --rm gua-auth-service config generate > config.yaml   # then edit it
docker run --rm -v "$PWD/config.yaml:/config.yaml:ro" -p 8080:8080 gua-auth-service server
```

Point the `upstream_oauth2` provider at your identity service and the `matrix` section at the homeserver the instance serves, as in upstream's configuration reference.

The image that [ci-cd.yml](.github/workflows/ci-cd.yml) publishes is private. Build your own from the [Dockerfile](Dockerfile) as shown above.

## How it relates to the rest of Gua

- [gua-resolver](https://github.com/Gua-ra/gua-resolver) tells a client which homeserver, and therefore which instance of this service, to sign in at.
- [identity-service](https://github.com/Gua-ra/identity-service) is the upstream OIDC provider today. Gua configures this service to delegate every sign-in to it, so the service holds no login credentials of its own.
- [gua-ios](https://github.com/Gua-ra/gua-ios), [gua-android](https://github.com/Gua-ra/gua-android) and [gua-web](https://github.com/Gua-ra/gua-web) are the clients.
- [rust-opa-wasm](https://github.com/Gua-ra/rust-opa-wasm) is Gua's fork of the OPA WebAssembly crate, with no code changes. `Cargo.toml` pins a commit from it.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security problems go through [SECURITY.md](SECURITY.md), never a public issue.

## Upstream relationship

This repository tracks [`element-hq/matrix-authentication-service`](https://github.com/element-hq/matrix-authentication-service) on `main`. To pull upstream changes:

```bash
git fetch upstream
git merge upstream/main   # or the relevant release tag
```

Matrix Authentication Service is written and maintained by [Element](https://element.io/). Its translation project, community room and support channels are Element's and do not cover Gua.

## Copyright and license

Copyright 2021-2024 The Matrix.org Foundation C.I.C.

Copyright 2024, 2025 New Vector Ltd.

Copyright 2025, 2026 Element Creations Ltd.

Copyright 2026 Gua (Gua modifications)

This software is dual-licensed by Element Creations Ltd (Element). It can be used either:

(1) for free under the terms of the GNU Affero General Public License (as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version); OR

(2) under the terms of a paid-for Element Commercial License agreement between you and Element (the terms of which may vary depending on what you and Element have agreed to).

Gua's modifications are available under the same AGPL terms. See [LICENSE](LICENSE) and [LICENSE-COMMERCIAL](LICENSE-COMMERCIAL).

Unless required by applicable law or agreed to in writing, software distributed under the Licenses is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licenses for the specific language governing permissions and limitations under the Licenses.
