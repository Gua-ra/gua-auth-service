# Contributing to the Gua Authentication Service

This repository is a fork of [Matrix Authentication Service](https://github.com/element-hq/matrix-authentication-service). Upstream's [contributor guide](docs/development/contributing.md) describes the codebase, the build and the test suite. This guide covers what is specific to Gua.

Upstream's CLA, Localazy and pull request instructions do not apply here. There is no CLA, and pull requests go to `Gua-ra/gua-auth-service`.

## Where the Gua code lives

Mark every Gua change with a `GUA FORK` comment. New Gua modules go under `crates/handlers/src/gua/` and `crates/tasks/src/gua.rs`; smaller changes live next to the upstream code they adjust. This keeps upstream merges small.

## Before opening a pull request

```bash
cargo +nightly fmt --all -- --check
cargo clippy --workspace --tests --bins --lib -- -D warnings
cargo nextest run --workspace   # needs DATABASE_URL pointing at PostgreSQL
cargo deny check
```

- Section 7 of the upstream guide covers the frontend and policy tests. [ci.yaml](.github/workflows/ci.yaml) runs all of these on every pull request. [ci-cd.yml](.github/workflows/ci-cd.yml) builds the container image; an unlabelled pull request stops at build and tests.
- A new Gua file starts with `Copyright <year> Gua` followed by the repository's SPDX line. A modified upstream file keeps its upstream notice.

## Pull requests

Branch from `main`. Commits, pull request text and writing follow the [org contribution guide](https://github.com/Gua-ra/.github/blob/main/CONTRIBUTING.md#pull-requests).

## Reporting problems

- Issues are turned off on this repository. Report problems through the [support form](https://gua.global/support) or [support@gua.global](mailto:support@gua.global).
- Security problems: [SECURITY.md](SECURITY.md).
