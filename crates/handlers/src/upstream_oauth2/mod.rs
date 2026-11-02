// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

// GUA FORK: the task worker builds the same credentials for the account
// deletion notice, so the helper lives in the tasks crate.
use mas_tasks::upstream_oauth2::{ProviderCredentialsError, client_credentials_for_provider};

pub(crate) mod authorize;
pub(crate) mod backchannel_logout;
pub(crate) mod cache;
pub(crate) mod callback;
mod cookie;
pub(crate) mod link;
mod template;

use self::cookie::UpstreamSessions as UpstreamSessionsCookie;
