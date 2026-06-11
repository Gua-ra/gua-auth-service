// Copyright 2025 Gua-ra <https://github.com/Gua-ra>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
//
// ============================================================
// GUA FORK — This file does not exist in the upstream project.
// It will never cause merge conflicts when pulling upstream
// updates. All Gua-specific configuration lives here.
// ============================================================

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use ulid::Ulid;

use super::ConfigurationSection;

/// Gua-specific configuration extensions.
///
/// This section is ignored by the upstream Matrix Authentication Service and
/// only processed by this fork. Add this block to `mas.conf.yaml` to enable
/// Gua customisations:
///
/// ```yaml
/// gua:
///   skip_consent_client_ids:
///     - 01JXTEST000000000000BCDE01  # gua-ios (first-party client)
/// ```
#[serde_as]
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct GUAConfig {
    /// Client IDs for which the OIDC consent screen
    /// ("Continue to {client}?") is skipped and the authorization grant is
    /// fulfilled automatically.
    ///
    /// Use this **only** for first-party, fully-trusted clients that you
    /// control. The OPA policy is still evaluated — this only suppresses the
    /// interactive consent UI.
    #[schemars(with = "Vec<String>")]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skip_consent_client_ids: Vec<Ulid>,
}

impl GUAConfig {
    pub(crate) fn is_default(&self) -> bool {
        self.skip_consent_client_ids.is_empty()
    }
}

impl ConfigurationSection for GUAConfig {
    const PATH: Option<&'static str> = Some("gua");
}
