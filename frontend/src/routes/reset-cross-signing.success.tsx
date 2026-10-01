// Copyright 2024, 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import { createFileRoute } from "@tanstack/react-router";
import IconCheckCircleSolid from "@vector-im/compound-design-tokens/assets/web/icons/check-circle-solid";
import { Button, Text } from "@vector-im/compound-web";
import { useEffect } from "react";
import { useTranslation } from "react-i18next";
import PageHeading from "../components/PageHeading";

// This value comes from Synapse and we have no way to query it from here
// https://github.com/element-hq/synapse/blob/34b758644611721911a223814a7b35d8e14067e6/synapse/rest/admin/users.py#L1335
const CROSS_SIGNING_REPLACEMENT_PERIOD_MS = 10 * 60 * 1000; // 10 minutes

// GUA FORK: the return scheme is untrusted. Only these are used, and the URL is built here.
const RETURNABLE_APP_SCHEMES = [
  "global.gua",
  "global.gua.dev",
  "global.gua.debug",
];

const returnUrlFor = (scheme: string): string =>
  `${scheme}:/reset-cross-signing-done`;

export const Route = createFileRoute("/reset-cross-signing/success")({
  component: () => {
    const { t } = useTranslation();
    const { guaReturn } = Route.useSearch();

    const returnUrl =
      guaReturn && RETURNABLE_APP_SCHEMES.includes(guaReturn)
        ? returnUrlFor(guaReturn)
        : undefined;

    // GUA FORK: navigating to the app's own scheme closes its web sheet.
    useEffect(() => {
      if (!returnUrl) return;
      window.location.href = returnUrl;
    }, [returnUrl]);

    return (
      <>
        <PageHeading
          Icon={IconCheckCircleSolid}
          title={t("frontend.reset_cross_signing.success.heading")}
          success
        />
        <Text className="text-center text-secondary" size="md">
          {t("frontend.reset_cross_signing.success.description", {
            minutes: CROSS_SIGNING_REPLACEMENT_PERIOD_MS / (60 * 1000),
          })}
        </Text>

        {/*
          A manual way back for when the automatic hand-off does not take (the app was uninstalled
          mid-flow, or the browser declined the navigation).
        */}
        {returnUrl ? (
          <Button as="a" href={returnUrl} kind="primary" size="lg">
            {t("action.continue")}
          </Button>
        ) : null}
      </>
    );
  },
});
