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

/**
 * GUA FORK: the URL schemes we will hand control back to.
 *
 * A fixed list, deliberately. The scheme arrives as a query parameter, so anything derived from it
 * has to be treated as untrusted: we compare against this list and navigate to a URL we build
 * ourselves, rather than to anything the caller supplied. That is what keeps this from being an
 * open redirect.
 */
const RETURNABLE_APP_SCHEMES = ["global.gua", "global.gua.dev"];

/** Where we send the app. The path is ours; only the scheme comes from the caller. */
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

    // GUA FORK: hand control straight back to the app that sent the user here.
    //
    // This page is where a reset finishes, and until now it was a dead end: it told people to go
    // back to the app, and they had to close the web sheet by hand. Navigating to the app's own
    // scheme is what makes that sheet close itself -- iOS matches the scheme at the
    // ASWebAuthenticationSession level, and on Android the scheme's intent filter brings the app
    // forward, which tears the Custom Tab down with it.
    //
    // Only ever for a caller that named an app scheme we recognise. Someone who did this from an
    // ordinary browser tab has no app to go back to, and must not be thrown at a protocol their
    // browser cannot open, so they keep the page below and the button.
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
          A manual way back, for the case where the automatic hand-off does not take: the app was
          uninstalled mid-flow, or the browser declined the navigation. Without it, refusing to
          redirect would leave the user staring at a page with nothing to press.
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
