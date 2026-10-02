// Copyright 2026 Gua
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

// @vitest-environment happy-dom

import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { TooltipProvider } from "@vector-im/compound-web";
import i18n from "i18next";
import { describe, expect, it } from "vitest";
import ES from "../../locales/es.json";
import FR from "../../locales/fr.json";
import PT_BR from "../../locales/pt-BR.json";
import { makeFragmentData } from "../gql";
import render from "../test-utils/render";
import AccountDeleteButton, {
  CONFIG_FRAGMENT,
  USER_FRAGMENT,
} from "./AccountDeleteButton";

// The dialog for an account without a password asks for the username. Every
// shipped language must fill it in and keep the protocol out of the text.
const languages = [
  { lang: "pt-BR", resources: PT_BR, button: "Excluir conta" },
  { lang: "es", resources: ES, button: "Eliminar cuenta" },
  { lang: "fr", resources: FR, button: "Supprimer le compte" },
];

describe("<AccountDeleteButton /> translations", () => {
  it.each(languages)("asks for the username in $lang", async ({
    lang,
    resources,
    button,
  }) => {
    i18n.addResourceBundle(lang, "translation", resources);
    await i18n.changeLanguage(lang);

    const user = makeFragmentData(
      {
        username: "alice",
        hasPassword: false,
        matrix: { mxid: "@alice:example.com", displayName: "Alice" },
      },
      USER_FRAGMENT,
    );
    const siteConfig = makeFragmentData(
      { passwordLoginEnabled: false },
      CONFIG_FRAGMENT,
    );

    render(
      <TooltipProvider>
        <AccountDeleteButton user={user} siteConfig={siteConfig} />
      </TooltipProvider>,
    );
    await userEvent.click(screen.getByRole("button", { name: button }));

    const dialog = screen.getByRole("dialog");
    const label = i18n.t("frontend.account.delete_account.mxid_label", {
      localpart: "alice",
    });
    expect(label).toContain("(alice)");
    expect(screen.getByLabelText(label)).toBeInTheDocument();
    expect(dialog.textContent).not.toMatch(/matrix|mxid|homeserver|\{\{/i);
    expect(dialog.textContent).not.toContain("example.com");
  });
});
