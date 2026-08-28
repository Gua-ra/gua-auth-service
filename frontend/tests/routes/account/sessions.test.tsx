// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

// @vitest-environment happy-dom

import { screen } from "@testing-library/react";
import { parseISO } from "date-fns";
import { HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { FRAGMENT as BROWSER_SESSIONS_FRAGMENT } from "../../../src/components/UserSessionsOverview/BrowserSessionsOverview";
import { makeFragmentData } from "../../../src/gql";
import {
  mockAppSessionsListQuery,
  mockSessionsOverviewQuery,
} from "../../../src/gql/graphql";
import { renderPage, server } from "../render";

describe("Account sessions page", () => {
  // The mocked sessions below carry fixed timestamps, but <LastActive /> renders
  // them relative to the current time, so the rendered page drifts as real time
  // passes: 90 days after the mocked `lastActiveAt` it flips from
  // "Active <date>" to "Inactive for 90+ days" and the snapshot breaks on a
  // branch nobody touched. Pin the clock just after the mocked timestamps so
  // the output is stable. Only `Date` is faked, so msw and react-query keep
  // running on real timers.
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(parseISO("2026-04-24T00:00:00.000Z"));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("renders the page", async () => {
    const { asFragment } = await renderPage("/sessions");
    expect(asFragment()).toMatchSnapshot();
  });

  describe("session limit", () => {
    it("displays an error if they've hit the session soft_limit", async () => {
      server.use(
        mockSessionsOverviewQuery(() =>
          HttpResponse.json({
            data: {
              viewer: {
                __typename: "User",
                id: "123",
                ...makeFragmentData(
                  {
                    browserSessions: {
                      totalCount: 3,
                    },
                  },
                  BROWSER_SESSIONS_FRAGMENT,
                ),
                unfilteredAppSessions: {
                  // They have 12 sessions
                  totalCount: 12,
                },
              },
              siteConfig: {
                sessionLimit: {
                  // The limit is 12
                  softLimit: 12,
                },
              },
            },
          }),
        ),
      );

      server.use(
        mockAppSessionsListQuery(() =>
          HttpResponse.json({
            data: {
              viewer: {
                __typename: "User",
                id: "123",
                appSessions: {
                  totalCount: 12,
                  // Edge for each device on the page (6 per page):
                  // { cursor: "", node: { __typename: "Oauth2Session", ... } }
                  // { cursor: "", node: { __typename: "CompatSession",... } }
                  edges: Array.from(Array(6).keys()).map((index) => ({
                    cursor: `cursor${index}`,
                    node: {
                      __typename: "CompatSession",
                      id: `compat_session:${index}`,
                      createdAt: "2026-04-23T21:25:43.353610+00:00",
                      deviceId: `zzzZZZzzz${index}`,
                      finishedAt: null,
                      lastActiveIp: "127.0.0.1",
                      lastActiveAt: "2026-04-23T21:25:43.367193+00:00",
                      humanName: "Jungle Phone",
                      userAgent: {
                        name: "Chrome",
                        os: "Linux",
                        model: null,
                        deviceType: "PC",
                      },
                      ssoLogin: null,
                    },
                  })),
                  // Doesn't matter for test
                  pageInfo: {
                    startCursor: "foo",
                    endCursor: "bar",
                    hasNextPage: false,
                    hasPreviousPage: true,
                  },
                },
              },
            },
          }),
        ),
      );

      const { asFragment } = await renderPage("/sessions");

      // Make sure there is an error on the page
      //
      // FIXME: Ideally, we'd use a more accessible way to look for the error on the
      // page (like `getByRole(...)`) but there doesn't seem to be an appropriate
      // `aria-role` for this kind of thing. `aria-role="status"` is for the result of
      // the user taking some action whereas this is just an error that's displayed
      // informationally on page load.
      //
      // Perhaps the best we could do is add a generic `aria-role="region"` with
      // `aria-labelledby="error-heading"` so we could use `getByRole('region', { name:
      // "You've hit the device limit"})` but this would require some changes to the
      // `Alert` component in Compound itself.
      screen.getByTestId("device-limit-error");

      // Sanity check page overall
      expect(asFragment()).toMatchSnapshot();
    });
  });
});
