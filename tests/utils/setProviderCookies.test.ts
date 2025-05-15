import type { OAuthProvider } from "../../types";
import type { Mock } from "vitest";

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { setProviderCookies } from "../../src/utils";
import { createMockEvent } from "../utils";
import { providerConfig } from "../../src/providerConfig";

// 👇️ Mock `setCookie` from the `h3` module before import
vi.mock("h3", async () => {
  const actual = await vi.importActual<typeof import("h3")>("h3");
  return {
    ...actual,
    setCookie: vi.fn(),
  };
});

import { setCookie } from "h3";

const cases = [
  {
    provider: "clio" as const,
    tokens: {
      access_token: "Bearer abc123",
      refresh_token: "refresh123",
      token_type: "bearer",
      expires_in: 3600,
      client_id: "client-xyz",
    },
    expectedCookies: [
      ["clio_access_token", "abc123"],
      ["clio_refresh_token", "refresh123"],
      ["clio_access_token_expires_at", expect.any(String)],
      ["clio_token_type", "bearer"], // ✅ covers typeof field === "string"
    ],
  },
  {
    provider: "azure" as const,
    tokens: {
      access_token: "Bearer xyz987",
      refresh_token: "refresh456",
      token_type: "bearer",
      expires_in: 7200,
      ext_expires_in: 10800,
    },
    expectedCookies: [
      ["azure_access_token", "xyz987"],
      ["azure_refresh_token", "refresh456"],
      ["azure_access_token_expires_at", expect.any(String)],
      ["azure_ext_expires_at", expect.any(String)],
    ],
  },
  {
    provider: "intuit" as const,
    tokens: {
      access_token: "Bearer intuit123",
      refresh_token: "refresh789",
      token_type: "bearer",
      expires_in: 1800,
      realm_id: "realm-abc",
      x_refresh_token_expires_in: 86400,
    },
    expectedCookies: [
      ["intuit_access_token", "intuit123"],
      ["intuit_refresh_token", "refresh789"],
      ["intuit_access_token_expires_at", expect.any(String)],
      ["intuit_refresh_token_expires_at", expect.any(String)],
    ],
  },
];

describe("setProviderCookies", () => {
  const originalClioFields = [...providerConfig.clio.providerSpecificFields];

  beforeEach(() => {
    (setCookie as unknown as Mock).mockClear();

    // Ensure Clio includes a simple string-based field
    providerConfig.clio.providerSpecificFields = ["token_type"];
  });

  afterEach(() => {
    // Restore original config to avoid side effects
    providerConfig.clio.providerSpecificFields = originalClioFields;
  });

  it.each(cases)(
    "writes cookies for $provider and returns full token",
    ({ provider, tokens, expectedCookies }) => {
      const event = createMockEvent();

      const result = setProviderCookies(
        event,
        tokens as any,
        provider as OAuthProvider
      );

      const cookieCalls = (setCookie as unknown as Mock).mock.calls.map(
        ([_, name, value, options]) => ({ name, value, options })
      );

      for (const [expectedName, expectedValue] of expectedCookies) {
        const cookie = cookieCalls.find((c) => c.name === expectedName);

        if (expectedName.endsWith("_access_token")) {
          const originalToken = tokens.access_token;
          const stripped = originalToken.startsWith("Bearer ")
            ? originalToken.slice(7)
            : originalToken;
          expect(cookie?.value).toEqual(stripped);
        } else {
          expect(cookie?.value).toEqual(expectedValue);
        }

        expect(cookie?.options).toMatchObject({
          httpOnly: true,
          secure: true,
          sameSite: "lax",
          path: "/",
        });
      }

      expect(result).toEqual(tokens);
    }
  );

  it("respects custom cookieOptions (sameSite and path)", () => {
    const event = createMockEvent();

    const tokens = {
      access_token: "Bearer custom123",
      refresh_token: "refreshCustom",
      token_type: "bearer" as const,
      expires_in: 1234,
      client_id: "custom-client-id",
    };

    setProviderCookies(event, tokens, "clio", {
      sameSite: "none",
      path: "/auth",
    });

    const cookieCalls = (setCookie as unknown as Mock).mock.calls;

    for (const [_, _name, _value, options] of cookieCalls) {
      expect(options).toMatchObject({
        httpOnly: true,
        secure: true,
        sameSite: "none",
        path: "/auth",
      });
    }
  });

  it("stores raw access_token if it does not start with 'Bearer '", () => {
    const event = createMockEvent();

    const tokens = {
      access_token: "abc123", // 👈 no Bearer prefix
      refresh_token: "refresh123",
      token_type: "bearer" as const,
      expires_in: 3600,
      client_id: "client-xyz",
    };

    setProviderCookies(event, tokens, "clio");

    const cookieCalls = (setCookie as unknown as Mock).mock.calls;

    const accessTokenCookie = cookieCalls.find(
      ([, name]) => name === "clio_access_token"
    );

    expect(accessTokenCookie?.[1]).toBe("clio_access_token");
    expect(accessTokenCookie?.[2]).toBe("abc123");
  });

  it("applies setter function when writing structured cookie fields", () => {
    const event = createMockEvent();

    providerConfig.clio.providerSpecificFields = [
      {
        key: "client_id",
        cookieName: "clio_custom_client_id",
        setter: (value) => `PREFIX_${value}`,
      },
    ];

    const tokens = {
      access_token: "Bearer xyz",
      refresh_token: "abc",
      expires_in: 3600,
      client_id: "1234",
      token_type: "bearer" as const,
    };

    setProviderCookies(event, tokens, "clio");

    const cookieCalls = (setCookie as unknown as Mock).mock.calls;

    const customCookie = cookieCalls.find(
      ([, name]) => name === "clio_custom_client_id"
    );

    expect(customCookie).toBeDefined();
    expect(customCookie?.[2]).toBe("PREFIX_1234");
  });
});
