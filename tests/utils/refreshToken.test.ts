import type { OAuthProviderConfigMap } from "../../src/types";

import { describe, it, expect, vi, beforeEach } from "vitest";
import { refreshToken } from "../../src/utils";

// 👇 Mock `ofetch` before importing the utils
vi.mock("ofetch", async () => {
  const actual = await vi.importActual<typeof import("ofetch")>("ofetch");
  return {
    ...actual,
    ofetch: vi.fn(),
  };
});

import { ofetch } from "ofetch";

const mockOfetch = ofetch as unknown as ReturnType<typeof vi.fn>;

const mockConfigs: OAuthProviderConfigMap = {
  azure: {
    clientId: "id",
    clientSecret: "secret",
    authorizeEndpoint: "",
    tokenEndpoint: "https://example.com/token",
    redirectUri: "",
    scopes: [],
    tenantId: "tenant",
  },
  clio: {
    clientId: "id",
    clientSecret: "secret",
    authorizeEndpoint: "",
    tokenEndpoint: "https://example.com/token",
    redirectUri: "",
    scopes: [],
  },
  intuit: {
    clientId: "id",
    clientSecret: "secret",
    authorizeEndpoint: "",
    tokenEndpoint: "https://example.com/token",
    redirectUri: "",
    scopes: [],
    environment: "sandbox",
  },
};

const testCases = [
  {
    provider: "azure" as const,
    response: {
      access_token: "abc",
      refresh_token: "ref1",
      token_type: "bearer",
      expires_in: 3600,
      ext_expires_in: 7200,
    },
  },
  {
    provider: "clio" as const,
    response: {
      access_token: "abc",
      refresh_token: "ref2",
      token_type: "bearer",
      expires_in: 3600,
    },
  },
  {
    provider: "intuit" as const,
    response: {
      access_token: "abc",
      refresh_token: "ref3",
      token_type: "bearer",
      expires_in: 3600,
      x_refresh_token_expires_in: 86400,
    },
  },
];

describe("refreshToken", () => {
  beforeEach(() => {
    mockOfetch.mockReset();
  });

  it.each(testCases)(
    "sends correct request and returns typed response for $provider",
    async ({ provider, response }) => {
      mockOfetch.mockResolvedValueOnce(response);

      const result = await refreshToken(
        "refreshTokenValue",
        mockConfigs[provider],
        provider
      );

      expect(ofetch).toHaveBeenCalledWith(
        "https://example.com/token",
        expect.objectContaining({
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: expect.stringContaining("grant_type=refresh_token"),
        })
      );

      expect(result).toEqual(response);
    }
  );

  it("throws a parsed H3 error if provider rejects the request", async () => {
    mockOfetch.mockRejectedValueOnce({
      response: {
        status: 401,
        json: async () => ({
          error: "invalid_grant",
          error_description: "Refresh token expired",
        }),
      },
    });

    await expect(() =>
      refreshToken("bad", mockConfigs.clio, "clio")
    ).rejects.toThrow(/Refresh token expired/);
  });
});
