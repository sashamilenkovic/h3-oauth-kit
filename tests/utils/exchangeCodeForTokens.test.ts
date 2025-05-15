import type {
  OAuthProviderTokenMap,
  OAuthProviderConfigMap,
} from "../../src/types";
import type { Mock } from "vitest";

import { describe, it, expect, vi } from "vitest";
import { exchangeCodeForTokens } from "../../src/utils";

// Mock ofetch before importing it
vi.mock("ofetch", () => ({
  ofetch: vi.fn(),
}));

import { ofetch } from "ofetch";

describe("exchangeCodeForTokens", () => {
  const mockConfig: OAuthProviderConfigMap["clio"] = {
    clientId: "my-client-id",
    clientSecret: "my-client-secret",
    redirectUri: "https://myapp.com/oauth/callback",
    authorizeEndpoint: "https://clio.com/oauth/authorize",
    tokenEndpoint: "https://clio.com/oauth/token",
    scopes: ["profile", "openid"],
  };

  const fakeTokenResponse: OAuthProviderTokenMap["clio"] = {
    access_token: "abc123",
    token_type: "bearer",
    expires_in: 3600,
    client_id: "client-xyz",
  };

  it("sends correct request and returns tokens", async () => {
    (ofetch as unknown as Mock).mockResolvedValueOnce(fakeTokenResponse);

    const tokens = await exchangeCodeForTokens(
      "auth-code-123",
      mockConfig,
      "clio"
    );

    expect(ofetch).toHaveBeenCalledWith("https://clio.com/oauth/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: expect.stringContaining("code=auth-code-123"),
    });

    expect(tokens).toEqual(fakeTokenResponse);
  });

  it("throws an H3 error if request fails", async () => {
    const mockError = {
      response: {
        status: 401,
        json: async () => ({
          error: "invalid_client",
          error_description: "Client ID not found",
        }),
      },
    };

    (ofetch as unknown as Mock).mockRejectedValueOnce(mockError);

    await expect(() =>
      exchangeCodeForTokens("bad-code", mockConfig, "clio")
    ).rejects.toThrow(/Client ID not found/);
  });
});
