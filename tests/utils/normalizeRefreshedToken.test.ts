import { describe, it, expect } from "vitest";
import { normalizeRefreshedToken } from "../../src/utils";
import type {
  OAuthProviderTokenMap,
  RefreshTokenResponse,
} from "../../src/types";

describe("normalizeRefreshedToken", () => {
  it("preserves ext_expires_in for azure", () => {
    const previous: OAuthProviderTokenMap["azure"] = {
      access_token: "old_access",
      refresh_token: "old_refresh",
      expires_in: 3600,
      token_type: "Bearer",
      ext_expires_in: 7200,
      scope: "user.read",
      id_token: "id_token",
    };

    const refreshed: RefreshTokenResponse<"azure"> = {
      access_token: "new_access",
      expires_in: 1800,
      token_type: "Bearer",
      refresh_token: "new_refresh",
      ext_expires_in: 7200,
    };

    const result = normalizeRefreshedToken("azure", refreshed, previous);

    expect(result).toEqual({
      access_token: "new_access",
      refresh_token: "new_refresh",
      expires_in: 1800,
      token_type: "Bearer",
      ext_expires_in: 7200,
    });
  });

  it("preserves client_id for clio", () => {
    const previous: OAuthProviderTokenMap["clio"] = {
      access_token: "a",
      refresh_token: "r",
      expires_in: 1000,
      token_type: "bearer",
      client_id: "client-abc",
    };

    const refreshed: RefreshTokenResponse<"clio"> = {
      access_token: "z",
      expires_in: 3000,
      token_type: "bearer",
    };

    const result = normalizeRefreshedToken("clio", refreshed, previous);

    expect(result).toEqual({
      access_token: "z",
      refresh_token: "r",
      expires_in: 3000,
      token_type: "bearer",
    });
  });

  it("preserves realm_id and x_refresh_token_expires_in for intuit", () => {
    const previous: OAuthProviderTokenMap["intuit"] = {
      access_token: "aaa",
      refresh_token: "bbb",
      expires_in: 3600,
      token_type: "bearer",
      x_refresh_token_expires_in: 9999,
      realm_id: "realm-1",
    };

    const refreshed: RefreshTokenResponse<"intuit"> = {
      access_token: "ccc",
      expires_in: 1800,
      token_type: "bearer",
      refresh_token: "ddd",
      x_refresh_token_expires_in: 9999,
    };

    const result = normalizeRefreshedToken("intuit", refreshed, previous);

    expect(result).toEqual({
      access_token: "ccc",
      refresh_token: "ddd",
      expires_in: 1800,
      token_type: "bearer",
      x_refresh_token_expires_in: 9999,
    });
  });

  it("ensures refresh_token is preserved if missing in refreshed", () => {
    const previous: OAuthProviderTokenMap["clio"] = {
      access_token: "old",
      refresh_token: "should-be-preserved",
      expires_in: 1000,
      token_type: "bearer",
      client_id: "client-abc",
    };

    const refreshed: RefreshTokenResponse<"clio"> = {
      access_token: "new",
      expires_in: 2000,
      token_type: "bearer",
    };

    const result = normalizeRefreshedToken("clio", refreshed, previous);

    expect(result.refresh_token).toBe("should-be-preserved");
  });
});
