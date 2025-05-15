import type { OAuthProviderTokenMap } from "../../src/types";
import { describe, it, expect } from "vitest";
import { preserveFields } from "../../src/utils";

describe("preserveFields", () => {
  it("preserves specific fields from an Azure token", () => {
    const fullToken: OAuthProviderTokenMap["azure"] = {
      access_token: "abc",
      refresh_token: "ref",
      expires_in: 3600,
      token_type: "Bearer",
      ext_expires_in: 7200,
      scope: "user.read",
      id_token: "id_token",
    };

    const result = preserveFields("azure", fullToken, ["ext_expires_in"]);

    expect(result).toEqual({ ext_expires_in: 7200 });
  });

  it("preserves multiple fields from an Intuit token", () => {
    const fullToken: OAuthProviderTokenMap["intuit"] = {
      access_token: "abc",
      refresh_token: "ref",
      expires_in: 3600,
      token_type: "bearer",
      realm_id: "realm123",
      x_refresh_token_expires_in: 86400,
    };

    const result = preserveFields("intuit", fullToken, [
      "realm_id",
      "x_refresh_token_expires_in",
    ]);

    expect(result).toEqual({
      realm_id: "realm123",
      x_refresh_token_expires_in: 86400,
    });
  });

  it("returns an empty object if no fields are preserved", () => {
    const fullToken: OAuthProviderTokenMap["clio"] = {
      access_token: "abc",
      refresh_token: "ref",
      expires_in: 3600,
      token_type: "bearer",
      client_id: "client123",
    };

    const result = preserveFields("clio", fullToken, []);

    expect(result).toEqual({});
  });
});
