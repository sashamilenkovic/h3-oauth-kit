import { describe, it, expect } from "vitest";
import { getProviderCookieKeys } from "../../src/utils";
import { providerConfig } from "../../src/providerConfig";
import type { OAuthProvider } from "../../src/types";

describe("getProviderCookieKeys", () => {
  it("returns correct keys for azure", () => {
    expect(getProviderCookieKeys("azure")).toEqual([
      "azure_access_token",
      "azure_refresh_token",
      "azure_access_token_expires_at",
      "azure_ext_expires_at",
    ]);
  });

  it("returns correct keys for clio", () => {
    expect(getProviderCookieKeys("clio")).toEqual([
      "clio_access_token",
      "clio_refresh_token",
      "clio_access_token_expires_at",
    ]);
  });

  it("returns correct keys for intuit", () => {
    expect(getProviderCookieKeys("intuit")).toEqual([
      "intuit_access_token",
      "intuit_refresh_token",
      "intuit_access_token_expires_at",
      "intuit_refresh_token_expires_at",
    ]);
  });

  it("handles string-based field correctly", () => {
    const fakeProvider = "fake" as OAuthProvider;
    providerConfig[fakeProvider] = {
      providerSpecificFields: ["custom_field"],
    } as any;

    const result = getProviderCookieKeys(fakeProvider);
    expect(result).toEqual([
      "fake_access_token",
      "fake_refresh_token",
      "fake_access_token_expires_at",
      "fake_custom_field",
    ]);
  });
});
