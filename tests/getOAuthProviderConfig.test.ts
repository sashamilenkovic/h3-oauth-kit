import type { OAuthProviderConfigMap } from "../types";

import { describe, it, expect, beforeEach } from "vitest";
import { getOAuthProviderConfig, registerOAuthProvider } from "../src";

describe("getOAuthProviderConfig", () => {
  beforeEach(async () => {
    // Clear registry between tests by resetting the module cache
    const registry = await import("../src");

    registry.providerRegistry.clear();
  });

  it("returns the registered config for a known provider", () => {
    const config: OAuthProviderConfigMap["clio"] = {
      clientId: "abc",
      clientSecret: "secret",
      tokenEndpoint: "https://example.com/token",
      authorizeEndpoint: "https://example.com/authorize",
      redirectUri: "https://myapp.com/callback",
      scopes: ["read", "write"],
    };

    registerOAuthProvider("clio", config);

    const result = getOAuthProviderConfig("clio");

    expect(result).toEqual(config);
  });

  it("throws if provider is not registered", () => {
    try {
      getOAuthProviderConfig("intuit");

      throw new Error("Expected error not thrown");
    } catch (err: any) {
      expect(err.statusCode).toBe(500);

      expect(err.statusMessage).toMatch(
        'OAuth provider "intuit" is not registered'
      );
    }
  });
});
