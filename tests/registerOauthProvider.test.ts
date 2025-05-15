import { describe, it, expect, beforeEach } from "vitest";
import { registerOAuthProvider } from "../src";
import { getOAuthProviderConfig } from "../src/index";
import type { OAuthProviderConfigMap } from "../src/types";

describe("registerOAuthProvider", () => {
  beforeEach(() => {
    // Clear registry between tests
    try {
      // HACK: access the internal providerRegistry via getOAuthProviderConfig’s cache
      (getOAuthProviderConfig as any)._registry?.clear?.();
    } catch {
      // fallback — registry is module-scoped, so this is a safety noop
    }
  });

  it("registers a provider config successfully", () => {
    const config: OAuthProviderConfigMap["clio"] = {
      clientId: "abc123",
      clientSecret: "secret",
      tokenEndpoint: "https://clio.com/oauth/token",
      authorizeEndpoint: "https://clio.com/oauth/authorize",
      redirectUri: "http://localhost/callback",
      scopes: ["activity.read", "contacts.read"],
    };

    registerOAuthProvider("clio", config);

    const stored = getOAuthProviderConfig("clio");
    expect(stored).toEqual(config);
  });

  it("overwrites an existing provider config", () => {
    const initial: OAuthProviderConfigMap["azure"] = {
      clientId: "original",
      clientSecret: "secret1",
      tokenEndpoint: "https://login.microsoftonline.com/token",
      authorizeEndpoint: "https://login.microsoftonline.com/authorize",
      redirectUri: "http://localhost/azure/callback",
      scopes: ["openid"],
      tenantId: "tenant-1",
    };

    const updated = {
      ...initial,
      clientId: "updated",
    };

    registerOAuthProvider("azure", initial);
    registerOAuthProvider("azure", updated);

    const result = getOAuthProviderConfig("azure");
    expect(result.clientId).toBe("updated");
  });
});
