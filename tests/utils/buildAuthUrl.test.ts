import { describe, it, expect } from "vitest";
import { buildAuthUrl } from "../../src/utils";

describe("buildAuthUrl", () => {
  const base = {
    authorizeEndpoint: "https://example.com/oauth/authorize",
    clientId: "my-client-id",
    redirectUri: "https://myapp.com/callback",
    scopes: ["openid", "email", "profile"],
    state: "abc123",
  };

  it("constructs a valid OAuth authorization URL", () => {
    const url = buildAuthUrl(base);
    const parsed = new URL(url);

    expect(parsed.origin).toBe("https://example.com");
    expect(parsed.pathname).toBe("/oauth/authorize");

    expect(parsed.searchParams.get("client_id")).toBe(base.clientId);
    expect(parsed.searchParams.get("redirect_uri")).toBe(base.redirectUri);
    expect(parsed.searchParams.get("response_type")).toBe("code");
    expect(parsed.searchParams.get("scope")).toBe("openid email profile");
    expect(parsed.searchParams.get("state")).toBe(base.state);
  });

  it("handles scopes with special characters", () => {
    const url = buildAuthUrl({
      ...base,
      scopes: ["email", "custom:scope/with-slash"],
    });

    const scopeParam = new URL(url).searchParams.get("scope");
    expect(scopeParam).toBe("email custom:scope/with-slash");
  });

  it("preserves existing query params in base URL", () => {
    const url = buildAuthUrl({
      ...base,
      authorizeEndpoint: "https://example.com/oauth/authorize?prompt=consent",
    });

    const parsed = new URL(url);
    expect(parsed.searchParams.get("prompt")).toBe("consent");
    expect(parsed.searchParams.get("client_id")).toBe(base.clientId);
  });

  describe("PKCE support", () => {
    it("includes code_challenge and code_challenge_method when provided", () => {
      const url = buildAuthUrl({
        ...base,
        codeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        codeChallengeMethod: "S256",
      });

      const parsed = new URL(url);
      expect(parsed.searchParams.get("code_challenge")).toBe(
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
      );
      expect(parsed.searchParams.get("code_challenge_method")).toBe("S256");
    });

    it("does not include PKCE params when not provided", () => {
      const url = buildAuthUrl(base);

      const parsed = new URL(url);
      expect(parsed.searchParams.has("code_challenge")).toBe(false);
      expect(parsed.searchParams.has("code_challenge_method")).toBe(false);
    });

    it("does not include PKCE params when only challenge is provided", () => {
      const url = buildAuthUrl({
        ...base,
        codeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
      });

      const parsed = new URL(url);
      expect(parsed.searchParams.has("code_challenge")).toBe(false);
      expect(parsed.searchParams.has("code_challenge_method")).toBe(false);
    });

    it("does not include PKCE params when only method is provided", () => {
      const url = buildAuthUrl({
        ...base,
        codeChallengeMethod: "S256",
      });

      const parsed = new URL(url);
      expect(parsed.searchParams.has("code_challenge")).toBe(false);
      expect(parsed.searchParams.has("code_challenge_method")).toBe(false);
    });
  });
});
