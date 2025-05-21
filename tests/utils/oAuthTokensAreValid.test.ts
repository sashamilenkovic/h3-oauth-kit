import { describe, it, expect, vi, beforeEach } from "vitest";
import { oAuthTokensAreValid } from "../../src/utils";
import { createMockEvent } from "../utils";
import { getCookie, setCookie } from "h3";
import { providerConfig } from "../../src/providerConfig";
import { encrypt } from "../../src/utils/encryption";
import { withEncryptedRefreshToken } from "../utils";

// 🧪 Mock getCookie before testing
vi.mock("h3", async () => {
  const actual = await vi.importActual<typeof import("h3")>("h3");
  return {
    ...actual,
    getCookie: vi.fn(),
  };
});

const mockedGetCookie = getCookie as unknown as ReturnType<typeof vi.fn>;

vi.mocked(getCookie);

const now = Math.floor(Date.now() / 1000);

const testCases = [
  {
    provider: "azure" as const,
    cookies: withEncryptedRefreshToken("azure", {
      azure_access_token: "abc",
      azure_refresh_token: "refresh",
      azure_access_token_expires_at: String(now + 60),
      azure_ext_expires_at: String(now + 120),
      azure_token_type: "Bearer",
    }),
    expected: {
      ext_expires_in: now + 120,
    },
  },
  {
    provider: "clio" as const,
    cookies: withEncryptedRefreshToken("clio", {
      clio_access_token: "abc",
      clio_refresh_token: "refresh",
      clio_access_token_expires_at: String(now + 60),
      clio_token_type: "bearer",
    }),
  },
  {
    provider: "intuit" as const,
    cookies: withEncryptedRefreshToken("intuit", {
      intuit_access_token: "abc",
      intuit_refresh_token: "refresh",
      intuit_access_token_expires_at: String(now + 60),
      intuit_refresh_token_expires_at: String(now + 60),
      intuit_token_type: "bearer",
    }),
    expected: {
      x_refresh_token_expires_in: now + 60,
    },
  },
];

describe("oAuthTokensAreValid", () => {
  beforeEach(() => {
    mockedGetCookie.mockReset();
  });

  it.each(testCases)(
    "returns valid token structure for $provider",
    async ({ provider, cookies, expected }) => {
      mockedGetCookie.mockImplementation(
        (_, key: string) => cookies[key as keyof typeof cookies]
      );

      const event = createMockEvent();
      const result = await oAuthTokensAreValid(event, provider);

      expect(result).toBeTruthy();
      expect(result).not.toBe(false);
      if (result === false) {
        throw new Error("Result is false");
      }

      expect(result.status).toBe("valid");
      expect(result.tokens).toMatchObject({
        access_token: "abc",
        refresh_token: "refresh",
        expires_in: expect.any(Number),
        ...(expected ?? {}),
      });
    }
  );

  it("returns false if required cookies are missing", async () => {
    mockedGetCookie.mockReturnValue(undefined);
    const event = createMockEvent();
    const result = await oAuthTokensAreValid(event, "clio");
    expect(result).toBe(false);
  });

  it("returns expired status if access token is expired", async () => {
    const expiredNow = String(now - 60);
    const cookies = withEncryptedRefreshToken("clio", {
      clio_access_token: "abc",
      clio_refresh_token: "refresh",
      clio_access_token_expires_at: expiredNow,
      clio_client_id: "client123",
      clio_token_type: "bearer",
    });

    mockedGetCookie.mockImplementation((_, key) => cookies[key]);

    const event = createMockEvent();
    const result = await oAuthTokensAreValid(event, "clio");

    if (result === false) throw new Error("Result is false");

    expect(result.status).toBe("expired");
  });

  it("returns false if token_type does not match expected", async () => {
    const event = createMockEvent();
    setCookie(event, "clio_access_token", "a");
    setCookie(event, "clio_refresh_token", encrypt("r")); // ✅ encrypt here
    setCookie(
      event,
      "clio_access_token_expires_at",
      `${Math.floor(Date.now() / 1000) + 3600}`
    );
    setCookie(event, "clio_token_type", "Bearer"); // should be lowercase
    setCookie(event, "clio_client_id", "abc");

    const result = await oAuthTokensAreValid(event, "clio");
    expect(result).toBe(false);
  });

  it("returns expired status if expiry is in the past", async () => {
    const expiredNow = `${Math.floor(Date.now() / 1000) - 100}`;
    const cookies = withEncryptedRefreshToken("clio", {
      clio_access_token: "a",
      clio_refresh_token: "r",
      clio_access_token_expires_at: expiredNow,
      clio_token_type: "bearer",
      clio_client_id: "123",
    });

    mockedGetCookie.mockImplementation((_, key) => cookies[key]);

    const event = createMockEvent();
    const result = await oAuthTokensAreValid(event, "clio");

    if (result === false) throw new Error("Result was false");

    expect(result.status).toBe("expired");
    expect(result.tokens).toMatchObject({
      access_token: "a",
      refresh_token: "r",
    });
  });

  it("skips unknown provider-specific field types gracefully", async () => {
    const provider = "clio" as const;
    const originalFields = providerConfig[provider].providerSpecificFields;
    providerConfig[provider].providerSpecificFields = [123 as any]; // malformed

    const cookies = withEncryptedRefreshToken(provider, {
      clio_access_token: "abc",
      clio_refresh_token: "refresh",
      clio_access_token_expires_at: String(now + 60),
      clio_token_type: "bearer",
      clio_client_id: "xyz",
    });

    mockedGetCookie.mockImplementation((_, key) => cookies[key]);

    const event = createMockEvent();
    const result = await oAuthTokensAreValid(event, provider);

    expect(result).toBeTruthy();
    if (result === false) throw new Error("Result was false");
    expect(result.status).toBe("valid");

    providerConfig[provider].providerSpecificFields = originalFields;
  });

  it("correctly reads plain string provider-specific fields", async () => {
    const provider = "clio" as const;
    const originalFields = providerConfig[provider].providerSpecificFields;
    providerConfig[provider].providerSpecificFields = ["token_type"];

    const cookies = withEncryptedRefreshToken(provider, {
      clio_access_token: "abc",
      clio_refresh_token: "refresh",
      clio_access_token_expires_at: String(now + 60),
      clio_token_type: "bearer",
    });

    mockedGetCookie.mockImplementation((_, key) => cookies[key]);

    const event = createMockEvent();
    const result = await oAuthTokensAreValid(event, provider);

    expect(result).toBeTruthy();
    if (result === false)
      throw new Error("Expected valid tokens but got false");

    expect(result.status).toBe("valid");
    expect(result.tokens.token_type).toBe("bearer");

    providerConfig[provider].providerSpecificFields = originalFields;
  });

  it("returns expired if refresh token expiry is not a number", async () => {
    const provider = "intuit" as const;
    const originalValidate =
      providerConfig[provider].validateRefreshTokenExpiry ?? false;
    providerConfig[provider].validateRefreshTokenExpiry = true;

    const cookies = withEncryptedRefreshToken(provider, {
      intuit_access_token: "abc",
      intuit_refresh_token: "refresh",
      intuit_access_token_expires_at: String(now + 60),
      intuit_refresh_token_expires_at: "not-a-number",
      intuit_token_type: "bearer",
    });

    mockedGetCookie.mockImplementation((_, key) => cookies[key]);

    const event = createMockEvent();
    const result = await oAuthTokensAreValid(event, provider);

    expect(result).toEqual({
      tokens: {
        access_token: "abc",
        refresh_token: "refresh",
        expires_in: expect.any(Number),
      },
      status: "expired",
    });

    providerConfig[provider].validateRefreshTokenExpiry = originalValidate;
  });
});
