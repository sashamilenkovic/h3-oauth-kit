import { describe, it, expect, vi, beforeEach } from "vitest";
import { defineProtectedRoute, registerOAuthProvider } from "../src";
import { createMockEvent } from "./utils";
import {
  oAuthTokensAreValid,
  refreshToken,
  setProviderCookies,
  normalizeRefreshedToken,
} from "../src/utils";

vi.mock("../src/utils", async () => {
  const actual = await vi.importActual<typeof import("../src/utils")>(
    "../src/utils"
  );
  return {
    ...actual,
    oAuthTokensAreValid: vi.fn(),
    refreshToken: vi.fn(),
    setProviderCookies: vi.fn(),
    normalizeRefreshedToken: vi.fn(),
  };
});

const mockTokensValid = vi.mocked(oAuthTokensAreValid);
const mockRefreshToken = vi.mocked(refreshToken);
const mockSetProviderCookies = vi.mocked(setProviderCookies);
const mockNormalizeRefreshedToken = vi.mocked(normalizeRefreshedToken);

describe("defineProtectedRoute (multi-provider)", () => {
  const clioConfig = {
    clientId: "clio-id",
    clientSecret: "secret",
    authorizeEndpoint: "https://clio.auth",
    tokenEndpoint: "https://clio.token",
    redirectUri: "https://myapp.com/callback",
    scopes: ["read"],
  };

  const intuitConfig = {
    clientId: "intuit-id",
    clientSecret: "secret",
    authorizeEndpoint: "https://intuit.auth",
    tokenEndpoint: "https://intuit.token",
    redirectUri: "https://myapp.com/callback",
    scopes: ["read"],
    environment: "sandbox" as const,
  };

  beforeEach(() => {
    vi.clearAllMocks();
    registerOAuthProvider("clio", clioConfig);
    registerOAuthProvider("intuit", intuitConfig);
  });

  it("supports multi-provider protection", async () => {
    const event = createMockEvent();

    mockTokensValid.mockImplementation(async (_, provider) => {
      return {
        status: "valid",
        tokens: {
          access_token: `${provider}-token`,
          refresh_token: "refresh",
          expires_in: 3600,
          token_type: "bearer",
          ...(provider === "clio"
            ? { client_id: "client-1" }
            : { realm_id: "realm-123", x_refresh_token_expires_in: 1234 }),
        },
      };
    });

    const handler = defineProtectedRoute(["clio", "intuit"], async (evt) => {
      return {
        clio: evt.context.clio_access_token,
        intuit: evt.context.intuit_access_token,
      };
    });

    const result = await handler(event);
    expect(result).toEqual({ clio: "clio-token", intuit: "intuit-token" });
  });

  it("fails if token refresh fails for any provider", async () => {
    const event = createMockEvent();

    mockTokensValid.mockImplementation(async (_, provider) => {
      return {
        status: "expired",
        tokens: {
          access_token: `${provider}-old`,
          refresh_token: "bad-refresh",
          expires_in: 0,
          token_type: "bearer",
          ...(provider === "clio"
            ? { client_id: "client-1" }
            : { realm_id: "realm-123", x_refresh_token_expires_in: 1234 }),
        },
      };
    });

    mockRefreshToken.mockResolvedValue(false);

    const handler = defineProtectedRoute(["clio", "intuit"], async () => {
      return { ok: true };
    });

    await expect(handler(event)).rejects.toMatchObject({
      statusCode: 401,
      message: expect.stringContaining("Token refresh failed"),
    });
  });

  it("refreshes expired token and updates cookies", async () => {
    const event = createMockEvent();

    mockTokensValid.mockResolvedValue({
      status: "expired",
      tokens: {
        access_token: "old-token",
        refresh_token: "valid-refresh",
        expires_in: 0,
        token_type: "bearer",
        client_id: "client-123",
      },
    });

    const refreshedToken = {
      access_token: "new-token",
      refresh_token: "valid-refresh",
      expires_in: 3600,
      token_type: "bearer" as const,
      client_id: "client-123",
      x_refresh_token_expires_in: 1234,
    };

    mockRefreshToken.mockResolvedValue({
      ...refreshedToken,
    });

    mockNormalizeRefreshedToken.mockReturnValue(refreshedToken);
    mockSetProviderCookies.mockReturnValue(refreshedToken);

    const handler = defineProtectedRoute(["clio"], async (evt) => {
      return {
        access: evt.context.clio_access_token,
      };
    });

    const result = await handler(event);
    expect(result).toEqual({ access: "new-token" });

    expect(mockRefreshToken).toHaveBeenCalled();
    expect(mockSetProviderCookies).toHaveBeenCalledWith(
      event,
      refreshedToken,
      "clio",
      undefined
    );
  });

  it("throws 401 if tokens are missing or invalid", async () => {
    const event = createMockEvent();

    // Simulate token validation failure
    mockTokensValid.mockResolvedValue(false);

    const handler = defineProtectedRoute(["clio"], async () => {
      return { ok: true };
    });

    await expect(handler(event)).rejects.toMatchObject({
      statusCode: 401,
      message: 'Missing or invalid tokens for "clio"',
    });

    // Optional: ensure refreshToken was never called
    expect(mockRefreshToken).not.toHaveBeenCalled();
  });

  it("passes cookieOptions to setProviderCookies during refresh", async () => {
    const event = createMockEvent();

    const cookieOptions = { sameSite: "lax" as const, path: "/secure" };

    mockTokensValid.mockResolvedValue({
      status: "expired",
      tokens: {
        access_token: "old-token",
        refresh_token: "valid-refresh",
        expires_in: 0,
        token_type: "bearer",
        client_id: "client-123",
      },
    });

    const refreshedToken = {
      access_token: "new-token",
      refresh_token: "valid-refresh",
      expires_in: 3600,
      token_type: "bearer" as const,
      client_id: "client-123",
      x_refresh_token_expires_in: 1234,
    };

    mockRefreshToken.mockResolvedValue(refreshedToken);
    mockNormalizeRefreshedToken.mockReturnValue(refreshedToken);
    mockSetProviderCookies.mockReturnValue(refreshedToken);

    const handler = defineProtectedRoute(
      ["clio"],
      async (evt) => {
        return { token: evt.context.clio_access_token };
      },
      { cookieOptions }
    );

    const result = await handler(event);

    expect(result).toEqual({ token: "new-token" });

    expect(mockSetProviderCookies).toHaveBeenCalledWith(
      event,
      refreshedToken,
      "clio",
      cookieOptions // <- this is the new assertion
    );
  });
});
