import { describe, it, expect, vi, beforeEach } from "vitest";
import { handleOAuthCallback, registerOAuthProvider } from "../src";
import { createMockEvent } from "./utils";
import { getCookie, getQuery, sendRedirect } from "h3";
import { ofetch } from "ofetch";

vi.mock("h3", async () => {
  const actual = await vi.importActual<typeof import("h3")>("h3");
  return {
    ...actual,
    getQuery: vi.fn(),
    sendRedirect: vi.fn(),
    setCookie: vi.fn(),
    getCookie: vi.fn(),
    deleteCookie: vi.fn(),
    createError: actual.createError,
  };
});

vi.mock("ofetch", () => ({
  ofetch: vi.fn(),
}));

const mockGetQuery = getQuery as ReturnType<typeof vi.fn>;
const mockSendRedirect = sendRedirect as ReturnType<typeof vi.fn>;
const mockOfetch = ofetch as unknown as ReturnType<typeof vi.fn>;

const mockGetCookie = vi.mocked(getCookie);
const stateValue = JSON.stringify({ foo: "bar" });

function mockOAuthStateCookie(provider: string, stateValue: string) {
  mockGetCookie.mockImplementation((_, key) =>
    key === `${provider}_oauth_state` ? stateValue : undefined
  );
}

describe("handleOAuthCallback", () => {
  const config = {
    clientId: "test-client-id",
    clientSecret: "test-secret",
    tokenEndpoint: "https://example.com/token",
    authorizeEndpoint: "https://example.com/auth",
    redirectUri: "https://myapp.com/callback",
    scopes: ["read", "write"],
  };

  beforeEach(() => {
    vi.clearAllMocks();
    registerOAuthProvider("clio", config);
  });

  it("returns tokens, state, and providerMetadata when redirect is false", async () => {
    const event = createMockEvent();
    mockGetQuery.mockReturnValue({
      code: "auth-code",
      state: JSON.stringify({ foo: "bar" }),
    });

    mockOfetch.mockResolvedValue({
      access_token: "abc",
      refresh_token: "def",
      expires_in: 3600,
      token_type: "bearer",
      client_id: "client-xyz",
    });

    mockOAuthStateCookie("clio", stateValue); // 👈 use helper here

    const result = await handleOAuthCallback(
      "clio",
      { redirect: false },
      event
    );

    expect(result.tokens.access_token).toBe("abc");
    expect(result.state).toEqual({ foo: "bar" });
    expect(result.callbackQueryData).toBeDefined();
  });

  it("performs redirect when redirect is true", async () => {
    const event = createMockEvent();
    mockGetQuery.mockReturnValue({
      code: "auth-code",
      state: JSON.stringify({ foo: "bar" }),
    });

    mockOfetch.mockResolvedValue({
      access_token: "abc",
      refresh_token: "def",
      expires_in: 3600,
      token_type: "bearer",
      client_id: "client-xyz",
    });

    mockOAuthStateCookie("clio", stateValue); // 👈 use helper here

    await handleOAuthCallback("clio", { redirect: true }, event);

    expect(mockSendRedirect).toHaveBeenCalledWith(event, "/", 302);
  });

  it("throws error if code is missing", async () => {
    const event = createMockEvent();
    mockGetQuery.mockReturnValue({ state: "abc" });

    await expect(
      handleOAuthCallback("clio", { redirect: false }, event)
    ).rejects.toMatchObject({
      statusCode: 400,
      statusMessage: "Authorization code missing in callback URL",
    });
  });

  it("throws error if state is missing", async () => {
    const event = createMockEvent();
    mockGetQuery.mockReturnValue({ code: "abc" });

    await expect(
      handleOAuthCallback("clio", { redirect: false }, event)
    ).rejects.toMatchObject({
      statusCode: 400,
      statusMessage: "State missing in callback URL",
    });
  });

  it("returns an event handler when called without event", () => {
    const handler = handleOAuthCallback("clio");
    expect(typeof handler).toBe("function");
  });
});
