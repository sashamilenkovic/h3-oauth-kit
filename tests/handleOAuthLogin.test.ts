import { describe, it, expect, vi, beforeEach } from "vitest";
import { handleOAuthLogin, registerOAuthProvider } from "../src";
import { createMockEvent } from "./utils";

import * as utils from "../src/utils";
import { sendRedirect } from "h3";

vi.mock("h3", async () => {
  const actual = await vi.importActual<typeof import("h3")>("h3");
  return {
    ...actual,
    sendRedirect: vi.fn(),
  };
});

const mockedSendRedirect = sendRedirect as unknown as ReturnType<typeof vi.fn>;

const clioConfig = {
  clientId: "abc",
  clientSecret: "secret",
  tokenEndpoint: "https://example.com/token",
  authorizeEndpoint: "https://example.com/authorize",
  redirectUri: "https://myapp.com/callback",
  scopes: ["read", "write"],
};

describe("handleOAuthLogin", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    vi.spyOn(utils, "resolveState").mockReturnValue("mocked-state");
    vi.spyOn(utils, "buildAuthUrl").mockReturnValue(
      "https://example.com/auth?client_id=abc"
    );
  });

  it("returns URL for manual login flow", async () => {
    registerOAuthProvider("clio", clioConfig);

    const event = createMockEvent();
    const result = await handleOAuthLogin("clio", { redirect: false }, event);

    expect(result).toEqual({ url: "https://example.com/auth?client_id=abc" });
    expect(utils.resolveState).toHaveBeenCalledWith(event, "clio", undefined);
    expect(utils.buildAuthUrl).toHaveBeenCalled();
  });

  it("performs redirect when redirect is true", async () => {
    registerOAuthProvider("clio", clioConfig);

    const event = createMockEvent();
    await handleOAuthLogin("clio", { redirect: true }, event);

    expect(mockedSendRedirect).toHaveBeenCalledWith(
      event,
      "https://example.com/auth?client_id=abc",
      302
    );
  });

  it("returns EventHandler when no event provided", () => {
    registerOAuthProvider("clio", clioConfig);
    const handler = handleOAuthLogin("clio");
    expect(typeof handler).toBe("function");
  });

  it("includes custom string state in URL", async () => {
    registerOAuthProvider("clio", clioConfig);

    const event = createMockEvent();
    vi.spyOn(utils, "resolveState").mockReturnValue("custom-string");

    const result = await handleOAuthLogin(
      "clio",
      { redirect: false, state: "custom-string" },
      event
    );
    expect(result.url).toContain("client_id=abc");
    expect(utils.resolveState).toHaveBeenCalledWith(
      event,
      "clio",
      "custom-string"
    );
  });

  it("includes custom object state in URL", async () => {
    registerOAuthProvider("clio", clioConfig);

    const event = createMockEvent();
    vi.spyOn(utils, "resolveState").mockReturnValue(
      JSON.stringify({ from: "/dashboard" })
    );

    const result = await handleOAuthLogin(
      "clio",
      { redirect: false, state: { from: "/dashboard" } },
      event
    );
    expect(utils.resolveState).toHaveBeenCalledWith(event, "clio", {
      from: "/dashboard",
    });
    expect(result.url).toContain("client_id=abc");
  });

  it("throws if provider is not registered", async () => {
    const event = createMockEvent();
    await expect(() =>
      handleOAuthLogin("intuit", { redirect: false }, event)
    ).rejects.toThrow('OAuth provider "intuit" is not registered');
  });
});
