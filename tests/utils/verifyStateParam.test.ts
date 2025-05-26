import { describe, expect, it } from "vitest";
import { verifyStateParam } from "../../src/utils";
import { createMockEvent } from "../utils";

describe("verifyStateParam", () => {
  it("throws if CSRF cookie is missing", () => {
    const event = createMockEvent(); // No cookies set

    const parsedState = {
      csrf: "abc123",
      providerKey: "clio",
    };

    expect(() => verifyStateParam(event, parsedState)).toThrow(/CSRF mismatch/);
  });

  it("throws if CSRF token does not match cookie", () => {
    const event = createMockEvent({
      cookieHeader: "oauth_csrf_clio=expected",
    });

    const parsedState = {
      csrf: "wrong",
      providerKey: "clio",
    };

    expect(() => verifyStateParam(event, parsedState)).toThrow(/CSRF mismatch/);
  });

  it("succeeds if CSRF matches cookie value", () => {
    const event = createMockEvent({
      cookieHeader: "oauth_csrf_clio=abc123",
    });

    const parsedState = {
      csrf: "abc123",
      providerKey: "clio",
    };

    expect(() => verifyStateParam(event, parsedState)).not.toThrow();
  });

  it("supports scoped providerKeys", () => {
    const event = createMockEvent({
      cookieHeader: "oauth_csrf_azure:tenant-a=xyz",
    });

    const parsedState = {
      csrf: "xyz",
      providerKey: "azure:tenant-a",
    };

    expect(() => verifyStateParam(event, parsedState)).not.toThrow();
  });

  it("deletes the CSRF cookie after validation", () => {
    const event = createMockEvent({
      cookieHeader: "oauth_csrf_intuit=abc123",
    });

    const parsedState = {
      csrf: "abc123",
      providerKey: "intuit",
    };

    verifyStateParam(event, parsedState);

    const setCookieHeader = event.node.res.getHeader("Set-Cookie");
    expect(setCookieHeader).toMatch(/oauth_csrf_intuit=;/);
  });
});
