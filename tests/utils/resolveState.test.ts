import { describe, it, expect, vi, beforeEach } from "vitest";
import { resolveState } from "../../src/utils";
import { createMockEvent } from "../utils";
import { setCookie } from "h3";

// Mock `setCookie` from `h3`
vi.mock("h3", async () => {
  const actual = await vi.importActual<typeof import("h3")>("h3");
  return {
    ...actual,
    setCookie: vi.fn(),
  };
});

const mockedSetCookie = setCookie as unknown as ReturnType<typeof vi.fn>;

describe("resolveState", () => {
  const providerKey = "clio";

  beforeEach(() => {
    mockedSetCookie.mockReset();
  });

  it("encodes a CSRF-protected base64url JSON object when no user state is provided", () => {
    const event = createMockEvent();

    const encoded = resolveState(event, providerKey);

    const decoded = JSON.parse(
      Buffer.from(decodeURIComponent(encoded), "base64url").toString(),
    );

    expect(decoded).toMatchObject({
      csrf: expect.any(String),
      providerKey: "clio",
    });

    expect(decoded.csrf).toHaveLength(36); // UUID v4

    expect(mockedSetCookie).toHaveBeenCalledWith(
      event,
      "oauth_csrf_clio",
      decoded.csrf,
      expect.objectContaining({
        httpOnly: true,
        sameSite: "lax",
        secure: true,
        path: "/",
        maxAge: 300,
      }),
    );
  });

  it("includes custom static state in encoded payload", () => {
    const event = createMockEvent();

    const encoded = resolveState(event, providerKey, {
      returnTo: "/dashboard",
    });

    const decoded = JSON.parse(
      Buffer.from(decodeURIComponent(encoded), "base64url").toString(),
    );

    expect(decoded).toMatchObject({
      csrf: expect.any(String),
      providerKey: "clio",
      returnTo: "/dashboard",
    });
  });

  it("resolves userState when passed a function", () => {
    const event = createMockEvent();

    const encoded = resolveState(event, providerKey, () => ({
      from: "/settings",
    }));

    const decoded = JSON.parse(
      Buffer.from(decodeURIComponent(encoded), "base64url").toString(),
    );

    expect(decoded).toMatchObject({
      csrf: expect.any(String),
      providerKey: "clio",
      from: "/settings",
    });
  });

  it("throws if state is not an object or function", () => {
    const event = createMockEvent();

    expect(() => resolveState(event, providerKey, "not-valid" as any)).toThrow(
      /must be a plain object/,
    );
  });

  it("throws if state resolves to an array", () => {
    const event = createMockEvent();

    expect(() =>
      resolveState(event, providerKey, () => ["bad"] as any),
    ).toThrow(/must be a plain object/);
  });

  it("throws if state resolves to null", () => {
    const event = createMockEvent();

    expect(() => resolveState(event, providerKey, () => null as any)).toThrow(
      /must be a plain object/,
    );
  });
});
