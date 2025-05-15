import { describe, it, expect, vi, beforeEach } from "vitest";
import { resolveState } from "../../src/utils";
import { createMockEvent } from "../utils";
import { setCookie } from "h3";

vi.mock("h3", async () => {
  const actual = await vi.importActual<typeof import("h3")>("h3");
  return {
    ...actual,
    setCookie: vi.fn(),
  };
});

const mockedSetCookie = setCookie as unknown as ReturnType<typeof vi.fn>;

describe("resolveState", () => {
  const provider = "clio";

  beforeEach(() => {
    mockedSetCookie.mockReset();
  });

  it("uses a static string state", () => {
    const event = createMockEvent();
    const result = resolveState(event, provider, "custom-state");

    expect(result).toBe("custom-state");
    expect(mockedSetCookie).toHaveBeenCalledWith(
      event,
      "clio_oauth_state",
      "custom-state",
      expect.objectContaining({
        httpOnly: true,
        sameSite: "lax",
        secure: true,
        path: "/",
        maxAge: 300,
      })
    );
  });

  it("serializes an object to JSON", () => {
    const event = createMockEvent();
    const result = resolveState(event, provider, { from: "/dashboard" });

    expect(result).toBe(JSON.stringify({ from: "/dashboard" }));
    expect(mockedSetCookie).toHaveBeenCalledWith(
      event,
      "clio_oauth_state",
      JSON.stringify({ from: "/dashboard" }),
      expect.any(Object)
    );
  });

  it("resolves a function that returns a string", () => {
    const event = createMockEvent();
    const result = resolveState(event, provider, () => "dynamic-state");

    expect(result).toBe("dynamic-state");
    expect(mockedSetCookie).toHaveBeenCalledWith(
      event,
      "clio_oauth_state",
      "dynamic-state",
      expect.any(Object)
    );
  });

  it("resolves a function that returns an object", () => {
    const event = createMockEvent();
    const result = resolveState(event, provider, () => ({ from: "/settings" }));

    expect(result).toBe(JSON.stringify({ from: "/settings" }));
    expect(mockedSetCookie).toHaveBeenCalledWith(
      event,
      "clio_oauth_state",
      JSON.stringify({ from: "/settings" }),
      expect.any(Object)
    );
  });

  it("generates a UUID when no state is provided", () => {
    const event = createMockEvent();
    const result = resolveState(event, provider);

    expect(typeof result).toBe("string");
    expect(result).toHaveLength(36); // UUID v4 length
    expect(mockedSetCookie).toHaveBeenCalledWith(
      event,
      "clio_oauth_state",
      result,
      expect.any(Object)
    );
  });
});
