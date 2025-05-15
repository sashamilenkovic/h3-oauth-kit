import { describe, expect, it } from "vitest";
import { verifyStateParam } from "../../src/utils";
import { createMockEvent } from "../utils";

describe("verifyStateParam", () => {
  it("throws if state is missing in cookie", () => {
    const event = createMockEvent(); // No cookies at all

    expect(() => verifyStateParam(event, "clio", "abc123")).toThrow(
      /Missing or invalid state/
    );
  });

  it("throws if state does not match", () => {
    const event = createMockEvent({
      cookieHeader: "clio_oauth_state=expected",
    });

    expect(() => verifyStateParam(event, "clio", "wrong")).toThrow(
      /State mismatch/
    );
  });

  it("succeeds if state matches", () => {
    const event = createMockEvent({
      cookieHeader: "clio_oauth_state=abc123",
    });

    expect(() => verifyStateParam(event, "clio", "abc123")).not.toThrow();
  });
});
