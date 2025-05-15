import { describe, it, expect } from "vitest";
import { parseOAuthCallbackQuery } from "../../src/utils";
import { createMockEvent } from "../utils";

describe("extractProviderMetadata", () => {
  it("returns full metadata for intuit", () => {
    const event = createMockEvent({
      query: {
        code: "abc",
        state: "xyz",
        error: "access_denied",
        error_description: "User denied access",
        realmId: "1234567890",
      },
    });

    const meta = parseOAuthCallbackQuery(event, "intuit");

    expect(meta).toEqual({
      code: "abc",
      state: "xyz",
      error: "access_denied",
      error_description: "User denied access",
      realmId: "1234567890",
    });
  });

  it("omits undefined metadata for intuit", () => {
    const event = createMockEvent({
      query: {
        state: "xyz",
        realmId: "123",
      },
    });

    const meta = parseOAuthCallbackQuery(event, "intuit");

    expect(meta).toEqual({
      state: "xyz",
      realmId: "123",
    });
  });

  it("returns only defined standard fields for clio", () => {
    const event = createMockEvent({
      query: {
        code: "abc",
        error_description: "invalid_scope",
      },
    });

    const meta = parseOAuthCallbackQuery(event, "clio");

    expect(meta).toEqual({
      code: "abc",
      error_description: "invalid_scope",
    });
  });

  it("returns empty object if nothing present", () => {
    const event = createMockEvent();

    const meta = parseOAuthCallbackQuery(event, "clio");

    expect(meta).toEqual({});
  });
});
