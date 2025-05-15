import { describe, it, expect } from "vitest";
import { parseOAuthState } from "../../src/utils";

describe("parseOAuthState", () => {
  it("parses a valid JSON object string", () => {
    const result = parseOAuthState(
      JSON.stringify({ foo: "bar", from: "/home" })
    );
    expect(result).toEqual({ foo: "bar", from: "/home" });
  });

  it("returns empty object for invalid JSON", () => {
    const result = parseOAuthState("{ invalid json }");
    expect(result).toEqual({});
  });

  it("returns empty object for non-object JSON values", () => {
    expect(parseOAuthState("123")).toEqual({});
    expect(parseOAuthState('"just a string"')).toEqual({});
    expect(parseOAuthState("true")).toEqual({});
    expect(parseOAuthState("null")).toEqual({});
  });

  it("returns empty object for empty string", () => {
    expect(parseOAuthState("")).toEqual({});
  });

  it("returns empty object for undefined-like object (edge case)", () => {
    const result = parseOAuthState(JSON.stringify(undefined));
    expect(result).toEqual({});
  });
});
