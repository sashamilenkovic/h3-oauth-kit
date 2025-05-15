import { describe, it, expect } from "vitest";
import { omitUndefinedValues } from "../../src/utils";

describe("omitUndefinedValues", () => {
  it("removes keys with undefined values", () => {
    const input = {
      a: 1,
      b: undefined,
      c: "test",
      d: undefined,
    };

    const result = omitUndefinedValues(input);

    expect(result).toEqual({
      a: 1,
      c: "test",
    });
  });

  it("returns an empty object if all values are undefined", () => {
    const input = {
      a: undefined,
      b: undefined,
    };

    const result = omitUndefinedValues(input);

    expect(result).toEqual({});
  });

  it("returns the same object if no values are undefined", () => {
    const input = {
      x: true,
      y: 42,
      z: null,
    };

    const result = omitUndefinedValues(input);

    expect(result).toEqual(input);
  });

  it("preserves key order and types", () => {
    const input = {
      alpha: "hello",
      beta: undefined,
      gamma: 0,
      delta: false,
    };

    const result = omitUndefinedValues(input);

    expect(result).toEqual({
      alpha: "hello",
      gamma: 0,
      delta: false,
    });
  });
});
