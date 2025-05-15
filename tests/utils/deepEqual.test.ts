import { describe, it, expect } from "vitest";
import { deepEqual } from "../../src/utils";

describe("deepEqual", () => {
  it("returns true for identical primitives", () => {
    expect(deepEqual(1, 1)).toBe(true);
    expect(deepEqual("hello", "hello")).toBe(true);
    expect(deepEqual(true, true)).toBe(true);
    expect(deepEqual(null, null)).toBe(true);
  });

  it("returns false for different primitives", () => {
    expect(deepEqual(1, 2)).toBe(false);
    expect(deepEqual("hello", "world")).toBe(false);
    expect(deepEqual(true, false)).toBe(false);
    expect(deepEqual(null, undefined)).toBe(false);
  });

  it("returns true for deeply equal objects", () => {
    const a = { foo: "bar", baz: [1, 2, 3] };
    const b = { foo: "bar", baz: [1, 2, 3] };
    expect(deepEqual(a, b)).toBe(true);
  });

  it("returns false for objects with different values", () => {
    const a = { foo: "bar", baz: [1, 2, 3] };
    const b = { foo: "bar", baz: [1, 2, 4] };
    expect(deepEqual(a, b)).toBe(false);
  });

  it("returns false for objects with different keys", () => {
    const a = { foo: "bar" };
    const b = { foo: "bar", extra: true };
    expect(deepEqual(a, b)).toBe(false);
  });

  it("returns true for deeply equal arrays", () => {
    expect(deepEqual([1, 2, { a: "x" }], [1, 2, { a: "x" }])).toBe(true);
  });

  it("returns false for arrays with different contents", () => {
    expect(deepEqual([1, 2, { a: "x" }], [1, 2, { a: "y" }])).toBe(false);
  });

  it("returns false if types don't match", () => {
    // @ts-expect-error - we want to test the type guard
    expect(deepEqual(123, "123")).toBe(false);
    expect(deepEqual([], {})).toBe(false);
    expect(deepEqual({}, null)).toBe(false);
  });

  it("returns false for different array lengths", () => {
    expect(deepEqual([1, 2], [1, 2, 3])).toBe(false);
  });

  it("returns false if nested structure is different", () => {
    const a = { a: { b: { c: "x" } } };
    const b = { a: { b: { c: "y" } } };
    expect(deepEqual(a, b)).toBe(false);
  });

  it("returns false when second object is missing a key", () => {
    const a = { foo: "bar", baz: 1 };
    const b = { foo: "bar" }; // missing `baz`

    expect(deepEqual(a, b)).toBe(false);
  });

  it("returns false if a key in A is missing from B, even if lengths match", () => {
    const a = { foo: "bar" };
    const b = Object.create(null); // no prototype, so `in` check works accurately
    // key is not in b at all

    expect(deepEqual(a, b)).toBe(false);
  });

  it("returns false if key exists in a but not in b (manual Object)", () => {
    const a = { foo: "bar" };
    const b = {}; // has no 'foo'

    // Manually set the same number of keys (trick TS)
    Object.defineProperty(b, "bar", {
      value: "baz",
      enumerable: true,
    });

    expect(deepEqual(a, b)).toBe(false);
  });
});
