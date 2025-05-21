import { describe, it, expect } from "vitest";
import { encrypt, decrypt } from "../../src/utils/encryption";

describe("Encryption utils", () => {
  it("encrypts and decrypts a string correctly", () => {
    const originalText = "super-secret-token";
    const encrypted = encrypt(originalText);
    const decrypted = decrypt(encrypted);

    expect(typeof encrypted).toBe("string");
    expect(encrypted).not.toBe(originalText); // Should be encrypted
    expect(decrypted).toBe(originalText); // Should match original
  });

  it("throws an error when decrypting malformed input", () => {
    expect(() => decrypt("not:valid:format")).toThrow();
  });

  it("throws if IV or ciphertext is invalid hex", () => {
    expect(() => decrypt("zzzz:nothex")).toThrow();
  });
});
