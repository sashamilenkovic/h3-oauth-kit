import { describe, it, expect, vi, afterEach } from 'vitest';
import { encrypt, decrypt } from '../../src/utils/encryption';

describe('Encryption utils', () => {
  it('encrypts and decrypts a string correctly', () => {
    const originalText = 'super-secret-token';
    const encrypted = encrypt(originalText);
    const decrypted = decrypt(encrypted);

    expect(typeof encrypted).toBe('string');
    expect(encrypted).not.toBe(originalText); // Should be encrypted
    expect(decrypted).toBe(originalText); // Should match original
  });

  it('throws an error when decrypting malformed input', () => {
    expect(() => decrypt('not:valid:format')).toThrow();
  });

  it('throws if IV or ciphertext is invalid hex', () => {
    expect(() => decrypt('zzzz:nothex')).toThrow();
  });
});

describe('Encryption module initialization', () => {
  const originalEnvKey = process.env.H3_OAUTH_ENCRYPTION_KEY;

  afterEach(() => {
    // Restore original environment variable
    if (originalEnvKey) {
      process.env.H3_OAUTH_ENCRYPTION_KEY = originalEnvKey;
    } else {
      delete process.env.H3_OAUTH_ENCRYPTION_KEY;
    }

    // Clear module cache to allow re-importing with different env vars
    vi.resetModules();
  });

  it('throws error when H3_OAUTH_ENCRYPTION_KEY is not set', async () => {
    // Remove the environment variable
    delete process.env.H3_OAUTH_ENCRYPTION_KEY;

    // Clear module cache and re-import to trigger initialization
    vi.resetModules();

    await expect(async () => {
      await import('../../src/utils/encryption');
    }).rejects.toThrow(
      '[h3-oauth-kit] H3_OAUTH_ENCRYPTION_KEY must be a 64-character hex string (32 bytes).',
    );
  });

  it('throws error when H3_OAUTH_ENCRYPTION_KEY has wrong length', async () => {
    // Set an invalid key (too short)
    process.env.H3_OAUTH_ENCRYPTION_KEY = 'abc123'; // Only 6 characters, needs 64

    // Clear module cache and re-import to trigger initialization
    vi.resetModules();

    await expect(async () => {
      await import('../../src/utils/encryption');
    }).rejects.toThrow(
      '[h3-oauth-kit] H3_OAUTH_ENCRYPTION_KEY must be a 64-character hex string (32 bytes).',
    );
  });

  it('throws error when H3_OAUTH_ENCRYPTION_KEY is empty string', async () => {
    // Set empty string
    process.env.H3_OAUTH_ENCRYPTION_KEY = '';

    // Clear module cache and re-import to trigger initialization
    vi.resetModules();

    await expect(async () => {
      await import('../../src/utils/encryption');
    }).rejects.toThrow(
      '[h3-oauth-kit] H3_OAUTH_ENCRYPTION_KEY must be a 64-character hex string (32 bytes).',
    );
  });

  it('accepts valid 64-character hex key', async () => {
    // Set a valid 64-character hex key
    process.env.H3_OAUTH_ENCRYPTION_KEY = 'a'.repeat(64); // 64 'a' characters

    // Clear module cache and re-import to trigger initialization
    vi.resetModules();

    // Should not throw - just await the import directly
    await expect(import('../../src/utils/encryption')).resolves.toBeDefined();
  });
});
