import { describe, it, expect, vi, afterEach, beforeAll } from 'vitest';
import { useOAuthRegistry, getOAuthProviderConfig } from '../../src/index'; // adjust path as needed

describe('Encryption utils', () => {
  let config: ReturnType<typeof getOAuthProviderConfig>;

  beforeAll(() => {
    // Use a fixed test key for deterministic encryption in tests
    const { registerOAuthProvider } = useOAuthRegistry('a'.repeat(64));
    registerOAuthProvider('clio', {
      clientId: 'test',
      clientSecret: 'test',
      authorizeEndpoint: 'test',
      tokenEndpoint: 'test',
      redirectUri: 'test',
      scopes: ['test'],
    });
    config = getOAuthProviderConfig('clio');
  });

  it('encrypts and decrypts a string correctly', async () => {
    const originalText = 'super-secret-token';
    const encrypted = await config.encrypt(originalText);
    const decrypted = await config.decrypt(encrypted);

    expect(typeof encrypted).toBe('string');
    expect(encrypted).not.toBe(originalText); // Should be encrypted
    expect(decrypted).toBe(originalText); // Should match original
  });

  it('throws an error when decrypting malformed input', async () => {
    await expect(config.decrypt('not:valid:format')).rejects.toThrow();
  });

  it('throws if IV or ciphertext is invalid hex', async () => {
    await expect(config.decrypt('zzzz:nothex')).rejects.toThrow();
  });
});

describe('Encryption module initialization', () => {
  const originalEnvKey = process.env.H3_OAUTH_ENCRYPTION_KEY;

  afterEach(() => {
    if (originalEnvKey !== undefined) {
      process.env.H3_OAUTH_ENCRYPTION_KEY = originalEnvKey;
    } else {
      delete process.env.H3_OAUTH_ENCRYPTION_KEY;
    }
    vi.resetModules();
  });

  it('accepts valid 64-character hex key', async () => {
    process.env.H3_OAUTH_ENCRYPTION_KEY = 'a'.repeat(64); // 64 'a' characters
    vi.resetModules();
    await expect(import('../../src/utils/encryption')).resolves.toBeDefined();
  });
});
