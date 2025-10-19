import { describe, it, expect, beforeEach, vi } from 'vitest';
import { oAuthTokensAreValid } from '../../src/utils';
import { useOAuthRegistry } from '../../src/index';
import { createMockEvent } from '../utils';
import { getCookie } from 'h3';

// Mock getCookie
vi.mock('h3', async () => {
  const actual = await vi.importActual<typeof import('h3')>('h3');
  return {
    ...actual,
    getCookie: vi.fn(),
  };
});

const mockedGetCookie = getCookie as unknown as ReturnType<typeof vi.fn>;

describe('oAuthTokensAreValid - No Refresh Token Support', () => {
  const mockEncryptionKey =
    'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789';
  const now = Math.floor(Date.now() / 1000);

  let registerOAuthProvider: ReturnType<typeof useOAuthRegistry>['registerOAuthProvider'];

  beforeEach(() => {
    vi.clearAllMocks();
    process.env.H3_OAUTH_ENCRYPTION_KEY = mockEncryptionKey;
    const registry = useOAuthRegistry(mockEncryptionKey);
    registerOAuthProvider = registry.registerOAuthProvider;
  });

  describe('when provider does not issue refresh tokens', () => {
    it('should return valid status when access token is not expired (clio provider - no special fields)', async () => {
      const futureExpiry = now + 3600; // 1 hour from now
      const mockEvent = createMockEvent();

      // Clio has no provider-specific fields, making it simpler to test
      mockedGetCookie.mockImplementation((_, key) => {
        if (key === 'clio_access_token') return 'test_access_token';
        if (key === 'clio_access_token_expires_at') return String(futureExpiry);
        // No refresh token!
        return undefined;
      });

      registerOAuthProvider('clio', {
        clientId: 'test-client-id',
        clientSecret: 'test-client-secret',
        redirectUri: 'http://localhost:3000/callback',
        tokenEndpoint: 'https://app.clio.com/oauth/token',
        authorizeEndpoint: 'https://app.clio.com/oauth/authorize',
        scopes: ['read'],
      });

      const result = await oAuthTokensAreValid(mockEvent, 'clio');

      expect(result).toEqual({
        tokens: {
          access_token: 'test_access_token',
          refresh_token: undefined,
          expires_in: futureExpiry,
        },
        status: 'valid',
      });
    });

    it('should return valid status with azure even without refresh token (when all provider fields present)', async () => {
      const futureExpiry = now + 3600;
      const mockEvent = createMockEvent();

      mockedGetCookie.mockImplementation((_, key) => {
        if (key === 'azure_access_token') return 'test_access_token';
        if (key === 'azure_access_token_expires_at') return String(futureExpiry);
        if (key === 'azure_ext_expires_at') return String(futureExpiry + 120); // Azure-specific field
        // No refresh token!
        return undefined;
      });

      registerOAuthProvider('azure', {
        clientId: 'test-client-id',
        clientSecret: 'test-client-secret',
        redirectUri: 'http://localhost:3000/callback',
        tokenEndpoint: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
        authorizeEndpoint: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
        scopes: ['openid'],
      });

      const result = await oAuthTokensAreValid(mockEvent, 'azure');

      expect(result).toMatchObject({
        status: 'valid',
        tokens: expect.objectContaining({
          access_token: 'test_access_token',
          refresh_token: undefined,
        }),
      });
    });

    it('should return false when access token is expired and no refresh token exists', async () => {
      const pastExpiry = now - 3600; // 1 hour ago
      const mockEvent = createMockEvent();

      mockedGetCookie.mockImplementation((_, key) => {
        if (key === 'clio_access_token') return 'test_access_token';
        if (key === 'clio_access_token_expires_at') return String(pastExpiry);
        // No refresh token to renew!
        return undefined;
      });

      registerOAuthProvider('clio', {
        clientId: 'test-client-id',
        clientSecret: 'test-client-secret',
        redirectUri: 'http://localhost:3000/callback',
        tokenEndpoint: 'https://app.clio.com/oauth/token',
        authorizeEndpoint: 'https://app.clio.com/oauth/authorize',
        scopes: ['read'],
      });

      const result = await oAuthTokensAreValid(mockEvent, 'clio');

      expect(result).toBe(false);
    });

    it('should return false when access token is missing entirely', async () => {
      const mockEvent = createMockEvent();

      mockedGetCookie.mockImplementation(() => undefined);

      registerOAuthProvider('clio', {
        clientId: 'test-client-id',
        clientSecret: 'test-client-secret',
        redirectUri: 'http://localhost:3000/callback',
        tokenEndpoint: 'https://app.clio.com/oauth/token',
        authorizeEndpoint: 'https://app.clio.com/oauth/authorize',
        scopes: ['read'],
      });

      const result = await oAuthTokensAreValid(mockEvent, 'clio');

      expect(result).toBe(false);
    });

    it('should return false when expiry info is missing', async () => {
      const mockEvent = createMockEvent();

      mockedGetCookie.mockImplementation((_, key) => {
        if (key === 'clio_access_token') return 'test_access_token';
        // No expiry info!
        return undefined;
      });

      registerOAuthProvider('clio', {
        clientId: 'test-client-id',
        clientSecret: 'test-client-secret',
        redirectUri: 'http://localhost:3000/callback',
        tokenEndpoint: 'https://app.clio.com/oauth/token',
        authorizeEndpoint: 'https://app.clio.com/oauth/authorize',
        scopes: ['read'],
      });

      const result = await oAuthTokensAreValid(mockEvent, 'clio');

      expect(result).toBe(false);
    });
  });

  describe('when provider does issue refresh tokens', () => {
    it('should attempt refresh when access token is expired and refresh token exists', async () => {
      const pastExpiry = now - 3600; // 1 hour ago
      const mockEvent = createMockEvent();

      // Create a properly encrypted refresh token using the actual encryption
      const { createEncryption } = await import('../../src/utils/encryption');
      const { encrypt } = createEncryption(mockEncryptionKey);
      const encryptedToken = await encrypt('test_refresh_token');

      mockedGetCookie.mockImplementation((_, key) => {
        if (key === 'clio_access_token') return 'test_access_token';
        if (key === 'clio_access_token_expires_at') return String(pastExpiry);
        if (key === 'clio_refresh_token') return encryptedToken;
        return undefined;
      });

      registerOAuthProvider('clio', {
        clientId: 'test-client-id',
        clientSecret: 'test-client-secret',
        redirectUri: 'http://localhost:3000/callback',
        tokenEndpoint: 'https://app.clio.com/oauth/token',
        authorizeEndpoint: 'https://app.clio.com/oauth/authorize',
        scopes: ['read'],
      });

      const result = await oAuthTokensAreValid(mockEvent, 'clio');

      // Should return expired status with tokens for refresh
      expect(result).toMatchObject({
        status: 'expired',
        tokens: expect.objectContaining({
          access_token: 'test_access_token',
          refresh_token: 'test_refresh_token',
        }),
      });
    });

    it('should decrypt refresh token when access token is still valid', async () => {
      const futureExpiry = now + 3600; // 1 hour from now
      const mockEvent = createMockEvent();

      // Create a properly encrypted refresh token using the actual encryption
      const { createEncryption } = await import('../../src/utils/encryption');
      const { encrypt } = createEncryption(mockEncryptionKey);
      const encryptedToken = await encrypt('test_refresh_token');

      mockedGetCookie.mockImplementation((_, key) => {
        if (key === 'clio_access_token') return 'test_access_token';
        if (key === 'clio_access_token_expires_at') return String(futureExpiry);
        if (key === 'clio_refresh_token') return encryptedToken;
        return undefined;
      });

      registerOAuthProvider('clio', {
        clientId: 'test-client-id',
        clientSecret: 'test-client-secret',
        redirectUri: 'http://localhost:3000/callback',
        tokenEndpoint: 'https://app.clio.com/oauth/token',
        authorizeEndpoint: 'https://app.clio.com/oauth/authorize',
        scopes: ['read'],
      });

      const result = await oAuthTokensAreValid(mockEvent, 'clio');

      expect(result).toMatchObject({
        status: 'valid',
        tokens: expect.objectContaining({
          access_token: 'test_access_token',
          refresh_token: 'test_refresh_token',
        }),
      });
    });
  });

  describe('edge cases', () => {
    it('should handle mycase provider (another simple provider)', async () => {
      const futureExpiry = now + 3600;
      const mockEvent = createMockEvent();

      // MyCase is another simple provider with no special fields
      mockedGetCookie.mockImplementation((_, key) => {
        if (key === 'mycase_access_token') return 'test_access_token';
        if (key === 'mycase_access_token_expires_at') return String(futureExpiry);
        // No refresh token exists
        return undefined;
      });

      registerOAuthProvider('mycase', {
        clientId: 'test-client-id',
        clientSecret: 'test-client-secret',
        redirectUri: 'http://localhost:3000/callback',
        tokenEndpoint: 'https://api.mycase.com/oauth/token',
        authorizeEndpoint: 'https://api.mycase.com/oauth/authorize',
        scopes: ['read'],
      });

      const result = await oAuthTokensAreValid(mockEvent, 'mycase');

      // Should succeed for mycase even without refresh token
      expect(result).toMatchObject({
        status: 'valid',
        tokens: expect.objectContaining({
          access_token: 'test_access_token',
          refresh_token: undefined,
        }),
      });
    });

    it('should work with scoped/instance providers without refresh tokens', async () => {
      const futureExpiry = now + 3600;
      const mockEvent = createMockEvent();

      mockedGetCookie.mockImplementation((_, key) => {
        if (key === 'clio:smithlaw_access_token') return 'test_access_token';
        if (key === 'clio:smithlaw_access_token_expires_at') return String(futureExpiry);
        // No refresh token
        return undefined;
      });

      registerOAuthProvider('clio', 'smithlaw', {
        clientId: 'test-client-id',
        clientSecret: 'test-client-secret',
        redirectUri: 'http://localhost:3000/callback',
        tokenEndpoint: 'https://app.clio.com/oauth/token',
        authorizeEndpoint: 'https://app.clio.com/oauth/authorize',
        scopes: ['read'],
      });

      const result = await oAuthTokensAreValid(mockEvent, 'clio', 'smithlaw');

      expect(result).toMatchObject({
        status: 'valid',
        tokens: expect.objectContaining({
          access_token: 'test_access_token',
          refresh_token: undefined,
        }),
      });
    });
  });
});

