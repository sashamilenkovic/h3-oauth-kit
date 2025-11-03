import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import {
  getClientCredentialsToken,
  clearClientCredentialsCache,
  getClientCredentialsCacheSize,
  useOAuthRegistry,
} from '../src/index';
import type { ClientCredentialsTokenResponse } from '../src/types';
import { ofetch } from 'ofetch';

// Mock ofetch
vi.mock('ofetch', () => ({
  ofetch: vi.fn(),
}));

describe('Client Credentials Flow', () => {
  const mockEncryptionKey = 'a'.repeat(64);
  let registerOAuthProvider: ReturnType<
    typeof useOAuthRegistry
  >['registerOAuthProvider'];

  beforeEach(() => {
    vi.clearAllMocks();
    clearClientCredentialsCache(); // Clear cache between tests
    const registry = useOAuthRegistry(mockEncryptionKey);
    registerOAuthProvider = registry.registerOAuthProvider;
  });

  afterEach(() => {
    clearClientCredentialsCache();
  });

  describe('getClientCredentialsToken', () => {
    it('should fetch a new token from the provider', async () => {
      const mockResponse: ClientCredentialsTokenResponse = {
        access_token: 'mock_access_token_123',
        token_type: 'Bearer',
        expires_in: 3600,
        scope: 'api:read api:write',
      };

      vi.mocked(ofetch).mockResolvedValueOnce(mockResponse);

      registerOAuthProvider('azure', {
        clientId: 'test-client-id',
        clientSecret: 'test-client-secret',
        redirectUri: 'http://localhost:3000/callback',
        authorizeEndpoint: 'https://provider.com/authorize',
        tokenEndpoint: 'https://provider.com/token',
        tenantId: 'common',
        scopes: ['openid', 'profile'],
      });

      const result = await getClientCredentialsToken('azure');

      expect(result).toEqual(mockResponse);
      expect(ofetch).toHaveBeenCalledTimes(1);
      expect(ofetch).toHaveBeenCalledWith('https://provider.com/token', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Accept: 'application/json',
        },
        body: expect.any(URLSearchParams),
      });

      // Check the request body
      const callArgs = vi.mocked(ofetch).mock.calls[0];
      const body = callArgs[1]?.body as URLSearchParams;
      expect(body.get('grant_type')).toBe('client_credentials');
      expect(body.get('client_id')).toBe('test-client-id');
      expect(body.get('client_secret')).toBe('test-client-secret');
      expect(body.get('scope')).toBe('openid profile');
    });

    it('should cache tokens and reuse them if not expired', async () => {
      const mockResponse: ClientCredentialsTokenResponse = {
        access_token: 'cached_token',
        token_type: 'Bearer',
        expires_in: 3600,
      };

      vi.mocked(ofetch).mockResolvedValueOnce(mockResponse);

      registerOAuthProvider('clio', {
        clientId: 'clio-client',
        clientSecret: 'clio-secret',
        redirectUri: 'http://localhost:3000/callback',
        authorizeEndpoint: 'https://clio.com/authorize',
        tokenEndpoint: 'https://clio.com/token',
        scopes: ['api'],
      });

      // First call - should fetch from provider
      const result1 = await getClientCredentialsToken('clio');
      expect(result1.access_token).toBe('cached_token');
      expect(ofetch).toHaveBeenCalledTimes(1);

      // Second call - should use cache
      const result2 = await getClientCredentialsToken('clio');
      expect(result2.access_token).toBe('cached_token');
      expect(ofetch).toHaveBeenCalledTimes(1); // Still only 1 call

      // Verify cache size
      expect(getClientCredentialsCacheSize()).toBe(1);
    });

    it('should fetch a new token when forceRefresh is true', async () => {
      const mockResponse1: ClientCredentialsTokenResponse = {
        access_token: 'first_token',
        token_type: 'Bearer',
        expires_in: 3600,
      };

      const mockResponse2: ClientCredentialsTokenResponse = {
        access_token: 'second_token',
        token_type: 'Bearer',
        expires_in: 3600,
      };

      vi.mocked(ofetch)
        .mockResolvedValueOnce(mockResponse1)
        .mockResolvedValueOnce(mockResponse2);

      registerOAuthProvider('intuit', {
        clientId: 'intuit-client',
        clientSecret: 'intuit-secret',
        redirectUri: 'http://localhost:3000/callback',
        authorizeEndpoint: 'https://intuit.com/authorize',
        tokenEndpoint: 'https://intuit.com/token',
        environment: 'sandbox',
        scopes: ['accounting'],
      });

      // First call
      const result1 = await getClientCredentialsToken('intuit');
      expect(result1.access_token).toBe('first_token');

      // Second call with forceRefresh
      const result2 = await getClientCredentialsToken('intuit', {
        forceRefresh: true,
      });
      expect(result2.access_token).toBe('second_token');
      expect(ofetch).toHaveBeenCalledTimes(2);
    });

    it('should support custom scopes', async () => {
      const mockResponse: ClientCredentialsTokenResponse = {
        access_token: 'custom_scope_token',
        token_type: 'Bearer',
        expires_in: 3600,
      };

      vi.mocked(ofetch).mockResolvedValueOnce(mockResponse);

      registerOAuthProvider('azure', {
        clientId: 'azure-client',
        clientSecret: 'azure-secret',
        redirectUri: 'http://localhost:3000/callback',
        authorizeEndpoint: 'https://azure.com/authorize',
        tokenEndpoint: 'https://azure.com/token',
        tenantId: 'common',
        scopes: ['default-scope'],
      });

      await getClientCredentialsToken('azure', {
        scopes: ['https://graph.microsoft.com/.default'],
      });

      const callArgs = vi.mocked(ofetch).mock.calls[0];
      const body = callArgs[1]?.body as URLSearchParams;
      expect(body.get('scope')).toBe('https://graph.microsoft.com/.default');
    });

    it('should support multi-tenant configurations with instanceKey', async () => {
      const mockResponse: ClientCredentialsTokenResponse = {
        access_token: 'tenant_a_token',
        token_type: 'Bearer',
        expires_in: 3600,
      };

      vi.mocked(ofetch).mockResolvedValueOnce(mockResponse);

      // Register tenant-specific config
      registerOAuthProvider('azure', 'tenant-a', {
        clientId: 'tenant-a-client',
        clientSecret: 'tenant-a-secret',
        redirectUri: 'http://localhost:3000/callback',
        authorizeEndpoint: 'https://azure.com/tenant-a/authorize',
        tokenEndpoint: 'https://azure.com/tenant-a/token',
        tenantId: 'tenant-a',
        scopes: ['api'],
      });

      const result = await getClientCredentialsToken('azure', {
        instanceKey: 'tenant-a',
      });

      expect(result.access_token).toBe('tenant_a_token');
      expect(ofetch).toHaveBeenCalledWith(
        'https://azure.com/tenant-a/token',
        expect.any(Object),
      );
    });

    it('should throw error if provider is not registered', async () => {
      await expect(
        getClientCredentialsToken('nonexistent' as any),
      ).rejects.toThrow(
        'Provider "nonexistent" is not registered. Call registerOAuthProvider() first.',
      );
    });

    it('should throw error if token request fails', async () => {
      vi.mocked(ofetch).mockRejectedValueOnce(
        new Error('Network error: 401 Unauthorized'),
      );

      registerOAuthProvider('clio', {
        clientId: 'bad-client',
        clientSecret: 'bad-secret',
        redirectUri: 'http://localhost:3000/callback',
        authorizeEndpoint: 'https://clio.com/authorize',
        tokenEndpoint: 'https://clio.com/token',
        scopes: ['api'],
      });

      await expect(getClientCredentialsToken('clio')).rejects.toThrow(
        'Failed to fetch client credentials token for "clio": Network error: 401 Unauthorized',
      );
    });

    it('should cache tokens separately for different scope combinations', async () => {
      const mockResponse1: ClientCredentialsTokenResponse = {
        access_token: 'scope1_token',
        token_type: 'Bearer',
        expires_in: 3600,
      };

      const mockResponse2: ClientCredentialsTokenResponse = {
        access_token: 'scope2_token',
        token_type: 'Bearer',
        expires_in: 3600,
      };

      vi.mocked(ofetch)
        .mockResolvedValueOnce(mockResponse1)
        .mockResolvedValueOnce(mockResponse2);

      registerOAuthProvider('azure', {
        clientId: 'azure-client',
        clientSecret: 'azure-secret',
        redirectUri: 'http://localhost:3000/callback',
        authorizeEndpoint: 'https://azure.com/authorize',
        tokenEndpoint: 'https://azure.com/token',
        tenantId: 'common',
        scopes: ['default'],
      });

      // Request with scope1
      const result1 = await getClientCredentialsToken('azure', {
        scopes: ['scope1'],
      });
      expect(result1.access_token).toBe('scope1_token');

      // Request with scope2 - should fetch new token
      const result2 = await getClientCredentialsToken('azure', {
        scopes: ['scope2'],
      });
      expect(result2.access_token).toBe('scope2_token');

      // Should have 2 cached tokens
      expect(getClientCredentialsCacheSize()).toBe(2);
      expect(ofetch).toHaveBeenCalledTimes(2);
    });

    it('should not return expired tokens from cache', async () => {
      const mockResponse1: ClientCredentialsTokenResponse = {
        access_token: 'expired_token',
        token_type: 'Bearer',
        expires_in: 0, // Already expired
      };

      const mockResponse2: ClientCredentialsTokenResponse = {
        access_token: 'new_token',
        token_type: 'Bearer',
        expires_in: 3600,
      };

      vi.mocked(ofetch)
        .mockResolvedValueOnce(mockResponse1)
        .mockResolvedValueOnce(mockResponse2);

      registerOAuthProvider('clio', {
        clientId: 'clio-client',
        clientSecret: 'clio-secret',
        redirectUri: 'http://localhost:3000/callback',
        authorizeEndpoint: 'https://clio.com/authorize',
        tokenEndpoint: 'https://clio.com/token',
        scopes: ['api'],
      });

      // First call - gets expired token
      await getClientCredentialsToken('clio');

      // Second call - should fetch new token since cached one is expired
      const result = await getClientCredentialsToken('clio');
      expect(result.access_token).toBe('new_token');
      expect(ofetch).toHaveBeenCalledTimes(2);
    });
  });

  describe('clearClientCredentialsCache', () => {
    it('should clear the entire cache when no provider specified', async () => {
      const mockResponse: ClientCredentialsTokenResponse = {
        access_token: 'token',
        token_type: 'Bearer',
        expires_in: 3600,
      };

      vi.mocked(ofetch).mockResolvedValue(mockResponse);

      registerOAuthProvider('azure', {
        clientId: 'azure-client',
        clientSecret: 'azure-secret',
        redirectUri: 'http://localhost:3000/callback',
        authorizeEndpoint: 'https://azure.com/authorize',
        tokenEndpoint: 'https://azure.com/token',
        tenantId: 'common',
        scopes: ['api'],
      });

      registerOAuthProvider('clio', {
        clientId: 'clio-client',
        clientSecret: 'clio-secret',
        redirectUri: 'http://localhost:3000/callback',
        authorizeEndpoint: 'https://clio.com/authorize',
        tokenEndpoint: 'https://clio.com/token',
        scopes: ['api'],
      });

      // Cache tokens for both providers
      await getClientCredentialsToken('azure');
      await getClientCredentialsToken('clio');

      expect(getClientCredentialsCacheSize()).toBe(2);

      // Clear all cache
      clearClientCredentialsCache();
      expect(getClientCredentialsCacheSize()).toBe(0);
    });

    it('should clear cache for a specific provider', async () => {
      const mockResponse: ClientCredentialsTokenResponse = {
        access_token: 'token',
        token_type: 'Bearer',
        expires_in: 3600,
      };

      vi.mocked(ofetch).mockResolvedValue(mockResponse);

      registerOAuthProvider('azure', {
        clientId: 'azure-client',
        clientSecret: 'azure-secret',
        redirectUri: 'http://localhost:3000/callback',
        authorizeEndpoint: 'https://azure.com/authorize',
        tokenEndpoint: 'https://azure.com/token',
        tenantId: 'common',
        scopes: ['api'],
      });

      registerOAuthProvider('clio', {
        clientId: 'clio-client',
        clientSecret: 'clio-secret',
        redirectUri: 'http://localhost:3000/callback',
        authorizeEndpoint: 'https://clio.com/authorize',
        tokenEndpoint: 'https://clio.com/token',
        scopes: ['api'],
      });

      // Cache tokens
      await getClientCredentialsToken('azure');
      await getClientCredentialsToken('clio');

      expect(getClientCredentialsCacheSize()).toBe(2);

      // Clear only azure cache
      clearClientCredentialsCache('azure');
      expect(getClientCredentialsCacheSize()).toBe(1);

      // Azure should fetch new token, clio should use cache
      vi.clearAllMocks();
      await getClientCredentialsToken('azure');
      await getClientCredentialsToken('clio');

      expect(ofetch).toHaveBeenCalledTimes(1); // Only azure fetches
    });

    it('should clear cache for a specific provider instance', async () => {
      const mockResponse: ClientCredentialsTokenResponse = {
        access_token: 'token',
        token_type: 'Bearer',
        expires_in: 3600,
      };

      vi.mocked(ofetch).mockResolvedValue(mockResponse);

      registerOAuthProvider('azure', 'tenant-a', {
        clientId: 'tenant-a-client',
        clientSecret: 'tenant-a-secret',
        redirectUri: 'http://localhost:3000/callback',
        authorizeEndpoint: 'https://azure.com/authorize',
        tokenEndpoint: 'https://azure.com/token',
        tenantId: 'tenant-a',
        scopes: ['api'],
      });

      registerOAuthProvider('azure', 'tenant-b', {
        clientId: 'tenant-b-client',
        clientSecret: 'tenant-b-secret',
        redirectUri: 'http://localhost:3000/callback',
        authorizeEndpoint: 'https://azure.com/authorize',
        tokenEndpoint: 'https://azure.com/token',
        tenantId: 'tenant-b',
        scopes: ['api'],
      });

      // Cache both
      await getClientCredentialsToken('azure', { instanceKey: 'tenant-a' });
      await getClientCredentialsToken('azure', { instanceKey: 'tenant-b' });

      expect(getClientCredentialsCacheSize()).toBe(2);

      // Clear only tenant-a
      clearClientCredentialsCache('azure', 'tenant-a');
      expect(getClientCredentialsCacheSize()).toBe(1);
    });
  });

  describe('getClientCredentialsCacheSize', () => {
    it('should return 0 for empty cache', () => {
      expect(getClientCredentialsCacheSize()).toBe(0);
    });

    it('should return correct cache size', async () => {
      const mockResponse: ClientCredentialsTokenResponse = {
        access_token: 'token',
        token_type: 'Bearer',
        expires_in: 3600,
      };

      vi.mocked(ofetch).mockResolvedValue(mockResponse);

      registerOAuthProvider('azure', {
        clientId: 'azure-client',
        clientSecret: 'azure-secret',
        redirectUri: 'http://localhost:3000/callback',
        authorizeEndpoint: 'https://azure.com/authorize',
        tokenEndpoint: 'https://azure.com/token',
        tenantId: 'common',
        scopes: ['api'],
      });

      expect(getClientCredentialsCacheSize()).toBe(0);

      await getClientCredentialsToken('azure');
      expect(getClientCredentialsCacheSize()).toBe(1);

      await getClientCredentialsToken('azure', { scopes: ['different'] });
      expect(getClientCredentialsCacheSize()).toBe(2);
    });
  });
});

