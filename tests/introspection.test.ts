import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  introspectToken,
  isTokenActive,
} from '../src/introspection';
import { useOAuthRegistry } from '../src/index';
import type { TokenIntrospectionResponse } from '../src/types';
import { ofetch } from 'ofetch';

// Mock ofetch
vi.mock('ofetch', () => ({
  ofetch: vi.fn(),
}));

describe('Token Introspection (RFC 7662)', () => {
  const mockEncryptionKey = 'a'.repeat(64);
  let registerOAuthProvider: ReturnType<
    typeof useOAuthRegistry
  >['registerOAuthProvider'];

  beforeEach(() => {
    vi.clearAllMocks();
    const registry = useOAuthRegistry(mockEncryptionKey);
    registerOAuthProvider = registry.registerOAuthProvider;
  });

  describe('introspectToken', () => {
    it('should successfully introspect an active token', async () => {
      registerOAuthProvider('azure', {
        clientId: 'test-client-id',
        clientSecret: 'test-client-secret',
        redirectUri: 'http://localhost:3000/callback',
        authorizeEndpoint: 'https://provider.com/authorize',
        tokenEndpoint: 'https://provider.com/token',
        introspectionEndpoint: 'https://provider.com/introspect',
        scopes: ['openid', 'profile'],
      });

      const mockResponse: TokenIntrospectionResponse = {
        active: true,
        scope: 'openid profile',
        client_id: 'test-client-id',
        username: 'testuser',
        token_type: 'Bearer',
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        sub: 'user-123',
      };

      vi.mocked(ofetch).mockResolvedValue(mockResponse);

      const result = await introspectToken('azure', 'test-access-token');

      expect(result).toEqual(mockResponse);
      expect(result.active).toBe(true);
      expect(vi.mocked(ofetch)).toHaveBeenCalledWith(
        'https://provider.com/introspect',
        expect.objectContaining({
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            Accept: 'application/json',
          },
        }),
      );

      // Check that the body contains the correct parameters
      const callArgs = vi.mocked(ofetch).mock.calls[0][1];
      const bodyParams = callArgs?.body as URLSearchParams;
      expect(bodyParams.get('token')).toBe('test-access-token');
      expect(bodyParams.get('client_id')).toBe('test-client-id');
      expect(bodyParams.get('client_secret')).toBe('test-client-secret');
    });

    it('should introspect an inactive/revoked token', async () => {
      registerOAuthProvider('azure', {
        clientId: 'test-client-id',
        clientSecret: 'test-client-secret',
        redirectUri: 'http://localhost:3000/callback',
        authorizeEndpoint: 'https://provider.com/authorize',
        tokenEndpoint: 'https://provider.com/token',
        introspectionEndpoint: 'https://provider.com/introspect',
        scopes: ['openid'],
      });

      const mockResponse: TokenIntrospectionResponse = {
        active: false,
      };

      vi.mocked(ofetch).mockResolvedValue(mockResponse);

      const result = await introspectToken('azure', 'revoked-token');

      expect(result.active).toBe(false);
      expect(result.scope).toBeUndefined();
    });

    it('should include token_type_hint when provided', async () => {
      registerOAuthProvider('azure', {
        clientId: 'test-client-id',
        clientSecret: 'test-client-secret',
        redirectUri: 'http://localhost:3000/callback',
        authorizeEndpoint: 'https://provider.com/authorize',
        tokenEndpoint: 'https://provider.com/token',
        introspectionEndpoint: 'https://provider.com/introspect',
        scopes: ['openid'],
      });

      const mockResponse: TokenIntrospectionResponse = {
        active: true,
        token_type: 'Bearer',
      };

      vi.mocked(ofetch).mockResolvedValue(mockResponse);

      await introspectToken('azure', 'refresh-token', {
        tokenTypeHint: 'refresh_token',
      });

      const callArgs = vi.mocked(ofetch).mock.calls[0][1];
      const bodyParams = callArgs?.body as URLSearchParams;
      expect(bodyParams.get('token_type_hint')).toBe('refresh_token');
    });

    it('should support multi-tenant with instanceKey', async () => {
      registerOAuthProvider('azure:tenant-a', {
        clientId: 'tenant-a-client-id',
        clientSecret: 'tenant-a-secret',
        redirectUri: 'http://localhost:3000/callback',
        authorizeEndpoint: 'https://provider.com/authorize',
        tokenEndpoint: 'https://provider.com/token',
        introspectionEndpoint: 'https://provider.com/introspect',
        scopes: ['openid'],
      });

      const mockResponse: TokenIntrospectionResponse = {
        active: true,
      };

      vi.mocked(ofetch).mockResolvedValue(mockResponse);

      await introspectToken('azure', 'test-token', {
        instanceKey: 'tenant-a',
      });

      const callArgs = vi.mocked(ofetch).mock.calls[0][1];
      const bodyParams = callArgs?.body as URLSearchParams;
      expect(bodyParams.get('client_id')).toBe('tenant-a-client-id');
    });

    it('should throw error if provider is not registered', async () => {
      // Don't register any provider for this test
      await expect(
        introspectToken('github' as any, 'test-token'),
      ).rejects.toThrow('Provider "github" is not registered');
    });

    it('should throw error if provider has no introspection endpoint', async () => {
      registerOAuthProvider('azure', {
        clientId: 'test-client-id',
        clientSecret: 'test-client-secret',
        redirectUri: 'http://localhost:3000/callback',
        authorizeEndpoint: 'https://provider.com/authorize',
        tokenEndpoint: 'https://provider.com/token',
        scopes: ['openid'],
        // No introspectionEndpoint configured
      });

      await expect(
        introspectToken('azure', 'test-token'),
      ).rejects.toThrow('does not have an introspection endpoint configured');
    });

    it('should throw error on network failure', async () => {
      registerOAuthProvider('azure', {
        clientId: 'test-client-id',
        clientSecret: 'test-client-secret',
        redirectUri: 'http://localhost:3000/callback',
        authorizeEndpoint: 'https://provider.com/authorize',
        tokenEndpoint: 'https://provider.com/token',
        introspectionEndpoint: 'https://provider.com/introspect',
        scopes: ['openid'],
      });

      vi.mocked(ofetch).mockRejectedValue(
        new Error('Network error'),
      );

      await expect(
        introspectToken('azure', 'test-token'),
      ).rejects.toThrow('Failed to introspect token');
    });
  });

  describe('isTokenActive', () => {
    it('should return true for active token', async () => {
      registerOAuthProvider('azure', {
        clientId: 'test-client-id',
        clientSecret: 'test-client-secret',
        redirectUri: 'http://localhost:3000/callback',
        authorizeEndpoint: 'https://provider.com/authorize',
        tokenEndpoint: 'https://provider.com/token',
        introspectionEndpoint: 'https://provider.com/introspect',
        scopes: ['openid'],
      });

      const mockResponse: TokenIntrospectionResponse = {
        active: true,
      };

      vi.mocked(ofetch).mockResolvedValue(mockResponse);

      const isActive = await isTokenActive('azure', 'test-token');

      expect(isActive).toBe(true);
    });

    it('should return false for inactive token', async () => {
      registerOAuthProvider('azure', {
        clientId: 'test-client-id',
        clientSecret: 'test-client-secret',
        redirectUri: 'http://localhost:3000/callback',
        authorizeEndpoint: 'https://provider.com/authorize',
        tokenEndpoint: 'https://provider.com/token',
        introspectionEndpoint: 'https://provider.com/introspect',
        scopes: ['openid'],
      });

      const mockResponse: TokenIntrospectionResponse = {
        active: false,
      };

      vi.mocked(ofetch).mockResolvedValue(mockResponse);

      const isActive = await isTokenActive('azure', 'revoked-token');

      expect(isActive).toBe(false);
    });

    it('should return false on error', async () => {
      registerOAuthProvider('azure', {
        clientId: 'test-client-id',
        clientSecret: 'test-client-secret',
        redirectUri: 'http://localhost:3000/callback',
        authorizeEndpoint: 'https://provider.com/authorize',
        tokenEndpoint: 'https://provider.com/token',
        introspectionEndpoint: 'https://provider.com/introspect',
        scopes: ['openid'],
      });

      vi.mocked(ofetch).mockRejectedValue(
        new Error('Network error'),
      );

      const isActive = await isTokenActive('azure', 'test-token');

      expect(isActive).toBe(false);
    });
  });
});

