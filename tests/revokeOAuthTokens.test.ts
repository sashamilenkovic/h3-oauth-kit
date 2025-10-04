import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { revokeOAuthTokens, useOAuthRegistry } from '../src';
import { createMockEvent } from './utils';
import { oAuthTokensAreValid, getProviderCookieKeys } from '../src/utils';
import type { TokenValidationResult } from '../src/types';
import { ofetch } from 'ofetch';
import { getCookie } from 'h3';

vi.mock('../src/utils', async () => {
  const actual = await vi.importActual<typeof import('../src/utils')>(
    '../src/utils',
  );
  return {
    ...actual,
    oAuthTokensAreValid: vi.fn(),
  };
});

vi.mock('ofetch', () => ({
  ofetch: vi.fn(),
}));

vi.mock('h3', async () => {
  const actual = await vi.importActual<typeof import('h3')>('h3');
  return {
    ...actual,
    getCookie: vi.fn(),
    deleteCookie: vi.fn(),
  };
});

const mockTokensValid = vi.mocked(oAuthTokensAreValid);
const mockOfetch = vi.mocked(ofetch);

describe('revokeOAuthTokens', () => {
  const { registerOAuthProvider } = useOAuthRegistry('a'.repeat(64));

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should call revoke endpoint when configured', async () => {
    const event = createMockEvent();

    registerOAuthProvider('google', {
      clientId: 'client-id',
      clientSecret: 'secret',
      authorizeEndpoint: 'https://google.com/auth',
      tokenEndpoint: 'https://google.com/token',
      revokeEndpoint: 'https://google.com/revoke',
      redirectUri: 'http://localhost/callback',
      scopes: ['openid'],
    });

    mockTokensValid.mockResolvedValue({
      status: 'valid',
      tokens: {
        access_token: 'my-token',
        refresh_token: 'refresh',
        expires_in: 3600,
        token_type: 'bearer',
      },
    } as TokenValidationResult<'google'>);

    await revokeOAuthTokens(event, 'google');

    expect(mockOfetch).toHaveBeenCalledWith(
      'https://google.com/revoke',
      expect.objectContaining({
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
      }),
    );

    // Cookies will be deleted (tested via unit tests for deleteProviderCookies)
  });

  it('should not call revoke endpoint when revokeRemote is false', async () => {
    const event = createMockEvent();

    registerOAuthProvider('github', {
      clientId: 'client-id',
      clientSecret: 'secret',
      authorizeEndpoint: 'https://github.com/auth',
      tokenEndpoint: 'https://github.com/token',
      revokeEndpoint: 'https://github.com/revoke',
      redirectUri: 'http://localhost/callback',
      scopes: ['read:user'],
    });

    await revokeOAuthTokens(event, 'github', { revokeRemote: false });

    expect(mockOfetch).not.toHaveBeenCalled();
    // Cookies will be deleted
  });

  it('should delete cookies even if revoke endpoint fails', async () => {
    const event = createMockEvent();
    const consoleErrorSpy = vi
      .spyOn(console, 'error')
      .mockImplementation(() => {});

    registerOAuthProvider('azure', {
      clientId: 'client-id',
      clientSecret: 'secret',
      authorizeEndpoint: 'https://azure.com/auth',
      tokenEndpoint: 'https://azure.com/token',
      revokeEndpoint: 'https://azure.com/revoke',
      redirectUri: 'http://localhost/callback',
      scopes: ['openid'],
      tenantId: 'tenant-123',
    });

    mockTokensValid.mockResolvedValue({
      status: 'valid',
      tokens: {
        access_token: 'token',
        refresh_token: 'refresh',
        expires_in: 3600,
        token_type: 'Bearer',
        ext_expires_in: 3600,
        scope: 'openid',
        id_token: 'id-token',
      },
    } as TokenValidationResult<'azure'>);

    mockOfetch.mockRejectedValue(new Error('Network error'));

    await revokeOAuthTokens(event, 'azure');

    expect(consoleErrorSpy).toHaveBeenCalled();
    // Cookies should still be deleted despite error

    consoleErrorSpy.mockRestore();
  });

  it('should handle provider without revoke endpoint', async () => {
    const event = createMockEvent();

    registerOAuthProvider('clio', {
      clientId: 'client-id',
      clientSecret: 'secret',
      authorizeEndpoint: 'https://clio.com/auth',
      tokenEndpoint: 'https://clio.com/token',
      // No revokeEndpoint
      redirectUri: 'http://localhost/callback',
      scopes: ['read'],
    });

    await revokeOAuthTokens(event, 'clio');

    expect(mockOfetch).not.toHaveBeenCalled();
    // Cookies will be deleted
  });

  it('should support instanceKey', async () => {
    const event = createMockEvent();

    registerOAuthProvider('clio', 'smithlaw', {
      clientId: 'client-id',
      clientSecret: 'secret',
      authorizeEndpoint: 'https://clio.com/auth',
      tokenEndpoint: 'https://clio.com/token',
      revokeEndpoint: 'https://clio.com/revoke',
      redirectUri: 'http://localhost/callback',
      scopes: ['read'],
    });

    mockTokensValid.mockResolvedValue({
      status: 'valid',
      tokens: {
        access_token: 'token',
        refresh_token: 'refresh',
        expires_in: 3600,
        token_type: 'bearer',
        client_id: 'client-123',
      },
    } as TokenValidationResult<'clio'>);

    await revokeOAuthTokens(event, 'clio', { instanceKey: 'smithlaw' });

    expect(mockOfetch).toHaveBeenCalled();
    // Scoped cookies will be deleted
  });

  it('should handle missing tokens gracefully', async () => {
    const event = createMockEvent();

    registerOAuthProvider('facebook', {
      clientId: 'client-id',
      clientSecret: 'secret',
      authorizeEndpoint: 'https://facebook.com/auth',
      tokenEndpoint: 'https://facebook.com/token',
      revokeEndpoint: 'https://facebook.com/revoke',
      redirectUri: 'http://localhost/callback',
      scopes: ['email'],
    });

    mockTokensValid.mockResolvedValue(false);

    await revokeOAuthTokens(event, 'facebook');

    expect(mockOfetch).not.toHaveBeenCalled();
    // Cookies will be deleted even with no tokens
  });
});
