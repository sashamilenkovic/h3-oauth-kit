import { describe, it, expect, beforeEach, vi } from 'vitest';
import { refreshToken } from '../../src/utils';
import type { OAuthProviderConfig } from '../../src/types';

// Mock ofetch
vi.mock('ofetch', () => ({
  ofetch: vi.fn(),
}));

describe('refreshToken - client_id parameter', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should include client_id in refresh token request', async () => {
    const { ofetch } = await import('ofetch');
    const mockOfetch = ofetch as ReturnType<typeof vi.fn>;

    mockOfetch.mockResolvedValue({
      access_token: 'new_access_token',
      refresh_token: 'new_refresh_token',
      expires_in: 3600,
      token_type: 'Bearer',
    });

    const providerConfig: OAuthProviderConfig<'azure'> = {
      clientId: 'test-client-id',
      clientSecret: 'test-client-secret',
      redirectUri: 'http://localhost:3000/callback',
      tokenEndpoint: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
      authorizeEndpoint: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
      scopes: ['openid'],
      encrypt: async (text: string) => text,
      decrypt: async (text: string) => text,
    };

    await refreshToken('test_refresh_token', providerConfig, 'azure');

    // Verify the call was made
    expect(mockOfetch).toHaveBeenCalledTimes(1);
    expect(mockOfetch).toHaveBeenCalledWith(
      'https://login.microsoftonline.com/common/oauth2/v2.0/token',
      expect.objectContaining({
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
      }),
    );

    // Verify all parameters are included in the body string
    const callArgs = mockOfetch.mock.calls[0];
    const bodyString = callArgs[1].body as string;
    expect(bodyString).toContain('client_id=test-client-id');
    expect(bodyString).toContain('client_secret=test-client-secret');
    expect(bodyString).toContain('refresh_token=test_refresh_token');
    expect(bodyString).toContain('grant_type=refresh_token');
  });

  it('should work with different providers (intuit example)', async () => {
    const { ofetch } = await import('ofetch');
    const mockOfetch = ofetch as ReturnType<typeof vi.fn>;

    mockOfetch.mockResolvedValue({
      access_token: 'new_access_token',
      expires_in: 3600,
      token_type: 'Bearer',
      x_refresh_token_expires_in: 8726400,
    });

    const providerConfig: OAuthProviderConfig<'intuit'> = {
      clientId: 'intuit-client-id',
      clientSecret: 'intuit-client-secret',
      redirectUri: 'http://localhost:3000/callback',
      tokenEndpoint: 'https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer',
      authorizeEndpoint: 'https://appcenter.intuit.com/connect/oauth2',
      scopes: ['com.intuit.quickbooks.accounting'],
      encrypt: async (text: string) => text,
      decrypt: async (text: string) => text,
    };

    await refreshToken('intuit_refresh_token', providerConfig, 'intuit');

    expect(mockOfetch).toHaveBeenCalledWith(
      'https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer',
      expect.objectContaining({
        method: 'POST',
        body: expect.any(String),
      }),
    );

    const callArgs = mockOfetch.mock.calls[0];
    const bodyString = callArgs[1].body as string;

    expect(bodyString).toContain('client_id=intuit-client-id');
    expect(bodyString).toContain('client_secret=intuit-client-secret');
    expect(bodyString).toContain('refresh_token=intuit_refresh_token');
    expect(bodyString).toContain('grant_type=refresh_token');
  });

  it('should handle providers that require client_id for refresh (clio example)', async () => {
    const { ofetch } = await import('ofetch');
    const mockOfetch = ofetch as ReturnType<typeof vi.fn>;

    // Simulate a provider that strictly requires client_id
    mockOfetch.mockResolvedValue({
      access_token: 'new_access_token',
      refresh_token: 'new_refresh_token',
      expires_in: 3600,
    });

    const providerConfig: OAuthProviderConfig<'clio'> = {
      clientId: 'clio-client-id',
      clientSecret: 'clio-client-secret',
      redirectUri: 'http://localhost:3000/callback',
      tokenEndpoint: 'https://app.clio.com/oauth/token',
      authorizeEndpoint: 'https://app.clio.com/oauth/authorize',
      scopes: ['read', 'write'],
      encrypt: async (text: string) => text,
      decrypt: async (text: string) => text,
    };

    const result = await refreshToken(
      'clio_refresh_token',
      providerConfig,
      'clio',
    );

    expect(result).toEqual({
      access_token: 'new_access_token',
      refresh_token: 'new_refresh_token',
      expires_in: 3600,
    });

    // Verify client_id was included
    const callArgs = mockOfetch.mock.calls[0];
    const bodyString = callArgs[1].body as string;
    expect(bodyString).toContain('client_id=clio-client-id');
  });

  it('should handle refresh token errors gracefully', async () => {
    const { ofetch } = await import('ofetch');
    const mockOfetch = ofetch as ReturnType<typeof vi.fn>;

    mockOfetch.mockRejectedValue(
      new Error('invalid_grant: Refresh token expired'),
    );

    const providerConfig: OAuthProviderConfig<'azure'> = {
      clientId: 'test-client-id',
      clientSecret: 'test-client-secret',
      redirectUri: 'http://localhost:3000/callback',
      tokenEndpoint: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
      authorizeEndpoint: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
      scopes: ['openid'],
      encrypt: async (text: string) => text,
      decrypt: async (text: string) => text,
    };

    await expect(
      refreshToken('expired_refresh_token', providerConfig, 'azure'),
    ).rejects.toThrow('invalid_grant: Refresh token expired');

    // Verify the request was still made with client_id
    const callArgs = mockOfetch.mock.calls[0];
    const bodyString = callArgs[1].body as string;
    expect(bodyString).toContain('client_id=test-client-id');
  });

  it('should include all four required parameters in token refresh', async () => {
    const { ofetch } = await import('ofetch');
    const mockOfetch = ofetch as ReturnType<typeof vi.fn>;

    mockOfetch.mockResolvedValue({
      access_token: 'new_token',
      expires_in: 3600,
    });

    const providerConfig: OAuthProviderConfig<'clio'> = {
      clientId: 'my-client-id',
      clientSecret: 'my-client-secret',
      redirectUri: 'http://localhost:3000/callback',
      tokenEndpoint: 'https://provider.com/token',
      authorizeEndpoint: 'https://provider.com/authorize',
      scopes: ['read'],
      encrypt: async (text: string) => text,
      decrypt: async (text: string) => text,
    };

    await refreshToken('my_refresh_token', providerConfig, 'clio');

    const callArgs = mockOfetch.mock.calls[0];
    const bodyString = callArgs[1].body as string;

    // All four parameters should be present
    const params = new URLSearchParams(bodyString);
    expect(params.get('client_id')).toBe('my-client-id');
    expect(params.get('client_secret')).toBe('my-client-secret');
    expect(params.get('refresh_token')).toBe('my_refresh_token');
    expect(params.get('grant_type')).toBe('refresh_token');
  });
});

