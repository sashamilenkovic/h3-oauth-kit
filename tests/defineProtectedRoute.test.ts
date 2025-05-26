import { describe, it, expect, vi, beforeEach } from 'vitest';
import type {
  AzureAuthTokens,
  AzureRefreshTokenResponse,
  TokenValidationResult,
} from '../src/types';
import { defineProtectedRoute, registerOAuthProvider } from '../src';
import { createMockEvent } from './utils';
import {
  oAuthTokensAreValid,
  refreshToken,
  setProviderCookies,
  normalizeRefreshedToken,
} from '../src/utils';

vi.mock('../src/utils', async () => {
  const actual = await vi.importActual<typeof import('../src/utils')>(
    '../src/utils',
  );
  return {
    ...actual,
    oAuthTokensAreValid: vi.fn(),
    refreshToken: vi.fn(),
    setProviderCookies: vi.fn(),
    normalizeRefreshedToken: vi.fn(),
  };
});

const mockTokensValid = vi.mocked(oAuthTokensAreValid);
const mockRefreshToken = vi.mocked(refreshToken);
const mockSetProviderCookies = vi.mocked(setProviderCookies);
const mockNormalizeRefreshedToken = vi.mocked(normalizeRefreshedToken);

describe('defineProtectedRoute (multi-provider)', () => {
  const clioConfig = {
    clientId: 'clio-id',
    clientSecret: 'secret',
    authorizeEndpoint: 'https://clio.auth',
    tokenEndpoint: 'https://clio.token',
    redirectUri: 'https://myapp.com/callback',
    scopes: ['read'],
  };

  const azureConfig = {
    clientId: 'azure-id',
    clientSecret: 'secret',
    authorizeEndpoint: 'https://azure.auth',
    tokenEndpoint: 'https://azure.token',
    redirectUri: 'https://myapp.com/callback',
    scopes: ['user.read'],
    tenantId: 'tenant-id',
  };

  beforeEach(() => {
    vi.clearAllMocks();
    registerOAuthProvider('clio', clioConfig);
    registerOAuthProvider('azure', 'dev', azureConfig);
  });

  it('supports mixed provider styles', async () => {
    const event = createMockEvent();

    mockTokensValid.mockImplementation(
      async <P extends 'clio' | 'azure' | 'intuit'>(
        _event: unknown,
        provider: P,
        instanceKey?: string,
      ): Promise<TokenValidationResult<P>> => {
        const key = instanceKey ? `${provider}:${instanceKey}` : provider;

        if (provider === 'intuit') {
          return {
            status: 'valid',
            tokens: {
              access_token: `token-${key}`,
              refresh_token: 'r',
              expires_in: 3600,
              token_type: 'bearer',
              realm_id: 'realm-123',
              x_refresh_token_expires_in: 1234,
            },
          } as TokenValidationResult<P>;
        }

        if (provider === 'azure') {
          return {
            status: 'valid',
            tokens: {
              access_token: `token-${key}`,
              refresh_token: 'r',
              expires_in: 3600,
              token_type: 'bearer',
              ext_expires_in: 3600,
              scope: 'user.read',
              id_token: 'id-token',
            },
          } as TokenValidationResult<P>;
        }

        return {
          status: 'valid',
          tokens: {
            access_token: `token-${key}`,
            refresh_token: 'r',
            expires_in: 3600,
            token_type: 'bearer',
            client_id: 'client-123',
          },
        } as TokenValidationResult<P>;
      },
    );

    const handler = defineProtectedRoute(
      ['clio', { provider: 'azure', instanceKey: 'dev' }],
      async (evt) => ({
        clio: evt.context.h3OAuthKit['clio'].access_token,
        azure: evt.context.h3OAuthKit['azure:dev'].access_token,
      }),
    );

    const result = await handler(event);
    expect(result).toEqual({
      clio: 'token-clio',
      azure: 'token-azure:dev',
    });
  });

  it('supports scoped-only providers', async () => {
    const event = createMockEvent();

    mockTokensValid.mockResolvedValue({
      status: 'valid',
      tokens: {
        access_token: 'azure-scoped-token',
        refresh_token: 'refresh',
        expires_in: 3600,
        token_type: 'bearer',
        ext_expires_in: 3600,
        scope: 'user.read',
        id_token: 'id-token',
      },
    } as TokenValidationResult<'azure'>);

    const handler = defineProtectedRoute(
      [{ provider: 'azure', instanceKey: 'dev' }],
      async (evt) => ({
        token: evt.context.h3OAuthKit['azure:dev'].access_token,
      }),
    );

    const result = await handler(event);
    expect(result).toEqual({ token: 'azure-scoped-token' });
    expect(mockTokensValid).toHaveBeenCalledWith(event, 'azure', 'dev');
  });

  it('uses instanceKey when refreshing tokens', async () => {
    const event = createMockEvent();

    mockTokensValid.mockResolvedValue({
      status: 'expired',
      tokens: {
        access_token: 'old',
        refresh_token: 'valid',
        expires_in: 0,
        token_type: 'bearer',
      },
    } as TokenValidationResult<'azure'>);

    // 👇 define using the proper AzureRefreshTokenResponse type
    const refreshed: AzureRefreshTokenResponse = {
      access_token: 'new',
      refresh_token: 'valid',
      expires_in: 3600,
      ext_expires_in: 3600,
      token_type: 'Bearer',
    };

    const fullToken: AzureAuthTokens = {
      ...refreshed,
      scope: 'user.read',
      id_token: 'mock-id-token',
    };

    mockRefreshToken.mockResolvedValue(refreshed); // ✅ returns RefreshTokenResponse
    mockNormalizeRefreshedToken.mockReturnValue(fullToken); // ✅ returns full token w/ scope + id_token
    mockSetProviderCookies.mockReturnValue(fullToken);

    const handler = defineProtectedRoute(
      [{ provider: 'azure', instanceKey: 'dev' }],
      async (evt) => ({
        token: evt.context.h3OAuthKit['azure:dev'].access_token,
      }),
    );

    const result = await handler(event);
    expect(result).toEqual({ token: 'new' });

    expect(mockSetProviderCookies).toHaveBeenCalledWith(
      event,
      fullToken,
      'azure',
      undefined,
      'dev',
    );
  });

  it('throws 401 error when tokens are missing or invalid', async () => {
    const event = createMockEvent();

    // Mock oAuthTokensAreValid to return false (missing/invalid tokens)
    mockTokensValid.mockResolvedValue(false);

    const handler = defineProtectedRoute(['clio'], async (evt) => ({
      token: evt.context.h3OAuthKit['clio'].access_token,
    }));

    await expect(handler(event)).rejects.toThrow(
      'Missing or invalid tokens for "clio"',
    );

    expect(mockTokensValid).toHaveBeenCalledWith(event, 'clio', undefined);
  });

  it('calls onAuthFailure when tokens are missing and handler is provided', async () => {
    const event = createMockEvent();
    const mockOnAuthFailure = vi
      .fn()
      .mockResolvedValue({ error: 'custom response' });

    // Mock oAuthTokensAreValid to return false (missing/invalid tokens)
    mockTokensValid.mockResolvedValue(false);

    const handler = defineProtectedRoute(
      ['clio'],
      async (evt) => ({
        token: evt.context.h3OAuthKit['clio'].access_token,
      }),
      {
        onAuthFailure: mockOnAuthFailure,
      },
    );

    const result = await handler(event);

    expect(result).toEqual({ error: 'custom response' });
    expect(mockOnAuthFailure).toHaveBeenCalledWith(
      event,
      'clio',
      'missing-or-invalid-tokens',
      expect.objectContaining({
        statusCode: 401,
        message: 'Missing or invalid tokens for "clio"',
      }),
    );
  });

  it('throws error when onAuthFailure returns undefined for missing tokens', async () => {
    const event = createMockEvent();
    const mockOnAuthFailure = vi.fn().mockResolvedValue(undefined);

    // Mock oAuthTokensAreValid to return false (missing/invalid tokens)
    mockTokensValid.mockResolvedValue(false);

    const handler = defineProtectedRoute(
      ['clio'],
      async (evt) => ({
        token: evt.context.h3OAuthKit['clio'].access_token,
      }),
      {
        onAuthFailure: mockOnAuthFailure,
      },
    );

    await expect(handler(event)).rejects.toThrow(
      'Missing or invalid tokens for "clio"',
    );

    expect(mockOnAuthFailure).toHaveBeenCalledWith(
      event,
      'clio',
      'missing-or-invalid-tokens',
      expect.objectContaining({
        statusCode: 401,
        message: 'Missing or invalid tokens for "clio"',
      }),
    );
  });

  it('uses instanceKey when getting provider config for token refresh', async () => {
    const event = createMockEvent();

    // Mock expired tokens for scoped provider
    mockTokensValid.mockResolvedValue({
      status: 'expired',
      tokens: {
        access_token: 'expired-token',
        refresh_token: 'valid-refresh',
        expires_in: 0,
        token_type: 'bearer',
        ext_expires_in: 3600,
        scope: 'user.read',
        id_token: 'id-token',
      },
    } as TokenValidationResult<'azure'>);

    const refreshed: AzureRefreshTokenResponse = {
      access_token: 'refreshed-token',
      refresh_token: 'new-refresh',
      expires_in: 3600,
      ext_expires_in: 3600,
      token_type: 'Bearer',
    };

    const fullToken: AzureAuthTokens = {
      ...refreshed,
      scope: 'user.read',
      id_token: 'new-id-token',
    };

    mockRefreshToken.mockResolvedValue(refreshed);
    mockNormalizeRefreshedToken.mockReturnValue(fullToken);
    mockSetProviderCookies.mockReturnValue(fullToken);

    const handler = defineProtectedRoute(
      [{ provider: 'azure', instanceKey: 'dev' }],
      async (evt) => ({
        token: evt.context.h3OAuthKit['azure:dev'].access_token,
      }),
    );

    const result = await handler(event);

    expect(result).toEqual({ token: 'refreshed-token' });

    // Verify that refreshToken was called with the config from the scoped provider
    expect(mockRefreshToken).toHaveBeenCalledWith(
      'valid-refresh',
      azureConfig, // This should be the config retrieved using instanceKey 'dev'
      'azure',
    );

    expect(mockSetProviderCookies).toHaveBeenCalledWith(
      event,
      fullToken,
      'azure',
      undefined,
      'dev',
    );
  });

  it('uses global provider config when no instanceKey during token refresh', async () => {
    const event = createMockEvent();

    // Mock expired tokens for NON-scoped provider (no instanceKey)
    mockTokensValid.mockResolvedValue({
      status: 'expired',
      tokens: {
        access_token: 'expired-token',
        refresh_token: 'valid-refresh',
        expires_in: 0,
        token_type: 'bearer',
        client_id: 'client-123',
      },
    } as TokenValidationResult<'clio'>);

    const refreshed = {
      access_token: 'refreshed-token',
      refresh_token: 'new-refresh',
      expires_in: 3600,
      token_type: 'bearer' as const,
    };

    const fullToken = {
      ...refreshed,
      client_id: 'client-123',
    };

    mockRefreshToken.mockResolvedValue(refreshed);
    mockNormalizeRefreshedToken.mockReturnValue(fullToken);
    mockSetProviderCookies.mockReturnValue(fullToken);

    const handler = defineProtectedRoute(
      ['clio'], // Non-scoped provider (no instanceKey)
      async (evt) => ({
        token: evt.context.h3OAuthKit['clio'].access_token,
      }),
    );

    const result = await handler(event);

    expect(result).toEqual({ token: 'refreshed-token' });

    // Verify that refreshToken was called with the global config (line 502)
    expect(mockRefreshToken).toHaveBeenCalledWith(
      'valid-refresh',
      clioConfig, // This should be the global config (no instanceKey)
      'clio',
    );

    expect(mockSetProviderCookies).toHaveBeenCalledWith(
      event,
      fullToken,
      'clio',
      undefined,
      undefined, // no instanceKey
    );
  });

  it('throws 401 error when token refresh fails', async () => {
    const event = createMockEvent();

    // Mock expired tokens
    mockTokensValid.mockResolvedValue({
      status: 'expired',
      tokens: {
        access_token: 'expired-token',
        refresh_token: 'invalid-refresh',
        expires_in: 0,
        token_type: 'bearer',
        client_id: 'client-123',
      },
    } as TokenValidationResult<'clio'>);

    // Mock refreshToken to return false (refresh failed)
    mockRefreshToken.mockResolvedValue(false);

    const handler = defineProtectedRoute(['clio'], async (evt) => ({
      token: evt.context.h3OAuthKit['clio'].access_token,
    }));

    await expect(handler(event)).rejects.toThrow(
      'Token refresh failed for "clio"',
    );

    expect(mockRefreshToken).toHaveBeenCalledWith(
      'invalid-refresh',
      clioConfig,
      'clio',
    );
  });

  it('calls onAuthFailure when token refresh fails and handler is provided', async () => {
    const event = createMockEvent();
    const mockOnAuthFailure = vi
      .fn()
      .mockResolvedValue({ error: 'refresh failed response' });

    // Mock expired tokens
    mockTokensValid.mockResolvedValue({
      status: 'expired',
      tokens: {
        access_token: 'expired-token',
        refresh_token: 'invalid-refresh',
        expires_in: 0,
        token_type: 'bearer',
        client_id: 'client-123',
      },
    } as TokenValidationResult<'clio'>);

    // Mock refreshToken to return false (refresh failed)
    mockRefreshToken.mockResolvedValue(false);

    const handler = defineProtectedRoute(
      ['clio'],
      async (evt) => ({
        token: evt.context.h3OAuthKit['clio'].access_token,
      }),
      {
        onAuthFailure: mockOnAuthFailure,
      },
    );

    const result = await handler(event);

    expect(result).toEqual({ error: 'refresh failed response' });
    expect(mockOnAuthFailure).toHaveBeenCalledWith(
      event,
      'clio',
      'token-refresh-failed',
      expect.objectContaining({
        statusCode: 401,
        message: 'Token refresh failed for "clio"',
      }),
    );
  });

  it('throws error when onAuthFailure returns undefined for refresh failure', async () => {
    const event = createMockEvent();
    const mockOnAuthFailure = vi.fn().mockResolvedValue(undefined);

    // Mock expired tokens
    mockTokensValid.mockResolvedValue({
      status: 'expired',
      tokens: {
        access_token: 'expired-token',
        refresh_token: 'invalid-refresh',
        expires_in: 0,
        token_type: 'bearer',
        client_id: 'client-123',
      },
    } as TokenValidationResult<'clio'>);

    // Mock refreshToken to return false (refresh failed)
    mockRefreshToken.mockResolvedValue(false);

    const handler = defineProtectedRoute(
      ['clio'],
      async (evt) => ({
        token: evt.context.h3OAuthKit['clio'].access_token,
      }),
      {
        onAuthFailure: mockOnAuthFailure,
      },
    );

    await expect(handler(event)).rejects.toThrow(
      'Token refresh failed for "clio"',
    );

    expect(mockOnAuthFailure).toHaveBeenCalledWith(
      event,
      'clio',
      'token-refresh-failed',
      expect.objectContaining({
        statusCode: 401,
        message: 'Token refresh failed for "clio"',
      }),
    );
  });

  it('handles non-H3Error through parseError path', async () => {
    const event = createMockEvent();

    // Mock oAuthTokensAreValid to throw a non-H3Error (plain object)
    // This will trigger the catch block in the provider validation loop
    mockTokensValid.mockImplementation(() => {
      throw {
        message: 'Custom non-H3 error during token validation',
        type: 'CUSTOM_TYPE',
      };
    });

    const handler = defineProtectedRoute(['clio'], async (evt) => ({
      token: evt.context.h3OAuthKit['clio'].access_token,
    }));

    // Expect the error to be processed through parseError and wrapped in createError
    await expect(handler(event)).rejects.toMatchObject({
      statusCode: 500, // parseError defaults to 500 for generic errors
      message: 'Custom non-H3 error during token validation',
    });

    expect(mockTokensValid).toHaveBeenCalledWith(event, 'clio', undefined);
  });

  it('handles non-H3Error through parseError path when onAuthFailure returns undefined', async () => {
    const event = createMockEvent();
    const mockOnAuthFailure = vi.fn().mockResolvedValue(undefined);

    // Mock oAuthTokensAreValid to throw a non-H3Error (plain object)
    // This will trigger the catch block in the provider validation loop
    mockTokensValid.mockImplementation(() => {
      throw {
        message: 'Generic error during token validation',
        code: 'CUSTOM_ERROR',
      };
    });

    const handler = defineProtectedRoute(
      ['clio'],
      async (evt) => ({
        token: evt.context.h3OAuthKit['clio'].access_token,
      }),
      {
        onAuthFailure: mockOnAuthFailure,
      },
    );

    // Expect the error to be processed through parseError
    await expect(handler(event)).rejects.toMatchObject({
      statusCode: 500,
      message: 'Generic error during token validation',
    });

    // onAuthFailure should be called with 'error-occurred' reason
    expect(mockOnAuthFailure).toHaveBeenCalledWith(
      event,
      'clio',
      'error-occurred',
      expect.objectContaining({
        message: 'Generic error during token validation',
        code: 'CUSTOM_ERROR',
      }),
    );
  });

  it('passes undefined cookieOptions to setProviderCookies when options is undefined', async () => {
    const event = createMockEvent();

    // Mock expired tokens to trigger token refresh
    mockTokensValid.mockResolvedValue({
      status: 'expired',
      tokens: {
        access_token: 'expired-token',
        refresh_token: 'valid-refresh',
        expires_in: 0,
        token_type: 'bearer',
        client_id: 'client-123',
      },
    } as TokenValidationResult<'clio'>);

    const refreshed = {
      access_token: 'refreshed-token',
      refresh_token: 'new-refresh',
      expires_in: 3600,
      token_type: 'bearer' as const,
    };

    const fullToken = {
      ...refreshed,
      client_id: 'client-123',
    };

    mockRefreshToken.mockResolvedValue(refreshed);
    mockNormalizeRefreshedToken.mockReturnValue(fullToken);
    mockSetProviderCookies.mockReturnValue(fullToken);

    // Create handler WITHOUT options parameter (options will be undefined)
    const handler = defineProtectedRoute(['clio'], async (evt) => ({
      token: evt.context.h3OAuthKit['clio'].access_token,
    }));

    await handler(event);

    // Verify that setProviderCookies was called with undefined for cookieOptions
    expect(mockSetProviderCookies).toHaveBeenCalledWith(
      event,
      fullToken,
      'clio',
      undefined, // options?.cookieOptions should be undefined
      undefined, // instanceKey should be undefined
    );
  });

  it('passes custom cookieOptions to setProviderCookies during token refresh', async () => {
    const event = createMockEvent();

    // Mock expired tokens to trigger token refresh
    mockTokensValid.mockResolvedValue({
      status: 'expired',
      tokens: {
        access_token: 'expired-token',
        refresh_token: 'valid-refresh',
        expires_in: 0,
        token_type: 'bearer',
        client_id: 'client-123',
      },
    } as TokenValidationResult<'clio'>);

    const refreshed = {
      access_token: 'refreshed-token',
      refresh_token: 'new-refresh',
      expires_in: 3600,
      token_type: 'bearer' as const,
    };

    const fullToken = {
      ...refreshed,
      client_id: 'client-123',
    };

    mockRefreshToken.mockResolvedValue(refreshed);
    mockNormalizeRefreshedToken.mockReturnValue(fullToken);
    mockSetProviderCookies.mockReturnValue(fullToken);

    const customCookieOptions = {
      sameSite: 'lax' as const,
      path: '/custom',
      maxAge: 7200,
    };

    // Create handler WITH custom cookieOptions
    const handler = defineProtectedRoute(
      ['clio'],
      async (evt) => ({
        token: evt.context.h3OAuthKit['clio'].access_token,
      }),
      {
        cookieOptions: customCookieOptions,
      },
    );

    await handler(event);

    // Verify that setProviderCookies was called with the custom cookieOptions
    expect(mockSetProviderCookies).toHaveBeenCalledWith(
      event,
      fullToken,
      'clio',
      customCookieOptions, // options?.cookieOptions should be the custom options
      undefined, // instanceKey should be undefined
    );
  });

  it('returns onAuthFailure response when error occurs and response is defined', async () => {
    const event = createMockEvent();
    const customErrorResponse = {
      error: 'custom error handling',
      redirectTo: '/login',
      statusCode: 403,
    };
    const mockOnAuthFailure = vi.fn().mockResolvedValue(customErrorResponse);

    // Mock oAuthTokensAreValid to throw an error during token validation
    // This will trigger the catch block and call onAuthFailure with 'error-occurred'
    mockTokensValid.mockImplementation(() => {
      throw new Error('Token validation failed unexpectedly');
    });

    const handler = defineProtectedRoute(
      ['clio'],
      async (evt) => ({
        token: evt.context.h3OAuthKit['clio'].access_token,
      }),
      {
        onAuthFailure: mockOnAuthFailure,
      },
    );

    const result = await handler(event);

    // Should return the custom response from onAuthFailure (line 558: if (response !== undefined) return response;)
    expect(result).toEqual(customErrorResponse);

    // Verify onAuthFailure was called with 'error-occurred' reason
    expect(mockOnAuthFailure).toHaveBeenCalledWith(
      event,
      'clio',
      'error-occurred',
      expect.any(Error),
    );
  });
});
