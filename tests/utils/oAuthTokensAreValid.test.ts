import { describe, it, expect, vi, beforeEach } from 'vitest';
import { oAuthTokensAreValid } from '../../src/utils';
import { createMockEvent } from '../utils';
import { getCookie, setCookie } from 'h3';
import { providerConfig } from '../../src/providerConfig';
import { withEncryptedRefreshToken } from '../utils';
import { getOAuthProviderConfig, useOAuthRegistry } from '../../src/index';

// 🧪 Mock getCookie before testing
vi.mock('h3', async () => {
  const actual = await vi.importActual<typeof import('h3')>('h3');
  return {
    ...actual,
    getCookie: vi.fn(),
  };
});

const mockedGetCookie = getCookie as unknown as ReturnType<typeof vi.fn>;

vi.mocked(getCookie);

const now = Math.floor(Date.now() / 1000);
const { registerOAuthProvider } = useOAuthRegistry('a'.repeat(64));
registerOAuthProvider('azure', {
  clientId: 'azure-client',
  clientSecret: 'azure-secret',
  authorizeEndpoint: 'https://azure.auth',
  tokenEndpoint: 'https://azure.token',
  redirectUri: 'https://myapp.com/callback',
  scopes: ['user.read'],
  tenantId: 'tenant-id',
});

registerOAuthProvider('clio', {
  clientId: 'clio-client',
  clientSecret: 'clio-secret',
  authorizeEndpoint: 'https://clio.auth',
  tokenEndpoint: 'https://clio.token',
  redirectUri: 'https://myapp.com/callback',
  scopes: ['read'],
});

const config = getOAuthProviderConfig('clio');

registerOAuthProvider('intuit', {
  clientId: 'intuit-client',
  environment: 'sandbox',
  clientSecret: 'intuit-secret',
  authorizeEndpoint: 'https://intuit.auth',
  tokenEndpoint: 'https://intuit.token',
  redirectUri: 'https://myapp.com/callback',
  scopes: ['accounting'],
});

registerOAuthProvider('clio', 'smithlaw', {
  clientId: 'clio-client',
  clientSecret: 'clio-secret',
  authorizeEndpoint: 'https://clio.auth',
  tokenEndpoint: 'https://clio.token',
  redirectUri: 'https://myapp.com/callback',
  scopes: ['read'],
});

registerOAuthProvider('intuit', 'company123', {
  clientId: 'intuit-client',
  environment: 'sandbox',
  clientSecret: 'intuit-secret',
  authorizeEndpoint: 'https://intuit.auth',
  tokenEndpoint: 'https://intuit.token',
  redirectUri: 'https://myapp.com/callback',
  scopes: ['accounting'],
});

registerOAuthProvider('clio', 'joneslaw', {
  clientId: 'clio-client',
  clientSecret: 'clio-secret',
  authorizeEndpoint: 'https://clio.auth',
  tokenEndpoint: 'https://clio.token',
  redirectUri: 'https://myapp.com/callback',
  scopes: ['read'],
});

registerOAuthProvider('intuit', 'company456', {
  clientId: 'intuit-client',
  clientSecret: 'intuit-secret',
  authorizeEndpoint: 'https://intuit.auth',
  tokenEndpoint: 'https://intuit.token',
  redirectUri: 'https://myapp.com/callback',
  scopes: ['accounting'],
  environment: 'sandbox',
});

registerOAuthProvider('azure', 'dev', {
  clientId: 'azure-client',
  clientSecret: 'azure-secret',
  authorizeEndpoint: 'https://azure.auth',
  tokenEndpoint: 'https://azure.token',
  redirectUri: 'https://myapp.com/callback',
  scopes: ['user.read'],
  tenantId: 'tenant-id',
});

const testCases = [
  {
    provider: 'azure' as const,
    cookies: await withEncryptedRefreshToken('azure', {
      azure_access_token: 'abc',
      azure_refresh_token: 'refresh',
      azure_access_token_expires_at: String(now + 60),
      azure_ext_expires_at: String(now + 120),
      azure_token_type: 'Bearer',
    }),
    expected: {
      ext_expires_in: now + 120,
    },
  },
  {
    provider: 'clio' as const,
    cookies: await withEncryptedRefreshToken('clio', {
      clio_access_token: 'abc',
      clio_refresh_token: 'refresh',
      clio_access_token_expires_at: String(now + 60),
      clio_token_type: 'bearer',
    }),
  },
  {
    provider: 'intuit' as const,
    cookies: await withEncryptedRefreshToken('intuit', {
      intuit_access_token: 'abc',
      intuit_refresh_token: 'refresh',
      intuit_access_token_expires_at: String(now + 60),
      intuit_refresh_token_expires_at: String(now + 60),
      intuit_token_type: 'bearer',
    }),
    expected: {
      x_refresh_token_expires_in: now + 60,
    },
  },
];

describe('oAuthTokensAreValid', () => {
  beforeEach(() => {
    mockedGetCookie.mockReset();
  });

  it.each(testCases)(
    'returns valid token structure for $provider',
    async ({ provider, cookies, expected }) => {
      mockedGetCookie.mockImplementation(
        (_, key: string) => cookies[key as keyof typeof cookies],
      );

      const event = createMockEvent();
      const result = await oAuthTokensAreValid(event, provider);

      expect(result).toBeTruthy();
      expect(result).not.toBe(false);
      if (result === false) {
        throw new Error('Result is false');
      }

      expect(result.status).toBe('valid');
      expect(result.tokens).toMatchObject({
        access_token: 'abc',
        refresh_token: 'refresh',
        expires_in: expect.any(Number),
        ...(expected ?? {}),
      });
    },
  );

  it('returns false if both access_token and refresh_token are missing', async () => {
    mockedGetCookie.mockReturnValue(undefined);
    const event = createMockEvent();
    const result = await oAuthTokensAreValid(event, 'clio');
    expect(result).toBe(false);
  });

  it('returns expired status when access_token is missing but refresh_token exists (enables refresh flow)', async () => {
    // This is a critical test: when access_token cookie is missing (e.g., expired/deleted)
    // but refresh_token exists, we should return 'expired' status to trigger token refresh
    // instead of returning false which would cause a 401 error.
    const cookies = await withEncryptedRefreshToken('clio', {
      // Note: clio_access_token is intentionally missing
      clio_refresh_token: 'valid-refresh-token',
      // expires_at is also missing since access_token doesn't exist
    });

    mockedGetCookie.mockImplementation(
      (_, key) => cookies[key as keyof typeof cookies],
    );

    const event = createMockEvent();
    const result = await oAuthTokensAreValid(event, 'clio');

    // Should NOT return false - should return expired status to enable refresh
    expect(result).not.toBe(false);
    if (result === false) throw new Error('Result should not be false');

    expect(result.status).toBe('expired');
    expect(result.tokens.access_token).toBe(''); // Empty access token
    expect(result.tokens.refresh_token).toBe('valid-refresh-token'); // Decrypted refresh token
  });

  it('returns expired status if access token is expired', async () => {
    const expiredNow = String(now - 60);
    const cookies = await withEncryptedRefreshToken('clio', {
      clio_access_token: 'abc',
      clio_refresh_token: 'refresh',
      clio_access_token_expires_at: expiredNow,
      clio_client_id: 'client123',
      clio_token_type: 'bearer',
    });

    mockedGetCookie.mockImplementation(
      (_, key) => cookies[key as keyof typeof cookies],
    );

    const event = createMockEvent();
    const result = await oAuthTokensAreValid(event, 'clio');

    if (result === false) throw new Error('Result is false');

    expect(result.status).toBe('expired');
  });

  it('returns false if token_type does not match expected', async () => {
    const event = createMockEvent();
    setCookie(event, 'clio_access_token', 'a');
    setCookie(event, 'clio_refresh_token', await config.encrypt('r')); // ✅ encrypt here
    setCookie(
      event,
      'clio_access_token_expires_at',
      `${Math.floor(Date.now() / 1000) + 3600}`,
    );
    setCookie(event, 'clio_token_type', 'Bearer'); // should be lowercase
    setCookie(event, 'clio_client_id', 'abc');

    const result = await oAuthTokensAreValid(event, 'clio');
    expect(result).toBe(false);
  });

  it('returns expired status if expiry is in the past', async () => {
    const expiredNow = `${Math.floor(Date.now() / 1000) - 100}`;
    const cookies = await withEncryptedRefreshToken('clio', {
      clio_access_token: 'a',
      clio_refresh_token: 'r',
      clio_access_token_expires_at: expiredNow,
      clio_token_type: 'bearer',
      clio_client_id: '123',
    });

    mockedGetCookie.mockImplementation(
      (_, key) => cookies[key as keyof typeof cookies],
    );

    const event = createMockEvent();
    const result = await oAuthTokensAreValid(event, 'clio');

    if (result === false) throw new Error('Result was false');

    expect(result.status).toBe('expired');
    expect(result.tokens).toMatchObject({
      access_token: 'a',
      refresh_token: 'r',
    });
  });

  it('skips unknown provider-specific field types gracefully', async () => {
    const provider = 'clio' as const;
    const originalFields = providerConfig[provider].providerSpecificFields;
    providerConfig[provider].providerSpecificFields = [123 as any]; // malformed

    const cookies = await withEncryptedRefreshToken(provider, {
      clio_access_token: 'abc',
      clio_refresh_token: 'refresh',
      clio_access_token_expires_at: String(now + 60),
      clio_token_type: 'bearer',
      clio_client_id: 'xyz',
    });

    mockedGetCookie.mockImplementation(
      (_, key) => cookies[key as keyof typeof cookies],
    );

    const event = createMockEvent();
    const result = await oAuthTokensAreValid(event, provider);

    expect(result).toBeTruthy();
    if (result === false) throw new Error('Result was false');
    expect(result.status).toBe('valid');

    providerConfig[provider].providerSpecificFields = originalFields;
  });

  it('correctly reads plain string provider-specific fields', async () => {
    const provider = 'clio' as const;
    const originalFields = providerConfig[provider].providerSpecificFields;
    providerConfig[provider].providerSpecificFields = ['token_type'];

    const cookies = await withEncryptedRefreshToken(provider, {
      clio_access_token: 'abc',
      clio_refresh_token: 'refresh',
      clio_access_token_expires_at: String(now + 60),
      clio_token_type: 'bearer',
    });

    mockedGetCookie.mockImplementation(
      (_, key) => cookies[key as keyof typeof cookies],
    );

    const event = createMockEvent();
    const result = await oAuthTokensAreValid(event, provider);

    expect(result).toBeTruthy();
    if (result === false)
      throw new Error('Expected valid tokens but got false');

    expect(result.status).toBe('valid');
    expect(result.tokens.token_type).toBe('bearer');

    providerConfig[provider].providerSpecificFields = originalFields;
  });

  it('returns expired if refresh token expiry is not a number', async () => {
    const provider = 'intuit' as const;
    const originalValidate =
      providerConfig[provider].validateRefreshTokenExpiry ?? false;
    providerConfig[provider].validateRefreshTokenExpiry = true;

    const cookies = await withEncryptedRefreshToken(provider, {
      intuit_access_token: 'abc',
      intuit_refresh_token: 'refresh',
      intuit_access_token_expires_at: String(now + 60),
      intuit_refresh_token_expires_at: 'not-a-number',
      intuit_token_type: 'bearer',
    });

    mockedGetCookie.mockImplementation(
      (_, key) => cookies[key as keyof typeof cookies],
    );

    const event = createMockEvent();
    const result = await oAuthTokensAreValid(event, provider);

    expect(result).toEqual({
      tokens: {
        access_token: 'abc',
        refresh_token: 'refresh',
        expires_in: expect.any(Number),
      },
      status: 'expired',
    });

    providerConfig[provider].validateRefreshTokenExpiry = originalValidate;
  });

  it('returns false when validateRefreshTokenExpiry is true but refreshExpiresAt cookie does not exist', async () => {
    const provider = 'intuit' as const;
    const originalValidate =
      providerConfig[provider].validateRefreshTokenExpiry ?? false;
    providerConfig[provider].validateRefreshTokenExpiry = true;

    // Create cookies WITHOUT the refresh_token_expires_at cookie
    const cookies = await withEncryptedRefreshToken(provider, {
      intuit_access_token: 'abc',
      intuit_refresh_token: 'refresh',
      intuit_access_token_expires_at: String(now + 60),
      intuit_token_type: 'bearer',
      // Note: intuit_refresh_token_expires_at is intentionally missing
    });

    mockedGetCookie.mockImplementation(
      (_, key) => cookies[key as keyof typeof cookies],
    );

    const event = createMockEvent();
    const result = await oAuthTokensAreValid(event, provider);

    // Should return false because refreshExpiresAt doesn't exist (line 618: if (!refreshExpiresAt) return false;)
    expect(result).toBe(false);

    providerConfig[provider].validateRefreshTokenExpiry = originalValidate;
  });

  it('returns false when provider-specific fields are missing (additionalFields === false)', async () => {
    const provider = 'azure' as const;
    const originalFields = providerConfig[provider].providerSpecificFields;

    // Temporarily configure azure to require a provider-specific field
    providerConfig[provider].providerSpecificFields = ['ext_expires_in'];

    // Create cookies with core fields but WITHOUT the required provider-specific field
    const cookies = await withEncryptedRefreshToken(provider, {
      azure_access_token: 'abc',
      azure_refresh_token: 'refresh',
      azure_access_token_expires_at: String(now + 60),
      azure_token_type: 'Bearer',
      // Note: azure_ext_expires_at is intentionally missing
    });

    mockedGetCookie.mockImplementation(
      (_, key) => cookies[key as keyof typeof cookies],
    );

    const event = createMockEvent();
    const result = await oAuthTokensAreValid(event, provider);

    // Should return false because getProviderCookieFields returns false when required cookies are missing
    expect(result).toBe(false);

    // Restore original configuration
    providerConfig[provider].providerSpecificFields = originalFields;
  });

  describe('with instanceKey (scoped providers)', () => {
    it('returns valid tokens when instanceKey is provided and scoped cookies exist', async () => {
      const provider = 'clio' as const;
      const instanceKey = 'smithlaw';

      // Create cookies with scoped provider key format: "clio:smithlaw_*"
      const scopedCookies = await withEncryptedRefreshToken(
        `${provider}:${instanceKey}` as any,
        {
          [`${provider}:${instanceKey}_access_token`]: 'scoped-access-token',
          [`${provider}:${instanceKey}_refresh_token`]: 'scoped-refresh-token',
          [`${provider}:${instanceKey}_access_token_expires_at`]: String(
            now + 60,
          ),
          [`${provider}:${instanceKey}_token_type`]: 'bearer',
          [`${provider}:${instanceKey}_client_id`]: 'scoped-client-id',
        },
      );

      mockedGetCookie.mockImplementation(
        (_, key) => scopedCookies[key as keyof typeof scopedCookies],
      );

      const event = createMockEvent();
      const result = await oAuthTokensAreValid(event, provider, instanceKey);

      expect(result).toBeTruthy();
      if (result === false) throw new Error('Result was false');

      expect(result.status).toBe('valid');
      expect(result.tokens).toMatchObject({
        access_token: 'scoped-access-token',
        refresh_token: 'scoped-refresh-token',
        expires_in: expect.any(Number),
      });
    });

    it('returns false when instanceKey is provided but scoped cookies do not exist', async () => {
      const provider = 'clio' as const;
      const instanceKey = 'smithlaw';

      // Create cookies for global provider (without instanceKey)
      const globalCookies = await withEncryptedRefreshToken(provider, {
        clio_access_token: 'global-access-token',
        clio_refresh_token: 'global-refresh-token',
        clio_access_token_expires_at: String(now + 60),
        clio_token_type: 'bearer',
      });

      mockedGetCookie.mockImplementation(
        (_, key) => globalCookies[key as keyof typeof globalCookies],
      );

      const event = createMockEvent();
      const result = await oAuthTokensAreValid(event, provider, instanceKey);

      // Should return false because it's looking for "clio:smithlaw_*" cookies but only "clio_*" exist
      expect(result).toBe(false);
    });

    it('returns expired status for scoped provider when access token is expired', async () => {
      const { registerOAuthProvider } = useOAuthRegistry('a'.repeat(64));
      registerOAuthProvider('azure', {
        clientId: 'azure-client',
        clientSecret: 'azure-secret',
        authorizeEndpoint: 'https://azure.auth',
        tokenEndpoint: 'https://azure.token',
        redirectUri: 'https://myapp.com/callback',
        scopes: ['user.read'],
        tenantId: 'tenant-id',
      });
      const provider = 'azure' as const;
      const instanceKey = 'dev';
      const expiredTime = String(now - 60);

      const scopedCookies = await withEncryptedRefreshToken(
        `${provider}:${instanceKey}` as any,
        {
          [`${provider}:${instanceKey}_access_token`]: 'expired-scoped-token',
          [`${provider}:${instanceKey}_refresh_token`]: 'scoped-refresh',
          [`${provider}:${instanceKey}_access_token_expires_at`]: expiredTime,
          [`${provider}:${instanceKey}_token_type`]: 'Bearer',
          [`${provider}:${instanceKey}_ext_expires_at`]: String(now + 120),
        },
      );

      mockedGetCookie.mockImplementation(
        (_, key) => scopedCookies[key as keyof typeof scopedCookies],
      );

      const event = createMockEvent();
      const result = await oAuthTokensAreValid(event, provider, instanceKey);

      if (result === false) throw new Error('Result was false');

      expect(result.status).toBe('expired');
      expect(result.tokens).toMatchObject({
        access_token: 'expired-scoped-token',
        refresh_token: 'scoped-refresh',
        expires_in: expect.any(Number),
      });
    });

    it('validates refresh token expiry for scoped intuit provider', async () => {
      const provider = 'intuit' as const;
      const instanceKey = 'company123';
      const originalValidate =
        providerConfig[provider].validateRefreshTokenExpiry ?? false;
      providerConfig[provider].validateRefreshTokenExpiry = true;

      const scopedCookies = await withEncryptedRefreshToken(
        `${provider}:${instanceKey}` as any,
        {
          [`${provider}:${instanceKey}_access_token`]: 'scoped-intuit-token',
          [`${provider}:${instanceKey}_refresh_token`]: 'scoped-refresh',
          [`${provider}:${instanceKey}_access_token_expires_at`]: String(
            now + 60,
          ),
          [`${provider}:${instanceKey}_refresh_token_expires_at`]: String(
            now + 3600,
          ),
          [`${provider}:${instanceKey}_token_type`]: 'bearer',
          [`${provider}:${instanceKey}_realm_id`]: 'scoped-realm-123',
        },
      );

      mockedGetCookie.mockImplementation(
        (_, key) => scopedCookies[key as keyof typeof scopedCookies],
      );

      const event = createMockEvent();
      const result = await oAuthTokensAreValid(event, provider, instanceKey);

      expect(result).toBeTruthy();
      if (result === false) throw new Error('Result was false');

      expect(result.status).toBe('valid');
      expect(result.tokens).toMatchObject({
        access_token: 'scoped-intuit-token',
        refresh_token: 'scoped-refresh',
        expires_in: expect.any(Number),
        x_refresh_token_expires_in: now + 3600,
      });

      providerConfig[provider].validateRefreshTokenExpiry = originalValidate;
    });

    it('returns false when scoped intuit provider has missing refresh token expiry', async () => {
      const provider = 'intuit' as const;
      const instanceKey = 'company456';
      const originalValidate =
        providerConfig[provider].validateRefreshTokenExpiry ?? false;
      providerConfig[provider].validateRefreshTokenExpiry = true;

      // Create scoped cookies WITHOUT refresh_token_expires_at
      const scopedCookies = await withEncryptedRefreshToken(
        `${provider}:${instanceKey}` as any,
        {
          [`${provider}:${instanceKey}_access_token`]: 'scoped-intuit-token',
          [`${provider}:${instanceKey}_refresh_token`]: 'scoped-refresh',
          [`${provider}:${instanceKey}_access_token_expires_at`]: String(
            now + 60,
          ),
          [`${provider}:${instanceKey}_token_type`]: 'bearer',
          // Note: refresh_token_expires_at is intentionally missing
        },
      );

      mockedGetCookie.mockImplementation(
        (_, key) => scopedCookies[key as keyof typeof scopedCookies],
      );

      const event = createMockEvent();
      const result = await oAuthTokensAreValid(event, provider, instanceKey);

      // Should return false because scoped refresh expiry cookie doesn't exist
      expect(result).toBe(false);

      providerConfig[provider].validateRefreshTokenExpiry = originalValidate;
    });

    it('handles different instanceKeys for the same provider independently', async () => {
      const provider = 'clio' as const;

      // Create cookies for "smithlaw" instance
      const smithlawCookies = await withEncryptedRefreshToken(
        `${provider}:smithlaw` as any,
        {
          [`${provider}:smithlaw_access_token`]: 'smithlaw-token',
          [`${provider}:smithlaw_refresh_token`]: 'smithlaw-refresh',
          [`${provider}:smithlaw_access_token_expires_at`]: String(now + 60),
          [`${provider}:smithlaw_token_type`]: 'bearer',
        },
      );

      // Create cookies for "joneslaw" instance
      const joneslawCookies = await withEncryptedRefreshToken(
        `${provider}:joneslaw` as any,
        {
          [`${provider}:joneslaw_access_token`]: 'joneslaw-token',
          [`${provider}:joneslaw_refresh_token`]: 'joneslaw-refresh',
          [`${provider}:joneslaw_access_token_expires_at`]: String(now + 120),
          [`${provider}:joneslaw_token_type`]: 'bearer',
        },
      );

      const allCookies = { ...smithlawCookies, ...joneslawCookies };

      mockedGetCookie.mockImplementation(
        (_, key) => allCookies[key as keyof typeof allCookies],
      );

      const event = createMockEvent();

      // Test smithlaw instance
      const smithlawResult = await oAuthTokensAreValid(
        event,
        provider,
        'smithlaw',
      );
      expect(smithlawResult).toBeTruthy();
      if (smithlawResult === false)
        throw new Error('Smithlaw result was false');
      expect(smithlawResult.tokens.access_token).toBe('smithlaw-token');

      // Test joneslaw instance
      const joneslawResult = await oAuthTokensAreValid(
        event,
        provider,
        'joneslaw',
      );
      expect(joneslawResult).toBeTruthy();
      if (joneslawResult === false)
        throw new Error('Joneslaw result was false');
      expect(joneslawResult.tokens.access_token).toBe('joneslaw-token');
    });
  });
});
