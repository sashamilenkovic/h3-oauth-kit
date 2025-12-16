import type { OAuthProvider } from '../../src/types';
import type { Mock } from 'vitest';

import {
  describe,
  it,
  expect,
  vi,
  beforeEach,
  afterEach,
  beforeAll,
} from 'vitest';
import { setProviderCookies } from '../../src/utils';
import { createMockEvent } from '../utils';
import { providerConfig } from '../../src/providerConfig';

vi.mock('h3', async () => {
  const actual = await vi.importActual<typeof import('h3')>('h3');
  return {
    ...actual,
    setCookie: vi.fn(),
  };
});

import { setCookie } from 'h3';
import { getOAuthProviderConfig, useOAuthRegistry } from '../../src';

const cases = [
  {
    provider: 'clio' as const,
    instanceKey: undefined,
    tokens: {
      access_token: 'Bearer abc123',
      refresh_token: 'refresh123',
      token_type: 'bearer',
      expires_in: 3600,
      client_id: 'client-xyz',
    },
    expectedCookies: [
      ['clio_access_token', 'abc123'],
      ['clio_refresh_token', 'refresh123'],
      ['clio_access_token_expires_at', expect.any(String)],
      ['clio_token_type', 'bearer'],
    ],
  },
  {
    provider: 'azure' as const,
    instanceKey: 'dev',
    tokens: {
      access_token: 'Bearer xyz987',
      refresh_token: 'refresh456',
      token_type: 'bearer',
      expires_in: 7200,
      ext_expires_in: 10800,
    },
    expectedCookies: [
      ['azure:dev_access_token', 'xyz987'],
      ['azure:dev_refresh_token', 'refresh456'],
      ['azure:dev_access_token_expires_at', expect.any(String)],
      ['azure:dev_ext_expires_at', expect.any(String)],
    ],
  },
];

let clioConfig: ReturnType<typeof getOAuthProviderConfig>;
let smithlawConfig: ReturnType<typeof getOAuthProviderConfig>;

describe('setProviderCookies', () => {
  const originalClioFields = [...providerConfig.clio.providerSpecificFields];

  beforeEach(() => {
    (setCookie as unknown as Mock).mockClear();
    providerConfig.clio.providerSpecificFields = ['token_type'];
  });

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

    registerOAuthProvider('azure', {
      clientId: 'test',
      clientSecret: 'test',
      authorizeEndpoint: 'test',
      tokenEndpoint: 'test',
      redirectUri: 'test',
      scopes: ['test'],
      tenantId: 'test',
    });

    registerOAuthProvider('azure', 'dev', {
      clientId: 'test',
      clientSecret: 'test',
      authorizeEndpoint: 'test',
      tokenEndpoint: 'test',
      redirectUri: 'test',
      scopes: ['test'],
      tenantId: 'test',
    });

    registerOAuthProvider('azure', 'smithlaw', {
      clientId: 'test',
      clientSecret: 'test',
      authorizeEndpoint: 'test',
      tokenEndpoint: 'test',
      redirectUri: 'test',
      scopes: ['test'],
      tenantId: 'test',
    });

    registerOAuthProvider('clio', 'smithlaw', {
      clientId: 'test',
      clientSecret: 'test',
      authorizeEndpoint: 'test',
      tokenEndpoint: 'test',
      redirectUri: 'test',
      scopes: ['test'],
    });

    registerOAuthProvider('intuit', {
      clientId: 'test',
      clientSecret: 'test',
      authorizeEndpoint: 'test',
      tokenEndpoint: 'test',
      redirectUri: 'test',
      scopes: ['test'],
      environment: 'sandbox',
    });

    registerOAuthProvider('clio', 'custom', {
      clientId: 'test',
      clientSecret: 'test',
      authorizeEndpoint: 'test',
      tokenEndpoint: 'test',
      redirectUri: 'test',
      scopes: ['test'],
    });

    clioConfig = getOAuthProviderConfig('clio');
    smithlawConfig = getOAuthProviderConfig('clio', 'smithlaw');
  });

  afterEach(() => {
    providerConfig.clio.providerSpecificFields = originalClioFields;
  });

  it.each(cases)(
    'writes cookies for $provider (scoped=$instanceKey) and returns full token',
    async ({ provider, tokens, expectedCookies, instanceKey }) => {
      const event = createMockEvent();

      const result = await setProviderCookies(
        event,
        tokens as any,
        provider as OAuthProvider,
        undefined,
        instanceKey,
      );

      const cookieCalls = (setCookie as unknown as Mock).mock.calls.map(
        ([_, name, value, options]) => ({ name, value, options }),
      );

      for (const [expectedName, expectedValue] of expectedCookies) {
        const cookie = cookieCalls.find((c) => c.name === expectedName);

        if (expectedName.endsWith('_access_token')) {
          const raw = tokens.access_token;
          const stripped = raw.startsWith('Bearer ') ? raw.slice(7) : raw;
          expect(cookie?.value).toBe(stripped);
        } else if (expectedName.endsWith('_refresh_token')) {
          expect(typeof cookie?.value).toBe('string');
          expect(await clioConfig.decrypt(cookie!.value)).toBe(expectedValue);
        } else {
          expect(cookie?.value).toEqual(expectedValue);
        }

        expect(cookie?.options).toMatchObject({
          httpOnly: true,
          secure: true,
          sameSite: 'lax',
          path: '/',
        });
      }

      expect(result).toEqual(tokens);
    },
  );

  it('respects custom cookieOptions', async () => {
    const event = createMockEvent();
    const tokens = {
      access_token: 'Bearer custom123',
      refresh_token: 'refreshCustom',
      token_type: 'bearer' as const,
      expires_in: 1234,
      client_id: 'abc',
    };

    await setProviderCookies(
      event,
      tokens,
      'clio',
      { sameSite: 'none', path: '/auth' },
      'custom',
    );

    const cookieCalls = (setCookie as unknown as Mock).mock.calls;

    for (const [, , , options] of cookieCalls) {
      expect(options).toMatchObject({
        httpOnly: true,
        secure: true,
        sameSite: 'none',
        path: '/auth',
      });
    }
  });

  it("stores raw access_token if it lacks 'Bearer' prefix", async () => {
    const event = createMockEvent();
    const tokens = {
      access_token: 'abc123',
      refresh_token: 'refresh123',
      token_type: 'bearer' as const,
      expires_in: 3600,
      client_id: 'client-xyz',
    };

    await setProviderCookies(event, tokens, 'clio');

    const accessCookie = (setCookie as unknown as Mock).mock.calls.find(
      ([, name]) => name === 'clio_access_token',
    );

    expect(accessCookie?.[2]).toBe('abc123');
  });

  it('applies custom field setter', async () => {
    const event = createMockEvent();

    providerConfig.clio.providerSpecificFields = [
      {
        key: 'client_id',
        cookieName: 'clio_custom_id',
        setter: (val) => `x_${val}`,
      },
    ];

    const tokens = {
      access_token: 'Bearer test',
      refresh_token: 'refresh',
      expires_in: 3600,
      token_type: 'bearer' as const,
      client_id: '789',
    };

    await setProviderCookies(event, tokens, 'clio');

    const customCookie = (setCookie as unknown as Mock).mock.calls.find(
      ([, name]) => name === 'clio_custom_id',
    );

    expect(customCookie?.[2]).toBe('x_789');
  });

  it('writes cookies using scoped key format', async () => {
    const event = createMockEvent();
    const tokens = {
      access_token: 'Bearer scoped123',
      refresh_token: 'scopedRefresh',
      token_type: 'bearer' as const,
      expires_in: 3600,
      client_id: 'abc',
    };

    await setProviderCookies(event, tokens, 'clio', undefined, 'smithlaw');

    const access = (setCookie as unknown as Mock).mock.calls.find(
      ([, name]) => name === 'clio:smithlaw_access_token',
    );
    const refresh = (setCookie as unknown as Mock).mock.calls.find(
      ([, name]) => name === 'clio:smithlaw_refresh_token',
    );

    expect(access?.[2]).toBe('scoped123');
    expect(await smithlawConfig.decrypt(refresh?.[2]!)).toBe('scopedRefresh');
  });

  it('applies Intuit x_refresh_token_expires_in setter to create absolute timestamp', async () => {
    const event = createMockEvent();

    // Save and override provider config for this test
    const originalFields = [...providerConfig.intuit.providerSpecificFields];
    providerConfig.intuit.providerSpecificFields = [
      {
        key: 'x_refresh_token_expires_in',
        cookieName: 'intuit_refresh_token_expires_at',
        setter: (val) => String(Math.floor(Date.now() / 1000) + Number(val)),
      },
      // ...other fields as needed
    ];

    // Mock Date.now() to return a fixed timestamp for predictable testing
    const mockNow = 1640995200000; // 2022-01-01 00:00:00 UTC
    const originalDateNow = Date.now;
    Date.now = vi.fn(() => mockNow);

    const tokens = {
      access_token: 'Bearer intuit123',
      refresh_token: 'intuitRefresh',
      token_type: 'bearer' as const,
      expires_in: 3600,
      realm_id: 'realm123',
      x_refresh_token_expires_in: 8640000, // 100 days in seconds
    };

    await setProviderCookies(event, tokens, 'intuit');

    // Find the cookie that should be set by the x_refresh_token_expires_in setter
    const refreshExpiresCookie = (setCookie as unknown as Mock).mock.calls.find(
      ([, name]) => name === 'intuit_refresh_token_expires_at',
    );

    // Calculate expected value: current timestamp (in seconds) + expires_in
    const expectedTimestamp = String(Math.floor(mockNow / 1000) + 8640000);

    expect(refreshExpiresCookie?.[2]).toBe(expectedTimestamp);

    // Restore original Date.now and provider config
    Date.now = originalDateNow;
    providerConfig.intuit.providerSpecificFields = originalFields;
  });

  it('skips setting cookies when token field value is undefined', async () => {
    const event = createMockEvent();

    // Configure provider to expect a field that will be undefined
    providerConfig.clio.providerSpecificFields = [
      'token_type',
      'client_id', // This will be undefined in our test tokens
    ];

    const tokens = {
      access_token: 'Bearer test123',
      refresh_token: 'refresh123',
      token_type: 'bearer' as const,
      expires_in: 3600,
      // client_id is intentionally omitted (undefined)
    } as any; // Use 'as any' to allow undefined client_id for testing

    await setProviderCookies(event, tokens, 'clio');

    const cookieCalls = (setCookie as unknown as Mock).mock.calls;

    // Should find token_type cookie
    const tokenTypeCookie = cookieCalls.find(
      ([, name]) => name === 'clio_token_type',
    );
    expect(tokenTypeCookie).toBeDefined();
    expect(tokenTypeCookie?.[2]).toBe('bearer');

    // Should NOT find client_id cookie since it was undefined
    const clientIdCookie = cookieCalls.find(
      ([, name]) => name === 'clio_client_id',
    );
    expect(clientIdCookie).toBeUndefined();
  });

  it('handles structured fields with and without cookieName (testing resolveProviderFieldMeta)', async () => {
    const event = createMockEvent();

    // Configure provider with mixed structured fields - some with cookieName, some without
    providerConfig.clio.providerSpecificFields = [
      {
        key: 'client_id',
        cookieName: 'clio_custom_client_cookie', // Has custom cookieName
      },
      {
        key: 'realm_id',
        // No cookieName - should fallback to default format
      },
      {
        key: 'expires_duration',
        cookieName: 'clio_custom_expires_cookie', // Has custom cookieName
        setter: (value: string) => `transformed_${value}`,
      },
    ] as any; // Use 'as any' to allow testing with custom field keys

    const tokens = {
      access_token: 'Bearer test123',
      refresh_token: 'refresh123',
      token_type: 'bearer' as const,
      expires_in: 3600,
      client_id: 'client-abc',
      realm_id: 'realm-xyz',
      expires_duration: '7200',
    };

    await setProviderCookies(event, tokens, 'clio');

    const cookieCalls = (setCookie as unknown as Mock).mock.calls;

    // Should use custom cookieName when defined
    const customClientCookie = cookieCalls.find(
      ([, name]) => name === 'clio_custom_client_cookie',
    );
    expect(customClientCookie).toBeDefined();
    expect(customClientCookie?.[2]).toBe('client-abc');

    // Should use fallback format when cookieName is undefined
    const defaultRealmCookie = cookieCalls.find(
      ([, name]) => name === 'clio_realm_id',
    );
    expect(defaultRealmCookie).toBeDefined();
    expect(defaultRealmCookie?.[2]).toBe('realm-xyz');

    // Should use custom cookieName with setter when both are defined
    const customExpiresCookie = cookieCalls.find(
      ([, name]) => name === 'clio_custom_expires_cookie',
    );
    expect(customExpiresCookie).toBeDefined();
    expect(customExpiresCookie?.[2]).toBe('transformed_7200');
  });

  it('never creates malformed cookie names when instanceKey is undefined', async () => {
    const event = createMockEvent();
    const tokens = {
      access_token: 'Bearer test-token',
      refresh_token: 'test-refresh',
      token_type: 'bearer' as const,
      expires_in: 3600,
      ext_expires_in: 7200,
      scope: 'read write',
      id_token: 'test-id-token',
    };

    // This should create cookies with "azure_" prefix, not "azure:azure_"
    await setProviderCookies(event, tokens, 'azure', undefined, undefined);

    const cookieCalls = (setCookie as unknown as Mock).mock.calls;
    const cookieNames = cookieCalls.map(([, name]) => name);

    // Verify no cookie names have the malformed "azure:azure_" pattern
    expect(cookieNames).not.toContain('azure:azure_access_token');
    expect(cookieNames).not.toContain('azure:azure_refresh_token');
    expect(cookieNames).not.toContain('azure:azure_access_token_expires_at');

    // Verify correct cookie names are used
    expect(cookieNames).toContain('azure_access_token');
    expect(cookieNames).toContain('azure_refresh_token');
    expect(cookieNames).toContain('azure_access_token_expires_at');
  });

  it('creates properly scoped cookie names when instanceKey is provided', async () => {
    const event = createMockEvent();
    const tokens = {
      access_token: 'Bearer scoped-token',
      refresh_token: 'scoped-refresh',
      token_type: 'bearer' as const,
      expires_in: 3600,
      ext_expires_in: 7200,
      scope: 'read write',
      id_token: 'scoped-id-token',
    };

    await setProviderCookies(event, tokens, 'azure', undefined, 'smithlaw');

    const cookieCalls = (setCookie as unknown as Mock).mock.calls;
    const cookieNames = cookieCalls.map(([, name]) => name);

    // Verify correct scoped cookie names are used
    expect(cookieNames).toContain('azure:smithlaw_access_token');
    expect(cookieNames).toContain('azure:smithlaw_refresh_token');
    expect(cookieNames).toContain('azure:smithlaw_access_token_expires_at');

    // Verify no unscoped names are created
    expect(cookieNames).not.toContain('azure_access_token');
    expect(cookieNames).not.toContain('azure_refresh_token');
    expect(cookieNames).not.toContain('azure_access_token_expires_at');
  });

  it('sets access_token and expires_at cookies with 30-day maxAge to enable token refresh', async () => {
    const event = createMockEvent();
    const tokens = {
      access_token: 'Bearer test-token',
      refresh_token: 'test-refresh',
      token_type: 'bearer' as const,
      expires_in: 3600, // 1 hour token lifetime
    };

    await setProviderCookies(event, tokens, 'clio');

    const cookieCalls = (setCookie as unknown as Mock).mock.calls;
    const thirtyDaysInSeconds = 30 * 24 * 60 * 60;

    // Find the access_token cookie and verify it has 30-day maxAge
    const accessTokenCookie = cookieCalls.find(
      ([, name]) => name === 'clio_access_token',
    );
    expect(accessTokenCookie).toBeDefined();
    expect(accessTokenCookie?.[3]?.maxAge).toBe(thirtyDaysInSeconds);

    // Find the expires_at cookie and verify it also has 30-day maxAge
    const expiresAtCookie = cookieCalls.find(
      ([, name]) => name === 'clio_access_token_expires_at',
    );
    expect(expiresAtCookie).toBeDefined();
    expect(expiresAtCookie?.[3]?.maxAge).toBe(thirtyDaysInSeconds);

    // The refresh_token cookie should also have 30-day maxAge (default)
    const refreshTokenCookie = cookieCalls.find(
      ([, name]) => name === 'clio_refresh_token',
    );
    expect(refreshTokenCookie).toBeDefined();
    expect(refreshTokenCookie?.[3]?.maxAge).toBe(thirtyDaysInSeconds);
  });
});
