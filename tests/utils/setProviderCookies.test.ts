import type { OAuthProvider } from '../../src/types';
import type { Mock } from 'vitest';

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { setProviderCookies } from '../../src/utils';
import { createMockEvent } from '../utils';
import { providerConfig } from '../../src/providerConfig';
import { decrypt } from '../../src/utils/encryption';

vi.mock('h3', async () => {
  const actual = await vi.importActual<typeof import('h3')>('h3');
  return {
    ...actual,
    setCookie: vi.fn(),
  };
});

import { setCookie } from 'h3';

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

describe('setProviderCookies', () => {
  const originalClioFields = [...providerConfig.clio.providerSpecificFields];

  beforeEach(() => {
    (setCookie as unknown as Mock).mockClear();
    providerConfig.clio.providerSpecificFields = ['token_type'];
  });

  afterEach(() => {
    providerConfig.clio.providerSpecificFields = originalClioFields;
  });

  it.each(cases)(
    'writes cookies for $provider (scoped=$instanceKey) and returns full token',
    ({ provider, tokens, expectedCookies, instanceKey }) => {
      const event = createMockEvent();

      const result = setProviderCookies(
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
          expect(decrypt(cookie!.value)).toBe(expectedValue);
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

  it('respects custom cookieOptions', () => {
    const event = createMockEvent();
    const tokens = {
      access_token: 'Bearer custom123',
      refresh_token: 'refreshCustom',
      token_type: 'bearer' as const,
      expires_in: 1234,
      client_id: 'abc',
    };

    setProviderCookies(
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

  it("stores raw access_token if it lacks 'Bearer' prefix", () => {
    const event = createMockEvent();
    const tokens = {
      access_token: 'abc123',
      refresh_token: 'refresh123',
      token_type: 'bearer' as const,
      expires_in: 3600,
      client_id: 'client-xyz',
    };

    setProviderCookies(event, tokens, 'clio');

    const accessCookie = (setCookie as unknown as Mock).mock.calls.find(
      ([, name]) => name === 'clio_access_token',
    );

    expect(accessCookie?.[2]).toBe('abc123');
  });

  it('applies custom field setter', () => {
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

    setProviderCookies(event, tokens, 'clio');

    const customCookie = (setCookie as unknown as Mock).mock.calls.find(
      ([, name]) => name === 'clio_custom_id',
    );

    expect(customCookie?.[2]).toBe('x_789');
  });

  it('writes cookies using scoped key format', () => {
    const event = createMockEvent();
    const tokens = {
      access_token: 'Bearer scoped123',
      refresh_token: 'scopedRefresh',
      token_type: 'bearer' as const,
      expires_in: 3600,
      client_id: 'abc',
    };

    setProviderCookies(event, tokens, 'clio', undefined, 'smithlaw');

    const access = (setCookie as unknown as Mock).mock.calls.find(
      ([, name]) => name === 'clio:smithlaw_access_token',
    );
    const refresh = (setCookie as unknown as Mock).mock.calls.find(
      ([, name]) => name === 'clio:smithlaw_refresh_token',
    );

    expect(access?.[2]).toBe('scoped123');
    expect(decrypt(refresh?.[2]!)).toBe('scopedRefresh');
  });

  it('applies Intuit x_refresh_token_expires_in setter to create absolute timestamp', () => {
    const event = createMockEvent();

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

    setProviderCookies(event, tokens, 'intuit');

    // Find the cookie that should be set by the x_refresh_token_expires_in setter
    const refreshExpiresCookie = (setCookie as unknown as Mock).mock.calls.find(
      ([, name]) => name === 'intuit_refresh_token_expires_at',
    );

    // Calculate expected value: current timestamp (in seconds) + expires_in
    const expectedTimestamp = String(Math.floor(mockNow / 1000) + 8640000);

    expect(refreshExpiresCookie?.[2]).toBe(expectedTimestamp);

    // Restore original Date.now
    Date.now = originalDateNow;
  });

  it('skips setting cookies when token field value is undefined', () => {
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

    setProviderCookies(event, tokens, 'clio');

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

  it('handles structured fields with and without cookieName (testing resolveProviderFieldMeta)', () => {
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

    setProviderCookies(event, tokens, 'clio');

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
});
