import { describe, it, expect } from 'vitest';
import { getProviderCookieKeys } from '../../src/utils';
import { providerConfig } from '../../src/providerConfig';
import type { OAuthProvider } from '../../src/types';

describe('getProviderCookieKeys', () => {
  it('returns correct keys for azure', () => {
    expect(getProviderCookieKeys('azure')).toEqual([
      'azure_access_token',
      'azure_refresh_token',
      'azure_access_token_expires_at',
      'azure_ext_expires_at',
    ]);
  });

  it('returns correct keys for clio', () => {
    expect(getProviderCookieKeys('clio')).toEqual([
      'clio_access_token',
      'clio_refresh_token',
      'clio_access_token_expires_at',
    ]);
  });

  it('returns correct keys for intuit', () => {
    expect(getProviderCookieKeys('intuit')).toEqual([
      'intuit_access_token',
      'intuit_refresh_token',
      'intuit_access_token_expires_at',
      'intuit_refresh_token_expires_at',
    ]);
  });

  it('handles string-based field correctly', () => {
    const fakeProvider = 'fake' as OAuthProvider;
    providerConfig[fakeProvider] = {
      baseCookieFields: [
        'access_token',
        'refresh_token',
        'access_token_expires_at',
      ],
      providerSpecificFields: ['custom_field'],
    } as any;

    const result = getProviderCookieKeys(fakeProvider);
    expect(result).toEqual([
      'fake_access_token',
      'fake_refresh_token',
      'fake_access_token_expires_at',
      'fake_custom_field',
    ]);
  });

  it('handles structured field objects with custom cookieName', () => {
    const fakeProvider = 'fake' as OAuthProvider;
    providerConfig[fakeProvider] = {
      baseCookieFields: [
        'access_token',
        'refresh_token',
        'access_token_expires_at',
      ],
      providerSpecificFields: [
        {
          key: 'realm_id',
          cookieName: 'fake_custom_realm_cookie',
        },
        {
          key: 'expires_duration',
          cookieName: 'fake_expires_at',
          setter: (value: string) => String(Date.now() + Number(value)),
        },
      ],
    } as any;

    const result = getProviderCookieKeys(fakeProvider);
    expect(result).toEqual([
      'fake_access_token',
      'fake_refresh_token',
      'fake_access_token_expires_at',
      'fake_custom_realm_cookie',
      'fake_expires_at',
    ]);
  });

  it('handles structured field objects without custom cookieName (fallback to key)', () => {
    const fakeProvider = 'fake' as OAuthProvider;
    providerConfig[fakeProvider] = {
      baseCookieFields: [
        'access_token',
        'refresh_token',
        'access_token_expires_at',
      ],
      providerSpecificFields: [
        {
          key: 'client_id',
          // No cookieName provided, should fallback to "fake_client_id"
        },
        {
          key: 'scope',
          setter: (value: string) => value.toUpperCase(),
          // No cookieName provided, should fallback to "fake_scope"
        },
      ],
    } as any;

    const result = getProviderCookieKeys(fakeProvider);
    expect(result).toEqual([
      'fake_access_token',
      'fake_refresh_token',
      'fake_access_token_expires_at',
      'fake_client_id',
      'fake_scope',
    ]);
  });

  it('handles scoped provider with structured fields', () => {
    const fakeProvider = 'fake' as OAuthProvider;
    providerConfig[fakeProvider] = {
      baseCookieFields: [
        'access_token',
        'refresh_token',
        'access_token_expires_at',
      ],
      providerSpecificFields: [
        'simple_field',
        {
          key: 'realm_id',
          cookieName: 'fake_realm_cookie',
        },
        {
          key: 'client_id',
          // No cookieName, should use fallback
        },
      ],
    } as any;

    const result = getProviderCookieKeys(fakeProvider, 'instance123');
    expect(result).toEqual([
      'fake:instance123_access_token',
      'fake:instance123_refresh_token',
      'fake:instance123_access_token_expires_at',
      'fake:instance123_simple_field',
      'fake:instance123_realm_cookie',
      'fake:instance123_client_id',
    ]);
  });
});
