import { describe, it, expect, vi, beforeEach } from 'vitest';
import { getProviderCookieFields } from '../../src/utils';
import { createMockEvent } from '../utils';
import { providerConfig } from '../../src/providerConfig';
import type { OAuthProvider } from '../../src/types';

vi.mock('h3', async () => {
  const actual = await vi.importActual<typeof import('h3')>('h3');
  return {
    ...actual,
    getCookie: vi.fn(),
  };
});

import { getCookie } from 'h3';

const mockGetCookie = vi.mocked(getCookie);

describe('getProviderCookieFields', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('parses numeric cookie values as numbers (testing parseTokenField)', () => {
    const event = createMockEvent();
    const fakeProvider = 'fake' as OAuthProvider;

    // Configure provider with fields that will have numeric values
    providerConfig[fakeProvider] = {
      providerSpecificFields: [
        'expires_in', // This will be a numeric string
        'token_type', // This will be a regular string
        {
          key: 'custom_duration',
          cookieName: 'fake_custom_duration',
        },
      ],
    } as any;

    // Mock cookie values - some numeric strings, some regular strings
    mockGetCookie.mockImplementation((_, cookieName) => {
      switch (cookieName) {
        case 'fake_expires_in':
          return '3600'; // Numeric string - should be parsed as number
        case 'fake_token_type':
          return 'bearer'; // Regular string - should stay as string
        case 'fake_custom_duration':
          return '7200'; // Numeric string - should be parsed as number
        default:
          return undefined;
      }
    });

    const result = getProviderCookieFields(event, fakeProvider, 'fake');

    expect(result).toEqual({
      expires_in: 3600, // Should be parsed as number
      token_type: 'bearer', // Should remain as string
      custom_duration: 7200, // Should be parsed as number
    });
  });

  it('keeps non-numeric strings as strings (testing parseTokenField)', () => {
    const event = createMockEvent();
    const fakeProvider = 'fake' as OAuthProvider;

    providerConfig[fakeProvider] = {
      providerSpecificFields: [
        'client_id',
        'scope',
        {
          key: 'realm_id',
          cookieName: 'fake_realm_id',
        },
      ],
    } as any;

    // Mock cookie values with various string formats
    mockGetCookie.mockImplementation((_, cookieName) => {
      switch (cookieName) {
        case 'fake_client_id':
          return 'abc123def'; // Alphanumeric - should stay as string
        case 'fake_scope':
          return 'read write'; // String with spaces - should stay as string
        case 'fake_realm_id':
          return 'realm-456-xyz'; // String with dashes - should stay as string
        default:
          return undefined;
      }
    });

    const result = getProviderCookieFields(event, fakeProvider, 'fake');

    expect(result).toEqual({
      client_id: 'abc123def', // Should remain as string
      scope: 'read write', // Should remain as string
      realm_id: 'realm-456-xyz', // Should remain as string
    });
  });

  it('handles mixed numeric and string values (testing parseTokenField)', () => {
    const event = createMockEvent();
    const fakeProvider = 'fake' as OAuthProvider;

    providerConfig[fakeProvider] = {
      providerSpecificFields: [
        'expires_in', // Will be numeric
        'client_id', // Will be string
        'refresh_expires_in', // Will be numeric
        'token_type', // Will be string
      ],
    } as any;

    mockGetCookie.mockImplementation((_, cookieName) => {
      switch (cookieName) {
        case 'fake_expires_in':
          return '3600'; // Pure numeric string
        case 'fake_client_id':
          return 'client_abc123'; // Mixed alphanumeric
        case 'fake_refresh_expires_in':
          return '86400'; // Pure numeric string
        case 'fake_token_type':
          return 'Bearer'; // String
        default:
          return undefined;
      }
    });

    const result = getProviderCookieFields(event, fakeProvider, 'fake');

    expect(result).toEqual({
      expires_in: 3600, // Parsed as number
      client_id: 'client_abc123', // Remains as string
      refresh_expires_in: 86400, // Parsed as number
      token_type: 'Bearer', // Remains as string
    });
  });

  it('handles edge cases for numeric parsing (testing parseTokenField)', () => {
    const event = createMockEvent();
    const fakeProvider = 'fake' as OAuthProvider;

    providerConfig[fakeProvider] = {
      providerSpecificFields: [
        'zero_value',
        'negative_looking',
        'decimal_looking',
        'leading_zeros',
        'mixed_chars',
      ],
    } as any;

    mockGetCookie.mockImplementation((_, cookieName) => {
      switch (cookieName) {
        case 'fake_zero_value':
          return '0'; // Should be parsed as number 0
        case 'fake_negative_looking':
          return '-123'; // Contains dash, should stay as string (regex is ^\d+$)
        case 'fake_decimal_looking':
          return '123.45'; // Contains decimal, should stay as string
        case 'fake_leading_zeros':
          return '0123'; // Leading zeros, should be parsed as number 123
        case 'fake_mixed_chars':
          return '123abc'; // Mixed, should stay as string
        default:
          return undefined;
      }
    });

    const result = getProviderCookieFields(event, fakeProvider, 'fake');

    expect(result).toEqual({
      zero_value: 0, // Parsed as number
      negative_looking: '-123', // Remains as string (regex doesn't match negative)
      decimal_looking: '123.45', // Remains as string (regex doesn't match decimals)
      leading_zeros: 123, // Parsed as number (parseInt handles leading zeros)
      mixed_chars: '123abc', // Remains as string
    });
  });

  it('returns false when any required cookie is missing', () => {
    const event = createMockEvent();
    const fakeProvider = 'fake' as OAuthProvider;

    providerConfig[fakeProvider] = {
      providerSpecificFields: ['field1', 'field2'],
    } as any;

    // Mock only one cookie, leaving the other missing
    mockGetCookie.mockImplementation((_, cookieName) => {
      return cookieName === 'fake_field1' ? 'value1' : undefined;
    });

    const result = getProviderCookieFields(event, fakeProvider, 'fake');

    expect(result).toBe(false);
  });

  it('works with scoped provider keys', () => {
    const event = createMockEvent();
    const fakeProvider = 'fake' as OAuthProvider;

    providerConfig[fakeProvider] = {
      providerSpecificFields: [
        'expires_in',
        {
          key: 'realm_id',
          cookieName: 'fake_realm_id',
        },
      ],
    } as any;

    // Mock cookies with scoped prefix
    mockGetCookie.mockImplementation((_, cookieName) => {
      switch (cookieName) {
        case 'fake:instance123_expires_in':
          return '1800'; // Should be parsed as number
        case 'fake:instance123_realm_id':
          return 'realm-scoped-456'; // Should remain as string
        default:
          return undefined;
      }
    });

    const result = getProviderCookieFields(
      event,
      fakeProvider,
      'fake:instance123',
    );

    expect(result).toEqual({
      expires_in: 1800, // Parsed as number
      realm_id: 'realm-scoped-456', // Remains as string
    });
  });

  it('returns empty object when provider has no specific fields', () => {
    const event = createMockEvent();
    const fakeProvider = 'fake' as OAuthProvider;

    // Configure provider with no specific fields
    providerConfig[fakeProvider] = {
      providerSpecificFields: [],
    } as any;

    const result = getProviderCookieFields(event, fakeProvider, 'fake');

    expect(result).toEqual({});
  });
});
