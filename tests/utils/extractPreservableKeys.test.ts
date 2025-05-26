import { describe, it, expect, beforeEach } from 'vitest';
import { normalizeRefreshedToken } from '../../src/utils';
import { providerConfig } from '../../src/providerConfig';
import type {
  TokenField,
  OAuthProviderTokenMap,
  RefreshTokenResponse,
} from '../../src/types';

describe('extractPreservableKeys (via normalizeRefreshedToken)', () => {
  beforeEach(() => {
    // Reset provider configs to avoid test interference
  });

  it('extracts keys from simple string fields', () => {
    const provider = 'clio' as const;
    const originalFields = providerConfig[provider].providerSpecificFields;

    // Configure simple string fields
    providerConfig[provider].providerSpecificFields = [
      'client_id',
      'token_type',
    ] as TokenField<'clio'>[];

    const previousToken: OAuthProviderTokenMap['clio'] = {
      access_token: 'old-access',
      refresh_token: 'old-refresh',
      expires_in: 3600,
      token_type: 'bearer',
      client_id: 'preserved-client-id',
    };

    const refreshedToken: RefreshTokenResponse<'clio'> = {
      access_token: 'new-access',
      token_type: 'bearer',
      expires_in: 7200,
    };

    const result = normalizeRefreshedToken(
      provider,
      refreshedToken,
      previousToken,
    );

    // Should preserve the simple string fields from previous token
    expect(result).toMatchObject({
      access_token: 'new-access',
      token_type: 'bearer',
      expires_in: 7200,
      client_id: 'preserved-client-id', // preserved from previous
    });

    // Restore original config
    providerConfig[provider].providerSpecificFields = originalFields;
  });

  it('extracts keys from structured token fields', () => {
    const provider = 'intuit' as const;
    const originalFields = providerConfig[provider].providerSpecificFields;

    // Configure structured fields (this tests isStructuredTokenField logic)
    providerConfig[provider].providerSpecificFields = [
      {
        key: 'x_refresh_token_expires_in',
        cookieName: 'intuit_refresh_token_expires_at',
        setter: (value) =>
          String(Math.floor(Date.now() / 1000) + Number(value)),
      },
      {
        key: 'realm_id',
        cookieName: 'intuit_realm_id',
      },
    ] as TokenField<'intuit'>[];

    const previousToken: OAuthProviderTokenMap['intuit'] = {
      access_token: 'old-access',
      refresh_token: 'old-refresh',
      expires_in: 3600,
      token_type: 'bearer',
      x_refresh_token_expires_in: 1234567890,
      realm_id: 'preserved-realm-123',
    };

    const refreshedToken: RefreshTokenResponse<'intuit'> = {
      access_token: 'new-access',
      refresh_token: 'new-refresh',
      token_type: 'bearer',
      expires_in: 7200,
      x_refresh_token_expires_in: 9876543210,
    };

    const result = normalizeRefreshedToken(
      provider,
      refreshedToken,
      previousToken,
    );

    // Should preserve structured fields from previous token (including x_refresh_token_expires_in)
    expect(result).toMatchObject({
      access_token: 'new-access',
      refresh_token: 'new-refresh',
      token_type: 'bearer',
      expires_in: 7200,
      x_refresh_token_expires_in: 1234567890, // preserved from previous token
      realm_id: 'preserved-realm-123', // preserved from previous
    });

    // Restore original config
    providerConfig[provider].providerSpecificFields = originalFields;
  });

  it('handles mixed array of simple strings and structured fields', () => {
    const provider = 'azure' as const;
    const originalFields = providerConfig[provider].providerSpecificFields;

    // Configure mixed fields
    providerConfig[provider].providerSpecificFields = [
      'scope', // simple string
      {
        key: 'ext_expires_in',
        cookieName: 'azure_ext_expires_at',
        setter: (value) =>
          String(Math.floor(Date.now() / 1000) + Number(value)),
      }, // structured field
      'id_token', // simple string
    ] as TokenField<'azure'>[];

    const previousToken: OAuthProviderTokenMap['azure'] = {
      access_token: 'old-access',
      refresh_token: 'old-refresh',
      expires_in: 3600,
      token_type: 'Bearer',
      ext_expires_in: 1234567890,
      scope: 'preserved-scope',
      id_token: 'preserved-id-token',
    };

    const refreshedToken: RefreshTokenResponse<'azure'> = {
      access_token: 'new-access',
      refresh_token: 'new-refresh',
      token_type: 'Bearer',
      expires_in: 7200,
      ext_expires_in: 9876543210,
    };

    const result = normalizeRefreshedToken(
      provider,
      refreshedToken,
      previousToken,
    );

    // Should preserve both simple and structured fields
    expect(result).toMatchObject({
      access_token: 'new-access',
      refresh_token: 'new-refresh',
      token_type: 'Bearer',
      expires_in: 7200,
      ext_expires_in: 1234567890, // preserved from previous token
      scope: 'preserved-scope', // preserved simple field
      id_token: 'preserved-id-token', // preserved simple field
    });

    // Restore original config
    providerConfig[provider].providerSpecificFields = originalFields;
  });

  it('handles empty provider-specific fields array', () => {
    const provider = 'clio' as const;
    const originalFields = providerConfig[provider].providerSpecificFields;

    // Configure empty fields (this is the default for clio)
    providerConfig[provider].providerSpecificFields = [];

    const previousToken: OAuthProviderTokenMap['clio'] = {
      access_token: 'old-access',
      refresh_token: 'old-refresh',
      expires_in: 3600,
      token_type: 'bearer',
      client_id: 'should-not-be-preserved',
    };

    const refreshedToken: RefreshTokenResponse<'clio'> = {
      access_token: 'new-access',
      token_type: 'bearer',
      expires_in: 7200,
    };

    const result = normalizeRefreshedToken(
      provider,
      refreshedToken,
      previousToken,
    );

    // Should not preserve any provider-specific fields
    expect(result).toEqual({
      access_token: 'new-access',
      token_type: 'bearer',
      expires_in: 7200,
      refresh_token: 'old-refresh', // refresh_token is preserved by default logic
    });

    // Restore original config
    providerConfig[provider].providerSpecificFields = originalFields;
  });

  it('handles structured field with only key property', () => {
    const provider = 'intuit' as const;
    const originalFields = providerConfig[provider].providerSpecificFields;

    // Configure structured field with minimal properties
    providerConfig[provider].providerSpecificFields = [
      {
        key: 'realm_id',
      },
    ] as TokenField<'intuit'>[];

    const previousToken: OAuthProviderTokenMap['intuit'] = {
      access_token: 'old-access',
      refresh_token: 'old-refresh',
      expires_in: 3600,
      token_type: 'bearer',
      x_refresh_token_expires_in: 1234567890,
      realm_id: 'preserved-realm-456',
    };

    const refreshedToken: RefreshTokenResponse<'intuit'> = {
      access_token: 'new-access',
      refresh_token: 'new-refresh',
      token_type: 'bearer',
      expires_in: 7200,
      x_refresh_token_expires_in: 9876543210,
    };

    const result = normalizeRefreshedToken(
      provider,
      refreshedToken,
      previousToken,
    );

    // Should preserve the structured field with minimal config
    expect(result).toMatchObject({
      access_token: 'new-access',
      refresh_token: 'new-refresh',
      token_type: 'bearer',
      expires_in: 7200,
      x_refresh_token_expires_in: 9876543210,
      realm_id: 'preserved-realm-456', // preserved from previous
    });

    // Restore original config
    providerConfig[provider].providerSpecificFields = originalFields;
  });
});
