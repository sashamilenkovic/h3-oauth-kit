import type {
  OAuthProvider,
  ProviderConfig,
  KnownOAuthProvider,
} from './types';

// Known provider configurations
const knownProviderConfig: {
  [P in KnownOAuthProvider]: ProviderConfig<P>;
} = {
  azure: {
    baseCookieFields: [
      'access_token',
      'refresh_token',
      'access_token_expires_at',
    ],
    providerSpecificFields: [
      {
        key: 'ext_expires_in',
        cookieName: 'azure_ext_expires_at',
        setter: (value) =>
          String(Math.floor(Date.now() / 1000) + Number(value)),
      },
    ],
    callbackQueryFields: ['session_state', 'id_token'],
  },
  clio: {
    baseCookieFields: [
      'access_token',
      'refresh_token',
      'access_token_expires_at',
    ],
    providerSpecificFields: [],
  },
  intuit: {
    baseCookieFields: [
      'access_token',
      'refresh_token',
      'access_token_expires_at',
    ],
    providerSpecificFields: [
      {
        key: 'x_refresh_token_expires_in',
        cookieName: 'intuit_refresh_token_expires_at',
        setter: (value) =>
          String(Math.floor(Date.now() / 1000) + Number(value)),
      },
    ],
    callbackQueryFields: ['realmId'],
    validateRefreshTokenExpiry: true,
  },
  mycase: {
    baseCookieFields: [
      'access_token',
      'refresh_token',
      'access_token_expires_at',
    ],
    providerSpecificFields: [],
  },
};

// Default configuration for custom/generic OAuth providers
const defaultProviderConfig: ProviderConfig<any> = {
  baseCookieFields: [
    'access_token',
    'refresh_token',
    'access_token_expires_at',
  ],
  providerSpecificFields: [],
};

/**
 * Gets the provider-specific configuration for cookie fields and callback query fields.
 * Returns a default configuration for custom providers not explicitly defined.
 *
 * @param provider - The OAuth provider key
 * @returns The provider configuration
 */
export function getProviderConfig<P extends OAuthProvider>(
  provider: P,
): ProviderConfig<P> {
  return (
    (knownProviderConfig as Record<string, ProviderConfig<any>>)[provider] ||
    defaultProviderConfig
  );
}

// Export the known provider config for backward compatibility
export const providerConfig = knownProviderConfig;
