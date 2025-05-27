import type { OAuthProvider, ProviderConfig } from './types';

export const providerConfig: {
  [P in OAuthProvider]: ProviderConfig<P>;
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
};
