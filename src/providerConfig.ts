import type { OAuthProvider, ProviderConfig } from './types';

export const providerConfig: {
  [P in OAuthProvider]: ProviderConfig<P>;
} = {
  azure: {
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
    providerSpecificFields: [],
  },
  intuit: {
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
