import type { H3Event } from 'h3';

export type OAuthProvider = 'azure' | 'clio' | 'intuit';

export type RequiredPick<T, K extends keyof T> = {
  [P in K]-?: NonNullable<T[P]>;
};

export interface BaseOAuthProviderConfig {
  clientId: string;
  clientSecret: string;
  authorizeEndpoint: string;
  tokenEndpoint: string;
  redirectUri: string;
  scopes: string[];
  encrypt: (text: string) => Promise<string>;
  decrypt: (encryptedText: string) => Promise<string>;
  meEndpoint?: string;
}

export type OAuthProviderConfig =
  | AzureOAuthProviderConfig
  | ClioOAuthProviderConfig
  | IntuitOAuthProviderConfig;

export interface AzureOAuthProviderConfig extends BaseOAuthProviderConfig {
  tenantId: string;
}

export interface ClioOAuthProviderConfig extends BaseOAuthProviderConfig {}

export interface IntuitOAuthProviderConfig extends BaseOAuthProviderConfig {
  environment: 'sandbox' | 'production';
}

export interface OAuthCodeExchangeInput {
  code: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  tokenEndpoint: string;
  scope?: string;
}

export interface OAuthTokenBase {
  access_token: string;
  refresh_token?: string;
  expires_in: number;
  token_type: 'Bearer' | 'bearer';
}

export type AzureAuthTokens = OAuthTokenBase & {
  ext_expires_in: number;
  scope: string;
  id_token: string;
};

export type ClioAuthTokens = OAuthTokenBase & {
  client_id: string;
};

export type IntuitAuthTokens = OAuthTokenBase & {
  realm_id: string;
  x_refresh_token_expires_in: number;
};

export type OAuthTokens = AzureAuthTokens | ClioAuthTokens | IntuitAuthTokens;

export interface AzureCookies {
  azure_access_token: string;
  azure_refresh_token: string;
  azure_access_token_expires_at: string;
  azure_ext_expires_in: string;
  azure_tenant_id: string;
}

export interface ClioCookies {
  clio_access_token: string;
  clio_refresh_token: string;
  clio_access_token_expires_at: string;
  clio_client_id: string;
}

export interface IntuitCookies {
  intuit_access_token: string;
  intuit_refresh_token: string;
  intuit_access_token_expires_at: string;
  intuit_refresh_token_expires_at: string;
  intuit_realm_id: string;
}

export interface IntuitRefreshTokenResponse {
  expires_in: number;
  access_token: string;
  refresh_token: string;
  x_refresh_token_expires_in: number;
  token_type: 'bearer';
}

export interface ClioRefreshTokenResponse {
  access_token: string;
  token_type: 'bearer';
  expires_in: number;
}

export interface AzureRefreshTokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: 'Bearer';
  expires_in: number;
  ext_expires_in: number;
}

export type OAuthProviderTokenMap = {
  azure: AzureAuthTokens;
  clio: ClioAuthTokens;
  intuit: IntuitAuthTokens;
};

// Add a type to help with token assignment
export type ProviderToken<T extends OAuthProvider> = OAuthProviderTokenMap[T];

// Update the token validation result to use TokenResponse
export type TokenValidationResult<T extends OAuthProvider> = {
  tokens: OAuthProviderTokenMap[T];
  status: 'valid' | 'expired';
};

export type AzureTokenValidationResult = TokenValidationResult<'azure'>;
export type ClioTokenValidationResult = TokenValidationResult<'clio'>;
export type IntuitTokenValidationResult = TokenValidationResult<'intuit'>;

export type OAuthProviderConfigMap = {
  azure: AzureOAuthProviderConfig;
  clio: ClioOAuthProviderConfig;
  intuit: IntuitOAuthProviderConfig;
};

export type RefreshTokenResponseMap = {
  azure: AzureRefreshTokenResponse;
  clio: ClioRefreshTokenResponse;
  intuit: IntuitRefreshTokenResponse;
};

export type RefreshTokenResponse<T extends OAuthProvider> =
  RefreshTokenResponseMap[T];

export type RefreshTokenConfig<T extends OAuthProvider> =
  OAuthProviderConfigMap[T];

export type RefreshTokenConfigBuilder<T extends OAuthProvider> = (
  config: RefreshTokenConfig<T>,
  refreshToken: string,
) => {
  url: string;
  params: Record<string, string>;
};

export type OAuthState = {
  csrf: string;
  [key: string]: unknown;
};

export type OAuthParsedState = {
  csrf: string;
  providerKey: string;
  instanceKey?: string;
  [key: string]: string | undefined;
};

export type OAuthStateValue =
  | Partial<OAuthState>
  | ((event: H3Event) => Partial<OAuthState>);

export interface CookieOptionsOverride {
  sameSite?: 'lax' | 'none';
  path?: string;
}

export interface HandleOAuthCallbackOptions {
  redirect?: boolean;
  redirectTo?: string;
  cookieOptions?: CookieOptionsOverride;
}

export interface ProtectedRouteOptions<_InstanceKeys extends string = never> {
  cookieOptions?: CookieOptionsOverride;
  onAuthFailure?: (
    event: H3Event,
    provider: OAuthProvider,
    reason:
      | 'missing-or-invalid-tokens'
      | 'token-refresh-failed'
      | 'error-occurred',
    error: unknown,
  ) => Promise<unknown> | unknown;
}

// Add new interface for login options
export interface OAuthLoginOptions {
  redirect?: boolean;
  state?: OAuthStateValue;
  preserveInstance?: boolean;
}

export interface OAuthErrorResponse {
  error?: string;
  error_description?: string;
}

export interface BaseOAuthCookies {
  access_token: string;
  refresh_token: string;
  access_token_expires_at: string;
}

export interface AzureTokenCookies extends BaseOAuthCookies {}

export interface ClioTokenCookies extends BaseOAuthCookies {}

export interface IntuitTokenCookies extends BaseOAuthCookies {
  refresh_token_expires_at: string;
}

export type BaseOAuthCallbackQuery = {
  code?: string;
  state?: string;
  error?: string;
  error_description?: string;
};

export interface AzureOAuthCallbackQuery extends BaseOAuthCallbackQuery {
  session_state: string;
  id_token: string;
}

export interface IntuitOAuthCallbackQuery extends BaseOAuthCallbackQuery {
  realmId: string;
}

export interface ClioOAuthCallbackQuery extends BaseOAuthCallbackQuery {}

export type OAuthCallbackQueryMap = {
  intuit: IntuitOAuthCallbackQuery;
  clio: ClioOAuthCallbackQuery;
  azure: AzureOAuthCallbackQuery;
};

export type OAuthCallbackQuery<P extends OAuthProvider> =
  OAuthCallbackQueryMap[P];

export interface StoredTokenCookiesBase {
  access_token: string;
  refresh_token: string;
  access_token_expires_at: string;
}

export type ProviderFieldValue<P extends OAuthProvider> =
  OAuthProviderTokenMap[P][keyof OAuthProviderTokenMap[P]];

export type TokenField<P extends OAuthProvider> =
  | keyof OAuthProviderTokenMap[P]
  | {
      key: keyof OAuthProviderTokenMap[P];
      cookieName?: string;
      setter?: (value: string) => string;
    };

export interface ProviderConfig<P extends OAuthProvider> {
  baseCookieFields: (keyof BaseOAuthCookies)[];
  providerSpecificFields: TokenField<P>[];
  callbackQueryFields?: (keyof OAuthCallbackQuery<P>)[];
  validateRefreshTokenExpiry?: boolean;
}

export interface OAuthErrorResponse {
  error?: string;
  error_description?: string;
}

export type ExtractInstanceKey<P> = P extends { instanceKey: infer I }
  ? I
  : undefined;

export type ScopedProvider =
  | { provider: OAuthProvider; instanceKey: string }
  | {
      provider: OAuthProvider;
      instanceResolver: (
        event: H3Event,
      ) => string | undefined | Promise<string | undefined>;
    }
  | {
      provider: OAuthProvider;
      instanceResolver: (
        event: H3Event,
      ) => string | undefined | Promise<string | undefined>;
      __instanceKeys: readonly string[];
    };

export type GetProviderKey<P> = P extends string
  ? P
  : P extends { provider: infer T; instanceKey: infer I }
  ? I extends string
    ? `${T & string}:${I & string}`
    : never
  : P extends { provider: infer T; __instanceKeys: readonly (infer K)[] }
  ? K extends string
    ? `${T & string}:${K}` | (T & string)
    : T & string
  : P extends { provider: infer T; instanceResolver: unknown }
  ? T & string // For instanceResolver without explicit keys, we can only know the base provider at compile time
  : never;

export type ProviderId<P> = P extends string
  ? P
  : P extends { provider: infer Prov }
  ? Prov extends OAuthProvider
    ? Prov
    : never
  : never;

export type AugmentedContext<
  Defs extends (OAuthProvider | ScopedProvider)[],
  _InstanceKeys extends string = never,
> = {
  h3OAuthKit: {
    [P in Defs[number] as GetProviderKey<P>]: OAuthProviderTokenMap[ProviderId<P>];
  };
};

export type ExtractProvider<P> = P extends { provider: infer T } ? T : P;

export type NormalizedProviders<
  T extends (
    | OAuthProvider
    | { provider: OAuthProvider; instanceKey?: string }
  )[],
> = {
  [K in keyof T]: T[K] extends OAuthProvider ? { provider: T[K] } : T[K];
};

export type TokenFor<P extends OAuthProvider> = OAuthProviderTokenMap[P];

export type LogoutProvider = {
  provider: OAuthProvider;
  instanceKey?: string;
};

export type LogoutResult = {
  loggedOut: true;
  providers: LogoutProvider[];
};

export type LogoutProviderInput =
  | OAuthProvider
  | { provider: OAuthProvider; instanceKey?: string };

export type InputBaseOAuthProviderConfig = Omit<
  BaseOAuthProviderConfig,
  'encrypt' | 'decrypt'
>;

export interface InputAzureOAuthProviderConfig
  extends Omit<AzureOAuthProviderConfig, 'encrypt' | 'decrypt'> {}
export interface InputClioOAuthProviderConfig
  extends Omit<ClioOAuthProviderConfig, 'encrypt' | 'decrypt'> {}
export interface InputIntuitOAuthProviderConfig
  extends Omit<IntuitOAuthProviderConfig, 'encrypt' | 'decrypt'> {}

export type InputOAuthProviderConfigMap = {
  azure: InputAzureOAuthProviderConfig;
  clio: InputClioOAuthProviderConfig;
  intuit: InputIntuitOAuthProviderConfig;
};
