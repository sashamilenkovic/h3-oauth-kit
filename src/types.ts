import type { H3Event, H3EventContext } from "h3";

export type OAuthProvider = "azure" | "clio" | "intuit";

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
  environment: "sandbox" | "production";
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
  token_type: "Bearer" | "bearer";
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
  token_type: "bearer";
}

export interface ClioRefreshTokenResponse {
  access_token: string;
  token_type: "bearer";
  expires_in: number;
}

export interface AzureRefreshTokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: "Bearer";
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
  status: "valid" | "expired";
};

export type AzureTokenValidationResult = TokenValidationResult<"azure">;
export type ClioTokenValidationResult = TokenValidationResult<"clio">;
export type IntuitTokenValidationResult = TokenValidationResult<"intuit">;

export type ProviderAccessTokenKeys<Providers extends OAuthProvider[]> =
  `${Providers[number]}_access_token`;

export type AugmentedContext<Providers extends OAuthProvider[]> = RequiredPick<
  H3EventContext,
  ProviderAccessTokenKeys<Providers>
> & {
  h3OAuthKit: {
    [P in Providers[number]]: OAuthProviderTokenMap[P];
  };
};

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
  refreshToken: string
) => {
  url: string;
  params: Record<string, string>;
};

export type OAuthStateValue =
  | string
  | Record<string, unknown>
  | ((event: H3Event) => string | Record<string, unknown>);

export type OAuthParsedState = Record<string, string>;

export interface CookieOptionsOverride {
  sameSite?: "lax" | "none";
  path?: string;
}

export interface HandleOAuthCallbackOptions {
  redirect?: boolean;
  redirectTo?: string;
  cookieOptions?: CookieOptionsOverride;
}

export interface ProtectedRouteOptions {
  cookieOptions?: CookieOptionsOverride;
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
  providerSpecificFields: TokenField<P>[];
  callbackQueryFields?: (keyof OAuthCallbackQuery<P>)[];
  validateRefreshTokenExpiry?: boolean;
}
