import type { H3Event } from 'h3';

// Base known providers
export type KnownOAuthProvider = 'azure' | 'clio' | 'intuit' | 'mycase';

// Allow module augmentation for custom providers
export interface CustomOAuthProviders {}

// Combined type that includes both known and custom providers
export type OAuthProvider =
  | KnownOAuthProvider
  | keyof CustomOAuthProviders
  | (string & {});

export type RequiredPick<T, K extends keyof T> = {
  [P in K]-?: NonNullable<T[P]>;
};

export interface OAuthProviderHooks<P extends OAuthProvider = OAuthProvider> {
  onLogin?: (
    event: H3Event,
    tokens: OAuthProviderTokenMap[P],
    provider: P,
    instanceKey?: string,
  ) => Promise<void> | void;
  onTokenRefresh?: (
    event: H3Event,
    oldTokens: OAuthProviderTokenMap[P],
    newTokens: OAuthProviderTokenMap[P],
    provider: P,
    instanceKey?: string,
  ) => Promise<void> | void;
  onTokenExpired?: (
    event: H3Event,
    provider: P,
    instanceKey?: string,
  ) => Promise<void> | void;
  onLogout?: (
    event: H3Event,
    provider: P,
    instanceKey?: string,
  ) => Promise<void> | void;
}

export interface BaseOAuthProviderConfig {
  clientId: string;
  clientSecret: string;
  authorizeEndpoint: string;
  tokenEndpoint: string;
  redirectUri: string;
  scopes: string[];
  encrypt: (text: string) => Promise<string>;
  decrypt: (encryptedText: string) => Promise<string>;
  usePKCE?: boolean;
  userInfoEndpoint?: string;
  revokeEndpoint?: string;
  /** RFC 7662 Token Introspection endpoint */
  introspectionEndpoint?: string;
  /** RFC 8628 Device Authorization endpoint */
  deviceAuthorizationEndpoint?: string;
  hooks?: OAuthProviderHooks;
}

export type OAuthProviderConfig =
  | AzureOAuthProviderConfig
  | ClioOAuthProviderConfig
  | IntuitOAuthProviderConfig
  | MyCaseOAuthProviderConfig
  | GenericOAuthProviderConfig;

export interface MyCaseOAuthProviderConfig extends BaseOAuthProviderConfig {}

export interface AzureOAuthProviderConfig extends BaseOAuthProviderConfig {
  tenantId: string;
}

export interface ClioOAuthProviderConfig extends BaseOAuthProviderConfig {}

export interface IntuitOAuthProviderConfig extends BaseOAuthProviderConfig {
  environment: 'sandbox' | 'production';
}

// Generic provider config for custom OAuth providers (e.g., Google, GitHub, etc.)
export interface GenericOAuthProviderConfig extends BaseOAuthProviderConfig {
  // Custom providers can add additional fields via the config object
  [key: string]: unknown;
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

export type MyCaseAuthTokens = OAuthTokenBase & {
  client_id: string;
};

// Generic token type for custom OAuth providers
export type GenericAuthTokens = OAuthTokenBase & {
  [key: string]: unknown;
};

export type OAuthTokens =
  | AzureAuthTokens
  | ClioAuthTokens
  | IntuitAuthTokens
  | GenericAuthTokens;

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

export interface MyCaseCookies {
  mycase_access_token: string;
  mycase_refresh_token: string;
  mycase_access_token_expires_at: string;
  mycase_client_id: string;
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

export interface MyCaseRefreshTokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: 'bearer';
  expires_in: number;
}

// Generic refresh token response for custom providers
export interface GenericRefreshTokenResponse {
  access_token: string;
  refresh_token?: string;
  token_type: 'Bearer' | 'bearer';
  expires_in: number;
  [key: string]: unknown;
}

// Known provider token map
type KnownProviderTokenMap = {
  azure: AzureAuthTokens;
  clio: ClioAuthTokens;
  intuit: IntuitAuthTokens;
  mycase: MyCaseAuthTokens;
};

// Custom provider token map (extensible via module augmentation)
export interface CustomProviderTokenMap {}

// Combined token map with fallback to generic for unknown providers
export type OAuthProviderTokenMap = KnownProviderTokenMap &
  CustomProviderTokenMap & {
    [K in string]: K extends keyof KnownProviderTokenMap
      ? KnownProviderTokenMap[K]
      : K extends keyof CustomProviderTokenMap
      ? CustomProviderTokenMap[K]
      : GenericAuthTokens;
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

// Known provider config map
type KnownProviderConfigMap = {
  azure: AzureOAuthProviderConfig;
  clio: ClioOAuthProviderConfig;
  intuit: IntuitOAuthProviderConfig;
  mycase: MyCaseOAuthProviderConfig;
};

// Custom provider config map (extensible via module augmentation)
export interface CustomProviderConfigMap {}

// Combined config map with fallback to generic for unknown providers
export type OAuthProviderConfigMap = KnownProviderConfigMap &
  CustomProviderConfigMap & {
    [K in string]: K extends keyof KnownProviderConfigMap
      ? KnownProviderConfigMap[K]
      : K extends keyof CustomProviderConfigMap
      ? CustomProviderConfigMap[K]
      : GenericOAuthProviderConfig;
  };

// Known refresh token response map
type KnownRefreshTokenResponseMap = {
  azure: AzureRefreshTokenResponse;
  clio: ClioRefreshTokenResponse;
  intuit: IntuitRefreshTokenResponse;
  mycase: MyCaseRefreshTokenResponse;
};

// Custom refresh token response map (extensible via module augmentation)
export interface CustomRefreshTokenResponseMap {}

// Combined refresh token response map with fallback to generic
export type RefreshTokenResponseMap = KnownRefreshTokenResponseMap &
  CustomRefreshTokenResponseMap & {
    [K in string]: K extends keyof KnownRefreshTokenResponseMap
      ? KnownRefreshTokenResponseMap[K]
      : K extends keyof CustomRefreshTokenResponseMap
      ? CustomRefreshTokenResponseMap[K]
      : GenericRefreshTokenResponse;
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
  refreshTokenMaxAge?: number;
}

export interface HandleOAuthCallbackOptions {
  redirect?: boolean;
  redirectTo?: string;
  cookieOptions?: CookieOptionsOverride;
}

export interface ProtectedRouteOptions<_InstanceKeys extends string = never> {
  cookieOptions?: CookieOptionsOverride;
  refreshThreshold?: number; // Seconds before expiry to trigger refresh
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

export interface MyCaseOAuthCallbackQuery extends BaseOAuthCallbackQuery {}

// Generic callback query for custom providers
export interface GenericOAuthCallbackQuery extends BaseOAuthCallbackQuery {}

// Known callback query map
type KnownCallbackQueryMap = {
  intuit: IntuitOAuthCallbackQuery;
  clio: ClioOAuthCallbackQuery;
  azure: AzureOAuthCallbackQuery;
  mycase: MyCaseOAuthCallbackQuery;
};

// Custom callback query map (extensible via module augmentation)
export interface CustomCallbackQueryMap {}

// Combined callback query map with fallback to generic
export type OAuthCallbackQueryMap = KnownCallbackQueryMap &
  CustomCallbackQueryMap & {
    [K in string]: K extends keyof KnownCallbackQueryMap
      ? KnownCallbackQueryMap[K]
      : K extends keyof CustomCallbackQueryMap
      ? CustomCallbackQueryMap[K]
      : GenericOAuthCallbackQuery;
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
    [P in Defs[number] as GetProviderKey<P>]: OAuthProviderTokenMap[ProviderId<P>] & {
      userInfo?: OAuthProviderUserInfoMap[ProviderId<P>];
      id_token_claims?: IDTokenClaims;
    };
  };
  h3OAuthKitInstances: ResolvedInstances<Defs>;
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
> & {
  usePKCE?: boolean;
  userInfoEndpoint?: string;
  revokeEndpoint?: string;
  hooks?: OAuthProviderHooks;
};

export interface InputAzureOAuthProviderConfig
  extends Omit<AzureOAuthProviderConfig, 'encrypt' | 'decrypt' | 'hooks'> {
  usePKCE?: boolean;
  userInfoEndpoint?: string;
  revokeEndpoint?: string;
  hooks?: OAuthProviderHooks<'azure'>;
}
export interface InputClioOAuthProviderConfig
  extends Omit<ClioOAuthProviderConfig, 'encrypt' | 'decrypt' | 'hooks'> {
  usePKCE?: boolean;
  userInfoEndpoint?: string;
  revokeEndpoint?: string;
  hooks?: OAuthProviderHooks<'clio'>;
}
export interface InputIntuitOAuthProviderConfig
  extends Omit<IntuitOAuthProviderConfig, 'encrypt' | 'decrypt' | 'hooks'> {
  usePKCE?: boolean;
  userInfoEndpoint?: string;
  revokeEndpoint?: string;
  hooks?: OAuthProviderHooks<'intuit'>;
}
export interface InputMyCaseOAuthProviderConfig
  extends Omit<MyCaseOAuthProviderConfig, 'encrypt' | 'decrypt' | 'hooks'> {
  usePKCE?: boolean;
  userInfoEndpoint?: string;
  revokeEndpoint?: string;
  hooks?: OAuthProviderHooks<'mycase'>;
}
export interface InputGenericOAuthProviderConfig
  extends Omit<GenericOAuthProviderConfig, 'encrypt' | 'decrypt' | 'hooks'> {
  usePKCE?: boolean;
  userInfoEndpoint?: string;
  revokeEndpoint?: string;
  hooks?: OAuthProviderHooks;
}

// Known input config map
type KnownInputProviderConfigMap = {
  azure: InputAzureOAuthProviderConfig;
  clio: InputClioOAuthProviderConfig;
  intuit: InputIntuitOAuthProviderConfig;
  mycase: InputMyCaseOAuthProviderConfig;
};

// Custom input config map (extensible via module augmentation)
export interface CustomInputProviderConfigMap {}

// Combined input config map with fallback to generic
export type InputOAuthProviderConfigMap = KnownInputProviderConfigMap &
  CustomInputProviderConfigMap & {
    [K in string]: K extends keyof KnownInputProviderConfigMap
      ? KnownInputProviderConfigMap[K]
      : K extends keyof CustomInputProviderConfigMap
      ? CustomInputProviderConfigMap[K]
      : InputGenericOAuthProviderConfig;
  };

// Type for resolved instance keys passed to the handler
export type ResolvedInstances<Defs extends (OAuthProvider | ScopedProvider)[]> =
  {
    [K in Defs[number] as ProviderId<K>]: K extends string
      ? undefined
      : K extends { instanceKey: string }
      ? K['instanceKey']
      : K extends { __instanceKeys: readonly (infer T)[] }
      ? T extends string
        ? T
        : undefined
      : undefined;
  };

// OIDC UserInfo standard claims
export interface OIDCUserInfo {
  sub: string; // Subject - unique identifier
  name?: string;
  given_name?: string;
  family_name?: string;
  middle_name?: string;
  nickname?: string;
  preferred_username?: string;
  profile?: string;
  picture?: string;
  website?: string;
  email?: string;
  email_verified?: boolean;
  gender?: string;
  birthdate?: string;
  zoneinfo?: string;
  locale?: string;
  phone_number?: string;
  phone_number_verified?: boolean;
  address?: {
    formatted?: string;
    street_address?: string;
    locality?: string;
    region?: string;
    postal_code?: string;
    country?: string;
  };
  updated_at?: number;
  [key: string]: unknown; // Allow additional provider-specific claims
}

// ID Token standard claims (JWT)
export interface IDTokenClaims {
  iss: string; // Issuer
  sub: string; // Subject
  aud: string | string[]; // Audience
  exp: number; // Expiration time
  iat: number; // Issued at
  auth_time?: number; // Authentication time
  nonce?: string; // Nonce
  acr?: string; // Authentication Context Class Reference
  amr?: string[]; // Authentication Methods References
  azp?: string; // Authorized party
  [key: string]: unknown; // Allow additional claims
}

// Provider-specific userInfo maps (extensible)
export interface CustomProviderUserInfoMap {}

export type OAuthProviderUserInfoMap = {
  [K in OAuthProvider]: K extends keyof CustomProviderUserInfoMap
    ? CustomProviderUserInfoMap[K]
    : OIDCUserInfo;
};

// Token status information
export interface TokenStatus {
  isValid: boolean;
  expiresIn?: number; // seconds until expiry
  expiresAt?: string; // ISO date string
  requiresRefresh: boolean;
  hasRefreshToken: boolean;
  provider: OAuthProvider;
  instanceKey?: string;
}

// ============================================================
// Client Credentials Flow Types (OAuth 2.0 Section 4.4)
// ============================================================

/**
 * Client Credentials token request parameters
 * Used for machine-to-machine authentication (no user involved)
 */
export interface ClientCredentialsTokenRequest {
  grant_type: 'client_credentials';
  client_id: string;
  client_secret: string;
  scope?: string;
}

/**
 * Client Credentials token response
 * Note: No refresh_token is typically issued for client credentials
 */
export interface ClientCredentialsTokenResponse {
  access_token: string;
  token_type: 'Bearer' | 'bearer';
  expires_in: number;
  scope?: string;
  /** Some providers may include additional fields */
  [key: string]: unknown;
}

/**
 * Cached client credentials token with expiration info
 * Used for in-memory caching to avoid unnecessary token requests
 */
export interface CachedClientCredentialsToken {
  access_token: string;
  token_type: 'Bearer' | 'bearer';
  expires_at: number; // Unix timestamp (ms)
  scope?: string;
}

/**
 * Options for fetching client credentials tokens
 */
export interface ClientCredentialsOptions {
  /** OAuth scopes to request. If not provided, uses provider's default scopes */
  scopes?: string[];
  /** Force a new token even if cached token is valid */
  forceRefresh?: boolean;
  /** Instance key for multi-tenant configurations */
  instanceKey?: string;
}

// ============================================================
// Token Introspection Types (RFC 7662)
// ============================================================

/**
 * Token introspection request parameters
 * Used to check if a token is valid and active
 */
export interface TokenIntrospectionRequest {
  token: string;
  token_type_hint?: 'access_token' | 'refresh_token';
  client_id?: string;
  client_secret?: string;
}

/**
 * Token introspection response (RFC 7662 Section 2.2)
 * Contains information about the token's validity and metadata
 */
export interface TokenIntrospectionResponse {
  /** REQUIRED - Boolean indicator of whether or not the token is currently active */
  active: boolean;
  /** OAuth 2.0 scope values for this token */
  scope?: string;
  /** Client identifier for the OAuth 2.0 client that requested this token */
  client_id?: string;
  /** Human-readable identifier for the resource owner who authorized this token */
  username?: string;
  /** Type of the token (e.g., "Bearer") */
  token_type?: string;
  /** Timestamp indicating when the token will expire (seconds since epoch) */
  exp?: number;
  /** Timestamp indicating when the token was issued (seconds since epoch) */
  iat?: number;
  /** Timestamp before which the token MUST NOT be accepted (seconds since epoch) */
  nbf?: number;
  /** Subject of the token - usually a machine-readable identifier */
  sub?: string;
  /** Intended audience of the token */
  aud?: string | string[];
  /** Issuer of the token */
  iss?: string;
  /** JWT ID - unique identifier for the token */
  jti?: string;
  /** Additional provider-specific fields */
  [key: string]: unknown;
}

/**
 * Options for token introspection
 */
export interface IntrospectionOptions {
  /** Instance key for multi-tenant configurations */
  instanceKey?: string;
  /** Hint about the type of token being introspected */
  tokenTypeHint?: 'access_token' | 'refresh_token';
}

// ============================================================
// Device Authorization Flow Types (RFC 8628)
// ============================================================

/**
 * Device authorization request parameters
 * Initiates the device flow
 */
export interface DeviceAuthorizationRequest {
  client_id: string;
  scope?: string;
}

/**
 * Device authorization response (RFC 8628 Section 3.2)
 * Contains codes and URL for user to authorize the device
 */
export interface DeviceAuthorizationResponse {
  /** The device verification code */
  device_code: string;
  /** The end-user verification code (shown to user) */
  user_code: string;
  /** The end-user verification URI on the authorization server */
  verification_uri: string;
  /** Optional: A verification URI that includes the user_code for easier UX */
  verification_uri_complete?: string;
  /** The lifetime in seconds of the device_code and user_code */
  expires_in: number;
  /** The minimum amount of time in seconds the client should wait between polling requests */
  interval?: number;
}

/**
 * Device token request parameters
 * Used to poll for token after user authorization
 */
export interface DeviceTokenRequest {
  grant_type: 'urn:ietf:params:oauth:grant-type:device_code';
  device_code: string;
  client_id: string;
}

/**
 * Device token response
 * Received after successful authorization
 */
export interface DeviceTokenResponse {
  access_token: string;
  token_type: 'Bearer' | 'bearer';
  expires_in: number;
  refresh_token?: string;
  scope?: string;
  /** Additional provider-specific fields */
  [key: string]: unknown;
}

/**
 * Device flow error response (RFC 8628 Section 3.5)
 */
export interface DeviceFlowError {
  error:
    | 'authorization_pending' // User hasn't authorized yet
    | 'slow_down' // Polling too frequently
    | 'access_denied' // User denied authorization
    | 'expired_token' // Device code expired
    | string; // Other OAuth errors
  error_description?: string;
  error_uri?: string;
}

/**
 * Options for initiating device flow
 */
export interface DeviceFlowOptions {
  /** OAuth scopes to request */
  scopes?: string[];
  /** Instance key for multi-tenant configurations */
  instanceKey?: string;
}

/**
 * Options for polling device token
 */
export interface DeviceTokenPollOptions {
  /** Maximum time to wait in seconds (default: 300 = 5 minutes) */
  maxWaitTime?: number;
  /** Custom polling interval in seconds (overrides server's interval) */
  pollInterval?: number;
  /** Instance key for multi-tenant configurations */
  instanceKey?: string;
  /** Callback invoked on each poll attempt */
  onPoll?: (attempt: number, secondsElapsed: number) => void | Promise<void>;
}

// ============================================================
// JWT Validation Types
// ============================================================

/**
 * Standard JWT header fields
 */
export interface JWTHeader {
  /** Algorithm used to sign the JWT (e.g., "RS256", "HS256") */
  alg: string;
  /** Token type, typically "JWT" */
  typ?: string;
  /** Key ID - hints which key was used to sign the JWT */
  kid?: string;
  /** Additional header fields */
  [key: string]: unknown;
}

/**
 * Standard JWT payload/claims
 */
export interface JWTPayload {
  /** Issuer - who created and signed the token */
  iss?: string;
  /** Subject - who the token is about */
  sub?: string;
  /** Audience - who the token is intended for */
  aud?: string | string[];
  /** Expiration time (seconds since epoch) */
  exp?: number;
  /** Not before time (seconds since epoch) */
  nbf?: number;
  /** Issued at time (seconds since epoch) */
  iat?: number;
  /** JWT ID - unique identifier for the token */
  jti?: string;
  /** Additional claims */
  [key: string]: unknown;
}

/**
 * Decoded JWT with header and payload
 */
export interface DecodedJWT {
  header: JWTHeader;
  payload: JWTPayload;
  signature: string;
}

/**
 * Options for JWT validation
 */
export interface JWTValidationOptions {
  /** Expected issuer (iss claim) - can be string or array */
  issuer?: string | string[];
  /** Expected audience (aud claim) - can be string or array */
  audience?: string | string[];
  /** Expected subject (sub claim) */
  subject?: string;
  /** Clock tolerance in seconds for time-based validations (default: 0) */
  clockTolerance?: number;
  /** Validate the JWT signature (default: true) */
  validateSignature?: boolean;
  /** JWKS URI to fetch public keys for signature verification */
  jwksUri?: string;
  /** Allowed signing algorithms (default: ['RS256', 'ES256']) */
  algorithms?: string[];
  /** Maximum token age in seconds (validates iat claim) */
  maxTokenAge?: number;
  /** Custom validation function for additional checks */
  customValidation?: (payload: JWTPayload) => void | Promise<void>;
}

/**
 * JSON Web Key (JWK) structure
 */
export interface JWK {
  /** Key type (e.g., "RSA", "EC") */
  kty: string;
  /** Public key use (e.g., "sig" for signature) */
  use?: string;
  /** Key operations */
  key_ops?: string[];
  /** Algorithm intended for use with the key */
  alg?: string;
  /** Key ID */
  kid?: string;
  /** X.509 certificate chain */
  x5c?: string[];
  /** X.509 certificate SHA-1 thumbprint */
  x5t?: string;
  /** X.509 certificate SHA-256 thumbprint */
  'x5t#S256'?: string;
  
  // RSA-specific fields
  /** RSA modulus */
  n?: string;
  /** RSA exponent */
  e?: string;
  
  // EC-specific fields
  /** Elliptic curve */
  crv?: string;
  /** X coordinate */
  x?: string;
  /** Y coordinate */
  y?: string;
  
  /** Additional fields */
  [key: string]: unknown;
}

/**
 * JSON Web Key Set (JWKS)
 */
export interface JWKS {
  keys: JWK[];
}

/**
 * JWT validation result
 */
export interface JWTValidationResult {
  /** Whether the JWT is valid */
  valid: boolean;
  /** Decoded payload if valid */
  payload?: JWTPayload;
  /** Error message if invalid */
  error?: string;
  /** Error code for programmatic handling */
  errorCode?: 'EXPIRED' | 'NOT_YET_VALID' | 'INVALID_SIGNATURE' | 'INVALID_ISSUER' | 'INVALID_AUDIENCE' | 'INVALID_FORMAT' | 'CUSTOM_VALIDATION_FAILED';
}

/**
 * Cached JWKS entry
 */
export interface CachedJWKS {
  jwks: JWKS;
  cachedAt: number;
  expiresAt: number;
}
