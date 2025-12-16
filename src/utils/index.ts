import type { H3Event } from 'h3';
import type {
  OAuthProvider,
  OAuthProviderTokenMap,
  CookieOptionsOverride,
  OAuthErrorResponse,
  OAuthStateValue,
  RefreshTokenResponse,
  TokenValidationResult,
  OAuthCallbackQuery,
  OAuthProviderConfigMap,
  BaseOAuthCallbackQuery,
  ProviderFieldValue,
  TokenField,
  OAuthParsedState,
} from '../types';

import { setCookie, getCookie, deleteCookie, getQuery, createError } from 'h3';
import { getProviderConfig } from '../providerConfig';
import { ofetch } from 'ofetch';
import { getOAuthProviderConfig } from '..';

export { generateCodeVerifier, generateCodeChallenge } from './pkce';
export { fetchUserInfo, parseIDToken, validateIDTokenClaims } from './oidc';
export {
  getClientCredentialsToken,
  clearClientCredentialsCache,
  getClientCredentialsCacheSize,
} from './clientCredentials';

/**
 * @internal
 *
 * Determines if a token should be refreshed based on a time threshold.
 *
 * This is used for token prefetching - refreshing tokens before they expire
 * to prevent interruptions in long-running requests or user sessions.
 *
 * @param tokens - The token object containing expires_in
 * @param thresholdSeconds - Number of seconds before expiry to trigger refresh
 *
 * @returns true if the token expires within the threshold, false otherwise
 */
export function shouldRefreshToken(
  tokens: { expires_in: number },
  thresholdSeconds: number,
): boolean {
  const now = Math.floor(Date.now() / 1000);
  const expiresAt = tokens.expires_in;
  const timeUntilExpiry = expiresAt - now;

  return timeUntilExpiry <= thresholdSeconds && timeUntilExpiry > 0;
}

/**
 * @internal
 *
 * Writes OAuth token data to secure HTTP-only cookies for the specified provider.
 *
 * This function stores the access token, refresh token (if present), and access token
 * expiration timestamp in cookies on the `H3Event`. It also delegates provider-specific
 * cookie storage to `setProviderCookieFields`, allowing for custom metadata like
 * `clio_client_id` or `azure_ext_expires_in` to be persisted as well.
 *
 * - Access tokens are stripped of any "Bearer " prefix before storage.
 * - The expiration time is stored as an absolute UNIX timestamp in seconds.
 * - All cookies use secure, HTTP-only settings with a default `SameSite=Lax` and path `/`.
 *
 * @param event - The current H3 event object.
 * @param tokens - The OAuth token response to store.
 * @param provider - The OAuth provider (e.g., "azure", "clio", "intuit").
 * @param options - Optional cookie config overrides (e.g., `sameSite`, `path`).
 *
 * @returns The original token object, unchanged.
 */

export async function setProviderCookies<P extends OAuthProvider>(
  event: H3Event,
  tokens: OAuthProviderTokenMap[P],
  provider: P,
  options?: CookieOptionsOverride,
  instanceKey?: string,
): Promise<OAuthProviderTokenMap[P]> {
  const providerKey = instanceKey ? `${provider}:${instanceKey}` : provider;

  const base: Parameters<typeof setCookie>[3] = {
    httpOnly: true,
    secure: true,
    sameSite: options?.sameSite ?? 'lax',
    path: options?.path ?? '/',
  };

  const expiresIn = tokens.expires_in;

  const cleanedAccessToken = tokens.access_token.startsWith('Bearer ')
    ? tokens.access_token.slice(7)
    : tokens.access_token;

  // Use a long maxAge for the access_token cookie (30 days) to ensure it persists
  // even after the token expires. Token validity is checked via expires_at timestamp,
  // not cookie existence. This allows the refresh flow to trigger properly.
  const accessTokenCookieMaxAge = 30 * 24 * 60 * 60; // 30 days

  setCookie(event, `${providerKey}_access_token`, cleanedAccessToken, {
    ...base,
    maxAge: accessTokenCookieMaxAge,
  });

  const expiry = Math.floor(Date.now() / 1000) + expiresIn;

  setCookie(
    event,
    `${providerKey}_access_token_expires_at`,
    String(expiry),
    {
      ...base,
      maxAge: accessTokenCookieMaxAge,
    },
  );

  const config = instanceKey
    ? getOAuthProviderConfig(provider, instanceKey)
    : getOAuthProviderConfig(provider);

  if (tokens.refresh_token) {
    const encryptedRefreshToken = await config.encrypt(tokens.refresh_token);

    let refreshTokenMaxAge = 30 * 24 * 60 * 60; // Default: 30 days

    if (
      getProviderConfig(provider).validateRefreshTokenExpiry &&
      hasXRefreshTokenExpiresIn(tokens)
    ) {
      refreshTokenMaxAge = tokens.x_refresh_token_expires_in;
    } else if (options?.refreshTokenMaxAge) {
      refreshTokenMaxAge = options.refreshTokenMaxAge;
    }

    setCookie(event, `${providerKey}_refresh_token`, encryptedRefreshToken, {
      ...base,
      maxAge: refreshTokenMaxAge,
    });
  }

  setProviderCookieFields(event, tokens, provider, providerKey, base);

  return tokens;
}

/**
 * @internal
 *
 * Parses an unknown error thrown during an OAuth token exchange
 * and attempts to extract a user-friendly message and HTTP status code.
 *
 * If the error includes a `response.status` and a `response.json()` method,
 * this function tries to read a structured error response from the OAuth provider
 * and use its `error_description` or `error` message.
 *
 * If the structure doesn't match or the parse fails, a fallback message and
 * a 500 status code are returned.
 *
 * @param error - The unknown error thrown during a failed `ofetch` call.
 *
 * @returns An object containing:
 * - `statusCode`: HTTP error status (default: `500`)
 * - `message`: A human-readable error message
 */
export async function parseError(error: unknown): Promise<{
  statusCode: number;
  message: string;
}> {
  let statusCode = 500;
  let message = 'h3-oauth-kit error';

  // Step 1: Check for `response.status` and `response.json()`
  if (isFetchErrorWithResponse(error)) {
    const response = error.response;

    if (typeof response.status === 'number') {
      statusCode = response.status;
    }

    if (typeof response.json === 'function') {
      try {
        const json = await response.json();
        if (isOAuthErrorResponse(json)) {
          message = json.error_description || json.error || message;
        }
      } catch {
        // ignore parse failure
      }
    }
  }

  // Step 2: Fallback to top-level `error.message` if message is still default
  if (message === 'h3-oauth-kit error' && isErrorWithMessage(error)) {
    message = error.message;
  }

  return { statusCode, message };
}

/**
 * @internal
 *
 * Checks if an error object has a `response` property with a `status` or `json` method.
 *
 * @param error - The error object to check.
 *
 * @returns `true` if the error has a `response` property with a `status` or `json` method, `false` otherwise.
 */
function isFetchErrorWithResponse(error: unknown): error is {
  response: {
    status?: number;
    json?: () => Promise<unknown>;
  };
} {
  if (typeof error === 'object' && error !== null && 'response' in error) {
    const maybeResponse = (error as { response: unknown }).response;

    return (
      typeof maybeResponse === 'object' &&
      maybeResponse !== null &&
      ('status' in maybeResponse || 'json' in maybeResponse)
    );
  }

  return false;
}

/**
 * @internal
 *
 * Checks if a JSON object is an OAuth error response.
 *
 * @param json - The JSON object to check.
 *
 * @returns `true` if the object is an OAuth error response, `false` otherwise.
 */
function isOAuthErrorResponse(json: unknown): json is OAuthErrorResponse {
  return (
    typeof json === 'object' &&
    json !== null &&
    ('error' in json || 'error_description' in json)
  );
}

/**
 * @internal
 *
 * Checks if an error object has a `message` property.
 *
 * @param error - The error object to check.
 *
 * @returns `true` if the error has a `message` property, `false` otherwise.
 */
function isErrorWithMessage(error: unknown): error is { message: string } {
  return (
    typeof error === 'object' &&
    error !== null &&
    'message' in error &&
    typeof (error as Record<string, unknown>).message === 'string'
  );
}

/**
 * @internal
 *
 * Removes all keys from an object where the value is undefined.
 *
 * @param input - The object to clean.
 *
 * @returns A new object with all undefined values removed.
 */
export function omitUndefinedValues<T extends Record<string, unknown>>(
  input: T,
): Partial<T> {
  return Object.fromEntries(
    Object.entries(input).filter(([_, v]) => v !== undefined),
  ) as Partial<T>;
}

/**
 * @internal
 *
 * Decodes and parses the `state` parameter returned from an OAuth callback.
 * Ensures the state includes both `csrf` and `providerKey` for CSRF and instance validation.
 *
 * @param rawState - The base64url-encoded state string from the OAuth callback.
 * @returns A strongly typed OAuthParsedState object.
 * @throws {H3Error} If decoding or validation fails.
 */
export function parseOAuthState(rawState: string): OAuthParsedState {
  try {
    const decoded = Buffer.from(
      decodeURIComponent(rawState),
      'base64url',
    ).toString('utf-8');
    const parsed = JSON.parse(decoded);

    if (
      typeof parsed !== 'object' ||
      parsed === null ||
      typeof parsed.csrf !== 'string' ||
      typeof parsed.providerKey !== 'string'
    ) {
      throw new Error('Invalid state structure');
    }

    return parsed as OAuthParsedState;
  } catch {
    throw createError({
      statusCode: 400,
      statusMessage: 'Invalid or malformed OAuth state parameter',
    });
  }
}

/**
 * @internal
 *
 * Constructs an OAuth 2.0 authorization URL for initiating the login flow.
 *
 * This utility builds a full URL to the provider's authorization endpoint,
 * including all required query parameters for the OAuth 2.0 Authorization Code flow:
 * - `client_id`
 * - `redirect_uri`
 * - `response_type` (always `"code"`)
 * - `scope`
 * - `state`
 * - `code_challenge` (PKCE, optional)
 * - `code_challenge_method` (PKCE, optional)
 *
 * This URL is used to redirect the user to the provider's login/consent screen.
 *
 * @param authorizeEndpoint - The full URL to the provider's authorization endpoint.
 * @param clientId - The OAuth client ID registered with the provider.
 * @param redirectUri - The URI the provider should redirect to after login.
 * @param scopes - An array of OAuth scopes to request during authorization.
 * @param state - A unique CSRF token to include for validating the callback.
 * @param codeChallenge - Optional PKCE code challenge (base64url-encoded SHA-256 hash).
 * @param codeChallengeMethod - Optional PKCE method (always 'S256' for SHA-256).
 *
 * @returns A full URL string with all required OAuth query parameters attached.
 *
 */
export function buildAuthUrl({
  authorizeEndpoint,
  clientId,
  redirectUri,
  scopes,
  state,
  codeChallenge,
  codeChallengeMethod,
}: {
  authorizeEndpoint: string;
  clientId: string;
  redirectUri: string;
  scopes: string[];
  state: string;
  codeChallenge?: string;
  codeChallengeMethod?: 'S256';
}): string {
  const url = new URL(authorizeEndpoint);
  url.searchParams.set('client_id', clientId);
  url.searchParams.set('redirect_uri', redirectUri);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('scope', scopes.join(' '));
  url.searchParams.set('state', state);

  // Add PKCE parameters if provided
  if (codeChallenge && codeChallengeMethod) {
    url.searchParams.set('code_challenge', codeChallenge);
    url.searchParams.set('code_challenge_method', codeChallengeMethod);
  }

  return url.toString();
}

/**
 * @internal
 *
 * Parses a provider key into its components.
 *
 * @param providerKey - The full provider key (e.g., "clio:smithlaw:preserve")
 * @param delimiter - The delimiter used to separate components (default: ":")
 * @returns An object with the base provider, optional instanceKey, and preserveInstance flag
 */
export function parseProviderKey(
  providerKey: string,
  delimiter: string = ':',
): {
  provider: string;
  instanceKey?: string;
  preserveInstance: boolean;
} {
  const parts = providerKey.split(delimiter);

  if (parts.length === 1) {
    return { provider: parts[0], preserveInstance: false };
  }

  if (parts.length === 2) {
    // Could be "clio:smithlaw" or "clio:preserve"
    if (parts[1] === 'preserve') {
      return { provider: parts[0], preserveInstance: true };
    }
    return {
      provider: parts[0],
      instanceKey: parts[1],
      preserveInstance: false,
    };
  }

  if (parts.length === 3 && parts[2] === 'preserve') {
    return {
      provider: parts[0],
      instanceKey: parts[1],
      preserveInstance: true,
    };
  }

  // Fallback for malformed keys
  return { provider: parts[0], instanceKey: parts[1], preserveInstance: false };
}

/**
 * @internal
 *
 * Resolves the `state` parameter to use in an OAuth 2.0 authorization request
 * and sets a secure, HTTP-only cookie to persist the CSRF token for verification.
 *
 * Always returns a base64-encoded JSON object that includes:
 * - A `csrf` token for request validation
 * - Any user-provided metadata (e.g. `returnTo`, `instanceKey`)
 * - The providerKey (e.g. "clio" or "clio:smithlaw")
 * - The instanceKey separately when present (e.g. "smithlaw")
 *
 * @param event - The H3 request event object
 * @param providerKey - A unique key identifying the OAuth config instance
 * @param userState - Optional state object or function returning a state object
 *
 * @returns A base64url-encoded string to use as the `state` query param
 */
export function resolveState(
  event: H3Event,
  providerKey: string,
  userState?: OAuthStateValue,
): string {
  const resolved =
    typeof userState === 'function' ? userState(event) : userState ?? {};

  if (
    typeof resolved !== 'object' ||
    resolved === null ||
    Array.isArray(resolved)
  ) {
    throw new TypeError('OAuth state must be a plain object');
  }

  const csrf = crypto.randomUUID();
  const { provider: _provider, instanceKey } = parseProviderKey(providerKey);

  const stateObject = {
    ...resolved,
    csrf,
    providerKey,
    ...(instanceKey && { instanceKey }),
  };

  const encodedState = encodeURIComponent(
    Buffer.from(JSON.stringify(stateObject)).toString('base64url'),
  );

  setCookie(event, `oauth_csrf_${providerKey}`, csrf, {
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    path: '/',
    maxAge: 300, // 5 minutes
  });

  return encodedState;
}

/**
 * @internal
 *
 * Verifies the CSRF token in the parsed `state` object against the cookie
 * set during the login step. Prevents replay attacks and forgery.
 *
 * Deletes the CSRF cookie after validation.
 *
 * @param event - The H3 request event
 * @param parsedState - The parsed OAuth state object (must include `csrf` and `providerKey`)
 *
 * @throws {H3Error} If the CSRF token is missing or does not match
 */
export function verifyStateParam(
  event: H3Event,
  parsedState: { csrf: string; providerKey: string },
): void {
  const { csrf, providerKey } = parsedState;
  const cookieKey = `oauth_csrf_${providerKey}`;
  const expected = getCookie(event, cookieKey);

  if (!expected || csrf !== expected) {
    throw createError({
      statusCode: 401,
      statusMessage: `CSRF mismatch for OAuth callback [${providerKey}]`,
    });
  }

  deleteCookie(event, cookieKey);
}

/**
 * @internal
 *
 * Exchanges an OAuth authorization code for access and refresh tokens.
 *
 * This function performs a POST request to the provider's token endpoint using
 * the OAuth 2.0 authorization code grant flow. It builds the request body using
 * provider-specific configuration (client ID, secret, scopes, redirect URI, etc.)
 * and returns the parsed token response typed for the given provider.
 *
 * When PKCE is used, the code_verifier must be provided to complete the flow.
 *
 * If the request fails (e.g., due to invalid credentials or code), it throws
 * an H3 error with the status and message parsed from the provider's error response.
 *
 * @param code - The authorization code received from the OAuth callback.
 * @param config - The provider-specific OAuth configuration (client ID, secret, etc.).
 * @param _provider - The OAuth provider identifier (e.g., "clio", "azure", "intuit").
 * @param codeVerifier - Optional PKCE code verifier (required if PKCE was used).
 *
 * @returns A typed object containing access and refresh tokens for the provider.
 *
 * @throws An H3 error if the token exchange request fails.
 */
export async function exchangeCodeForTokens<P extends OAuthProvider>(
  code: string,
  config: OAuthProviderConfigMap[P],
  _provider: P,
  codeVerifier?: string,
): Promise<OAuthProviderTokenMap[P]> {
  const params: Record<string, string> = {
    client_id: config.clientId,
    client_secret: config.clientSecret,
    grant_type: 'authorization_code',
    code,
    redirect_uri: config.redirectUri,
  };

  if (config.scopes) {
    params.scope = config.scopes.join(' ');
  }

  // Add PKCE code_verifier if provided
  if (codeVerifier) {
    params.code_verifier = codeVerifier;
  }

  try {
    return await ofetch<OAuthProviderTokenMap[P]>(config.tokenEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams(params).toString(),
    });
  } catch (error: unknown) {
    const { statusCode, message } = await parseError(error);

    throw createError({ statusCode, message });
  }
}

/**
 * @internal
 *
 * Parses and normalizes OAuth callback query parameters from the H3 event.
 *
 * Includes:
 * - Standard OAuth2/OpenID Connect parameters: `code`, `state`, `error`, `error_description`
 * - Provider-specific parameters (e.g., `realmId`, `session_state`, `id_token`), as defined
 *   in `providerSpecificCallbackQueryFields`.
 *
 * All non-string or missing fields are omitted from the final result.
 *
 * @param event - The H3 event representing the OAuth callback request.
 * @param provider - The OAuth provider key (e.g., "azure", "clio", or "intuit").
 *
 * @returns A normalized `OAuthCallbackQuery<P>` object containing valid, provider-aware fields.
 */
export function parseOAuthCallbackQuery<P extends OAuthProvider>(
  event: H3Event,
  provider: P,
): OAuthCallbackQuery<P> {
  const query = getQuery(event);

  const base = omitUndefinedValues({
    code: typeof query.code === 'string' ? query.code : undefined,
    state: typeof query.state === 'string' ? query.state : undefined,
    error: typeof query.error === 'string' ? query.error : undefined,
    error_description:
      typeof query.error_description === 'string'
        ? query.error_description
        : undefined,
  }) as BaseOAuthCallbackQuery;

  const providerSpecificFields =
    getProviderConfig(provider).callbackQueryFields ?? [];

  const extras: Record<string, string> = {};

  for (const field of providerSpecificFields) {
    const key = field as string;

    const value = query[key];

    if (typeof value === 'string') {
      extras[key] = value;
    }
  }

  return {
    ...base,
    ...extras,
  } as OAuthCallbackQuery<P>;
}

/**
 * @internal
 *
 * Uses a refresh token to obtain a new set of OAuth tokens from the provider.
 *
 * This function sends a POST request to the configured token endpoint, exchanging
 * the given refresh token for a new access token. If successful, it returns the
 * provider-specific token response, preserving types.
 *
 * If the request fails (e.g., due to an invalid or expired refresh token), an H3 error
 * is thrown with a parsed error message from the provider.
 *
 * @param refreshTokenValue - The previously issued refresh token.
 * @param providerConfig - OAuth configuration specific to the provider.
 * @param _provider - The OAuth provider identifier (used for type narrowing only).
 *
 * @returns A new typed access token response for the provider, or `false` if refresh fails.
 *
 * @throws {H3Error} If the token refresh request fails.
 */

export async function refreshToken<P extends OAuthProvider>(
  refreshTokenValue: string,
  providerConfig: OAuthProviderConfigMap[P],
  _provider: P,
): Promise<RefreshTokenResponse<P> | false> {
  const requestConfig = {
    url: providerConfig.tokenEndpoint,
    params: {
      client_id: providerConfig.clientId,
      client_secret: providerConfig.clientSecret,
      refresh_token: refreshTokenValue,
      grant_type: 'refresh_token',
    },
  };

  try {
    const tokenResponse = await ofetch<RefreshTokenResponse<P>>(
      requestConfig.url,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams(requestConfig.params).toString(),
      },
    );

    // Cast back to token response — optional string coercion step removed
    return tokenResponse;
  } catch (error: unknown) {
    const { statusCode, message } = await parseError(error);

    throw createError({ statusCode, message });
  }
}

function parseTokenField(raw: string): string | number {
  return /^\d+$/.test(raw) ? parseInt(raw, 10) : raw;
}

/**
 * @internal
 *
 * Checks if the stored OAuth tokens in cookies are present and valid for a given provider.
 *
 * This utility is primarily used in `defineProtectedRoute` to determine whether
 * access and refresh tokens for a provider are still usable or need to be refreshed.
 *
 * The function reads the `*_access_token`, `*_refresh_token`, and
 * `*_access_token_expires_at` cookies, along with any provider-specific cookies
 * defined in the provider config.
 *
 * If all required fields are present and not expired, the parsed tokens are returned
 * with a `"valid"` status. If expired, `"expired"` is returned. If any fields are missing,
 * `false` is returned.
 *
 * @param event - The H3 event containing the cookie headers.
 * @param provider - The OAuth provider name ("azure", "clio", "intuit").
 *
 * @returns `false` if tokens are missing; otherwise a token validation result
 * with either `"valid"` or `"expired"` status.
 */
export async function oAuthTokensAreValid<P extends OAuthProvider>(
  event: H3Event,
  provider: P,
  instanceKey?: string,
): Promise<TokenValidationResult<P> | false> {
  const providerKey = getProviderKey(provider, instanceKey);

  const access_token = getCookie(event, `${providerKey}_access_token`);
  const refresh_token = getCookie(event, `${providerKey}_refresh_token`);
  const access_token_expires_at = getCookie(
    event,
    `${providerKey}_access_token_expires_at`,
  );

  // Check if we have a refresh token
  const hasRefreshToken = !!refresh_token;

  // If no refresh token and no access token, we can't do anything
  if (!access_token && !hasRefreshToken) {
    return false;
  }

  const config = instanceKey
    ? getOAuthProviderConfig(provider, instanceKey)
    : getOAuthProviderConfig(provider);

  const now = Math.floor(Date.now() / 1000);

  // If we have a refresh token, decrypt it
  let decryptedRefreshToken: string | undefined;
  if (hasRefreshToken) {
    decryptedRefreshToken = await config.decrypt(refresh_token);
  }

  // If access_token is missing but we have refresh_token, trigger refresh
  // by returning 'expired' status. The refresh flow will get new tokens.
  if (!access_token && hasRefreshToken) {
    const base = {
      access_token: '', // Empty - will be replaced after refresh
      refresh_token: decryptedRefreshToken,
      expires_in: now, // Set to now to indicate expired
    };

    return {
      tokens: base as OAuthProviderTokenMap[P],
      status: 'expired',
    };
  }

  // If no expiry info but we have access_token, we can't validate - fail safe
  if (!access_token_expires_at) {
    return false;
  }

  const expires_in = parseInt(access_token_expires_at, 10);
  const isAccessTokenExpired = now >= expires_in;

  // If access token is expired and we have no refresh token, fail
  if (isAccessTokenExpired && !hasRefreshToken) {
    return false;
  }

  const base = {
    access_token,
    refresh_token: decryptedRefreshToken,
    expires_in,
  };

  // Optionally validate refresh token expiry (only if we have a refresh token)
  if (hasRefreshToken && getProviderConfig(provider).validateRefreshTokenExpiry) {
    const refreshExpiresAt = getCookie(
      event,
      `${providerKey}_refresh_token_expires_at`,
    );

    if (!refreshExpiresAt) {
      return false;
    }

    const refreshExpiry = parseInt(refreshExpiresAt, 10);

    if (isNaN(refreshExpiry) || now >= refreshExpiry) {
      return {
        tokens: {
          ...base,
          // fallback to partial fields even if refresh is expired
        } as OAuthProviderTokenMap[P],
        status: 'expired',
      };
    }
  }

  const additionalFields = getProviderCookieFields(
    event,
    provider,
    providerKey,
  );

  if (additionalFields === false) {
    return false;
  }

  const tokens = {
    ...base,
    ...additionalFields,
  } as OAuthProviderTokenMap[P];

  if (provider === 'intuit' || provider === 'azure' || provider === 'clio') {
  }

  return {
    tokens,
    status: isAccessTokenExpired ? 'expired' : 'valid',
  };
}

/**
 * @internal
 *
 * Merges a refreshed token response with any provider-specific fields that may
 * be missing from the response, ensuring a complete token object.
 *
 * This function is typically called after a refresh token exchange to reconstruct
 * the full token payload expected by the application — including metadata like
 * `clio_client_id`, `intuit_realm_id`, or `azure_ext_expires_in`, which may not
 * be returned by all providers during refresh.
 *
 * It preserves required fields from the previously stored token using a
 * provider-defined list of field names, and ensures `refresh_token` is always
 * present when required (avoiding type errors with `exactOptionalPropertyTypes`).
 *
 * @param provider - The OAuth provider (e.g., "azure", "clio", "intuit")
 * @param refreshed - The token response returned from the refresh flow
 * @param previous - The previously saved full token, used to backfill any missing metadata
 *
 * @returns A fully normalized token object matching the shape of `OAuthProviderTokenMap[P]`
 */
export function normalizeRefreshedToken<P extends OAuthProvider>(
  provider: P,
  refreshed: RefreshTokenResponse<P>,
  previous: OAuthProviderTokenMap[P],
): OAuthProviderTokenMap[P] {
  const keysToPreserve = getProviderConfig(provider).providerSpecificFields;

  const preserved = preserveFields(
    provider,
    previous,
    extractPreservableKeys(keysToPreserve),
  );

  const merged = {
    ...refreshed,
    ...preserved,
  };

  // Ensure refresh_token is not undefined for exactOptionalPropertyTypes
  if (!merged.refresh_token && previous.refresh_token) {
    merged.refresh_token = previous.refresh_token;
  }

  return merged as OAuthProviderTokenMap[P];
}

/**
 * @internal
 *
 * Extracts a flat list of token field keys from a provider's field definition list.
 *
 * This utility normalizes a mixed array of simple field strings and structured field
 * objects (with optional metadata) into a consistent array of plain token property keys
 * that can be used for preserving token fields across refreshes or when merging tokens.
 *
 * @param fields - An array of token field definitions from the provider config.
 * These may be simple strings or structured objects containing a `.key`.
 *
 * @returns An array of plain `OAuthProviderTokenMap` keys to preserve.
 *
 * @example
 * ```ts
 * extractPreservableKeys(["client_id", { key: "realm_id", cookieName: "intuit_realm_id" }]);
 * // => ["client_id", "realm_id"]
 * ```
 */
function extractPreservableKeys<P extends OAuthProvider>(
  fields: TokenField<P>[],
): (keyof OAuthProviderTokenMap[P])[] {
  return fields.map((field) =>
    isStructuredTokenField(field) ? field.key : field,
  );
}

/**
 * @internal
 *
 * Extracts and returns a subset of properties from a source token object,
 * based on an explicit list of keys.
 *
 * Used internally to carry over provider-specific metadata fields from
 * a previous token during normalization.
 *
 * @param source - The full token object to extract fields from
 * @param keys - The specific keys to preserve from the source token
 *
 * @returns A new object containing only the requested key-value pairs
 */
export function preserveFields<
  P extends OAuthProvider,
  K extends keyof OAuthProviderTokenMap[P],
>(
  _provider: P,
  source: OAuthProviderTokenMap[P],
  keys: K[],
): Pick<OAuthProviderTokenMap[P], K> {
  const result = {} as Pick<OAuthProviderTokenMap[P], K>;
  for (const key of keys) {
    result[key] = source[key];
  }
  return result;
}

/**
 * @internal
 *
 * Type guard to determine if a given token field is a structured field object.
 *
 * Structured token fields are used to define provider-specific cookie metadata,
 * such as custom cookie names or setter functions for transforming values. This
 * utility narrows the `TokenField` type to only those objects containing a `key`.
 *
 * Used primarily in utilities that normalize or persist provider-specific fields
 * across cookies and token merges.
 *
 * @param field - A token field from the provider config, which may be a string or object.
 *
 * @returns `true` if the field is an object with a `key` property, otherwise `false`.
 */
function isStructuredTokenField<P extends OAuthProvider>(
  field: TokenField<P>,
): field is Extract<TokenField<P>, { key: keyof OAuthProviderTokenMap[P] }> {
  return typeof field === 'object' && field !== null && 'key' in field;
}

/**
 * @internal
 *
 * Reads and parses all provider-specific token metadata fields from cookies.
 *
 * This function uses the provider's config to determine which extra fields were
 * stored in cookies (e.g., `clio_client_id`, `azure_ext_expires_in`) and attempts
 * to read and parse each of them from the incoming `H3Event`'s cookie headers.
 *
 * If any required cookie is missing, `false` is returned to indicate an invalid or
 * incomplete token state. Otherwise, the parsed fields are returned as a partial
 * token payload typed to the specific provider.
 *
 * @param event - The incoming H3 event containing the request cookies.
 * @param provider - The OAuth provider identifier (e.g., "clio", "azure", "intuit").
 *
 * @returns A partial token object containing all parsed provider-specific fields,
 *          or `false` if any expected cookie is missing.
 */
export function getProviderCookieFields<P extends OAuthProvider>(
  event: H3Event,
  provider: P,
  providerKey: string,
):
  | Partial<Record<keyof OAuthProviderTokenMap[P], ProviderFieldValue<P>>>
  | false {
  const result = {} as Partial<
    Record<keyof OAuthProviderTokenMap[P], ProviderFieldValue<P>>
  >;

  for (const { cookieKey, fieldKey } of resolveProviderFieldMeta(provider)) {
    // Adjust cookie key to use instance-scoped prefix
    const scopedCookieKey = cookieKey.replace(
      `${provider}_`,
      `${providerKey}_`,
    );

    const raw = getCookie(event, scopedCookieKey);

    if (raw == null) return false;

    result[fieldKey] = parseTokenField(raw) as ProviderFieldValue<P>;
  }

  return result;
}

/**
 * @internal
 *
 * Writes provider-specific token metadata fields to HTTP-only cookies.
 *
 * This function iterates over the provider's configured metadata fields
 * (via `providerConfig[provider].providerSpecificFields`) and sets each
 * as a secure, serializable cookie. It supports both raw string/number
 * fields and structured fields with custom `setter` functions for transforming
 * the value before storage.
 *
 * The cookies are prefixed using the full providerKey, which includes
 * the instanceKey when available (e.g. `clio:sam_ext_expires_at`).
 *
 * @param event - The H3 event to attach cookies to.
 * @param tokens - The typed OAuth token payload for the provider.
 * @param provider - The base OAuth provider name (e.g., "clio", "azure", "intuit").
 * @param providerKey - The full provider key including instance (e.g., "clio:sam").
 * @param baseOptions - Default cookie options (e.g., secure, path, sameSite).
 */
export function setProviderCookieFields<P extends OAuthProvider>(
  event: H3Event,
  tokens: OAuthProviderTokenMap[P],
  provider: P,
  providerKey: string,
  baseOptions: Parameters<typeof setCookie>[3],
): void {
  for (const { cookieKey, fieldKey, setter } of resolveProviderFieldMeta(
    provider,
  )) {
    const raw = tokens[fieldKey];

    if (raw === undefined) continue;

    const value = setter ? setter(String(raw)) : String(raw);

    if (typeof raw === 'string' || typeof raw === 'number') {
      const scopedCookieKey = cookieKey.replace(
        `${provider}_`,
        `${providerKey}_`,
      );

      setCookie(event, scopedCookieKey, value, baseOptions);
    }
  }
}

/**
 * @internal
 *
 * Retrieves all cookie keys for a given OAuth provider.
 *
 * This function constructs an array of all cookie names used for a provider's
 * tokens and fields, optionally scoped by an instanceKey (e.g., "clio:sam").
 *
 * @param provider - The base OAuth provider key (e.g., "clio", "azure", "intuit").
 * @param instanceKey - Optional instance key to prefix cookies with (e.g., "sam").
 *
 * @returns An array of all cookie keys for the scoped provider.
 */
export function getProviderCookieKeys(
  provider: OAuthProvider,
  instanceKey?: string,
): string[] {
  const providerKey = instanceKey ? `${provider}:${instanceKey}` : provider;

  const base = getProviderConfig(provider).baseCookieFields.map(
    (field) => `${providerKey}_${field}`,
  );

  const specific = getProviderConfig(provider).providerSpecificFields.map(
    (field) => {
      const rawKey =
        typeof field === 'string'
          ? `${provider}_${field}`
          : field.cookieName ?? `${provider}_${String(field.key)}`;

      return rawKey.replace(`${provider}_`, `${providerKey}_`);
    },
  );

  return [...base, ...specific];
}

/**
 * @internal
 *
 * Generates all possible cookie key patterns that this library could create for a provider.
 *
 * This includes:
 * - Base cookie patterns (access_token, refresh_token, etc.)
 * - Provider-specific field patterns
 * - Both global and scoped instance patterns
 *
 * Used for intelligent wildcard deletion that only removes cookies we know we created.
 *
 * @param provider - The OAuth provider (e.g., "clio", "azure", "intuit").
 * @returns An array of regex patterns that match cookies created by this library.
 */
export function getProviderCookiePatterns(provider: OAuthProvider): RegExp[] {
  const patterns: RegExp[] = [];

  // Base cookie patterns for both global and scoped instances
  for (const field of getProviderConfig(provider).baseCookieFields) {
    const suffix = `_${field}`;
    // Global pattern: clio_access_token
    patterns.push(new RegExp(`^${provider}${suffix.replace('_', '\\_')}$`));
    // Scoped pattern: clio:instanceKey_access_token
    patterns.push(
      new RegExp(`^${provider}:[^_]+${suffix.replace('_', '\\_')}$`),
    );
  }

  // Provider-specific field patterns
  for (const field of getProviderConfig(provider).providerSpecificFields) {
    const cookieName =
      typeof field === 'string'
        ? `${provider}_${field}`
        : field.cookieName ?? `${provider}_${String(field.key)}`;

    // Extract the suffix part (everything after provider_)
    const suffix = cookieName.replace(`${provider}_`, '_');

    // Global pattern: clio_token_type
    patterns.push(new RegExp(`^${provider}${suffix.replace('_', '\\_')}$`));
    // Scoped pattern: clio:instanceKey_token_type
    patterns.push(
      new RegExp(`^${provider}:[^_]+${suffix.replace('_', '\\_')}$`),
    );
  }

  // CSRF cookie patterns (oauth_csrf_provider and oauth_csrf_provider:instanceKey)
  patterns.push(new RegExp(`^oauth_csrf_${provider}$`));
  patterns.push(new RegExp(`^oauth_csrf_${provider}:[^_]+$`));

  return patterns;
}

/**
 * @internal
 *
 * Resolves the metadata fields configured for a given OAuth provider into a normalized list.
 *
 * Each entry in the returned array describes:
 * - The cookie key used to read/write the value
 * - The corresponding field key in the token object
 * - An optional `setter` function (used to transform values before setting cookies)
 *
 * This utility abstracts over the two forms of provider fields:
 * - Simple string keys (e.g., `"token_type"`)
 * - Structured field objects (e.g., `{ key: "realm_id", cookieName: "...", setter: fn }`)
 *
 * Malformed or unknown field definitions are silently ignored.
 *
 * @param provider - The OAuth provider key (e.g., `"clio"`, `"azure"`, `"intuit"`).
 *
 * @returns An array of resolved metadata field descriptors for cookie handling.
 */
function resolveProviderFieldMeta<P extends OAuthProvider>(
  provider: P,
): Array<{
  cookieKey: string;
  fieldKey: keyof OAuthProviderTokenMap[P];
  setter?: (raw: string) => string;
}> {
  const fields = getProviderConfig(provider).providerSpecificFields;

  return fields.flatMap((field) => {
    if (typeof field === 'string') {
      return [
        {
          cookieKey: `${provider}_${field}`,
          fieldKey: field,
        },
      ];
    }

    if (isStructuredTokenField(field)) {
      const base = {
        cookieKey: field.cookieName ?? `${provider}_${String(field.key)}`,
        fieldKey: field.key,
      };

      return field.setter ? [{ ...base, setter: field.setter }] : [base];
    }

    return []; // skip malformed
  });
}

/**
 * Resolves a full provider key based on provider and optional instanceKey.
 *
 * The returned key is used for namespacing cookies and CSRF tokens.
 * By default, the format is `${provider}:${instanceKey}`.
 *
 * When preserveInstance is true, it appends `:preserve` to indicate
 * that this login should use scoped cookies rather than replacing
 * the global provider cookies.
 *
 * @param provider - The base OAuth provider name (e.g. "clio").
 * @param instanceKey - Optional instance key (e.g. "smithlaw").
 * @param preserveInstance - Whether this should use preserve mode.
 * @param delimiter - The delimiter used to separate components (default: ":").
 * @returns A full provider key (e.g. "clio:smithlaw:preserve" or "clio")
 */
export function getProviderKey(
  provider: string,
  instanceKey?: string,
  preserveInstance?: boolean,
  delimiter: string = ':',
): string {
  let key = instanceKey ? `${provider}${delimiter}${instanceKey}` : provider;

  if (preserveInstance) {
    key += `${delimiter}preserve`;
  }

  return key;
}

/**
 * @internal
 *
 * Clears non-preserved cookies for a provider when setting tokens in single-instance mode.
 *
 * This function is called when `preserveInstance` is false (default behavior) to ensure
 * that only one "current" instance is active at a time. It clears the global provider
 * cookies (e.g., `clio_*`) but leaves scoped instance cookies (e.g., `clio:smithlaw_*`) intact.
 *
 * @param event - The H3 event to clear cookies from.
 * @param provider - The OAuth provider (e.g., "clio", "azure", "intuit").
 */
export function clearNonPreservedCookies(
  event: H3Event,
  provider: OAuthProvider,
): void {
  // Clear global provider cookies (e.g., clio_access_token, clio_refresh_token)
  for (const cookieName of getProviderCookieKeys(provider)) {
    deleteCookie(event, cookieName);
  }
}

/**
 * @internal
 *
 * Auto-discovers available instances for a provider by scanning cookies.
 *
 * This function is used when a string provider (e.g., 'clio') is specified
 * without an explicit instanceKey or resolveInstance function. It will:
 * 1. First check for global provider cookies (e.g., clio_access_token)
 * 2. If not found, scan for scoped instance cookies (e.g., clio:loag_access_token)
 * 3. Return the first available instance or undefined if none found
 *
 * @param event - The H3 event containing cookies
 * @param provider - The OAuth provider to scan for
 * @returns The discovered instanceKey or undefined if none found
 */
export function discoverProviderInstance(
  event: H3Event,
  provider: OAuthProvider,
): string | undefined {
  // First try global provider
  const globalKey = `${provider}_refresh_token`;
  if (getCookie(event, globalKey)) {
    return undefined; // Global provider found, no instanceKey needed
  }

  // Scan for scoped instances by looking at all cookies
  const cookies = event.node?.req?.headers?.cookie;
  if (!cookies) return undefined;

  const cookiePattern = new RegExp(`${provider}:([^_]+)_refresh_token=`);
  const matches = cookies.match(cookiePattern);

  if (matches && matches[1]) {
    return matches[1]; // Return the first discovered instanceKey
  }

  return undefined;
}

/**
 * Creates a provider definition with explicit instance keys for better type safety.
 * This allows TypeScript to know about the resolved instance keys at compile time.
 *
 * @example
 * ```typescript
 * defineProtectedRoute([
 *   "azure",
 *   withInstanceKeys("clio", ["LOAG", "smithlaw"], (event) => {
 *     const { clioClientId } = getRouterParams(event);
 *     return clioClientId === "LOAG" ? "LOAG" : "smithlaw";
 *   })
 * ], async (event) => {
 *   // TypeScript knows about both 'clio:LOAG' and 'clio:smithlaw'
 *   const tokens = event.context.h3OAuthKit['clio:LOAG'];
 * });
 * ```
 */
export function withInstanceKeys<
  P extends OAuthProvider,
  K extends readonly string[],
>(
  provider: P,
  instanceKeys: K,
  resolver: (
    event: H3Event,
  ) => K[number] | undefined | Promise<K[number] | undefined>,
): {
  provider: P;
  instanceResolver: typeof resolver;
  __instanceKeys: K;
} {
  return {
    provider,
    instanceResolver: resolver,
    __instanceKeys: instanceKeys,
  };
}

// Add a type guard for x_refresh_token_expires_in
function hasXRefreshTokenExpiresIn(
  obj: unknown,
): obj is { x_refresh_token_expires_in: number } {
  return (
    typeof obj === 'object' &&
    obj !== null &&
    'x_refresh_token_expires_in' in obj &&
    typeof (obj as Record<string, unknown>).x_refresh_token_expires_in ===
      'number'
  );
}
