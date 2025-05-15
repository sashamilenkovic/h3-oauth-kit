import type { H3Event } from "h3";
import type {
  OAuthProvider,
  OAuthProviderTokenMap,
  CookieOptionsOverride,
  OAuthErrorResponse,
  OAuthParsedState,
  OAuthStateValue,
  RefreshTokenResponse,
  TokenValidationResult,
  OAuthCallbackQuery,
  OAuthProviderConfigMap,
  BaseOAuthCallbackQuery,
  ProviderFieldValue,
  TokenField,
} from "../types";

import { setCookie, getCookie, deleteCookie, getQuery, createError } from "h3";
import { providerConfig } from "./providerConfig";
import { ofetch } from "ofetch";

/**
 * Performs a deep equality check between two values of the same type.
 *
 * This function recursively compares objects, arrays, and primitives to determine
 * if the two values are structurally and deeply equal. It is designed to work
 * with JSON-serializable data (i.e., no functions, symbols, Dates, Maps, Sets, etc.).
 *
 * @typeParam T - The type of the values being compared.
 * @param a - The first value to compare.
 * @param b - The second value to compare.
 *
 * @returns `true` if the values are deeply equal, `false` otherwise.
 *
 * @example
 * ```ts
 * deepEqual({ foo: "bar" }, { foo: "bar" }); // true
 * deepEqual([1, 2, 3], [1, 2, 3]); // true
 * deepEqual({ a: 1 }, { a: 1, b: 2 }); // false
 * ```
 */
export function deepEqual<T>(a: T, b: T): boolean {
  if (a === b) return true;

  if (typeof a !== typeof b) return false;

  if (a === null || b === null) return a === b;

  if (typeof a !== "object" || typeof b !== "object") return false;

  if (Array.isArray(a) !== Array.isArray(b)) return false;

  if (Array.isArray(a) && Array.isArray(b)) {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
      if (!deepEqual(a[i], b[i])) return false;
    }
    return true;
  }

  const keysA = Object.keys(a) as (keyof T)[];
  const keysB = Object.keys(b) as (keyof T)[];

  if (keysA.length !== keysB.length) return false;

  for (const key of keysA) {
    if (!(key in b)) return false;
    if (!deepEqual(a[key], b[key])) return false;
  }

  return true;
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

export function setProviderCookies<P extends OAuthProvider>(
  event: H3Event,
  tokens: OAuthProviderTokenMap[P],
  provider: P,
  options?: CookieOptionsOverride
): OAuthProviderTokenMap[P] {
  const base: Parameters<typeof setCookie>[3] = {
    httpOnly: true,
    secure: true,
    sameSite: options?.sameSite ?? "lax",
    path: options?.path ?? "/",
  };

  const cleanedAccessToken = tokens.access_token.startsWith("Bearer ")
    ? tokens.access_token.slice(7)
    : tokens.access_token;

  setCookie(event, `${provider}_access_token`, cleanedAccessToken, {
    ...base,
    maxAge: tokens.expires_in,
  });

  const expiry = Math.floor(Date.now() / 1000) + tokens.expires_in;
  setCookie(event, `${provider}_access_token_expires_at`, String(expiry), base);

  if (tokens.refresh_token) {
    setCookie(event, `${provider}_refresh_token`, tokens.refresh_token, {
      ...base,
      maxAge: 30 * 24 * 60 * 60,
    });
  }

  setProviderCookieFields(event, tokens, provider, base);

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
export async function parseOAuthError(error: unknown): Promise<{
  statusCode: number;
  message: string;
}> {
  let statusCode = 500;
  let message = "Token exchange failed";

  if (typeof error === "object" && error !== null && "response" in error) {
    const response = (error as { response: unknown }).response;

    if (
      typeof response === "object" &&
      response !== null &&
      "status" in response &&
      typeof (response as { status: unknown }).status === "number"
    ) {
      statusCode = (response as { status: number }).status;
    }

    if (
      typeof response === "object" &&
      response !== null &&
      "json" in response &&
      typeof (response as { json: unknown }).json === "function"
    ) {
      try {
        const json = await (
          response as {
            json: () => Promise<OAuthErrorResponse>;
          }
        ).json();

        if (json.error_description || json.error) {
          message = json.error_description || json.error!;
        }
      } catch {
        // Swallow JSON parse errors — fallback to default message
      }
    }
  }

  return { statusCode, message };
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
  input: T
): Partial<T> {
  return Object.fromEntries(
    Object.entries(input).filter(([_, v]) => v !== undefined)
  ) as Partial<T>;
}

/**
 * @internal
 *
 * Parses the `state` parameter returned from an OAuth callback into a structured object.
 *
 * This function safely attempts to parse the raw `state` string (usually a JSON-encoded object)
 * that was previously encoded and sent during the OAuth login flow. It ensures the result is
 * an object, and returns an empty object if parsing fails or the result is invalid.
 *
 * @param rawState - The raw `state` string from the OAuth callback query.
 *
 * @returns A plain object representation of the parsed state, or an empty object if invalid.
 */
export function parseOAuthState(rawState: string): OAuthParsedState {
  try {
    const parsed = JSON.parse(rawState);

    return typeof parsed === "object" && parsed !== null ? parsed : {};
  } catch {
    return {};
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
 *
 * This URL is used to redirect the user to the provider's login/consent screen.
 *
 * @param authorizeEndpoint - The full URL to the provider's authorization endpoint.
 * @param clientId - The OAuth client ID registered with the provider.
 * @param redirectUri - The URI the provider should redirect to after login.
 * @param scopes - An array of OAuth scopes to request during authorization.
 * @param state - A unique CSRF token to include for validating the callback.
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
}: {
  authorizeEndpoint: string;
  clientId: string;
  redirectUri: string;
  scopes: string[];
  state: string;
}): string {
  const url = new URL(authorizeEndpoint);
  url.searchParams.set("client_id", clientId);
  url.searchParams.set("redirect_uri", redirectUri);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", scopes.join(" "));
  url.searchParams.set("state", state);
  return url.toString();
}

/**
 * @internal
 *
 * Resolves the `state` parameter to use in an OAuth 2.0 authorization request
 * and sets it as a secure, HTTP-only cookie for CSRF protection.
 *
 * This function supports several types of user-provided `state` values:
 * - A static string
 * - An object (which will be serialized to JSON)
 * - A function returning either a string or serializable object
 * - If no value is provided, a random UUID will be generated
 *
 * The resolved state value is stored in a cookie named `${provider}_oauth_state`
 * with a 5-minute expiration, and returned for inclusion in the authorization URL.
 *
 * @param event - The H3 request event object, used to set the cookie.
 * @param provider - The OAuth provider name (used in the cookie name).
 * @param userState - An optional string, object, or function returning a string/object.
 *
 * @returns The resolved `state` string to include in the OAuth authorization request.
 *
 * @example
 * ```ts
 * const state = resolveState(event, "clio", { from: "/dashboard" });
 * const url = buildAuthUrl({ ..., state });
 * ```
 */
export function resolveState(
  event: H3Event,
  provider: string,
  userState?: OAuthStateValue
): string {
  let stateValue: string;

  if (typeof userState === "function") {
    const result = userState(event);
    stateValue = typeof result === "string" ? result : JSON.stringify(result);
  } else if (typeof userState === "string") {
    stateValue = userState;
  } else if (typeof userState === "object" && userState !== null) {
    stateValue = JSON.stringify(userState);
  } else {
    stateValue = crypto.randomUUID();
  }

  setCookie(event, `${provider}_oauth_state`, stateValue, {
    httpOnly: true,
    path: "/",
    sameSite: "lax",
    secure: true,
    maxAge: 300,
  });

  return stateValue;
}

/**
 * @internal
 *
 * Verifies the `state` parameter returned in an OAuth callback against the value
 * previously stored in a secure, HTTP-only cookie during the login flow.
 *
 * This function ensures that the OAuth response was not forged or intercepted
 * by comparing the returned `state` to the expected value stored in
 * `${provider}_oauth_state`. If the values don't match, it throws an error
 * to prevent the token exchange from proceeding.
 *
 * The state cookie is deleted after verification, regardless of success or failure.
 *
 * @param event - The current H3 request event, containing cookies and context.
 * @param provider - The OAuth provider name (e.g., "azure", "clio", "intuit").
 * @param state - The `state` query parameter received from the OAuth callback URL.
 *
 * @throws {H3Error} If the state cookie is missing or the values do not match.
 *
 */
export function verifyStateParam(
  event: H3Event,
  provider: OAuthProvider,
  state: string
): void {
  const cookieKey = `${provider}_oauth_state`;

  const expectedStateRaw = getCookie(event, cookieKey);

  if (!expectedStateRaw || typeof state !== "string") {
    throw createError({
      statusCode: 400,
      statusMessage: `Missing or invalid state for ${provider} OAuth callback`,
    });
  }

  // Attempt to parse both as JSON; fall back to string comparison if parsing fails
  let parsedExpected: unknown = expectedStateRaw;
  let parsedReceived: unknown = state;

  try {
    parsedExpected = JSON.parse(expectedStateRaw);
    parsedReceived = JSON.parse(state);
  } catch {
    // Leave them as raw strings
  }

  const isMatch =
    typeof parsedExpected === "object" && typeof parsedReceived === "object"
      ? deepEqual(parsedExpected, parsedReceived)
      : parsedExpected === parsedReceived;

  if (!isMatch) {
    throw createError({
      statusCode: 401,
      statusMessage: `State mismatch for ${provider} OAuth callback`,
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
 * If the request fails (e.g., due to invalid credentials or code), it throws
 * an H3 error with the status and message parsed from the provider's error response.
 *
 * @param code - The authorization code received from the OAuth callback.
 * @param config - The provider-specific OAuth configuration (client ID, secret, etc.).
 * @param _provider - The OAuth provider identifier (e.g., "clio", "azure", "intuit").
 *
 * @returns A typed object containing access and refresh tokens for the provider.
 *
 * @throws An H3 error if the token exchange request fails.
 */
export async function exchangeCodeForTokens<P extends OAuthProvider>(
  code: string,
  config: OAuthProviderConfigMap[P],
  _provider: P
): Promise<OAuthProviderTokenMap[P]> {
  const params: Record<string, string> = {
    client_id: config.clientId,
    client_secret: config.clientSecret,
    grant_type: "authorization_code",
    code,
    redirect_uri: config.redirectUri,
  };

  if (config.scopes) {
    params.scope = config.scopes.join(" ");
  }

  try {
    return await ofetch<OAuthProviderTokenMap[P]>(config.tokenEndpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams(params).toString(),
    });
  } catch (error: unknown) {
    const { statusCode, message } = await parseOAuthError(error);

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
  provider: P
): OAuthCallbackQuery<P> {
  const query = getQuery(event);

  const base = omitUndefinedValues({
    code: typeof query.code === "string" ? query.code : undefined,
    state: typeof query.state === "string" ? query.state : undefined,
    error: typeof query.error === "string" ? query.error : undefined,
    error_description:
      typeof query.error_description === "string"
        ? query.error_description
        : undefined,
  }) as BaseOAuthCallbackQuery;

  const providerSpecificFields =
    providerConfig[provider].callbackQueryFields ?? [];

  const extras: Record<string, string> = {};

  for (const field of providerSpecificFields) {
    const key = field as string;

    const value = query[key];

    if (typeof value === "string") {
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
  _provider: P
): Promise<RefreshTokenResponse<P> | false> {
  const requestConfig = {
    url: providerConfig.tokenEndpoint,
    params: {
      client_secret: providerConfig.clientSecret,
      refresh_token: refreshTokenValue,
      grant_type: "refresh_token",
    },
  };

  try {
    const tokenResponse = await ofetch<RefreshTokenResponse<P>>(
      requestConfig.url,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams(requestConfig.params).toString(),
      }
    );

    // Cast back to token response — optional string coercion step removed
    return tokenResponse;
  } catch (error: unknown) {
    const { statusCode, message } = await parseOAuthError(error);

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
  provider: P
): Promise<TokenValidationResult<P> | false> {
  const access_token = getCookie(event, `${provider}_access_token`);
  const refresh_token = getCookie(event, `${provider}_refresh_token`);
  const access_token_expires_at = getCookie(
    event,
    `${provider}_access_token_expires_at`
  );

  if (!access_token || !refresh_token || !access_token_expires_at) return false;

  const expires_in = parseInt(access_token_expires_at, 10);
  const now = Math.floor(Date.now() / 1000);
  const isAccessTokenExpired = now >= expires_in;

  const base = { access_token, refresh_token, expires_in };

  // Optionally validate refresh token expiry
  if (providerConfig[provider].validateRefreshTokenExpiry) {
    const refreshExpiresAt = getCookie(
      event,
      `${provider}_refresh_token_expires_at`
    );
    if (!refreshExpiresAt) return false;

    const refreshExpiry = parseInt(refreshExpiresAt, 10);
    if (isNaN(refreshExpiry) || now >= refreshExpiry) {
      return {
        tokens: {
          ...base,
          // fallback to partial fields even if refresh is expired
        } as OAuthProviderTokenMap[P],
        status: "expired",
      };
    }
  }

  const additionalFields = getProviderCookieFields(event, provider);
  if (additionalFields === false) return false;

  const tokens = {
    ...base,
    ...additionalFields,
  } as OAuthProviderTokenMap[P];

  return {
    tokens,
    status: isAccessTokenExpired ? "expired" : "valid",
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
  previous: OAuthProviderTokenMap[P]
): OAuthProviderTokenMap[P] {
  const keysToPreserve = providerConfig[provider].providerSpecificFields;

  const preserved = preserveFields(
    provider,
    previous,
    extractPreservableKeys(keysToPreserve)
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
  fields: TokenField<P>[]
): (keyof OAuthProviderTokenMap[P])[] {
  return fields.map((field) =>
    isStructuredTokenField(field) ? field.key : field
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
  K extends keyof OAuthProviderTokenMap[P]
>(
  _provider: P,
  source: OAuthProviderTokenMap[P],
  keys: K[]
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
  field: TokenField<P>
): field is Extract<TokenField<P>, { key: keyof OAuthProviderTokenMap[P] }> {
  return typeof field === "object" && field !== null && "key" in field;
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
  provider: P
):
  | Partial<Record<keyof OAuthProviderTokenMap[P], ProviderFieldValue<P>>>
  | false {
  const result = {} as Partial<
    Record<keyof OAuthProviderTokenMap[P], ProviderFieldValue<P>>
  >;

  for (const { cookieKey, fieldKey } of resolveProviderFieldMeta(provider)) {
    const raw = getCookie(event, cookieKey);
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
 * This function iterates over the provider’s configured metadata fields
 * (via `providerConfig[provider].providerSpecificFields`) and sets each
 * as a secure, serializable cookie. It supports both raw string/number
 * fields and structured fields with custom `setter` functions for transforming
 * the value before storage.
 *
 * Only values that are defined and of type `string` or `number` are written.
 * Undefined or non-serializable values are ignored.
 *
 * @param event - The H3 event to attach cookies to.
 * @param tokens - The typed OAuth token payload for the provider.
 * @param provider - The OAuth provider key (e.g., "clio", "azure", "intuit").
 * @param baseOptions - The default cookie options to apply to each write (e.g., `secure`, `httpOnly`).
 */
export function setProviderCookieFields<P extends OAuthProvider>(
  event: H3Event,
  tokens: OAuthProviderTokenMap[P],
  provider: P,
  baseOptions: Parameters<typeof setCookie>[3]
): void {
  for (const { cookieKey, fieldKey, setter } of resolveProviderFieldMeta(
    provider
  )) {
    const raw = tokens[fieldKey];
    if (raw === undefined) continue;

    const value = setter ? setter(String(raw)) : String(raw);

    // Only set cookies for serializable types
    if (typeof raw === "string" || typeof raw === "number") {
      setCookie(event, cookieKey, value, baseOptions);
    }
  }
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
  provider: P
): Array<{
  cookieKey: string;
  fieldKey: keyof OAuthProviderTokenMap[P];
  setter?: (raw: string) => string;
}> {
  const fields = providerConfig[provider].providerSpecificFields;

  return fields.flatMap((field) => {
    if (typeof field === "string") {
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
