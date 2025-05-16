import * as h3 from 'h3';
import { H3Event, H3EventContext, EventHandler } from 'h3';

type OAuthProvider = "azure" | "clio" | "intuit";
type RequiredPick<T, K extends keyof T> = {
    [P in K]-?: NonNullable<T[P]>;
};
interface BaseOAuthProviderConfig {
    clientId: string;
    clientSecret: string;
    authorizeEndpoint: string;
    tokenEndpoint: string;
    redirectUri: string;
    scopes: string[];
}
type OAuthProviderConfig = AzureOAuthProviderConfig | ClioOAuthProviderConfig | IntuitOAuthProviderConfig;
interface AzureOAuthProviderConfig extends BaseOAuthProviderConfig {
    tenantId: string;
}
interface ClioOAuthProviderConfig extends BaseOAuthProviderConfig {
}
interface IntuitOAuthProviderConfig extends BaseOAuthProviderConfig {
    environment: "sandbox" | "production";
}
interface OAuthCodeExchangeInput {
    code: string;
    clientId: string;
    clientSecret: string;
    redirectUri: string;
    tokenEndpoint: string;
    scope?: string;
}
interface OAuthTokenBase {
    access_token: string;
    refresh_token?: string;
    expires_in: number;
    token_type: "Bearer" | "bearer";
}
type AzureAuthTokens = OAuthTokenBase & {
    ext_expires_in: number;
    scope: string;
    id_token: string;
};
type ClioAuthTokens = OAuthTokenBase & {
    client_id: string;
};
type IntuitAuthTokens = OAuthTokenBase & {
    realm_id: string;
    x_refresh_token_expires_in: number;
};
type OAuthTokens = AzureAuthTokens | ClioAuthTokens | IntuitAuthTokens;
interface AzureCookies {
    azure_access_token: string;
    azure_refresh_token: string;
    azure_access_token_expires_at: string;
    azure_ext_expires_in: string;
    azure_tenant_id: string;
}
interface ClioCookies {
    clio_access_token: string;
    clio_refresh_token: string;
    clio_access_token_expires_at: string;
    clio_client_id: string;
}
interface IntuitCookies {
    intuit_access_token: string;
    intuit_refresh_token: string;
    intuit_access_token_expires_at: string;
    intuit_refresh_token_expires_at: string;
    intuit_realm_id: string;
}
interface IntuitRefreshTokenResponse {
    expires_in: number;
    access_token: string;
    refresh_token: string;
    x_refresh_token_expires_in: number;
    token_type: "bearer";
}
interface ClioRefreshTokenResponse {
    access_token: string;
    token_type: "bearer";
    expires_in: number;
}
interface AzureRefreshTokenResponse {
    access_token: string;
    refresh_token: string;
    token_type: "Bearer";
    expires_in: number;
    ext_expires_in: number;
}
type OAuthProviderTokenMap = {
    azure: AzureAuthTokens;
    clio: ClioAuthTokens;
    intuit: IntuitAuthTokens;
};
type ProviderToken<T extends OAuthProvider> = OAuthProviderTokenMap[T];
type TokenValidationResult<T extends OAuthProvider> = {
    tokens: OAuthProviderTokenMap[T];
    status: "valid" | "expired";
};
type AzureTokenValidationResult = TokenValidationResult<"azure">;
type ClioTokenValidationResult = TokenValidationResult<"clio">;
type IntuitTokenValidationResult = TokenValidationResult<"intuit">;
type ProviderAccessTokenKeys<Providers extends OAuthProvider[]> = `${Providers[number]}_access_token`;
type AugmentedContext<Providers extends OAuthProvider[]> = RequiredPick<H3EventContext, ProviderAccessTokenKeys<Providers>> & {
    h3OAuthKit: {
        [P in Providers[number]]: OAuthProviderTokenMap[P];
    };
};
type OAuthProviderConfigMap = {
    azure: AzureOAuthProviderConfig;
    clio: ClioOAuthProviderConfig;
    intuit: IntuitOAuthProviderConfig;
};
type RefreshTokenResponseMap = {
    azure: AzureRefreshTokenResponse;
    clio: ClioRefreshTokenResponse;
    intuit: IntuitRefreshTokenResponse;
};
type RefreshTokenResponse<T extends OAuthProvider> = RefreshTokenResponseMap[T];
type RefreshTokenConfig<T extends OAuthProvider> = OAuthProviderConfigMap[T];
type RefreshTokenConfigBuilder<T extends OAuthProvider> = (config: RefreshTokenConfig<T>, refreshToken: string) => {
    url: string;
    params: Record<string, string>;
};
type OAuthStateValue = string | Record<string, unknown> | ((event: H3Event) => string | Record<string, unknown>);
type OAuthParsedState = Record<string, string>;
interface CookieOptionsOverride {
    sameSite?: "lax" | "none";
    path?: string;
}
interface HandleOAuthCallbackOptions {
    redirect?: boolean;
    redirectTo?: string;
    cookieOptions?: CookieOptionsOverride;
}
interface ProtectedRouteOptions {
    cookieOptions?: CookieOptionsOverride;
    onAuthFailure?: (event: H3Event, provider: OAuthProvider, reason: "missing-or-invalid-tokens" | "token-refresh-failed" | "error-occurred", error: unknown) => Promise<unknown> | unknown;
}
interface BaseOAuthCookies {
    access_token: string;
    refresh_token: string;
    access_token_expires_at: string;
}
interface AzureTokenCookies extends BaseOAuthCookies {
}
interface ClioTokenCookies extends BaseOAuthCookies {
}
interface IntuitTokenCookies extends BaseOAuthCookies {
    refresh_token_expires_at: string;
}
type BaseOAuthCallbackQuery = {
    code?: string;
    state?: string;
    error?: string;
    error_description?: string;
};
interface AzureOAuthCallbackQuery extends BaseOAuthCallbackQuery {
    session_state: string;
    id_token: string;
}
interface IntuitOAuthCallbackQuery extends BaseOAuthCallbackQuery {
    realmId: string;
}
interface ClioOAuthCallbackQuery extends BaseOAuthCallbackQuery {
}
type OAuthCallbackQueryMap = {
    intuit: IntuitOAuthCallbackQuery;
    clio: ClioOAuthCallbackQuery;
    azure: AzureOAuthCallbackQuery;
};
type OAuthCallbackQuery<P extends OAuthProvider> = OAuthCallbackQueryMap[P];
interface StoredTokenCookiesBase {
    access_token: string;
    refresh_token: string;
    access_token_expires_at: string;
}
type ProviderFieldValue<P extends OAuthProvider> = OAuthProviderTokenMap[P][keyof OAuthProviderTokenMap[P]];
type TokenField<P extends OAuthProvider> = keyof OAuthProviderTokenMap[P] | {
    key: keyof OAuthProviderTokenMap[P];
    cookieName?: string;
    setter?: (value: string) => string;
};
interface ProviderConfig<P extends OAuthProvider> {
    providerSpecificFields: TokenField<P>[];
    callbackQueryFields?: (keyof OAuthCallbackQuery<P>)[];
    validateRefreshTokenExpiry?: boolean;
}
interface OAuthErrorResponse {
    error?: string;
    error_description?: string;
}
interface OAuthErrorResponse {
    error?: string;
    error_description?: string;
}

/**
 * @internal
 *
 * Internal in-memory registry of OAuth provider configurations.
 *
 * This map is used to store and retrieve provider-specific OAuth settings such as
 * `clientId`, `clientSecret`, `scopes`, `tokenEndpoint`, and `redirectUri`.
 *
 * Providers must be registered before calling any functions that rely on provider metadata,
 * such as `handleOAuthLogin`, `handleOAuthCallback`, or `defineProtectedRoute`.
 *
 * Keys are the provider identifiers (e.g., `"clio"`, `"azure"`, `"intuit"`).
 */
declare const providerRegistry: Map<OAuthProvider, OAuthProviderConfig>;
/**
 * Registers an OAuth provider configuration into the internal registry.
 *
 * This function must be called before any OAuth operations involving the provider
 * can take place. It allows you to dynamically provide credentials and endpoints
 * for each OAuth provider at runtime.
 *
 * @template P - The name of the OAuth provider (e.g., `"azure"`, `"clio"`).
 *
 * @param provider - The unique identifier for the provider.
 * @param config - The full OAuth configuration object for that provider, including
 * client credentials, token endpoint, and redirect URI.
 *
 */
declare function registerOAuthProvider<P extends OAuthProvider>(provider: P, config: OAuthProviderConfigMap[P]): void;
/**
 * Retrieves the registered configuration for a given OAuth provider.
 *
 * Throws an error if the provider has not been registered. Used internally
 * by login, callback, and route-protection utilities to obtain the
 * provider's token endpoint, redirect URI, and other required metadata.
 *
 * @template P - The name of the OAuth provider (e.g., `"azure"`, `"clio"`).
 *
 * @param provider - The provider identifier whose config should be returned.
 * @returns The typed OAuth configuration object for the provider.
 *
 * @throws {Error} If the provider has not been registered via `registerOAuthProvider`.
 */
declare function getOAuthProviderConfig<P extends OAuthProvider>(provider: P): OAuthProviderConfigMap[P];
/**
 * Initiates the OAuth login flow for the given provider.
 *
 * Can be used in two ways:
 *
 * 1. As a route handler (automatic redirect):
 *    ```ts
 *    export default handleOAuthLogin("clio", { redirect: true });
 *    ```
 *
 * 2. As a utility inside a custom handler (manual redirect):
 *    ```ts
 *    const { url } = await handleOAuthLogin("clio", {}, event);
 *    return sendRedirect(event, url);
 *    ```
 *
 * If `redirect` is explicitly set to `true`, the user is redirected immediately.
 * Otherwise (default), the authorization URL is returned for manual handling.
 *
 * @param provider - The OAuth provider to use (e.g., "azure", "clio", "intuit").
 * @param options.redirect - Whether to automatically redirect the user. Defaults to `false`.
 * @param options.state - Optional state value or generator function to include in the login URL.
 * @param event - The H3 event, required when using this as a utility inside a custom handler.
 *
 * @returns An `EventHandler` when used as a route.
 *          A `{ url }` object when `redirect` is false (default).
 *          `void` when `redirect` is true and a redirect is performed.
 */
declare function handleOAuthLogin<P extends OAuthProvider>(provider: P, options: {
    redirect?: false;
    state?: OAuthStateValue;
}, event: H3Event): Promise<{
    url: string;
}>;
declare function handleOAuthLogin<P extends OAuthProvider>(provider: P, options: {
    redirect: true;
    state?: OAuthStateValue;
}, event: H3Event): Promise<void>;
declare function handleOAuthLogin<P extends OAuthProvider>(provider: P, options?: {
    redirect?: boolean;
    state?: OAuthStateValue;
}, event?: undefined): EventHandler;
/**
 * Handles the OAuth callback flow.
 *
 * Can be used as:
 * - A route handler: `export default handleOAuthCallback(...)`
 * - A utility: `const { tokens, redirectTo } = await handleOAuthCallback(..., event)`
 *
 * If `redirect` is explicitly set to `true` (default), the user is redirected.
 * Otherwise, tokens and the resolved redirect target are returned.
 *
 * @param provider - The OAuth provider to use.
 * @param options.redirectTo - The path to redirect to on success (default: "/").
 * @param options.redirect - Whether to automatically redirect (default: `true`).
 * @param options.cookieOptions - Cookie options to use for the tokens.
 * @param event - The event to use when calling inside a custom handler.
 *
 * @returns An `EventHandler`, or `{ tokens }` if `redirect: false`.
 */
declare function handleOAuthCallback<P extends OAuthProvider>(provider: P, options: {
    redirect?: false;
    redirectTo?: string;
    cookieOptions?: CookieOptionsOverride;
    onError?: (error: unknown, event: H3Event, provider: P) => Promise<unknown> | unknown;
}, event: H3Event): Promise<{
    tokens: OAuthProviderTokenMap[P];
    state: OAuthParsedState;
    callbackQueryData: OAuthCallbackQuery<P>;
}>;
declare function handleOAuthCallback<P extends OAuthProvider>(provider: P, options: {
    redirect: true;
    redirectTo?: string;
    cookieOptions?: CookieOptionsOverride;
    onError?: (error: unknown, event: H3Event, provider: P) => Promise<unknown> | unknown;
}, event: H3Event): Promise<void>;
declare function handleOAuthCallback<P extends OAuthProvider>(provider: P, options?: {
    redirect?: boolean;
    redirectTo?: string;
    cookieOptions?: CookieOptionsOverride;
    onError?: (error: unknown, event: H3Event, provider: P) => Promise<unknown> | unknown;
}, event?: undefined): EventHandler;
/**
 * Defines an H3 route handler that requires valid OAuth tokens for one or more providers.
 *
 * This function performs the following steps for each specified provider:
 * - Verifies that access, refresh, and metadata cookies are present.
 * - Checks whether the access token is expired.
 * - If expired, attempts to refresh the token using the stored refresh token.
 * - Normalizes and re-stores tokens using `setProviderCookies`.
 * - Injects the provider's access token into `event.context` under `${provider}_access_token`.
 * - Injects the full token object into `event.context.h3OAuthKit[provider]`.
 *
 * If any provider's tokens are missing or invalid, the request is rejected with a `401 Unauthorized` error.
 *
 * @template Providers - A tuple of OAuth provider names (e.g., `["clio", "intuit"]`).
 *
 * @param providers - An array of providers to protect the route with.
 * @param handler - A function that handles the request if all tokens are valid. It receives a strongly typed `H3Event` with provider tokens injected into the context.
 * @param options - Optional configuration for token cookie behavior (e.g., `cookieOptions` to customize `sameSite`, `path`, etc.).
 *
 * @returns A wrapped `defineEventHandler` that enforces token validation before invoking the handler.
 *
 */
declare function defineProtectedRoute<Providers extends OAuthProvider[]>(providers: [...Providers], handler: (event: H3Event & {
    context: AugmentedContext<Providers>;
}) => Promise<unknown>, options?: ProtectedRouteOptions): EventHandler<h3.EventHandlerRequest, Promise<unknown>>;

export { defineProtectedRoute, getOAuthProviderConfig, handleOAuthCallback, handleOAuthLogin, providerRegistry, registerOAuthProvider };
export type { AugmentedContext, AzureAuthTokens, AzureCookies, AzureOAuthCallbackQuery, AzureOAuthProviderConfig, AzureRefreshTokenResponse, AzureTokenCookies, AzureTokenValidationResult, BaseOAuthCallbackQuery, BaseOAuthCookies, BaseOAuthProviderConfig, ClioAuthTokens, ClioCookies, ClioOAuthCallbackQuery, ClioOAuthProviderConfig, ClioRefreshTokenResponse, ClioTokenCookies, ClioTokenValidationResult, CookieOptionsOverride, HandleOAuthCallbackOptions, IntuitAuthTokens, IntuitCookies, IntuitOAuthCallbackQuery, IntuitOAuthProviderConfig, IntuitRefreshTokenResponse, IntuitTokenCookies, IntuitTokenValidationResult, OAuthCallbackQuery, OAuthCallbackQueryMap, OAuthCodeExchangeInput, OAuthErrorResponse, OAuthParsedState, OAuthProvider, OAuthProviderConfig, OAuthProviderConfigMap, OAuthProviderTokenMap, OAuthStateValue, OAuthTokenBase, OAuthTokens, ProtectedRouteOptions, ProviderAccessTokenKeys, ProviderConfig, ProviderFieldValue, ProviderToken, RefreshTokenConfig, RefreshTokenConfigBuilder, RefreshTokenResponse, RefreshTokenResponseMap, RequiredPick, StoredTokenCookiesBase, TokenField, TokenValidationResult };
