import type { H3Event, EventHandler } from "h3";
import type {
  OAuthProvider,
  AugmentedContext,
  ProviderAccessTokenKeys,
  ProviderToken,
  ProtectedRouteOptions,
  OAuthProviderConfigMap,
  OAuthProviderTokenMap,
  OAuthProviderConfig,
  OAuthStateValue,
  CookieOptionsOverride,
  OAuthParsedState,
  OAuthCallbackQuery,
} from "./types";

import {
  defineEventHandler,
  createError,
  sendRedirect,
  getQuery,
  isError,
} from "h3";
import {
  setProviderCookies,
  parseOAuthState,
  resolveState,
  buildAuthUrl,
  verifyStateParam,
  exchangeCodeForTokens,
  normalizeRefreshedToken,
  parseOAuthCallbackQuery,
  oAuthTokensAreValid,
  refreshToken,
  parseError,
} from "./utils";

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
export const providerRegistry = new Map<OAuthProvider, OAuthProviderConfig>();

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
export function registerOAuthProvider<P extends OAuthProvider>(
  provider: P,
  config: OAuthProviderConfigMap[P]
): void {
  providerRegistry.set(provider, config);
}

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
export function getOAuthProviderConfig<P extends OAuthProvider>(
  provider: P
): OAuthProviderConfigMap[P] {
  const config = providerRegistry.get(provider);

  if (!config) {
    throw createError({
      statusCode: 500,
      statusMessage: `OAuth provider "${provider}" is not registered`,
    });
  }

  // We know that the config is of the correct type because we registered it.
  return config as OAuthProviderConfigMap[P];
}

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

export function handleOAuthLogin<P extends OAuthProvider>(
  provider: P,
  options: { redirect?: false; state?: OAuthStateValue },
  event: H3Event
): Promise<{ url: string }>;

export function handleOAuthLogin<P extends OAuthProvider>(
  provider: P,
  options: { redirect: true; state?: OAuthStateValue },
  event: H3Event
): Promise<void>;

export function handleOAuthLogin<P extends OAuthProvider>(
  provider: P,
  options?: { redirect?: boolean; state?: OAuthStateValue },
  event?: undefined
): EventHandler;

export function handleOAuthLogin(
  provider: OAuthProvider,
  options?: { redirect?: boolean; state?: OAuthStateValue },
  event?: H3Event
): EventHandler | Promise<{ url: string } | void> {
  const handler = async (evt: H3Event) => {
    const config = getOAuthProviderConfig(provider);

    const state = resolveState(evt, provider, options?.state);

    const authUrl = buildAuthUrl({
      authorizeEndpoint: config.authorizeEndpoint,
      clientId: config.clientId,
      redirectUri: config.redirectUri,
      scopes: config.scopes,
      state,
    });

    if (options?.redirect === true) {
      return sendRedirect(evt, authUrl, 302);
    }

    return { url: authUrl };
  };

  return event ? handler(event) : defineEventHandler(handler);
}

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

// Utility usage — no redirect
export function handleOAuthCallback<P extends OAuthProvider>(
  provider: P,
  options: {
    redirect?: false;
    redirectTo?: string;
    cookieOptions?: CookieOptionsOverride;
    onError?: (
      error: unknown,
      event: H3Event,
      provider: P
    ) => Promise<unknown> | unknown;
  },
  event: H3Event
): Promise<{
  tokens: OAuthProviderTokenMap[P];
  state: OAuthParsedState;
  callbackQueryData: OAuthCallbackQuery<P>;
}>;

// Utility usage — with redirect
export function handleOAuthCallback<P extends OAuthProvider>(
  provider: P,
  options: {
    redirect: true;
    redirectTo?: string;
    cookieOptions?: CookieOptionsOverride;
    onError?: (
      error: unknown,
      event: H3Event,
      provider: P
    ) => Promise<unknown> | unknown;
  },
  event: H3Event
): Promise<void>;

// Route handler usage
export function handleOAuthCallback<P extends OAuthProvider>(
  provider: P,
  options?: {
    redirect?: boolean;
    redirectTo?: string;
    cookieOptions?: CookieOptionsOverride;
    onError?: (
      error: unknown,
      event: H3Event,
      provider: P
    ) => Promise<unknown> | unknown;
  },
  event?: undefined
): EventHandler;

export function handleOAuthCallback<P extends OAuthProvider>(
  provider: P,
  options?: {
    redirect?: boolean;
    redirectTo?: string;
    cookieOptions?: CookieOptionsOverride;
    onError?: (
      error: unknown,
      event: H3Event,
      provider: P
    ) => Promise<unknown> | unknown;
  },
  event?: H3Event
):
  | EventHandler
  | Promise<{
      tokens: OAuthProviderTokenMap[P];
      state: OAuthParsedState;
      callbackQueryData: OAuthCallbackQuery<P>;
    }>
  | Promise<void> {
  const handler = async (evt: H3Event) => {
    try {
      const query = getQuery(evt);

      const { code, state } = query;

      if (!code || typeof code !== "string") {
        throw createError({
          statusCode: 400,
          statusMessage: "Authorization code missing in callback URL",
        });
      }

      if (!state || typeof state !== "string") {
        throw createError({
          statusCode: 400,
          statusMessage: "State missing in callback URL",
        });
      }

      verifyStateParam(evt, provider, state);

      const parsedState = parseOAuthState(state);

      const config = getOAuthProviderConfig(provider);

      const rawTokens = await exchangeCodeForTokens(code, config, provider);

      const callbackQueryData = parseOAuthCallbackQuery(evt, provider);

      const tokens = setProviderCookies(
        evt,
        rawTokens,
        provider,
        options?.cookieOptions
      );

      const redirectTo = options?.redirectTo || "/";

      if (options?.redirect === false) {
        return { tokens, state: parsedState, callbackQueryData };
      }

      return sendRedirect(evt, redirectTo, 302);
    } catch (error) {
      if (options?.onError) {
        const result = await options.onError(error, evt, provider);
        if (result !== undefined) return result;
      }

      if (isError(error)) {
        throw error; // already an H3Error (e.g. from `createError`)
      }

      const { statusCode, message } = await parseError(error);
      throw createError({
        statusCode,
        statusMessage: message,
        cause: error,
      });
    }
  };

  if (event) {
    if (options?.redirect === false) {
      return handler(event) as Promise<{
        tokens: OAuthProviderTokenMap[P];
        state: OAuthParsedState;
        callbackQueryData: OAuthCallbackQuery<P>;
      }>;
    } else {
      return handler(event) as Promise<void>;
    }
  }

  return defineEventHandler(handler);
}

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
export function defineProtectedRoute<Providers extends OAuthProvider[]>(
  providers: [...Providers],
  handler: (
    event: H3Event & { context: AugmentedContext<Providers> }
  ) => Promise<unknown>,
  options?: ProtectedRouteOptions
) {
  return defineEventHandler(async (event): Promise<unknown> => {
    const ctx = event.context as AugmentedContext<Providers>;
    ctx.h3OAuthKit = {} as AugmentedContext<Providers>["h3OAuthKit"];

    for (const provider of providers) {
      try {
        const result = await oAuthTokensAreValid(event, provider);

        if (!result) {
          const error = createError({
            statusCode: 401,
            message: `Missing or invalid tokens for "${provider}"`,
          });

          if (options?.onAuthFailure) {
            const response = await options.onAuthFailure(
              event,
              provider,
              "missing-or-invalid-tokens",
              error
            );

            if (response !== undefined) return response;
          }

          throw error;
        }

        let tokens = result.tokens;

        if (result.status === "expired") {
          const config = getOAuthProviderConfig(provider);

          const refreshed = await refreshToken(
            result.tokens.refresh_token!,
            config,
            provider
          );

          if (!refreshed) {
            const error = createError({
              statusCode: 401,
              message: `Token refresh failed for "${provider}"`,
            });

            if (options?.onAuthFailure) {
              const response = await options.onAuthFailure(
                event,
                provider,
                "token-refresh-failed",
                error
              );

              if (response !== undefined) return response;
            }

            throw error;
          }

          const fullToken = normalizeRefreshedToken(
            provider,
            refreshed,
            tokens
          );

          tokens = setProviderCookies(
            event,
            fullToken,
            provider,
            options?.cookieOptions
          );
        }

        const key =
          `${provider}_access_token` as ProviderAccessTokenKeys<Providers>;

        ctx[key as keyof typeof ctx] = tokens.access_token;

        ctx.h3OAuthKit[provider] = tokens as ProviderToken<typeof provider>;
      } catch (error) {
        if (options?.onAuthFailure) {
          const response = await options.onAuthFailure(
            event,
            provider,
            "error-occurred",
            error
          );

          if (response !== undefined) return response;
        }

        if (isError(error)) {
          throw error;
        }

        const { statusCode, message } = await parseError(error);

        throw createError({
          statusCode,
          statusMessage: message,
          cause: error,
        });
      }
    }

    return handler(event as H3Event & { context: AugmentedContext<Providers> });
  });
}

export * from "./types";
