import type { H3Event, EventHandler } from 'h3';
import type {
  OAuthProvider,
  AugmentedContext,
  ProtectedRouteOptions,
  OAuthProviderConfigMap,
  OAuthProviderTokenMap,
  OAuthProviderConfig,
  OAuthStateValue,
  CookieOptionsOverride,
  OAuthParsedState,
  OAuthCallbackQuery,
  ScopedProvider,
  TokenFor,
  ProviderId,
  GetProviderKey,
} from './types';

import {
  defineEventHandler,
  createError,
  sendRedirect,
  getQuery,
  isError,
  deleteCookie,
} from 'h3';
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
  getProviderCookieKeys,
  getProviderKey,
} from './utils';

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
 * Keys are the provider identifiers (e.g., `"clio"`, `"azure"`, `"intuit"`) or
 * scoped identifiers (e.g., `"clio:smithlaw"`).
 */
export const providerRegistry = new Map<string, OAuthProviderConfig>();

/**
 * Registers an OAuth provider configuration into the internal registry.
 *
 * ### Usage:
 * - Global (default for the provider):
 *   ```ts
 *   registerOAuthProvider("clio", config);
 *   ```
 *
 * - Per-instance (e.g. multi-tenant or per OAuth app):
 *   ```ts
 *   registerOAuthProvider("clio", "smithlaw", config);
 *   ```
 *
 * @param provider - The provider key (e.g., `"clio"`, `"intuit"`).
 * @param instanceKey - Optional instance identifier for multi-tenant use.
 * @param config - The OAuth configuration object.
 */
export function registerOAuthProvider<P extends OAuthProvider>(
  provider: P,
  config: OAuthProviderConfigMap[P],
): void;

export function registerOAuthProvider<P extends OAuthProvider>(
  provider: P,
  instanceKey: string,
  config: OAuthProviderConfigMap[P],
): void;

export function registerOAuthProvider<P extends OAuthProvider>(
  provider: P,
  instanceOrConfig: string | OAuthProviderConfigMap[P],
  maybeConfig?: OAuthProviderConfigMap[P],
): void {
  const isScoped = typeof instanceOrConfig === 'string';
  const key = isScoped ? `${provider}:${instanceOrConfig}` : provider;
  const config = isScoped ? maybeConfig! : instanceOrConfig;

  providerRegistry.set(key, config);
}

/**
 * Retrieves the registered configuration for a given OAuth provider.
 *
 * You can retrieve either a global config (e.g., for a single-tenant app), or
 * an instance-scoped config for a specific account or integration.
 *
 * ### Usage
 * ```ts
 * getOAuthProviderConfig("clio");             // global default
 * getOAuthProviderConfig("clio", "smithlaw"); // scoped per instanceKey
 * ```
 *
 * @template P - The OAuth provider key (e.g., `"clio"`, `"intuit"`).
 * @param provider - The provider identifier.
 * @param instanceKey - Optional key to retrieve a specific instance's config.
 * @returns The corresponding OAuth configuration object.
 * @throws {Error} If the provider config is not registered.
 */
export function getOAuthProviderConfig<P extends OAuthProvider>(
  provider: P,
): OAuthProviderConfigMap[P];

export function getOAuthProviderConfig<P extends OAuthProvider>(
  provider: P,
  instanceKey: string,
): OAuthProviderConfigMap[P];

export function getOAuthProviderConfig<P extends OAuthProvider>(
  provider: P,
  instanceKey?: string,
): OAuthProviderConfigMap[P] {
  const key = instanceKey ? `${provider}:${instanceKey}` : provider;

  const config = providerRegistry.get(key);

  if (!config) {
    throw createError({
      statusCode: 500,
      statusMessage: `OAuth provider "${key}" is not registered`,
    });
  }

  return config as OAuthProviderConfigMap[P];
}

/**
 * Initiates the OAuth login flow for a given provider, optionally scoped to a specific instance.
 *
 * This function supports both single-tenant and multi-tenant usage:
 *
 * ### Single-tenant (global provider configuration)
 * ```ts
 * export default handleOAuthLogin("clio", { redirect: true });
 * const { url } = await handleOAuthLogin("clio", {}, event);
 * ```
 *
 * ### Multi-tenant (instance-specific configuration)
 * ```ts
 * export default handleOAuthLogin("clio", "smithlaw", { redirect: true });
 * const { url } = await handleOAuthLogin("clio", "smithlaw", {}, event);
 * ```
 *
 * The login flow constructs an OAuth authorization URL using the registered provider config
 * and optionally redirects the user or returns the URL for manual redirection.
 *
 * ---
 *
 * @template P - The provider name (e.g., `"clio"`, `"azure"`, `"intuit"`).
 *
 * @param provider - The OAuth provider key.
 * @param instanceKey - *(Optional)* A unique identifier for the registered instance of the provider (e.g., `"smithlaw"`).
 *                      Use this to support multi-tenant or multi-app logins.
 *                      When omitted, the globally registered provider config is used.
 * @param options - Login options:
 *   - `redirect` (default: `false`) — Whether to automatically redirect to the provider’s login page.
 *   - `state` — Optional state object or string to persist across login/callback.
 * @param event - *(Optional)* H3 event object. Required when calling the function imperatively inside a custom route handler.
 *
 * @returns
 * - An `EventHandler` when `event` is not provided (for use as an API route).
 * - A `{ url }` object when `redirect` is `false` (manual redirect flow).
 * - `void` when `redirect` is `true` and the user is redirected.
 *
 * @throws
 * - If the provider or instanceKey is not registered via `registerOAuthProvider`.
 */
export function handleOAuthLogin<P extends OAuthProvider>(
  provider: P,
  options: { redirect?: false; state?: OAuthStateValue },
  event: H3Event,
): Promise<{ url: string }>;

export function handleOAuthLogin<P extends OAuthProvider>(
  provider: P,
  options: { redirect: true; state?: OAuthStateValue },
  event: H3Event,
): Promise<void>;

export function handleOAuthLogin<P extends OAuthProvider>(
  provider: P,
  instanceKey?: string,
  options?: { redirect?: false; state?: OAuthStateValue },
  event?: H3Event,
): Promise<{ url: string }>;

export function handleOAuthLogin<P extends OAuthProvider>(
  provider: P,
  instanceKey: string,
  options: { redirect: true; state?: OAuthStateValue },
  event: H3Event,
): Promise<void>;

export function handleOAuthLogin<P extends OAuthProvider>(
  provider: P,
  instanceKey?: string | { redirect?: boolean; state?: OAuthStateValue },
  optionsOrEvent?: { redirect?: boolean; state?: OAuthStateValue } | H3Event,
  maybeEvent?: H3Event,
): EventHandler | Promise<{ url: string } | void> {
  const isScoped = typeof instanceKey === 'string';

  const resolvedInstanceKey = isScoped ? instanceKey : undefined;

  const options = isScoped
    ? (optionsOrEvent as { redirect?: boolean; state?: OAuthStateValue })
    : (instanceKey as { redirect?: boolean; state?: OAuthStateValue }) ?? {};

  const event = isScoped ? maybeEvent : (optionsOrEvent as H3Event | undefined);

  const handler = async (evt: H3Event) => {
    const config = resolvedInstanceKey
      ? getOAuthProviderConfig(provider, resolvedInstanceKey)
      : getOAuthProviderConfig(provider);

    const providerKey = getProviderKey(provider, resolvedInstanceKey);

    const state = resolveState(evt, providerKey, options?.state);

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
      provider: P,
    ) => Promise<unknown> | unknown;
  },
  event: H3Event,
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
      provider: P,
    ) => Promise<unknown> | unknown;
  },
  event: H3Event,
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
      provider: P,
    ) => Promise<unknown> | unknown;
  },
  event?: undefined,
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
      provider: P,
    ) => Promise<unknown> | unknown;
  },
  event?: H3Event,
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

      if (!code || typeof code !== 'string') {
        throw createError({
          statusCode: 400,
          statusMessage: 'Authorization code missing in callback URL',
        });
      }

      if (!state || typeof state !== 'string') {
        throw createError({
          statusCode: 400,
          statusMessage: 'State missing in callback URL',
        });
      }

      const parsedState = parseOAuthState(state);

      verifyStateParam(evt, parsedState);

      const providerKey = getProviderKey(provider, parsedState.instanceKey);

      const config = parsedState.instanceKey
        ? getOAuthProviderConfig(provider, parsedState.instanceKey)
        : getOAuthProviderConfig(provider);

      const rawTokens = await exchangeCodeForTokens(code, config, provider);

      const tokens = setProviderCookies(
        evt,
        rawTokens,
        provider,
        options?.cookieOptions,
        providerKey,
      );

      const redirectTo = options?.redirectTo || '/';

      if (options?.redirect === false) {
        const callbackQueryData = parseOAuthCallbackQuery(evt, provider);

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
        message,
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
export function defineProtectedRoute<
  Defs extends (OAuthProvider | ScopedProvider)[],
>(
  providers: Defs,
  handler: (
    event: H3Event & { context: AugmentedContext<Defs> },
  ) => Promise<unknown>,
  options?: ProtectedRouteOptions,
): EventHandler {
  return defineEventHandler(async (event): Promise<unknown> => {
    const ctx = event.context as AugmentedContext<Defs>;

    ctx.h3OAuthKit = {} as AugmentedContext<Defs>['h3OAuthKit'];

    for (const def of providers) {
      const isScoped = typeof def !== 'string';
      const provider = isScoped ? def.provider : def;
      const instanceKey = isScoped ? def.instanceKey : undefined;

      const providerKey = getProviderKey(provider, instanceKey);

      try {
        const result = await oAuthTokensAreValid(event, provider, instanceKey);

        if (!result) {
          const error = createError({
            statusCode: 401,
            message: `Missing or invalid tokens for "${providerKey}"`,
          });

          if (options?.onAuthFailure) {
            const response = await options.onAuthFailure(
              event,
              provider,
              'missing-or-invalid-tokens',
              error,
            );
            if (response !== undefined) return response;
          }

          throw error;
        }

        let tokens = result.tokens;

        if (result.status === 'expired') {
          const config = instanceKey
            ? getOAuthProviderConfig(provider, instanceKey)
            : getOAuthProviderConfig(provider);

          const refreshed = await refreshToken(
            tokens.refresh_token!,
            config,
            provider,
          );

          if (!refreshed) {
            const error = createError({
              statusCode: 401,
              message: `Token refresh failed for "${providerKey}"`,
            });

            if (options?.onAuthFailure) {
              const response = await options.onAuthFailure(
                event,
                provider,
                'token-refresh-failed',
                error,
              );
              if (response !== undefined) return response;
            }

            throw error;
          }

          const fullToken = normalizeRefreshedToken(
            provider,
            refreshed,
            tokens,
          );

          tokens = setProviderCookies(
            event,
            fullToken,
            provider,
            options?.cookieOptions,
            instanceKey,
          );
        }

        // Correctly type-safe assign token using GetProviderKey
        type Def = typeof def;
        type Key = GetProviderKey<Def>;
        type Token = TokenFor<ProviderId<Def>>;

        (ctx.h3OAuthKit as Record<Key, Token>)[providerKey as Key] =
          tokens as Token;
      } catch (error) {
        if (options?.onAuthFailure) {
          const response = await options.onAuthFailure(
            event,
            provider,
            'error-occurred',
            error,
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

    return handler(event as H3Event & { context: AugmentedContext<Defs> });
  });
}

/**
 * Deletes all cookies for a given OAuth provider, optionally scoped by instance.
 *
 * This function uses `getProviderCookieKeys` to delete all stored tokens and
 * provider-specific fields for the given provider and optional instanceKey.
 *
 * @param event - The H3 event to delete cookies from.
 * @param provider - The base OAuth provider key (e.g., `"clio"`).
 * @param instanceKey - Optional instance key (e.g., `"smithlaw"`).
 */
export function deleteProviderCookies(
  event: H3Event,
  provider: OAuthProvider,
  instanceKey?: string,
): void {
  for (const cookieName of getProviderCookieKeys(provider, instanceKey)) {
    deleteCookie(event, cookieName);
  }
}

type LogoutProvider = {
  provider: OAuthProvider;
  instanceKey?: string;
};

type LogoutResult = {
  loggedOut: true;
  providers: LogoutProvider[];
};
export type LogoutProviderInput =
  | OAuthProvider
  | { provider: OAuthProvider; instanceKey?: string };

export function handleOAuthLogout(
  providers: LogoutProviderInput[],
): EventHandler;
export function handleOAuthLogout(
  providers: LogoutProviderInput[],
  options: { redirectTo?: string },
): EventHandler;
export function handleOAuthLogout(
  providers: LogoutProviderInput[],
  options: { redirectTo?: string },
  event: H3Event,
): Promise<{ loggedOut: true; providers: LogoutProvider[] }> | Promise<void>;

export function handleOAuthLogout(
  providers: LogoutProviderInput[],
  options?: { redirectTo?: string },
  event?: H3Event,
): EventHandler | Promise<LogoutResult | void> {
  const normalized: LogoutProvider[] = providers.map((p) =>
    typeof p === 'string' ? { provider: p } : p,
  );

  const handler = async (evt: H3Event) => {
    for (const { provider, instanceKey } of normalized) {
      deleteProviderCookies(evt, provider, instanceKey);
    }

    if (options?.redirectTo) {
      await sendRedirect(evt, options.redirectTo, 302);
      return;
    }

    return {
      loggedOut: true,
      providers: normalized,
    } as const;
  };

  return event ? handler(event) : defineEventHandler(handler);
}

export * from './types';
