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
  OAuthLoginOptions,
  LogoutProviderInput,
  LogoutResult,
  LogoutProvider,
  ProviderId,
  GetProviderKey,
  TokenFor,
  InputOAuthProviderConfigMap,
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
  parseProviderKey,
  clearNonPreservedCookies,
  discoverProviderInstance,
} from './utils';
import { createEncryption } from './utils/encryption';

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

export function useOAuthRegistry(encryptionKey: string) {
  const { encrypt, decrypt } = createEncryption(encryptionKey);

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
  function registerOAuthProvider<P extends OAuthProvider>(
    provider: P,
    config: InputOAuthProviderConfigMap[P],
  ): void;

  function registerOAuthProvider<P extends OAuthProvider>(
    provider: P,
    instanceKey: string,
    config: InputOAuthProviderConfigMap[P],
  ): void;

  function registerOAuthProvider<P extends OAuthProvider>(
    provider: P,
    instanceOrConfig: string | InputOAuthProviderConfigMap[P],
    maybeConfig?: InputOAuthProviderConfigMap[P],
  ): void {
    const isScoped = typeof instanceOrConfig === 'string';
    const key = isScoped ? `${provider}:${instanceOrConfig}` : provider;
    const userConfig = isScoped ? maybeConfig! : instanceOrConfig;
    // Add encrypt/decrypt internally
    const config = {
      ...userConfig,
      encrypt,
      decrypt,
    } as OAuthProviderConfigMap[P];
    providerRegistry.set(key, config);
  }

  return {
    registerOAuthProvider,
  };
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
 *
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
  const key = getProviderKey(provider, instanceKey);

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
 * Checks if a provider configuration is registered.
 *
 * @param provider - The provider key.
 * @param instanceKey - Optional instance key.
 *
 * @returns `true` if the provider is registered, `false` otherwise.
 */
export function hasOAuthProviderConfig<P extends OAuthProvider>(
  provider: P,
  instanceKey?: string,
): boolean {
  const key = getProviderKey(provider, instanceKey);

  return providerRegistry.has(key);
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
 * ### Multi-instance mode (preserves multiple instances)
 * ```ts
 * export default handleOAuthLogin("clio", "smithlaw", { redirect: true, preserveInstance: true });
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
 *   - `redirect` (default: `false`) — Whether to automatically redirect to the provider's login page.
 *   - `state` — Optional state object or string to persist across login/callback.
 *   - `preserveInstance` (default: `false`) — Whether to preserve this instance in scoped cookies.
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
  options: {
    redirect?: false;
    state?: OAuthStateValue;
    preserveInstance?: boolean;
  },
  event: H3Event,
): Promise<{ url: string }>;

export function handleOAuthLogin<P extends OAuthProvider>(
  provider: P,
  options: {
    redirect: true;
    state?: OAuthStateValue;
    preserveInstance?: boolean;
  },
  event: H3Event,
): Promise<void>;

export function handleOAuthLogin<P extends OAuthProvider>(
  provider: P,
  instanceKey?: string,
  options?: OAuthLoginOptions,
  event?: H3Event,
): Promise<{ url: string }>;

export function handleOAuthLogin<P extends OAuthProvider>(
  provider: P,
  instanceKey: string,
  options: {
    redirect: true;
    state?: OAuthStateValue;
    preserveInstance?: boolean;
  },
  event: H3Event,
): Promise<void>;

export function handleOAuthLogin<P extends OAuthProvider>(
  provider: P,
  instanceKey?: string | OAuthLoginOptions,
  optionsOrEvent?: OAuthLoginOptions | H3Event,
  maybeEvent?: H3Event,
): EventHandler | Promise<{ url: string } | void> {
  const isScoped = typeof instanceKey === 'string';
  const resolvedInstanceKey = isScoped ? instanceKey : undefined;

  const options = isScoped
    ? (optionsOrEvent as OAuthLoginOptions)
    : (instanceKey as OAuthLoginOptions) ?? {};

  const event = isScoped ? maybeEvent : (optionsOrEvent as H3Event | undefined);

  const handler = async (evt: H3Event) => {
    const config = resolvedInstanceKey
      ? getOAuthProviderConfig(provider, resolvedInstanceKey)
      : getOAuthProviderConfig(provider);

    const providerKey = getProviderKey(
      provider,
      resolvedInstanceKey,
      options?.preserveInstance,
    );

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
    instanceEquivalent?: (
      rawTokens: OAuthProviderTokenMap[P],
      event: H3Event,
      provider: P,
      instanceKey?: string,
    ) => Promise<boolean> | boolean;
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
    instanceEquivalent?: (
      rawTokens: OAuthProviderTokenMap[P],
      event: H3Event,
      provider: P,
      instanceKey?: string,
    ) => Promise<boolean> | boolean;
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
    instanceEquivalent?: (
      rawTokens: OAuthProviderTokenMap[P],
      event: H3Event,
      provider: P,
      instanceKey?: string,
    ) => Promise<boolean> | boolean;
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
    instanceEquivalent?: (
      rawTokens: OAuthProviderTokenMap[P],
      event: H3Event,
      provider: P,
      instanceKey?: string,
    ) => Promise<boolean> | boolean;
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

      // Parse the provider key to extract preserveInstance flag
      const {
        provider: _baseProvider,
        instanceKey,
        preserveInstance,
      } = parseProviderKey(parsedState.providerKey);

      const config = instanceKey
        ? getOAuthProviderConfig(provider, instanceKey)
        : getOAuthProviderConfig(provider);

      const rawTokens = await exchangeCodeForTokens(code, config, provider);

      // Add user validation step
      if (options?.instanceEquivalent) {
        const isValid = await options.instanceEquivalent(
          rawTokens,
          evt,
          provider,
          instanceKey,
        );

        if (!isValid) {
          throw createError({
            statusCode: 401,
            statusMessage: 'User validation failed after OAuth callback',
          });
        }
      }

      // Clear non-preserved cookies if not in preserve mode
      if (!preserveInstance) {
        clearNonPreservedCookies(evt, provider);
      }

      // Set cookies with instance scoping (preserveInstance only affects clearing, not scoping)
      const tokens = await setProviderCookies(
        evt,
        rawTokens,
        provider,
        options?.cookieOptions,
        instanceKey,
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
 * - Resolves the instance key (either from explicit definition or via `resolveInstance`)
 * - Verifies that access, refresh, and metadata cookies are present.
 * - Checks whether the access token is expired.
 * - If expired, attempts to refresh the token using the stored refresh token.
 * - Normalizes and re-stores tokens using `setProviderCookies`.
 * - Injects the provider's access token into `event.context` under `${provider}_access_token`.
 * - Injects the full token object into `event.context.h3OAuthKit[provider]`.
 *
 * ### Dynamic Instance Resolution
 *
 * When providers are defined as strings (e.g., `["clio"]`) and a `resolveInstance` function
 * is provided in options, the function will be called to dynamically determine the instance
 * key based on the request context:
 *
 * ```ts
 * defineProtectedRoute(
 *   ["clio"],
 *   async (event) => { ... },
 *   {
 *     resolveInstance: async (event, provider) => {
 *       // Extract tenant/instance from request headers, URL, etc.
 *       return event.node.req.headers['x-tenant-id'];
 *     }
 *   }
 * );
 * ```
 *
 * When providers are defined as objects with explicit `instanceKey`, that takes precedence
 * over `resolveInstance`.
 *
 * If any provider's tokens are missing or invalid, the request is rejected with a `401 Unauthorized` error.
 *
 * @template Providers - A tuple of OAuth provider names (e.g., `["clio", "intuit"]`).
 *
 * @param providers - An array of providers to protect the route with.
 * @param handler - A function that handles the request if all tokens are valid. It receives a strongly typed `H3Event` with provider tokens injected into the context.
 * @param options - Optional configuration including:
 *   - `cookieOptions`: Customize cookie behavior (`sameSite`, `path`, etc.)
 *   - `onAuthFailure`: Custom error handling for auth failures
 *   - `resolveInstance`: Dynamic instance resolution function
 *
 * @returns A wrapped `defineEventHandler` that enforces token validation before invoking the handler.
 *
 */
export function defineProtectedRoute<
  Defs extends (OAuthProvider | ScopedProvider)[],
  InstanceKeys extends string = never,
>(
  providers: Defs,
  handler: (
    event: H3Event & { context: AugmentedContext<Defs, InstanceKeys> },
  ) => Promise<unknown>,
  options?: ProtectedRouteOptions<InstanceKeys>,
): EventHandler {
  return defineEventHandler(async (event): Promise<unknown> => {
    const ctx = event.context as AugmentedContext<Defs, InstanceKeys>;

    ctx.h3OAuthKit = {} as AugmentedContext<Defs, InstanceKeys>['h3OAuthKit'];
    ctx.h3OAuthKitInstances = {} as AugmentedContext<
      Defs,
      InstanceKeys
    >['h3OAuthKitInstances'];

    for (const def of providers) {
      const isScoped = typeof def !== 'string';
      const provider = isScoped ? def.provider : def;

      try {
        // Resolve instanceKey: use explicit instanceKey or instanceResolver
        let instanceKey: string | undefined;
        if (isScoped) {
          if ('instanceKey' in def) {
            instanceKey = def.instanceKey;
          } else if ('instanceResolver' in def) {
            instanceKey = await def.instanceResolver(event);
          }
        }

        let providerKey = getProviderKey(provider, instanceKey);
        let result = await oAuthTokensAreValid(event, provider, instanceKey);

        // If no result and this is a string provider, try auto-discovery
        if (!result && !isScoped) {
          const discoveredInstanceKey = discoverProviderInstance(
            event,
            provider,
          );
          if (discoveredInstanceKey) {
            instanceKey = discoveredInstanceKey;
            providerKey = getProviderKey(provider, instanceKey);
            result = await oAuthTokensAreValid(event, provider, instanceKey);
          }
        }

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

          tokens = await setProviderCookies(
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
        (ctx.h3OAuthKit as unknown as Record<Key, Token>)[providerKey as Key] =
          tokens as Token;

        // Store the resolved instance key
        const baseProvider = isScoped ? def.provider : def;
        (ctx.h3OAuthKitInstances as Record<string, string | undefined>)[
          baseProvider
        ] = instanceKey;
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

    return handler(
      event as H3Event & { context: AugmentedContext<Defs, InstanceKeys> },
    );
  });
}

/**
 * Deletes all cookies for a given OAuth provider, optionally scoped by instance.
 *
 * When `instanceKey` is provided, deletes only cookies for that specific instance.
 * When `instanceKey` is undefined, deletes ALL cookies for registered instances of
 * this provider by looking up the provider registry.
 *
 * If no providers are registered for the given provider key, no cookies are deleted.
 * This ensures we only delete cookies for configurations that were actually registered.
 *
 * @param event - The H3 event to delete cookies from.
 * @param provider - The base OAuth provider key (e.g., `"clio"`).
 * @param instanceKey - Optional instance key (e.g., `"smithlaw"`). If undefined, deletes all provider cookies.
 */
export function deleteProviderCookies(
  event: H3Event,
  provider: OAuthProvider,
  instanceKey?: string,
): void {
  if (instanceKey) {
    // Specific instance: delete only those cookies
    for (const cookieName of getProviderCookieKeys(provider, instanceKey)) {
      deleteCookie(event, cookieName);
    }
  } else {
    // Wildcard: find all registered instances for this provider
    const registeredKeys = Array.from(providerRegistry.keys());
    const providerKeys = registeredKeys.filter(
      (key) => key === provider || key.startsWith(`${provider}:`),
    );

    // Registry-based deletion: delete cookies for each registered provider key
    for (const providerKey of providerKeys) {
      const extractedInstanceKey = providerKey.includes(':')
        ? providerKey.split(':')[1]
        : undefined;

      for (const cookieName of getProviderCookieKeys(
        provider,
        extractedInstanceKey,
      )) {
        deleteCookie(event, cookieName);
      }
    }
  }
}

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

/**
 * @internal
 *
 * Gets the discovered provider tokens from the context, handling both global and scoped instances.
 *
 * This utility helps when you need to access tokens that were auto-discovered by defineProtectedRoute
 * but don't know the exact instance key that was used.
 *
 * @param context - The h3OAuthKit context from the event
 * @param provider - The OAuth provider to get tokens for
 * @returns Object with the tokens and the discovered key, or undefined if not found
 */
export function getDiscoveredProviderTokens<P extends OAuthProvider>(
  context: Record<string, unknown>,
  provider: P,
): { tokens: OAuthProviderTokenMap[P]; key: string } | undefined {
  // First try global provider
  if (context[provider]) {
    return {
      tokens: context[provider] as OAuthProviderTokenMap[P],
      key: provider,
    };
  }

  // Then try scoped instances
  for (const [key, tokens] of Object.entries(context)) {
    if (key.startsWith(`${provider}:`)) {
      return { tokens: tokens as OAuthProviderTokenMap[P], key };
    }
  }

  return undefined;
}

/**
 * Creates a typed instance resolver that helps TypeScript understand what instance key
 * your resolver function will return, enabling better type safety when accessing tokens.
 *
 * @example
 * ```typescript
 * const resolver = typedInstanceResolver<"smithlaw">((event) => {
 *   const { firmId } = getRouterParams(event);
 *   return firmId === "smith" ? "smithlaw" : undefined;
 * });
 *
 * defineProtectedRoute([
 *   { provider: "clio", instanceResolver: resolver }
 * ], async (event) => {
 *   // TypeScript knows about 'clio:smithlaw'
 *   const tokens = event.context.h3OAuthKit['clio:smithlaw'];
 * });
 * ```
 *
 * @param resolver - The instance resolver function
 * @returns The same resolver function with enhanced type information
 */
export function typedInstanceResolver<T extends string>(
  resolver: (event: H3Event) => T | undefined | Promise<T | undefined>,
): (event: H3Event) => T | undefined | Promise<T | undefined> {
  return resolver;
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

export * from './types';
