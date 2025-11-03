import { ofetch } from 'ofetch';
import type {
  OAuthProvider,
  ClientCredentialsTokenRequest,
  ClientCredentialsTokenResponse,
  CachedClientCredentialsToken,
  ClientCredentialsOptions,
} from '../types';
import { providerRegistry } from '../index';

/**
 * In-memory cache for client credentials tokens
 * Key format: `{provider}:{instanceKey}:{scopes}`
 */
const tokenCache = new Map<string, CachedClientCredentialsToken>();

/**
 * Generates a cache key for storing/retrieving cached tokens
 */
function getCacheKey(
  provider: OAuthProvider,
  scopes: string[] | undefined,
  instanceKey?: string,
): string {
  const scopeKey = scopes?.sort().join(',') || 'default';
  return instanceKey
    ? `${provider}:${instanceKey}:${scopeKey}`
    : `${provider}::${scopeKey}`;
}

/**
 * Checks if a cached token is still valid
 * Tokens are considered expired if they expire within the next 60 seconds (buffer)
 */
function isCachedTokenValid(cached: CachedClientCredentialsToken): boolean {
  const now = Date.now();
  const bufferMs = 60 * 1000; // 60 second buffer
  return cached.expires_at > now + bufferMs;
}

/**
 * Retrieves a client credentials access token for machine-to-machine authentication
 *
 * This implements the OAuth 2.0 Client Credentials flow (RFC 6749 Section 4.4).
 * Unlike the Authorization Code flow, this doesn't involve user authentication
 * and is used for backend services to authenticate with APIs.
 *
 * ### Features:
 * - **Automatic caching**: Tokens are cached in memory until they expire
 * - **Multi-tenant support**: Works with scoped provider configurations
 * - **Custom scopes**: Override default scopes on a per-request basis
 *
 * ### Example:
 * ```typescript
 * // Get token for Azure API calls
 * const token = await getClientCredentialsToken('azure', {
 *   scopes: ['https://graph.microsoft.com/.default'],
 * });
 *
 * // Use token to call Microsoft Graph API
 * const user = await $fetch('https://graph.microsoft.com/v1.0/me', {
 *   headers: { Authorization: `Bearer ${token.access_token}` },
 * });
 * ```
 *
 * ### Multi-Tenant Example:
 * ```typescript
 * const token = await getClientCredentialsToken('azure', {
 *   instanceKey: 'tenant-a',
 *   scopes: ['api://myapp/.default'],
 * });
 * ```
 *
 * @param provider - The OAuth provider (e.g., 'azure', 'clio', 'intuit')
 * @param options - Optional configuration (scopes, instanceKey, forceRefresh)
 * @returns A promise that resolves to the access token response
 * @throws Error if the provider is not registered or if the token request fails
 */
export async function getClientCredentialsToken(
  provider: OAuthProvider,
  options: ClientCredentialsOptions = {},
): Promise<ClientCredentialsTokenResponse> {
  const { scopes, forceRefresh = false, instanceKey } = options;

  // Construct provider key (with optional instance)
  const providerKey = instanceKey ? `${provider}:${instanceKey}` : provider;

  // Get provider config
  const config = providerRegistry.get(providerKey);
  if (!config) {
    throw new Error(
      `Provider "${providerKey}" is not registered. Call registerOAuthProvider() first.`,
    );
  }

  // Determine which scopes to use
  const requestScopes = scopes || config.scopes;
  const cacheKey = getCacheKey(provider, requestScopes, instanceKey);

  // Check cache (unless force refresh is requested)
  if (!forceRefresh) {
    const cached = tokenCache.get(cacheKey);
    if (cached && isCachedTokenValid(cached)) {
      return {
        access_token: cached.access_token,
        token_type: cached.token_type,
        expires_in: Math.floor((cached.expires_at - Date.now()) / 1000),
        scope: cached.scope,
      };
    }
  }

  // Prepare token request
  const tokenRequest: ClientCredentialsTokenRequest = {
    grant_type: 'client_credentials',
    client_id: config.clientId,
    client_secret: config.clientSecret,
  };

  // Add scopes if provided
  if (requestScopes && requestScopes.length > 0) {
    tokenRequest.scope = requestScopes.join(' ');
  }

  // Request new token from OAuth provider
  try {
    const response = await ofetch<ClientCredentialsTokenResponse>(
      config.tokenEndpoint,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Accept: 'application/json',
        },
        body: new URLSearchParams(tokenRequest as Record<string, string>),
      },
    );

    // Cache the token
    const expiresAt = Date.now() + response.expires_in * 1000;
    const cachedToken: CachedClientCredentialsToken = {
      access_token: response.access_token,
      token_type: response.token_type,
      expires_at: expiresAt,
      scope: response.scope,
    };
    tokenCache.set(cacheKey, cachedToken);

    return response;
  } catch (error: unknown) {
    const errorMessage =
      error instanceof Error ? error.message : 'Unknown error';
    throw new Error(
      `Failed to fetch client credentials token for "${providerKey}": ${errorMessage}`,
    );
  }
}

/**
 * Clears the token cache for a specific provider/instance
 * Useful for testing or forcing a token refresh
 *
 * @param provider - The OAuth provider
 * @param instanceKey - Optional instance key for multi-tenant configurations
 */
export function clearClientCredentialsCache(
  provider?: OAuthProvider,
  instanceKey?: string,
): void {
  if (!provider) {
    // Clear entire cache
    tokenCache.clear();
    return;
  }

  // Clear specific provider/instance
  const prefix = instanceKey ? `${provider}:${instanceKey}:` : `${provider}::`;
  for (const key of tokenCache.keys()) {
    if (key.startsWith(prefix)) {
      tokenCache.delete(key);
    }
  }
}

/**
 * Gets the current size of the token cache (for debugging/monitoring)
 */
export function getClientCredentialsCacheSize(): number {
  return tokenCache.size;
}

