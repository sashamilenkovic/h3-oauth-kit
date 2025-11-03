/**
 * Token Introspection (RFC 7662)
 *
 * This module is tree-shakable - only bundled if you import it.
 * Import directly for best tree-shaking:
 *   import { introspectToken } from '@milencode/h3-oauth-kit/introspection'
 */

import { ofetch } from 'ofetch';
import type {
  OAuthProvider,
  TokenIntrospectionRequest,
  TokenIntrospectionResponse,
  IntrospectionOptions,
} from './types';
import { providerRegistry } from './index';

/**
 * Introspects a token to check if it's valid and active (RFC 7662)
 *
 * Token introspection allows you to validate whether an access token or refresh token
 * is still active, hasn't been revoked, and retrieve metadata about the token.
 *
 * ### Use Cases:
 * - **Security-critical applications**: Verify tokens haven't been revoked
 * - **Token validation**: Check token status before making API calls
 * - **Audit logging**: Get token metadata for compliance
 * - **Token debugging**: Inspect token details during development
 *
 * ### Important Notes:
 * - Not all OAuth providers support introspection (requires RFC 7662 support)
 * - Provider must have `introspectionEndpoint` configured
 * - Some providers require client authentication for introspection
 *
 * ### Examples:
 *
 * **Basic Usage:**
 * ```typescript
 * import { introspectToken } from '@milencode/h3-oauth-kit/introspection';
 *
 * const result = await introspectToken('azure', 'access_token_here');
 *
 * if (result.active) {
 *   console.log('Token is valid!');
 *   console.log('Expires at:', new Date(result.exp! * 1000));
 *   console.log('Scopes:', result.scope);
 * } else {
 *   console.log('Token is invalid or revoked');
 * }
 * ```
 *
 * **With Type Hint:**
 * ```typescript
 * // Hint that this is a refresh token (optimization for provider)
 * const result = await introspectToken('clio', refreshToken, {
 *   tokenTypeHint: 'refresh_token',
 * });
 * ```
 *
 * **Multi-Tenant:**
 * ```typescript
 * const result = await introspectToken('azure', token, {
 *   instanceKey: 'tenant-a',
 * });
 * ```
 *
 * **In a Protected Route:**
 * ```typescript
 * import { defineProtectedRoute } from '@milencode/h3-oauth-kit';
 * import { introspectToken } from '@milencode/h3-oauth-kit/introspection';
 *
 * export default defineProtectedRoute(['azure'], async (event) => {
 *   const token = event.context.h3OAuthKit.azure.access_token;
 *
 *   // Double-check token is still active
 *   const introspection = await introspectToken('azure', token);
 *
 *   if (!introspection.active) {
 *     throw createError({
 *       statusCode: 401,
 *       message: 'Token has been revoked',
 *     });
 *   }
 *
 *   // Proceed with API call...
 * });
 * ```
 *
 * @param provider - The OAuth provider (e.g., 'azure', 'clio')
 * @param token - The access token or refresh token to introspect
 * @param options - Optional configuration (instanceKey, tokenTypeHint)
 * @returns A promise that resolves to the introspection response
 * @throws Error if the provider doesn't have an introspection endpoint or if the request fails
 */
export async function introspectToken(
  provider: OAuthProvider,
  token: string,
  options: IntrospectionOptions = {},
): Promise<TokenIntrospectionResponse> {
  const { instanceKey, tokenTypeHint } = options;

  // Construct provider key
  const providerKey = instanceKey ? `${provider}:${instanceKey}` : provider;

  // Get provider config
  const config = providerRegistry.get(providerKey);
  if (!config) {
    throw new Error(
      `Provider "${providerKey}" is not registered. Call registerOAuthProvider() first.`,
    );
  }

  // Check if provider supports introspection
  if (!('introspectionEndpoint' in config) || !config.introspectionEndpoint) {
    throw new Error(
      `Provider "${providerKey}" does not have an introspection endpoint configured. ` +
        `Add 'introspectionEndpoint' to the provider configuration.`,
    );
  }

  // Prepare introspection request
  const requestBody: TokenIntrospectionRequest = {
    token,
    client_id: config.clientId,
    client_secret: config.clientSecret,
  };

  if (tokenTypeHint) {
    requestBody.token_type_hint = tokenTypeHint;
  }

  // Make introspection request
  try {
    const response = await ofetch<TokenIntrospectionResponse>(
      config.introspectionEndpoint,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Accept: 'application/json',
        },
        body: new URLSearchParams(requestBody as Record<string, string>),
      },
    );

    return response;
  } catch (error: unknown) {
    const errorMessage =
      error instanceof Error ? error.message : 'Unknown error';
    throw new Error(
      `Failed to introspect token for "${providerKey}": ${errorMessage}`,
    );
  }
}

/**
 * Helper function to check if a token is active (simplified introspection)
 *
 * This is a convenience wrapper around introspectToken that only returns
 * whether the token is active or not.
 *
 * ### Example:
 * ```typescript
 * import { isTokenActive } from '@milencode/h3-oauth-kit/introspection';
 *
 * const isValid = await isTokenActive('azure', accessToken);
 * if (isValid) {
 *   // Token is good to use
 * }
 * ```
 *
 * @param provider - The OAuth provider
 * @param token - The token to check
 * @param options - Optional configuration
 * @returns A promise that resolves to true if token is active, false otherwise
 */
export async function isTokenActive(
  provider: OAuthProvider,
  token: string,
  options: IntrospectionOptions = {},
): Promise<boolean> {
  try {
    const result = await introspectToken(provider, token, options);
    return result.active;
  } catch {
    // If introspection fails, consider token inactive
    return false;
  }
}

