import type {
  OAuthProvider,
  OIDCUserInfo,
  IDTokenClaims,
  OAuthProviderUserInfoMap,
} from '../types';
import { ofetch } from 'ofetch';

/**
 * @internal
 *
 * Fetches user information from the provider's userInfo endpoint.
 *
 * This function makes an authenticated request to the OIDC userInfo endpoint
 * to retrieve the user's profile information (email, name, picture, etc.).
 *
 * @param userInfoEndpoint - The full URL to the provider's userInfo endpoint
 * @param accessToken - The access token to authenticate the request
 * @param provider - The OAuth provider identifier
 *
 * @returns The user's profile information typed for the provider
 *
 * @throws An error if the request fails or the endpoint is not configured
 */
export async function fetchUserInfo<P extends OAuthProvider>(
  userInfoEndpoint: string | undefined,
  accessToken: string,
  _provider: P,
): Promise<OAuthProviderUserInfoMap[P] | undefined> {
  if (!userInfoEndpoint) {
    return undefined;
  }

  try {
    const userInfo = await ofetch<OAuthProviderUserInfoMap[P]>(
      userInfoEndpoint,
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      },
    );

    return userInfo;
  } catch (error) {
    // If userInfo fetch fails, we don't want to block the entire flow
    // Just return undefined and log the error
    console.error(`Failed to fetch userInfo from ${userInfoEndpoint}:`, error);
    return undefined;
  }
}

/**
 * @internal
 *
 * Parses and decodes an ID token (JWT) into its claims.
 *
 * This function performs basic JWT parsing to extract the payload claims.
 * It does NOT verify the signature - signature verification should be done
 * server-side with the provider's public keys if needed.
 *
 * The ID token is expected to be in the format: header.payload.signature
 *
 * @param idToken - The ID token (JWT) string
 *
 * @returns The parsed ID token claims, or undefined if parsing fails
 */
export function parseIDToken(
  idToken: string | undefined,
): IDTokenClaims | undefined {
  if (!idToken) {
    return undefined;
  }

  try {
    // JWT format: header.payload.signature
    const parts = idToken.split('.');

    if (parts.length !== 3) {
      console.error('Invalid ID token format: expected 3 parts');
      return undefined;
    }

    // Decode the payload (second part)
    const payload = parts[1];
    const decoded = base64UrlDecode(payload);
    const claims = JSON.parse(decoded) as IDTokenClaims;

    // Basic validation
    if (
      !claims.iss ||
      !claims.sub ||
      !claims.aud ||
      !claims.exp ||
      !claims.iat
    ) {
      console.error('ID token missing required claims');
      return undefined;
    }

    return claims;
  } catch (error) {
    console.error('Failed to parse ID token:', error);
    return undefined;
  }
}

/**
 * @internal
 *
 * Decodes a base64url-encoded string.
 *
 * Base64url encoding is similar to base64 but uses URL-safe characters:
 * - replaces '+' with '-'
 * - replaces '/' with '_'
 * - removes padding '='
 *
 * @param base64Url - The base64url-encoded string
 *
 * @returns The decoded string
 */
function base64UrlDecode(base64Url: string): string {
  // Convert base64url to base64
  let base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');

  // Add padding if needed
  const padding = base64.length % 4;
  if (padding > 0) {
    base64 += '='.repeat(4 - padding);
  }

  // Decode base64
  const decoded = atob(base64);

  // Handle UTF-8 encoding
  return decodeURIComponent(
    decoded
      .split('')
      .map((c) => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
      .join(''),
  );
}

/**
 * @internal
 *
 * Validates ID token claims (expiry, audience, issuer).
 *
 * This performs basic claim validation according to OIDC spec.
 * It does NOT verify the cryptographic signature.
 *
 * @param claims - The parsed ID token claims
 * @param expectedAudience - The expected audience (client ID)
 * @param expectedIssuer - Optional expected issuer URL
 *
 * @returns true if claims are valid, false otherwise
 */
export function validateIDTokenClaims(
  claims: IDTokenClaims,
  expectedAudience: string,
  expectedIssuer?: string,
): boolean {
  const now = Math.floor(Date.now() / 1000);

  // Check expiration
  if (claims.exp <= now) {
    console.error('ID token has expired');
    return false;
  }

  // Check audience (can be string or array)
  const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!audiences.includes(expectedAudience)) {
    console.error('ID token audience mismatch');
    return false;
  }

  // Check issuer if provided
  if (expectedIssuer && claims.iss !== expectedIssuer) {
    console.error('ID token issuer mismatch');
    return false;
  }

  return true;
}
