/**
 * PKCE (Proof Key for Code Exchange) utilities for OAuth 2.0
 * RFC 7636: https://tools.ietf.org/html/rfc7636
 */

/**
 * Generates a cryptographically random code verifier for PKCE.
 * 
 * The code verifier is a cryptographically random string using the characters
 * [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~", with a minimum length of 43
 * characters and a maximum length of 128 characters.
 * 
 * @returns A base64url-encoded random string suitable for use as a code_verifier
 */
export function generateCodeVerifier(): string {
  const randomBytes = crypto.getRandomValues(new Uint8Array(32));
  return base64UrlEncode(randomBytes);
}

/**
 * Generates a code challenge from a code verifier using SHA-256.
 * 
 * code_challenge = BASE64URL(SHA256(ASCII(code_verifier)))
 * 
 * @param codeVerifier - The code verifier string
 * @returns A promise that resolves to the base64url-encoded SHA-256 hash
 */
export async function generateCodeChallenge(
  codeVerifier: string,
): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(codeVerifier);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return base64UrlEncode(new Uint8Array(hash));
}

/**
 * Base64url-encodes a Uint8Array without padding.
 * 
 * This is required by the PKCE spec which uses base64url encoding
 * (RFC 4648 Section 5) without padding.
 * 
 * @param buffer - The bytes to encode
 * @returns A base64url-encoded string without padding
 */
function base64UrlEncode(buffer: Uint8Array): string {
  const base64 = btoa(String.fromCharCode(...buffer));
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

