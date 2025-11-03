/**
 * JWT Validation (RFC 7519)
 *
 * This module is tree-shakable - only bundled if you import it.
 * Import directly for best tree-shaking:
 *   import { validateJWT } from '@milencode/h3-oauth-kit/jwt'
 */

import { ofetch } from 'ofetch';
import type {
  JWTHeader,
  JWTPayload,
  DecodedJWT,
  JWTValidationOptions,
  JWTValidationResult,
  JWKS,
  JWK,
  CachedJWKS,
} from './types';

/**
 * JWKS cache - stores fetched public keys
 * Key format: jwksUri
 */
const jwksCache = new Map<string, CachedJWKS>();

/**
 * Decodes a base64url-encoded string
 */
function base64urlDecode(str: string): string {
  // Convert base64url to base64
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  
  // Add padding if needed
  while (base64.length % 4 !== 0) {
    base64 += '=';
  }
  
  // Decode base64
  try {
    // Use Buffer in Node.js environments
    if (typeof Buffer !== 'undefined') {
      return Buffer.from(base64, 'base64').toString('utf-8');
    }
    // Use atob in browser environments
    return decodeURIComponent(
      atob(base64)
        .split('')
        .map((c) => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
        .join(''),
    );
  } catch (error) {
    throw new Error('Invalid base64url encoding');
  }
}

/**
 * Decodes a JWT without validation
 *
 * This function only decodes the JWT structure - it does NOT validate:
 * - Signature
 * - Expiration
 * - Claims
 *
 * Use `validateJWT()` for secure validation.
 *
 * ### Example:
 * ```typescript
 * import { decodeJWT } from '@milencode/h3-oauth-kit/jwt';
 *
 * const decoded = decodeJWT(token);
 * console.log('User ID:', decoded.payload.sub);
 * console.log('Expires:', new Date(decoded.payload.exp! * 1000));
 * ```
 *
 * @param token - The JWT string
 * @returns Decoded JWT with header, payload, and signature
 * @throws Error if the JWT format is invalid
 */
export function decodeJWT(token: string): DecodedJWT {
  const parts = token.split('.');
  
  if (parts.length !== 3) {
    throw new Error('Invalid JWT format: expected 3 parts separated by dots');
  }
  
  try {
    const header = JSON.parse(base64urlDecode(parts[0])) as JWTHeader;
    const payload = JSON.parse(base64urlDecode(parts[1])) as JWTPayload;
    const signature = parts[2];
    
    return { header, payload, signature };
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    throw new Error(`Failed to decode JWT: ${message}`);
  }
}

/**
 * Gets the payload from a JWT without validation
 *
 * Convenience function that returns only the payload.
 * **Warning:** This does NOT validate the token!
 *
 * ### Example:
 * ```typescript
 * import { getJWTPayload } from '@milencode/h3-oauth-kit/jwt';
 *
 * const payload = getJWTPayload(token);
 * console.log('User:', payload.sub);
 * ```
 *
 * @param token - The JWT string
 * @returns JWT payload
 */
export function getJWTPayload(token: string): JWTPayload {
  return decodeJWT(token).payload;
}

/**
 * Validates JWT claims (exp, nbf, iat, iss, aud)
 */
function validateClaims(
  payload: JWTPayload,
  options: JWTValidationOptions,
): JWTValidationResult {
  const now = Math.floor(Date.now() / 1000);
  const clockTolerance = options.clockTolerance || 0;
  
  // Check expiration (exp)
  if (payload.exp !== undefined) {
    if (now > payload.exp + clockTolerance) {
      return {
        valid: false,
        error: `Token expired at ${new Date(payload.exp * 1000).toISOString()}`,
        errorCode: 'EXPIRED',
      };
    }
  }
  
  // Check not-before (nbf)
  if (payload.nbf !== undefined) {
    if (now < payload.nbf - clockTolerance) {
      return {
        valid: false,
        error: `Token not valid until ${new Date(payload.nbf * 1000).toISOString()}`,
        errorCode: 'NOT_YET_VALID',
      };
    }
  }
  
  // Check token age (iat + maxTokenAge)
  if (options.maxTokenAge !== undefined && payload.iat !== undefined) {
    const tokenAge = now - payload.iat;
    if (tokenAge > options.maxTokenAge) {
      return {
        valid: false,
        error: `Token is too old (issued ${tokenAge}s ago, max age is ${options.maxTokenAge}s)`,
        errorCode: 'EXPIRED',
      };
    }
  }
  
  // Check issuer (iss)
  if (options.issuer !== undefined) {
    const expectedIssuers = Array.isArray(options.issuer)
      ? options.issuer
      : [options.issuer];
    
    if (!payload.iss || !expectedIssuers.includes(payload.iss)) {
      return {
        valid: false,
        error: `Invalid issuer: expected one of [${expectedIssuers.join(', ')}], got "${payload.iss}"`,
        errorCode: 'INVALID_ISSUER',
      };
    }
  }
  
  // Check audience (aud)
  if (options.audience !== undefined) {
    const expectedAudiences = Array.isArray(options.audience)
      ? options.audience
      : [options.audience];
    
    const tokenAudiences = Array.isArray(payload.aud)
      ? payload.aud
      : payload.aud
        ? [payload.aud]
        : [];
    
    const hasValidAudience = expectedAudiences.some((expectedAud) =>
      tokenAudiences.includes(expectedAud),
    );
    
    if (!hasValidAudience) {
      return {
        valid: false,
        error: `Invalid audience: expected one of [${expectedAudiences.join(', ')}], got [${tokenAudiences.join(', ')}]`,
        errorCode: 'INVALID_AUDIENCE',
      };
    }
  }
  
  // Check subject (sub)
  if (options.subject !== undefined) {
    if (payload.sub !== options.subject) {
      return {
        valid: false,
        error: `Invalid subject: expected "${options.subject}", got "${payload.sub}"`,
        errorCode: 'INVALID_AUDIENCE',
      };
    }
  }
  
  return { valid: true, payload };
}

/**
 * Fetches JWKS from a URI with caching
 */
async function fetchJWKS(jwksUri: string): Promise<JWKS> {
  // Check cache first
  const cached = jwksCache.get(jwksUri);
  if (cached && Date.now() < cached.expiresAt) {
    return cached.jwks;
  }
  
  // Fetch new JWKS
  try {
    const jwks = await ofetch<JWKS>(jwksUri, {
      headers: {
        Accept: 'application/json',
      },
    });
    
    // Cache for 1 hour
    const cachedEntry: CachedJWKS = {
      jwks,
      cachedAt: Date.now(),
      expiresAt: Date.now() + 3600000, // 1 hour
    };
    
    jwksCache.set(jwksUri, cachedEntry);
    
    return jwks;
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    throw new Error(`Failed to fetch JWKS from ${jwksUri}: ${message}`);
  }
}

/**
 * Converts a JWK to a CryptoKey for verification
 */
async function jwkToCryptoKey(jwk: JWK, alg: string): Promise<CryptoKey> {
  if (!globalThis.crypto?.subtle) {
    throw new Error('Web Crypto API not available');
  }
  
  try {
    if (jwk.kty === 'RSA') {
      return await globalThis.crypto.subtle.importKey(
        'jwk',
        jwk as JsonWebKey,
        {
          name: 'RSASSA-PKCS1-v1_5',
          hash: alg.startsWith('RS') ? `SHA-${alg.slice(2)}` : 'SHA-256',
        },
        false,
        ['verify'],
      );
    }
    
    if (jwk.kty === 'EC') {
      return await globalThis.crypto.subtle.importKey(
        'jwk',
        jwk as JsonWebKey,
        {
          name: 'ECDSA',
          namedCurve: jwk.crv || 'P-256',
        },
        false,
        ['verify'],
      );
    }
    
    throw new Error(`Unsupported key type: ${jwk.kty}`);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    throw new Error(`Failed to import JWK: ${message}`);
  }
}

/**
 * Verifies JWT signature using JWKS
 */
async function verifySignature(
  token: string,
  decoded: DecodedJWT,
  jwksUri: string,
  allowedAlgorithms: string[],
): Promise<boolean> {
  const { header } = decoded;
  
  // Check algorithm is allowed
  if (!allowedAlgorithms.includes(header.alg)) {
    throw new Error(
      `Algorithm "${header.alg}" not allowed. Allowed: [${allowedAlgorithms.join(', ')}]`,
    );
  }
  
  // Fetch JWKS
  const jwks = await fetchJWKS(jwksUri);
  
  // Find matching key
  let matchingKey: JWK | undefined;
  
  if (header.kid) {
    // Try to find by kid first
    matchingKey = jwks.keys.find((key) => key.kid === header.kid);
  }
  
  if (!matchingKey) {
    // Try to find by alg and use
    matchingKey = jwks.keys.find(
      (key) =>
        (!key.alg || key.alg === header.alg) &&
        (!key.use || key.use === 'sig'),
    );
  }
  
  if (!matchingKey) {
    throw new Error(
      `No matching key found in JWKS for kid="${header.kid}" and alg="${header.alg}"`,
    );
  }
  
  // Convert JWK to CryptoKey
  const cryptoKey = await jwkToCryptoKey(matchingKey, header.alg);
  
  // Get the data to verify (header.payload)
  const parts = token.split('.');
  const data = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);
  
  // Decode signature from base64url
  const signatureBytes = Uint8Array.from(
    atob(parts[2].replace(/-/g, '+').replace(/_/g, '/')),
    (c) => c.charCodeAt(0),
  );
  
  // Verify signature
  try {
    const algorithm =
      header.alg.startsWith('RS')
        ? { name: 'RSASSA-PKCS1-v1_5' }
        : {
            name: 'ECDSA',
            hash: `SHA-${header.alg.slice(2)}`,
          };
    
    return await globalThis.crypto.subtle.verify(
      algorithm,
      cryptoKey,
      signatureBytes,
      data,
    );
  } catch (error) {
    return false;
  }
}

/**
 * Validates a JWT token with comprehensive checks
 *
 * This function performs full JWT validation including:
 * - Format validation
 * - Claims validation (exp, nbf, iat, iss, aud, sub)
 * - Signature verification (optional, using JWKS)
 * - Custom validation logic
 *
 * ### Basic Usage:
 * ```typescript
 * import { validateJWT } from '@milencode/h3-oauth-kit/jwt';
 *
 * const result = await validateJWT(token, {
 *   issuer: 'https://login.microsoftonline.com',
 *   audience: 'api://myapp',
 * });
 *
 * if (result.valid) {
 *   console.log('Valid token!', result.payload);
 * } else {
 *   console.error('Invalid:', result.error);
 * }
 * ```
 *
 * ### With Signature Verification:
 * ```typescript
 * const result = await validateJWT(token, {
 *   issuer: 'https://accounts.google.com',
 *   audience: 'my-client-id',
 *   validateSignature: true,
 *   jwksUri: 'https://www.googleapis.com/oauth2/v3/certs',
 * });
 * ```
 *
 * ### In a Protected Route:
 * ```typescript
 * import { defineEventHandler, getHeader, createError } from 'h3';
 * import { validateJWT } from '@milencode/h3-oauth-kit/jwt';
 *
 * export default defineEventHandler(async (event) => {
 *   const token = getHeader(event, 'authorization')?.split(' ')[1];
 *   
 *   if (!token) {
 *     throw createError({ statusCode: 401, message: 'No token provided' });
 *   }
 *   
 *   const result = await validateJWT(token, {
 *     issuer: 'https://login.microsoftonline.com',
 *     audience: 'api://myapp',
 *     clockTolerance: 60, // 1 minute tolerance
 *   });
 *   
 *   if (!result.valid) {
 *     throw createError({
 *       statusCode: 401,
 *       message: `Invalid token: ${result.error}`,
 *     });
 *   }
 *   
 *   // Token is valid - proceed with API logic
 *   return { userId: result.payload!.sub };
 * });
 * ```
 *
 * @param token - The JWT string to validate
 * @param options - Validation options
 * @returns Validation result with payload if valid, or error details if invalid
 */
export async function validateJWT(
  token: string,
  options: JWTValidationOptions = {},
): Promise<JWTValidationResult> {
  try {
    // Decode JWT
    const decoded = decodeJWT(token);
    
    // Validate claims
    const claimsResult = validateClaims(decoded.payload, options);
    if (!claimsResult.valid) {
      return claimsResult;
    }
    
    // Verify signature if requested
    if (options.validateSignature !== false && options.jwksUri) {
      const allowedAlgorithms = options.algorithms || ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512'];
      
      try {
        const isValid = await verifySignature(
          token,
          decoded,
          options.jwksUri,
          allowedAlgorithms,
        );
        
        if (!isValid) {
          return {
            valid: false,
            error: 'Invalid signature',
            errorCode: 'INVALID_SIGNATURE',
          };
        }
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Unknown error';
        return {
          valid: false,
          error: `Signature verification failed: ${message}`,
          errorCode: 'INVALID_SIGNATURE',
        };
      }
    }
    
    // Run custom validation if provided
    if (options.customValidation) {
      try {
        await options.customValidation(decoded.payload);
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Custom validation failed';
        return {
          valid: false,
          error: message,
          errorCode: 'CUSTOM_VALIDATION_FAILED',
        };
      }
    }
    
    // All validations passed
    return {
      valid: true,
      payload: decoded.payload,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    return {
      valid: false,
      error: message,
      errorCode: 'INVALID_FORMAT',
    };
  }
}

/**
 * Clears the JWKS cache
 *
 * Useful for testing or when you need to force a fresh fetch of keys.
 *
 * ### Example:
 * ```typescript
 * import { clearJWKSCache } from '@milencode/h3-oauth-kit/jwt';
 *
 * // Clear all cached JWKS
 * clearJWKSCache();
 *
 * // Clear specific JWKS URI
 * clearJWKSCache('https://login.microsoftonline.com/common/discovery/v2.0/keys');
 * ```
 *
 * @param jwksUri - Optional specific URI to clear. If not provided, clears all.
 */
export function clearJWKSCache(jwksUri?: string): void {
  if (jwksUri) {
    jwksCache.delete(jwksUri);
  } else {
    jwksCache.clear();
  }
}

/**
 * Gets the size of the JWKS cache
 *
 * Useful for monitoring and debugging.
 *
 * @returns Number of cached JWKS entries
 */
export function getJWKSCacheSize(): number {
  return jwksCache.size;
}

