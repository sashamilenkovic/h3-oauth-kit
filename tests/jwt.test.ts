import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import {
  decodeJWT,
  getJWTPayload,
  validateJWT,
  clearJWKSCache,
  getJWKSCacheSize,
} from '../src/jwt';
import type { JWTPayload } from '../src/types';
import { ofetch } from 'ofetch';

// Mock ofetch
vi.mock('ofetch', () => ({
  ofetch: vi.fn(),
}));

/**
 * Helper to create a mock JWT (base64url encoded, but not cryptographically signed)
 */
function createMockJWT(payload: JWTPayload, header: Record<string, unknown> = {}): string {
  const defaultHeader = { alg: 'RS256', typ: 'JWT', kid: 'test-key', ...header };
  
  const encodeBase64Url = (obj: unknown): string => {
    const json = JSON.stringify(obj);
    const base64 = Buffer.from(json).toString('base64');
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  };
  
  const headerEncoded = encodeBase64Url(defaultHeader);
  const payloadEncoded = encodeBase64Url(payload);
  const signature = 'mock-signature';
  
  return `${headerEncoded}.${payloadEncoded}.${signature}`;
}

describe('JWT Validation', () => {
  const now = Math.floor(Date.now() / 1000);
  
  beforeEach(() => {
    vi.clearAllMocks();
    clearJWKSCache();
  });
  
  afterEach(() => {
    clearJWKSCache();
  });
  
  describe('decodeJWT', () => {
    it('should decode a valid JWT', () => {
      const payload: JWTPayload = {
        sub: 'user-123',
        iss: 'https://provider.com',
        aud: 'my-app',
        exp: now + 3600,
        iat: now,
      };
      
      const token = createMockJWT(payload);
      const decoded = decodeJWT(token);
      
      expect(decoded.header.alg).toBe('RS256');
      expect(decoded.header.typ).toBe('JWT');
      expect(decoded.payload.sub).toBe('user-123');
      expect(decoded.payload.iss).toBe('https://provider.com');
      expect(decoded.signature).toBe('mock-signature');
    });
    
    it('should throw error for invalid JWT format (less than 3 parts)', () => {
      expect(() => decodeJWT('invalid.token')).toThrow('expected 3 parts');
    });
    
    it('should throw error for invalid JWT format (more than 3 parts)', () => {
      expect(() => decodeJWT('invalid.token.with.extra')).toThrow('expected 3 parts');
    });
    
    it('should throw error for invalid base64url encoding', () => {
      expect(() => decodeJWT('invalid!!!.token!!!.sig')).toThrow('Failed to decode JWT');
    });
  });
  
  describe('getJWTPayload', () => {
    it('should return only the payload', () => {
      const payload: JWTPayload = {
        sub: 'user-456',
        name: 'John Doe',
        email: 'john@example.com',
      };
      
      const token = createMockJWT(payload);
      const result = getJWTPayload(token);
      
      expect(result).toEqual(payload);
    });
  });
  
  describe('validateJWT - Claims Validation', () => {
    it('should validate a token with no options', async () => {
      const payload: JWTPayload = {
        sub: 'user-123',
        exp: now + 3600,
      };
      
      const token = createMockJWT(payload);
      const result = await validateJWT(token);
      
      expect(result.valid).toBe(true);
      expect(result.payload).toEqual(payload);
    });
    
    it('should reject expired token', async () => {
      const payload: JWTPayload = {
        sub: 'user-123',
        exp: now - 3600, // Expired 1 hour ago
      };
      
      const token = createMockJWT(payload);
      const result = await validateJWT(token);
      
      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('EXPIRED');
      expect(result.error).toContain('expired');
    });
    
    it('should accept expired token within clock tolerance', async () => {
      const payload: JWTPayload = {
        sub: 'user-123',
        exp: now - 30, // Expired 30 seconds ago
      };
      
      const token = createMockJWT(payload);
      const result = await validateJWT(token, {
        clockTolerance: 60, // 1 minute tolerance
      });
      
      expect(result.valid).toBe(true);
    });
    
    it('should reject token with nbf (not before) in the future', async () => {
      const payload: JWTPayload = {
        sub: 'user-123',
        nbf: now + 3600, // Not valid for another hour
      };
      
      const token = createMockJWT(payload);
      const result = await validateJWT(token);
      
      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('NOT_YET_VALID');
      expect(result.error).toContain('not valid until');
    });
    
    it('should validate issuer (single string)', async () => {
      const payload: JWTPayload = {
        sub: 'user-123',
        iss: 'https://provider.com',
      };
      
      const token = createMockJWT(payload);
      const result = await validateJWT(token, {
        issuer: 'https://provider.com',
      });
      
      expect(result.valid).toBe(true);
    });
    
    it('should reject invalid issuer', async () => {
      const payload: JWTPayload = {
        sub: 'user-123',
        iss: 'https://wrong-provider.com',
      };
      
      const token = createMockJWT(payload);
      const result = await validateJWT(token, {
        issuer: 'https://provider.com',
      });
      
      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('INVALID_ISSUER');
    });
    
    it('should validate issuer (multiple allowed)', async () => {
      const payload: JWTPayload = {
        sub: 'user-123',
        iss: 'https://provider2.com',
      };
      
      const token = createMockJWT(payload);
      const result = await validateJWT(token, {
        issuer: ['https://provider1.com', 'https://provider2.com'],
      });
      
      expect(result.valid).toBe(true);
    });
    
    it('should validate audience (single string)', async () => {
      const payload: JWTPayload = {
        sub: 'user-123',
        aud: 'my-app',
      };
      
      const token = createMockJWT(payload);
      const result = await validateJWT(token, {
        audience: 'my-app',
      });
      
      expect(result.valid).toBe(true);
    });
    
    it('should validate audience (array in token)', async () => {
      const payload: JWTPayload = {
        sub: 'user-123',
        aud: ['my-app', 'another-app'],
      };
      
      const token = createMockJWT(payload);
      const result = await validateJWT(token, {
        audience: 'my-app',
      });
      
      expect(result.valid).toBe(true);
    });
    
    it('should reject invalid audience', async () => {
      const payload: JWTPayload = {
        sub: 'user-123',
        aud: 'wrong-app',
      };
      
      const token = createMockJWT(payload);
      const result = await validateJWT(token, {
        audience: 'my-app',
      });
      
      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('INVALID_AUDIENCE');
    });
    
    it('should validate subject', async () => {
      const payload: JWTPayload = {
        sub: 'user-123',
      };
      
      const token = createMockJWT(payload);
      const result = await validateJWT(token, {
        subject: 'user-123',
      });
      
      expect(result.valid).toBe(true);
    });
    
    it('should reject invalid subject', async () => {
      const payload: JWTPayload = {
        sub: 'user-456',
      };
      
      const token = createMockJWT(payload);
      const result = await validateJWT(token, {
        subject: 'user-123',
      });
      
      expect(result.valid).toBe(false);
    });
    
    it('should validate maxTokenAge', async () => {
      const payload: JWTPayload = {
        sub: 'user-123',
        iat: now - 7200, // Issued 2 hours ago
      };
      
      const token = createMockJWT(payload);
      const result = await validateJWT(token, {
        maxTokenAge: 3600, // Max 1 hour
      });
      
      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('EXPIRED');
      expect(result.error).toContain('too old');
    });
    
    it('should run custom validation successfully', async () => {
      const payload: JWTPayload = {
        sub: 'user-123',
        role: 'admin',
      };
      
      const token = createMockJWT(payload);
      const result = await validateJWT(token, {
        customValidation: (payload) => {
          if (payload.role !== 'admin') {
            throw new Error('User must be admin');
          }
        },
      });
      
      expect(result.valid).toBe(true);
    });
    
    it('should reject when custom validation fails', async () => {
      const payload: JWTPayload = {
        sub: 'user-123',
        role: 'user',
      };
      
      const token = createMockJWT(payload);
      const result = await validateJWT(token, {
        customValidation: (payload) => {
          if (payload.role !== 'admin') {
            throw new Error('User must be admin');
          }
        },
      });
      
      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('CUSTOM_VALIDATION_FAILED');
      expect(result.error).toBe('User must be admin');
    });
  });
  
  describe('validateJWT - Signature Verification', () => {
    it('should skip signature verification when validateSignature is false', async () => {
      const payload: JWTPayload = { sub: 'user-123' };
      const token = createMockJWT(payload);
      
      const result = await validateJWT(token, {
        validateSignature: false,
      });
      
      expect(result.valid).toBe(true);
    });
    
    it('should skip signature verification when no jwksUri provided', async () => {
      const payload: JWTPayload = { sub: 'user-123' };
      const token = createMockJWT(payload);
      
      const result = await validateJWT(token, {
        validateSignature: true,
        // No jwksUri
      });
      
      expect(result.valid).toBe(true);
    });
    
    it('should reject if algorithm not in allowed list', async () => {
      const payload: JWTPayload = { sub: 'user-123' };
      const token = createMockJWT(payload, { alg: 'HS256' });
      
      const result = await validateJWT(token, {
        validateSignature: true,
        jwksUri: 'https://provider.com/.well-known/jwks.json',
        algorithms: ['RS256'], // Only allow RS256
      });
      
      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('INVALID_SIGNATURE');
      expect(result.error).toContain('Algorithm "HS256" not allowed');
    });
    
    it('should reject if JWKS fetch fails', async () => {
      const payload: JWTPayload = { sub: 'user-123' };
      const token = createMockJWT(payload);
      
      vi.mocked(ofetch).mockRejectedValue(new Error('Network error'));
      
      const result = await validateJWT(token, {
        validateSignature: true,
        jwksUri: 'https://provider.com/.well-known/jwks.json',
      });
      
      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('INVALID_SIGNATURE');
    });
  });
  
  describe('JWKS Cache', () => {
    it('should cache JWKS after fetching', async () => {
      const mockJWKS = {
        keys: [
          {
            kty: 'RSA',
            kid: 'test-key',
            use: 'sig',
            alg: 'RS256',
            n: 'mock-n',
            e: 'AQAB',
          },
        ],
      };
      
      vi.mocked(ofetch).mockResolvedValue(mockJWKS);
      
      const payload: JWTPayload = { sub: 'user-123' };
      const token = createMockJWT(payload);
      
      // First call - should fetch
      await validateJWT(token, {
        validateSignature: true,
        jwksUri: 'https://provider.com/.well-known/jwks.json',
      });
      
      expect(vi.mocked(ofetch)).toHaveBeenCalledTimes(1);
      expect(getJWKSCacheSize()).toBe(1);
      
      // Second call - should use cache
      await validateJWT(token, {
        validateSignature: true,
        jwksUri: 'https://provider.com/.well-known/jwks.json',
      });
      
      // Should still only be 1 call (cached)
      expect(vi.mocked(ofetch)).toHaveBeenCalledTimes(1);
    });
    
    it('should clear JWKS cache', async () => {
      const mockJWKS = { keys: [] };
      vi.mocked(ofetch).mockResolvedValue(mockJWKS);
      
      const payload: JWTPayload = { sub: 'user-123' };
      const token = createMockJWT(payload);
      
      await validateJWT(token, {
        validateSignature: true,
        jwksUri: 'https://provider.com/.well-known/jwks.json',
      });
      
      expect(getJWKSCacheSize()).toBe(1);
      
      clearJWKSCache();
      
      expect(getJWKSCacheSize()).toBe(0);
    });
    
    it('should clear specific JWKS URI from cache', async () => {
      const mockJWKS = { keys: [] };
      vi.mocked(ofetch).mockResolvedValue(mockJWKS);
      
      const payload: JWTPayload = { sub: 'user-123' };
      const token = createMockJWT(payload);
      
      // Cache two different URIs
      await validateJWT(token, {
        validateSignature: true,
        jwksUri: 'https://provider1.com/.well-known/jwks.json',
      });
      
      await validateJWT(token, {
        validateSignature: true,
        jwksUri: 'https://provider2.com/.well-known/jwks.json',
      });
      
      expect(getJWKSCacheSize()).toBe(2);
      
      clearJWKSCache('https://provider1.com/.well-known/jwks.json');
      
      expect(getJWKSCacheSize()).toBe(1);
    });
  });
});

