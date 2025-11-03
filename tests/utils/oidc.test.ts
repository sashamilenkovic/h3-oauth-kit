import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { parseIDToken, validateIDTokenClaims } from '../../src/utils/oidc';
import type { IDTokenClaims } from '../../src/types';

describe('OIDC Utilities', () => {
  describe('parseIDToken', () => {
    it('should parse a valid ID token', () => {
      // Create a mock ID token
      const header = btoa(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
      const payload = btoa(
        JSON.stringify({
          iss: 'https://accounts.google.com',
          sub: '1234567890',
          aud: 'my-client-id',
          exp: Math.floor(Date.now() / 1000) + 3600,
          iat: Math.floor(Date.now() / 1000),
          email: 'user@example.com',
        }),
      );
      const signature = 'fake-signature';
      const idToken = `${header}.${payload}.${signature}`;

      const claims = parseIDToken(idToken);

      expect(claims).toBeDefined();
      expect(claims?.iss).toBe('https://accounts.google.com');
      expect(claims?.sub).toBe('1234567890');
      expect(claims?.aud).toBe('my-client-id');
      expect(claims?.email).toBe('user@example.com');
    });

    it('should return undefined for undefined token', () => {
      const claims = parseIDToken(undefined);
      expect(claims).toBeUndefined();
    });

    it('should return undefined for invalid format (not 3 parts)', () => {
      const consoleSpy = vi
        .spyOn(console, 'error')
        .mockImplementation(() => {});

      const claims = parseIDToken('invalid.token');
      expect(claims).toBeUndefined();
      expect(consoleSpy).toHaveBeenCalledWith(
        'Invalid ID token format: expected 3 parts',
      );

      consoleSpy.mockRestore();
    });

    it('should return undefined for invalid JSON payload', () => {
      const consoleSpy = vi
        .spyOn(console, 'error')
        .mockImplementation(() => {});

      const header = btoa(JSON.stringify({ alg: 'RS256' }));
      const payload = 'not-valid-base64-json';
      const signature = 'fake-signature';
      const idToken = `${header}.${payload}.${signature}`;

      const claims = parseIDToken(idToken);
      expect(claims).toBeUndefined();

      consoleSpy.mockRestore();
    });

    it('should return undefined for missing required claims', () => {
      const consoleSpy = vi
        .spyOn(console, 'error')
        .mockImplementation(() => {});

      const header = btoa(JSON.stringify({ alg: 'RS256' }));
      const payload = btoa(
        JSON.stringify({
          sub: '1234567890',
          // Missing iss, aud, exp, iat
        }),
      );
      const signature = 'fake-signature';
      const idToken = `${header}.${payload}.${signature}`;

      const claims = parseIDToken(idToken);
      expect(claims).toBeUndefined();
      expect(consoleSpy).toHaveBeenCalledWith(
        'ID token missing required claims',
      );

      consoleSpy.mockRestore();
    });

    it('should handle base64url encoding correctly', () => {
      // Create a payload with special characters that require base64url
      const header = btoa(JSON.stringify({ alg: 'RS256', typ: 'JWT' }))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
      const payload = btoa(
        JSON.stringify({
          iss: 'https://provider.com',
          sub: 'user-123',
          aud: 'client-id',
          exp: Math.floor(Date.now() / 1000) + 3600,
          iat: Math.floor(Date.now() / 1000),
          name: 'Test User',
        }),
      )
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
      const signature = 'signature';
      const idToken = `${header}.${payload}.${signature}`;

      const claims = parseIDToken(idToken);

      expect(claims).toBeDefined();
      expect(claims?.name).toBe('Test User');
    });
  });

  describe('validateIDTokenClaims', () => {
    let validClaims: IDTokenClaims;

    beforeEach(() => {
      validClaims = {
        iss: 'https://accounts.google.com',
        sub: '1234567890',
        aud: 'my-client-id',
        exp: Math.floor(Date.now() / 1000) + 3600, // 1 hour from now
        iat: Math.floor(Date.now() / 1000),
      };
    });

    afterEach(() => {
      vi.restoreAllMocks();
    });

    it('should validate correct claims', () => {
      const isValid = validateIDTokenClaims(validClaims, 'my-client-id');
      expect(isValid).toBe(true);
    });

    it('should validate with correct issuer', () => {
      const isValid = validateIDTokenClaims(
        validClaims,
        'my-client-id',
        'https://accounts.google.com',
      );
      expect(isValid).toBe(true);
    });

    it('should reject expired token', () => {
      const consoleSpy = vi
        .spyOn(console, 'error')
        .mockImplementation(() => {});

      const expiredClaims = {
        ...validClaims,
        exp: Math.floor(Date.now() / 1000) - 3600, // 1 hour ago
      };

      const isValid = validateIDTokenClaims(expiredClaims, 'my-client-id');
      expect(isValid).toBe(false);
      expect(consoleSpy).toHaveBeenCalledWith('ID token has expired');
    });

    it('should reject mismatched audience', () => {
      const consoleSpy = vi
        .spyOn(console, 'error')
        .mockImplementation(() => {});

      const isValid = validateIDTokenClaims(validClaims, 'wrong-client-id');
      expect(isValid).toBe(false);
      expect(consoleSpy).toHaveBeenCalledWith('ID token audience mismatch');
    });

    it('should handle audience as array', () => {
      const claimsWithArrayAud = {
        ...validClaims,
        aud: ['my-client-id', 'other-client-id'],
      };

      const isValid = validateIDTokenClaims(claimsWithArrayAud, 'my-client-id');
      expect(isValid).toBe(true);
    });

    it('should reject mismatched issuer', () => {
      const consoleSpy = vi
        .spyOn(console, 'error')
        .mockImplementation(() => {});

      const isValid = validateIDTokenClaims(
        validClaims,
        'my-client-id',
        'https://wrong-issuer.com',
      );
      expect(isValid).toBe(false);
      expect(consoleSpy).toHaveBeenCalledWith('ID token issuer mismatch');
    });

    it('should accept valid token at exact expiry boundary', () => {
      const boundaryClaims = {
        ...validClaims,
        exp: Math.floor(Date.now() / 1000) + 1, // 1 second from now
      };

      const isValid = validateIDTokenClaims(boundaryClaims, 'my-client-id');
      expect(isValid).toBe(true);
    });
  });
});
