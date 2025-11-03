import { describe, it, expect } from 'vitest';
import {
  generateCodeVerifier,
  generateCodeChallenge,
} from '../../src/utils/pkce';

describe('PKCE Utilities', () => {
  describe('generateCodeVerifier', () => {
    it('should generate a code verifier', () => {
      const verifier = generateCodeVerifier();
      expect(verifier).toBeDefined();
      expect(typeof verifier).toBe('string');
    });

    it('should generate a verifier with minimum length of 43 characters', () => {
      const verifier = generateCodeVerifier();
      expect(verifier.length).toBeGreaterThanOrEqual(43);
    });

    it('should generate a verifier with maximum length of 128 characters', () => {
      const verifier = generateCodeVerifier();
      expect(verifier.length).toBeLessThanOrEqual(128);
    });

    it('should only contain valid base64url characters', () => {
      const verifier = generateCodeVerifier();
      // base64url alphabet: A-Z, a-z, 0-9, -, _
      const validChars = /^[A-Za-z0-9\-_]+$/;
      expect(verifier).toMatch(validChars);
    });

    it('should not contain padding characters', () => {
      const verifier = generateCodeVerifier();
      expect(verifier).not.toContain('=');
    });

    it('should generate unique verifiers', () => {
      const verifier1 = generateCodeVerifier();
      const verifier2 = generateCodeVerifier();
      expect(verifier1).not.toBe(verifier2);
    });

    it('should generate cryptographically random values', () => {
      // Generate multiple verifiers and ensure they're all different
      const verifiers = new Set();
      for (let i = 0; i < 10; i++) {
        verifiers.add(generateCodeVerifier());
      }
      expect(verifiers.size).toBe(10);
    });
  });

  describe('generateCodeChallenge', () => {
    it('should generate a code challenge from a verifier', async () => {
      const verifier = generateCodeVerifier();
      const challenge = await generateCodeChallenge(verifier);
      expect(challenge).toBeDefined();
      expect(typeof challenge).toBe('string');
    });

    it('should generate consistent challenges for the same verifier', async () => {
      const verifier = 'test_verifier_1234567890';
      const challenge1 = await generateCodeChallenge(verifier);
      const challenge2 = await generateCodeChallenge(verifier);
      expect(challenge1).toBe(challenge2);
    });

    it('should generate different challenges for different verifiers', async () => {
      const verifier1 = generateCodeVerifier();
      const verifier2 = generateCodeVerifier();
      const challenge1 = await generateCodeChallenge(verifier1);
      const challenge2 = await generateCodeChallenge(verifier2);
      expect(challenge1).not.toBe(challenge2);
    });

    it('should only contain valid base64url characters', async () => {
      const verifier = generateCodeVerifier();
      const challenge = await generateCodeChallenge(verifier);
      const validChars = /^[A-Za-z0-9\-_]+$/;
      expect(challenge).toMatch(validChars);
    });

    it('should not contain padding characters', async () => {
      const verifier = generateCodeVerifier();
      const challenge = await generateCodeChallenge(verifier);
      expect(challenge).not.toContain('=');
    });

    it('should generate SHA-256 hash (43 characters for 32 bytes)', async () => {
      const verifier = generateCodeVerifier();
      const challenge = await generateCodeChallenge(verifier);
      // SHA-256 produces 32 bytes = 256 bits
      // Base64url encoding of 32 bytes = 43 characters (without padding)
      expect(challenge.length).toBe(43);
    });

    it('should handle known test vectors correctly', async () => {
      // Test vector from RFC 7636 Appendix B
      // Note: The actual challenge will depend on the SHA-256 implementation
      const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
      const challenge = await generateCodeChallenge(verifier);

      // This is the expected challenge for the above verifier
      // Calculated as: BASE64URL(SHA256(ASCII(code_verifier)))
      expect(challenge).toBe('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
    });
  });

  describe('PKCE Flow Integration', () => {
    it('should work together in a complete PKCE flow', async () => {
      // Simulate a complete PKCE flow
      const codeVerifier = generateCodeVerifier();
      const codeChallenge = await generateCodeChallenge(codeVerifier);

      // Verify both are valid
      expect(codeVerifier).toBeDefined();
      expect(codeChallenge).toBeDefined();
      expect(codeVerifier.length).toBeGreaterThanOrEqual(43);
      expect(codeChallenge.length).toBe(43);

      // Verify they're different (challenge is a hash of verifier)
      expect(codeVerifier).not.toBe(codeChallenge);
    });

    it('should generate unique challenge-verifier pairs', async () => {
      const pairs = new Map();

      for (let i = 0; i < 5; i++) {
        const verifier = generateCodeVerifier();
        const challenge = await generateCodeChallenge(verifier);
        pairs.set(challenge, verifier);
      }

      // All challenges should be unique
      expect(pairs.size).toBe(5);
    });
  });
});
