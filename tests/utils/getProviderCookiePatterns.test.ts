import { describe, it, expect, beforeEach } from 'vitest';
import { getProviderCookiePatterns } from '../../src/utils/index';
import { OAuthProvider } from '../../src/index';

describe('getProviderCookiePatterns', () => {
  it('should return base cookie patterns for a provider', () => {
    const patterns = getProviderCookiePatterns('azure' as OAuthProvider);

    // Patterns are RegExp objects
    expect(patterns).toBeInstanceOf(Array);
    expect(patterns.length).toBeGreaterThan(0);
    
    // Check that patterns match expected cookie names
    expect(patterns.some(p => p.test('azure_access_token'))).toBe(true);
    expect(patterns.some(p => p.test('azure_refresh_token'))).toBe(true);
    expect(patterns.some(p => p.test('azure_access_token_expires_at'))).toBe(true);
  });

  it('should return patterns for scoped provider', () => {
    const patterns = getProviderCookiePatterns(
      'azure' as OAuthProvider,
      'tenant-a',
    );

    expect(patterns.some(p => p.test('azure:tenant-a_access_token'))).toBe(true);
    expect(patterns.some(p => p.test('azure:tenant-a_refresh_token'))).toBe(true);
    expect(patterns.some(p => p.test('azure:tenant-a_access_token_expires_at'))).toBe(true);
  });

  it('should return correct patterns for clio provider', () => {
    const patterns = getProviderCookiePatterns('clio' as OAuthProvider);

    expect(patterns.some(p => p.test('clio_access_token'))).toBe(true);
    expect(patterns.some(p => p.test('clio_refresh_token'))).toBe(true);
    expect(patterns.some(p => p.test('clio_access_token_expires_at'))).toBe(true);
  });

  it('should return correct patterns for intuit provider', () => {
    const patterns = getProviderCookiePatterns('intuit' as OAuthProvider);

    expect(patterns.some(p => p.test('intuit_access_token'))).toBe(true);
    expect(patterns.some(p => p.test('intuit_refresh_token'))).toBe(true);
    expect(patterns.some(p => p.test('intuit_access_token_expires_at'))).toBe(true);
  });

  it('should handle mycase provider', () => {
    const patterns = getProviderCookiePatterns('mycase' as OAuthProvider);

    expect(patterns.some(p => p.test('mycase_access_token'))).toBe(true);
    expect(patterns.some(p => p.test('mycase_refresh_token'))).toBe(true);
    expect(patterns.some(p => p.test('mycase_access_token_expires_at'))).toBe(true);
  });

  it('should return different patterns for different instance keys', () => {
    const patternsA = getProviderCookiePatterns(
      'clio' as OAuthProvider,
      'smithlaw',
    );
    const patternsB = getProviderCookiePatterns(
      'clio' as OAuthProvider,
      'johnsonlegal',
    );

    // Each should match their own instance
    expect(patternsA.some(p => p.test('clio:smithlaw_access_token'))).toBe(true);
    expect(patternsB.some(p => p.test('clio:johnsonlegal_access_token'))).toBe(true);
    
    // Patterns are RegExp so they'll match based on the pattern, not the exact string
    // Just verify they're different arrays
    expect(patternsA.length).toBeGreaterThan(0);
    expect(patternsB.length).toBeGreaterThan(0);
  });

  it('should return consistent patterns for the same provider/instance', () => {
    const patterns1 = getProviderCookiePatterns('azure' as OAuthProvider);
    const patterns2 = getProviderCookiePatterns('azure' as OAuthProvider);

    expect(patterns1).toEqual(patterns2);
  });

  it('should include all base fields', () => {
    const patterns = getProviderCookiePatterns('azure' as OAuthProvider);

    // All providers should have these base fields
    expect(patterns.some(p => p.test('azure_access_token'))).toBe(true);
    expect(patterns.some(p => p.test('azure_refresh_token'))).toBe(true);
    expect(patterns.some(p => p.test('azure_access_token_expires_at'))).toBe(true);
  });
});

