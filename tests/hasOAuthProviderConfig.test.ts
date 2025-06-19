import { describe, it, expect, beforeEach } from 'vitest';
import { useOAuthRegistry, hasOAuthProviderConfig } from '../src';

describe('hasOAuthProviderConfig', () => {
  const { registerOAuthProvider } = useOAuthRegistry('a'.repeat(64));
  beforeEach(async () => {
    // Clear registry between tests by resetting the module cache
    const registry = await import('../src');
    registry.providerRegistry.clear();
  });

  it('returns false for unregistered provider', () => {
    const result = hasOAuthProviderConfig('clio');
    expect(result).toBe(false);
  });

  it('returns true for registered provider', () => {
    const config = {
      clientId: 'test-client',
      clientSecret: 'test-secret',
      tokenEndpoint: 'https://example.com/token',
      authorizeEndpoint: 'https://example.com/authorize',
      redirectUri: 'https://myapp.com/callback',
      scopes: ['read', 'write'],
    };

    registerOAuthProvider('clio', config);

    const result = hasOAuthProviderConfig('clio');
    expect(result).toBe(true);
  });

  it('returns false for unregistered scoped provider instance', () => {
    const result = hasOAuthProviderConfig('clio', 'smithlaw');
    expect(result).toBe(false);
  });

  it('returns true for registered scoped provider instance', () => {
    const config = {
      clientId: 'scoped-client',
      clientSecret: 'scoped-secret',
      tokenEndpoint: 'https://example.com/token',
      authorizeEndpoint: 'https://example.com/authorize',
      redirectUri: 'https://myapp.com/callback/smithlaw',
      scopes: ['read', 'write'],
    };

    registerOAuthProvider('clio', 'smithlaw', config);

    const result = hasOAuthProviderConfig('clio', 'smithlaw');
    expect(result).toBe(true);
  });

  it('distinguishes between global and scoped provider configurations', () => {
    const globalConfig = {
      clientId: 'global-client',
      clientSecret: 'global-secret',
      tokenEndpoint: 'https://example.com/token',
      authorizeEndpoint: 'https://example.com/authorize',
      redirectUri: 'https://myapp.com/callback',
      scopes: ['read'],
    };

    const scopedConfig = {
      clientId: 'scoped-client',
      clientSecret: 'scoped-secret',
      tokenEndpoint: 'https://example.com/token',
      authorizeEndpoint: 'https://example.com/authorize',
      redirectUri: 'https://example.com/callback/smithlaw',
      scopes: ['read', 'write'],
    };

    // Register only global config
    registerOAuthProvider('clio', globalConfig);

    // Global should exist, scoped should not
    expect(hasOAuthProviderConfig('clio')).toBe(true);
    expect(hasOAuthProviderConfig('clio', 'smithlaw')).toBe(false);

    // Register scoped config
    registerOAuthProvider('clio', 'smithlaw', scopedConfig);

    // Both should now exist
    expect(hasOAuthProviderConfig('clio')).toBe(true);
    expect(hasOAuthProviderConfig('clio', 'smithlaw')).toBe(true);
  });

  it('handles multiple scoped instances for the same provider', () => {
    const smithlawConfig = {
      clientId: 'smithlaw-client',
      clientSecret: 'smithlaw-secret',
      tokenEndpoint: 'https://example.com/token',
      authorizeEndpoint: 'https://example.com/authorize',
      redirectUri: 'https://myapp.com/callback/smithlaw',
      scopes: ['read', 'write'],
    };

    const joneslawConfig = {
      clientId: 'joneslaw-client',
      clientSecret: 'joneslaw-secret',
      tokenEndpoint: 'https://example.com/token',
      authorizeEndpoint: 'https://example.com/authorize',
      redirectUri: 'https://myapp.com/callback/joneslaw',
      scopes: ['read'],
    };

    // Initially, none should exist
    expect(hasOAuthProviderConfig('clio', 'smithlaw')).toBe(false);
    expect(hasOAuthProviderConfig('clio', 'joneslaw')).toBe(false);

    // Register first instance
    registerOAuthProvider('clio', 'smithlaw', smithlawConfig);
    expect(hasOAuthProviderConfig('clio', 'smithlaw')).toBe(true);
    expect(hasOAuthProviderConfig('clio', 'joneslaw')).toBe(false);

    // Register second instance
    registerOAuthProvider('clio', 'joneslaw', joneslawConfig);
    expect(hasOAuthProviderConfig('clio', 'smithlaw')).toBe(true);
    expect(hasOAuthProviderConfig('clio', 'joneslaw')).toBe(true);
  });

  it('works with different provider types', () => {
    const clioConfig = {
      clientId: 'clio-client',
      clientSecret: 'clio-secret',
      tokenEndpoint: 'https://clio.com/token',
      authorizeEndpoint: 'https://clio.com/authorize',
      redirectUri: 'https://myapp.com/callback/clio',
      scopes: ['read', 'write'],
    };

    const intuitConfig = {
      clientId: 'intuit-client',
      clientSecret: 'intuit-secret',
      tokenEndpoint: 'https://intuit.com/token',
      authorizeEndpoint: 'https://intuit.com/authorize',
      redirectUri: 'https://myapp.com/callback/intuit',
      scopes: ['accounting'],
      environment: 'sandbox' as 'sandbox',
    };

    // Initially, neither should exist
    expect(hasOAuthProviderConfig('clio')).toBe(false);
    expect(hasOAuthProviderConfig('intuit')).toBe(false);

    // Register clio
    registerOAuthProvider('clio', clioConfig);
    expect(hasOAuthProviderConfig('clio')).toBe(true);
    expect(hasOAuthProviderConfig('intuit')).toBe(false);

    // Register intuit
    registerOAuthProvider('intuit', intuitConfig);
    expect(hasOAuthProviderConfig('clio')).toBe(true);
    expect(hasOAuthProviderConfig('intuit')).toBe(true);
  });

  it('handles empty instance keys correctly', () => {
    const config = {
      clientId: 'test-client',
      clientSecret: 'test-secret',
      tokenEndpoint: 'https://example.com/token',
      authorizeEndpoint: 'https://example.com/authorize',
      redirectUri: 'https://myapp.com/callback',
      scopes: ['read'],
    };

    registerOAuthProvider('clio', config);

    // These should be equivalent (both check for global config)
    // Empty string is falsy, so it's treated the same as undefined
    expect(hasOAuthProviderConfig('clio')).toBe(true);
    expect(hasOAuthProviderConfig('clio', undefined)).toBe(true);
    expect(hasOAuthProviderConfig('clio', '')).toBe(true);

    // Non-empty string should be treated as a scoped instance
    expect(hasOAuthProviderConfig('clio', 'nonexistent')).toBe(false);
  });
});
