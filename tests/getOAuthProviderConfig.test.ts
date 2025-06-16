import type { OAuthProviderConfigMap } from '../src/types';

import { describe, it, expect, beforeEach } from 'vitest';
import { getOAuthProviderConfig, useOAuthRegistry } from '../src';

describe('getOAuthProviderConfig', () => {
  const { registerOAuthProvider } = useOAuthRegistry('a'.repeat(64));
  beforeEach(async () => {
    // Clear registry between tests by resetting the module cache
    const registry = await import('../src');
    registry.providerRegistry.clear();
  });

  it('returns the registered config for a known provider', () => {
    const config = {
      clientId: 'abc',
      clientSecret: 'secret',
      tokenEndpoint: 'https://example.com/token',
      authorizeEndpoint: 'https://example.com/authorize',
      redirectUri: 'https://myapp.com/callback',
      scopes: ['read', 'write'],
    };

    registerOAuthProvider('clio', config);

    const result = getOAuthProviderConfig('clio');

    expect(result).toMatchObject(config);
  });

  it('throws if provider is not registered', () => {
    try {
      getOAuthProviderConfig('intuit');

      throw new Error('Expected error not thrown');
    } catch (err: any) {
      expect(err.statusCode).toBe(500);

      expect(err.statusMessage).toMatch(
        'OAuth provider "intuit" is not registered',
      );
    }
  });

  it('returns the registered config for a scoped provider instance', () => {
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
      redirectUri: 'https://myapp.com/callback/smithlaw',
      scopes: ['read', 'write'],
    };

    // Register both global and scoped configs
    registerOAuthProvider('clio', globalConfig);
    registerOAuthProvider('clio', 'smithlaw', scopedConfig);

    // Should return global config when no instanceKey provided
    const globalResult = getOAuthProviderConfig('clio');
    expect(globalResult).toMatchObject(globalConfig);

    // Should return scoped config when instanceKey provided
    const scopedResult = getOAuthProviderConfig('clio', 'smithlaw');
    expect(scopedResult).toMatchObject(scopedConfig);
  });

  it('throws if scoped provider instance is not registered', () => {
    const globalConfig = {
      clientId: 'global-client',
      clientSecret: 'global-secret',
      tokenEndpoint: 'https://example.com/token',
      authorizeEndpoint: 'https://example.com/authorize',
      redirectUri: 'https://myapp.com/callback',
      scopes: ['read'],
    };

    // Register only global config
    registerOAuthProvider('clio', globalConfig);

    // Should work for global
    expect(() => getOAuthProviderConfig('clio')).not.toThrow();

    // Should throw for unregistered scoped instance
    try {
      getOAuthProviderConfig('clio', 'unregistered-instance');
      throw new Error('Expected error not thrown');
    } catch (err: any) {
      expect(err.statusCode).toBe(500);
      expect(err.statusMessage).toMatch(
        'OAuth provider "clio:unregistered-instance" is not registered',
      );
    }
  });

  it('allows multiple scoped instances for the same provider', () => {
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

    // Register multiple scoped instances
    registerOAuthProvider('clio', 'smithlaw', smithlawConfig);
    registerOAuthProvider('clio', 'joneslaw', joneslawConfig);

    // Should return correct config for each instance
    const smithlawResult = getOAuthProviderConfig('clio', 'smithlaw');
    expect(smithlawResult).toMatchObject(smithlawConfig);

    const joneslawResult = getOAuthProviderConfig('clio', 'joneslaw');
    expect(joneslawResult).toMatchObject(joneslawConfig);

    // Configs should be independent
    expect(smithlawResult).not.toEqual(joneslawResult);
  });
});
