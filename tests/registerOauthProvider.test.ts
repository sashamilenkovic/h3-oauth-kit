import { describe, it, expect, beforeEach } from 'vitest';
import { getOAuthProviderConfig, useOAuthRegistry } from '../src';

describe('registerOAuthProvider', () => {
  const { registerOAuthProvider: useOAuthProvider } = useOAuthRegistry(
    'a'.repeat(64),
  );
  beforeEach(() => {
    // Clear registry between tests
    try {
      // HACK: access the internal providerRegistry via getOAuthProviderConfig's cache
      (getOAuthProviderConfig as any)._registry?.clear?.();
    } catch {
      // fallback — registry is module-scoped, so this is a safety noop
    }
  });

  it('registers a provider config successfully', () => {
    const config = {
      clientId: 'abc123',
      clientSecret: 'secret',
      tokenEndpoint: 'https://clio.com/oauth/token',
      authorizeEndpoint: 'https://clio.com/oauth/authorize',
      redirectUri: 'http://localhost/callback',
      scopes: ['activity.read', 'contacts.read'],
    };

    useOAuthProvider('clio', config);

    const stored = getOAuthProviderConfig('clio');
    expect(stored).toMatchObject(config);
  });

  it('overwrites an existing provider config', () => {
    const initial = {
      clientId: 'original',
      clientSecret: 'secret1',
      tokenEndpoint: 'https://login.microsoftonline.com/token',
      authorizeEndpoint: 'https://login.microsoftonline.com/authorize',
      redirectUri: 'http://localhost/azure/callback',
      scopes: ['openid'],
      tenantId: 'tenant-1',
    };

    const updated = {
      ...initial,
      clientId: 'updated',
    };

    useOAuthProvider('azure', initial);
    useOAuthProvider('azure', updated);

    const result = getOAuthProviderConfig('azure');
    expect(result.clientId).toBe('updated');
  });

  describe('scoped/instance key registration', () => {
    it('registers a scoped provider config with instance key', () => {
      const config = {
        clientId: 'smithlaw-client-id',
        clientSecret: 'smithlaw-secret',
        tokenEndpoint: 'https://clio.com/oauth/token',
        authorizeEndpoint: 'https://clio.com/oauth/authorize',
        redirectUri: 'http://localhost/callback/smithlaw',
        scopes: ['activity.read', 'contacts.read'],
      };

      useOAuthProvider('clio', 'smithlaw', config);

      const stored = getOAuthProviderConfig('clio', 'smithlaw');
      expect(stored).toMatchObject(config);
    });

    it('allows different configs for global and scoped providers', () => {
      const globalConfig = {
        clientId: 'global-client-id',
        clientSecret: 'global-secret',
        tokenEndpoint: 'https://clio.com/oauth/token',
        authorizeEndpoint: 'https://clio.com/oauth/authorize',
        redirectUri: 'http://localhost/callback',
        scopes: ['activity.read'],
      };

      const smithlawConfig = {
        clientId: 'smithlaw-client-id',
        clientSecret: 'smithlaw-secret',
        tokenEndpoint: 'https://clio.com/oauth/token',
        authorizeEndpoint: 'https://clio.com/oauth/authorize',
        redirectUri: 'http://localhost/callback/smithlaw',
        scopes: ['activity.read', 'contacts.read'],
      };

      useOAuthProvider('clio', globalConfig);
      useOAuthProvider('clio', 'smithlaw', smithlawConfig);

      const globalStored = getOAuthProviderConfig('clio');
      const smithlawStored = getOAuthProviderConfig('clio', 'smithlaw');

      expect(globalStored).toMatchObject(globalConfig);
      expect(smithlawStored).toMatchObject(smithlawConfig);
      expect(globalStored.clientId).toBe('global-client-id');
      expect(smithlawStored.clientId).toBe('smithlaw-client-id');
    });

    it('allows multiple scoped instances for the same provider', () => {
      const smithlawConfig = {
        clientId: 'smithlaw-client-id',
        clientSecret: 'smithlaw-secret',
        tokenEndpoint: 'https://clio.com/oauth/token',
        authorizeEndpoint: 'https://clio.com/oauth/authorize',
        redirectUri: 'http://localhost/callback/smithlaw',
        scopes: ['activity.read'],
      };

      const joneslawConfig = {
        clientId: 'joneslaw-client-id',
        clientSecret: 'joneslaw-secret',
        tokenEndpoint: 'https://clio.com/oauth/token',
        authorizeEndpoint: 'https://clio.com/oauth/authorize',
        redirectUri: 'http://localhost/callback/joneslaw',
        scopes: ['contacts.read'],
      };

      useOAuthProvider('clio', 'smithlaw', smithlawConfig);
      useOAuthProvider('clio', 'joneslaw', joneslawConfig);

      const smithlawStored = getOAuthProviderConfig('clio', 'smithlaw');
      const joneslawStored = getOAuthProviderConfig('clio', 'joneslaw');

      expect(smithlawStored).toMatchObject(smithlawConfig);
      expect(joneslawStored).toMatchObject(joneslawConfig);
      expect(smithlawStored.clientId).toBe('smithlaw-client-id');
      expect(joneslawStored.clientId).toBe('joneslaw-client-id');
    });

    it('overwrites existing scoped provider config', () => {
      const initialConfig = {
        clientId: 'initial-smithlaw-id',
        clientSecret: 'secret',
        tokenEndpoint: 'https://login.microsoftonline.com/token',
        authorizeEndpoint: 'https://login.microsoftonline.com/authorize',
        redirectUri: 'http://localhost/azure/callback',
        scopes: ['openid'],
        tenantId: 'tenant-1',
      };

      const updatedConfig = {
        clientId: 'updated-smithlaw-id',
        clientSecret: 'secret',
        tokenEndpoint: 'https://login.microsoftonline.com/token',
        authorizeEndpoint: 'https://login.microsoftonline.com/authorize',
        redirectUri: 'http://localhost/azure/callback',
        scopes: ['openid', 'profile'],
        tenantId: 'tenant-2',
      };

      useOAuthProvider('azure', 'smithlaw', initialConfig);
      useOAuthProvider('azure', 'smithlaw', updatedConfig);

      const stored = getOAuthProviderConfig('azure', 'smithlaw');
      expect(stored).toMatchObject(updatedConfig);
      expect(stored.clientId).toBe('updated-smithlaw-id');
      expect(stored.tenantId).toBe('tenant-2');
    });

    it('works with different provider types for scoped registration', () => {
      const intuitConfig = {
        clientId: 'intuit-smithlaw-id',
        clientSecret: 'intuit-secret',
        tokenEndpoint:
          'https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer',
        authorizeEndpoint: 'https://appcenter.intuit.com/connect/oauth2',
        redirectUri: 'http://localhost/intuit/callback',
        scopes: ['com.intuit.quickbooks.accounting'],
        environment: 'sandbox' as 'sandbox',
      };

      useOAuthProvider('intuit', 'smithlaw', intuitConfig);

      const stored = getOAuthProviderConfig('intuit', 'smithlaw');
      expect(stored).toMatchObject(intuitConfig);
      expect(stored.environment).toBe('sandbox');
    });
  });
});
