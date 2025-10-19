import { describe, it, expect } from 'vitest';
import { getProviderConfig } from '../../src/providerConfig';

describe('getProviderConfig', () => {
  describe('known providers', () => {
    it('should return azure config with provider-specific fields', () => {
      const config = getProviderConfig('azure');

      expect(config.baseCookieFields).toEqual([
        'access_token',
        'refresh_token',
        'access_token_expires_at',
      ]);
      expect(config.providerSpecificFields).toBeDefined();
      expect(Array.isArray(config.providerSpecificFields)).toBe(true);
      expect(config.providerSpecificFields.length).toBeGreaterThan(0);
      expect(config.callbackQueryFields).toContain('session_state');
      expect(config.callbackQueryFields).toContain('id_token');
    });

    it('should return clio config (simple provider)', () => {
      const config = getProviderConfig('clio');

      expect(config).toEqual({
        baseCookieFields: [
          'access_token',
          'refresh_token',
          'access_token_expires_at',
        ],
        providerSpecificFields: [],
      });
    });

    it('should return intuit config with validateRefreshTokenExpiry', () => {
      const config = getProviderConfig('intuit');

      expect(config.baseCookieFields).toEqual([
        'access_token',
        'refresh_token',
        'access_token_expires_at',
      ]);
      expect(config.validateRefreshTokenExpiry).toBe(true);
      expect(config.callbackQueryFields).toContain('realmId');
    });

    it('should return mycase config', () => {
      const config = getProviderConfig('mycase');

      expect(config).toEqual({
        baseCookieFields: [
          'access_token',
          'refresh_token',
          'access_token_expires_at',
        ],
        providerSpecificFields: [],
      });
    });
  });

  describe('custom/unknown providers', () => {
    it('should return default config for unknown provider', () => {
      const config = getProviderConfig('unknown-provider' as any);

      expect(config).toEqual({
        baseCookieFields: [
          'access_token',
          'refresh_token',
          'access_token_expires_at',
        ],
        providerSpecificFields: [],
      });
    });

    it('should return default config for custom provider not in config (e.g. google)', () => {
      const config = getProviderConfig('google' as any);

      expect(config).toEqual({
        baseCookieFields: [
          'access_token',
          'refresh_token',
          'access_token_expires_at',
        ],
        providerSpecificFields: [],
      });
    });

    it('should not have validateRefreshTokenExpiry for default providers', () => {
      const config = getProviderConfig('custom-provider' as any);

      expect(config.validateRefreshTokenExpiry).toBeUndefined();
    });

    it('should not have callbackQueryFields for default providers', () => {
      const config = getProviderConfig('custom-provider' as any);

      expect(config.callbackQueryFields).toBeUndefined();
    });
  });

  describe('provider-specific features', () => {
    it('should indicate which providers validate refresh token expiry', () => {
      const intuitConfig = getProviderConfig('intuit');
      const azureConfig = getProviderConfig('azure');
      const clioConfig = getProviderConfig('clio');

      expect(intuitConfig.validateRefreshTokenExpiry).toBe(true);
      expect(azureConfig.validateRefreshTokenExpiry).toBeUndefined();
      expect(clioConfig.validateRefreshTokenExpiry).toBeUndefined();
    });

    it('should indicate which providers have callback query fields', () => {
      const intuitConfig = getProviderConfig('intuit');
      const azureConfig = getProviderConfig('azure');
      const clioConfig = getProviderConfig('clio');

      expect(intuitConfig.callbackQueryFields).toContain('realmId');
      expect(azureConfig.callbackQueryFields).toContain('session_state');
      expect(azureConfig.callbackQueryFields).toContain('id_token');
      expect(clioConfig.callbackQueryFields).toBeUndefined();
    });

    it('should indicate which providers have specific cookie fields', () => {
      const azureConfig = getProviderConfig('azure');
      const clioConfig = getProviderConfig('clio');

      expect(azureConfig.providerSpecificFields.length).toBeGreaterThan(0);

      // Azure has a providerSpecificField for ext_expires_in
      const hasExtExpiresIn = azureConfig.providerSpecificFields.some(
        (field) => typeof field === 'object' && field.key === 'ext_expires_in'
      );
      expect(hasExtExpiresIn).toBe(true);

      expect(clioConfig.providerSpecificFields).toEqual([]);
    });
  });

  describe('extensibility', () => {
    it('should support type-safe access to known providers', () => {
      // This is more of a TypeScript compile-time check, but we can verify runtime behavior
      const providers = ['azure', 'clio', 'intuit', 'mycase'] as const;

      providers.forEach((provider) => {
        const config = getProviderConfig(provider);
        expect(config).toBeDefined();
        expect(config.baseCookieFields).toContain('access_token');
      });
    });

    it('should gracefully handle new providers added at runtime', () => {
      // Simulating a custom provider that might be added via module augmentation
      const customProvider = 'github' as any;
      const config = getProviderConfig(customProvider);

      expect(config).toEqual({
        baseCookieFields: [
          'access_token',
          'refresh_token',
          'access_token_expires_at',
        ],
        providerSpecificFields: [],
      });
    });
  });

  describe('consistency', () => {
    it('should return same config structure for repeated calls to same provider', () => {
      const config1 = getProviderConfig('azure');
      const config2 = getProviderConfig('azure');

      expect(config1).toEqual(config2);
    });

    it('should always include base cookie fields', () => {
      const providers = ['azure', 'clio', 'intuit', 'mycase', 'unknown' as any];

      providers.forEach((provider) => {
        const config = getProviderConfig(provider);
        expect(config.baseCookieFields).toContain('access_token');
        expect(config.baseCookieFields).toContain('refresh_token');
        expect(config.baseCookieFields).toContain('access_token_expires_at');
      });
    });
  });

  describe('default config for extensibility', () => {
    it('should allow custom providers to work with default configuration', () => {
      // Simulating various custom providers that might be added
      const customProviders = ['google', 'github', 'facebook', 'twitter'] as any[];

      customProviders.forEach((provider) => {
        const config = getProviderConfig(provider);

        // Should get default config
        expect(config.baseCookieFields).toHaveLength(3);
        expect(config.providerSpecificFields).toEqual([]);

        // Should not have special features
        expect(config.validateRefreshTokenExpiry).toBeUndefined();
        expect(config.callbackQueryFields).toBeUndefined();
      });
    });

    it('should support the extensibility model for custom OAuth providers', () => {
      // This test verifies that the default config is suitable for any standard OAuth 2.0 provider
      const config = getProviderConfig('custom-oauth-provider' as any);

      // Should have the three essential OAuth fields
      expect(config.baseCookieFields).toEqual([
        'access_token',
        'refresh_token',
        'access_token_expires_at',
      ]);

      // Should not have any provider-specific requirements
      expect(config.providerSpecificFields).toEqual([]);
      expect(config.validateRefreshTokenExpiry).toBeUndefined();
      expect(config.callbackQueryFields).toBeUndefined();
    });
  });
});

