import { describe, it, expect, beforeEach } from 'vitest';
import {
  getDiscoveredProviderTokens,
  typedInstanceResolver,
  withInstanceKeys,
  OAuthProvider,
} from '../src/index';
import type { H3Event } from 'h3';
import { createMockEvent } from './utils';

describe('Utility Functions', () => {
  describe('getDiscoveredProviderTokens', () => {
    it('should find global provider tokens', () => {
      const context = {
        azure: {
          access_token: 'token-123',
          refresh_token: 'refresh-123',
          expires_in: 3600,
        },
      };

      const result = getDiscoveredProviderTokens(
        context,
        'azure' as OAuthProvider,
      );

      expect(result).toBeDefined();
      expect(result?.key).toBe('azure');
      expect(result?.tokens.access_token).toBe('token-123');
    });

    it('should find scoped provider tokens', () => {
      const context = {
        'azure:tenant-a': {
          access_token: 'token-scoped',
          refresh_token: 'refresh-scoped',
          expires_in: 3600,
        },
      };

      const result = getDiscoveredProviderTokens(
        context,
        'azure' as OAuthProvider,
      );

      expect(result).toBeDefined();
      expect(result?.key).toBe('azure:tenant-a');
      expect(result?.tokens.access_token).toBe('token-scoped');
    });

    it('should prefer global over scoped if both exist', () => {
      const context = {
        azure: {
          access_token: 'global-token',
          refresh_token: 'global-refresh',
          expires_in: 3600,
        },
        'azure:tenant-a': {
          access_token: 'scoped-token',
          refresh_token: 'scoped-refresh',
          expires_in: 3600,
        },
      };

      const result = getDiscoveredProviderTokens(
        context,
        'azure' as OAuthProvider,
      );

      expect(result?.key).toBe('azure');
      expect(result?.tokens.access_token).toBe('global-token');
    });

    it('should return undefined if provider not found', () => {
      const context = {
        clio: {
          access_token: 'clio-token',
          refresh_token: 'clio-refresh',
          expires_in: 3600,
        },
      };

      const result = getDiscoveredProviderTokens(
        context,
        'azure' as OAuthProvider,
      );

      expect(result).toBeUndefined();
    });

    it('should return undefined for empty context', () => {
      const context = {};

      const result = getDiscoveredProviderTokens(
        context,
        'azure' as OAuthProvider,
      );

      expect(result).toBeUndefined();
    });

    it('should find first matching scoped provider when multiple exist', () => {
      const context = {
        'azure:tenant-a': {
          access_token: 'token-a',
          refresh_token: 'refresh-a',
          expires_in: 3600,
        },
        'azure:tenant-b': {
          access_token: 'token-b',
          refresh_token: 'refresh-b',
          expires_in: 3600,
        },
      };

      const result = getDiscoveredProviderTokens(
        context,
        'azure' as OAuthProvider,
      );

      expect(result).toBeDefined();
      expect(result?.key).toMatch(/^azure:tenant-/);
      expect(['token-a', 'token-b']).toContain(result?.tokens.access_token);
    });
  });

  describe('typedInstanceResolver', () => {
    it('should return the same function', () => {
      const resolver = (event: H3Event) => 'tenant-a';
      const typedResolver = typedInstanceResolver(resolver);

      expect(typedResolver).toBe(resolver);
    });

    it('should preserve function behavior', () => {
      const mockEvent = createMockEvent();
      const resolver = (event: H3Event) => 'smithlaw';
      const typedResolver = typedInstanceResolver(resolver);

      const result = typedResolver(mockEvent);

      expect(result).toBe('smithlaw');
    });

    it('should work with async resolvers', async () => {
      const mockEvent = createMockEvent();
      const resolver = async (event: H3Event) =>
        Promise.resolve('async-tenant');
      const typedResolver = typedInstanceResolver(resolver);

      const result = await typedResolver(mockEvent);

      expect(result).toBe('async-tenant');
    });

    it('should handle undefined returns', () => {
      const mockEvent = createMockEvent();
      const resolver = (event: H3Event) => undefined;
      const typedResolver = typedInstanceResolver(resolver);

      const result = typedResolver(mockEvent);

      expect(result).toBeUndefined();
    });
  });

  describe('withInstanceKeys', () => {
    it('should create a provider definition with instance keys', () => {
      const resolver = (event: H3Event) => 'smithlaw';

      const result = withInstanceKeys(
        'clio' as OAuthProvider,
        ['smithlaw', 'johnsonlegal', 'LOAG'] as const,
        resolver,
      );

      expect(result).toHaveProperty('provider', 'clio');
      expect(result).toHaveProperty('instanceResolver', resolver);
      expect(result).toHaveProperty('__instanceKeys', [
        'smithlaw',
        'johnsonlegal',
        'LOAG',
      ]);
    });

    it('should preserve the resolver function', () => {
      const mockEvent = createMockEvent();
      const resolver = (event: H3Event) => 'LOAG';

      const result = withInstanceKeys(
        'clio' as OAuthProvider,
        ['smithlaw', 'LOAG'] as const,
        resolver,
      );

      const instanceKey = result.instanceResolver(mockEvent);

      expect(instanceKey).toBe('LOAG');
    });

    it('should work with async resolvers', async () => {
      const mockEvent = createMockEvent();
      const resolver = async (event: H3Event) => Promise.resolve('smithlaw');

      const result = withInstanceKeys(
        'clio' as OAuthProvider,
        ['smithlaw', 'LOAG'] as const,
        resolver,
      );

      const instanceKey = await result.instanceResolver(mockEvent);

      expect(instanceKey).toBe('smithlaw');
    });

    it('should handle undefined resolver returns', () => {
      const mockEvent = createMockEvent();
      const resolver = (event: H3Event) => undefined;

      const result = withInstanceKeys(
        'clio' as OAuthProvider,
        ['smithlaw', 'LOAG'] as const,
        resolver,
      );

      const instanceKey = result.instanceResolver(mockEvent);

      expect(instanceKey).toBeUndefined();
    });

    it('should work with single instance key', () => {
      const resolver = (event: H3Event) => 'only-one';

      const result = withInstanceKeys(
        'azure' as OAuthProvider,
        ['only-one'] as const,
        resolver,
      );

      expect(result.__instanceKeys).toEqual(['only-one']);
    });

    it('should preserve multiple instance keys', () => {
      const resolver = (event: H3Event) => 'tenant-1';

      const result = withInstanceKeys(
        'azure' as OAuthProvider,
        ['tenant-1', 'tenant-2', 'tenant-3', 'tenant-4'] as const,
        resolver,
      );

      expect(result.__instanceKeys).toHaveLength(4);
      expect(result.__instanceKeys).toContain('tenant-1');
      expect(result.__instanceKeys).toContain('tenant-4');
    });
  });
});

