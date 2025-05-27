import { describe, it, expect, vi, beforeEach } from 'vitest';
import { deleteProviderCookies, providerRegistry } from '../../src/index';
import { getProviderCookieKeys } from '../../src/utils';
import { deleteCookie } from 'h3';
import { createMockEvent } from '../utils';

// Mock deleteCookie
vi.mock('h3', async () => {
  const actual = await vi.importActual<typeof import('h3')>('h3');
  return {
    ...actual,
    deleteCookie: vi.fn(),
  };
});

const mockDeleteCookie = vi.mocked(deleteCookie);

describe('deleteProviderCookies', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Clear the provider registry before each test
    providerRegistry.clear();
  });

  describe('specific instance deletion', () => {
    it('calls deleteCookie for all azure cookies with instanceKey', () => {
      const mockEvent = createMockEvent();
      deleteProviderCookies(mockEvent, 'azure', 'dev');

      const expected = getProviderCookieKeys('azure', 'dev');
      for (const key of expected) {
        expect(mockDeleteCookie).toHaveBeenCalledWith(mockEvent, key);
      }
    });

    it('calls deleteCookie for all clio cookies with instanceKey', () => {
      const mockEvent = createMockEvent();
      deleteProviderCookies(mockEvent, 'clio', 'smithlaw');

      const expected = getProviderCookieKeys('clio', 'smithlaw');
      for (const key of expected) {
        expect(mockDeleteCookie).toHaveBeenCalledWith(mockEvent, key);
      }
    });

    it('calls deleteCookie for all intuit cookies with instanceKey', () => {
      const mockEvent = createMockEvent();
      deleteProviderCookies(mockEvent, 'intuit', 'sandbox');

      const expected = getProviderCookieKeys('intuit', 'sandbox');
      for (const key of expected) {
        expect(mockDeleteCookie).toHaveBeenCalledWith(mockEvent, key);
      }
    });
  });

  describe('wildcard deletion (no instanceKey)', () => {
    it('deletes cookies for all registered clio instances', () => {
      const mockEvent = createMockEvent();

      // Register multiple clio instances in the provider registry
      providerRegistry.set('clio', { clientId: 'global-clio' } as any);
      providerRegistry.set('clio:smithlaw', {
        clientId: 'smithlaw-clio',
      } as any);
      providerRegistry.set('clio:firm', { clientId: 'firm-clio' } as any);

      deleteProviderCookies(mockEvent, 'clio');

      // Should delete cookies for global clio
      expect(mockDeleteCookie).toHaveBeenCalledWith(
        mockEvent,
        'clio_access_token',
      );
      expect(mockDeleteCookie).toHaveBeenCalledWith(
        mockEvent,
        'clio_refresh_token',
      );
      expect(mockDeleteCookie).toHaveBeenCalledWith(
        mockEvent,
        'clio_access_token_expires_at',
      );

      // Should delete cookies for clio:smithlaw instance
      expect(mockDeleteCookie).toHaveBeenCalledWith(
        mockEvent,
        'clio:smithlaw_access_token',
      );
      expect(mockDeleteCookie).toHaveBeenCalledWith(
        mockEvent,
        'clio:smithlaw_refresh_token',
      );
      expect(mockDeleteCookie).toHaveBeenCalledWith(
        mockEvent,
        'clio:smithlaw_access_token_expires_at',
      );

      // Should delete cookies for clio:firm instance
      expect(mockDeleteCookie).toHaveBeenCalledWith(
        mockEvent,
        'clio:firm_access_token',
      );
      expect(mockDeleteCookie).toHaveBeenCalledWith(
        mockEvent,
        'clio:firm_refresh_token',
      );
      expect(mockDeleteCookie).toHaveBeenCalledWith(
        mockEvent,
        'clio:firm_access_token_expires_at',
      );

      // Total: 3 global + 3 smithlaw + 3 firm = 9 cookies
      expect(mockDeleteCookie).toHaveBeenCalledTimes(9);
    });

    it('deletes azure cookies including provider-specific fields', () => {
      const mockEvent = createMockEvent();

      // Register azure instances
      providerRegistry.set('azure', { clientId: 'global-azure' } as any);
      providerRegistry.set('azure:dev', { clientId: 'dev-azure' } as any);

      deleteProviderCookies(mockEvent, 'azure');

      // Should delete global azure cookies (including provider-specific ext_expires_at)
      expect(mockDeleteCookie).toHaveBeenCalledWith(
        mockEvent,
        'azure_access_token',
      );
      expect(mockDeleteCookie).toHaveBeenCalledWith(
        mockEvent,
        'azure_refresh_token',
      );
      expect(mockDeleteCookie).toHaveBeenCalledWith(
        mockEvent,
        'azure_access_token_expires_at',
      );
      expect(mockDeleteCookie).toHaveBeenCalledWith(
        mockEvent,
        'azure_ext_expires_at',
      );

      // Should delete azure:dev cookies
      expect(mockDeleteCookie).toHaveBeenCalledWith(
        mockEvent,
        'azure:dev_access_token',
      );
      expect(mockDeleteCookie).toHaveBeenCalledWith(
        mockEvent,
        'azure:dev_refresh_token',
      );
      expect(mockDeleteCookie).toHaveBeenCalledWith(
        mockEvent,
        'azure:dev_access_token_expires_at',
      );
      expect(mockDeleteCookie).toHaveBeenCalledWith(
        mockEvent,
        'azure:dev_ext_expires_at',
      );

      // Total: 4 global + 4 dev = 8 cookies
      expect(mockDeleteCookie).toHaveBeenCalledTimes(8);
    });

    it('deletes intuit cookies including provider-specific fields', () => {
      const mockEvent = createMockEvent();

      // Register intuit instances
      providerRegistry.set('intuit', { clientId: 'global-intuit' } as any);
      providerRegistry.set('intuit:sandbox', {
        clientId: 'sandbox-intuit',
      } as any);

      deleteProviderCookies(mockEvent, 'intuit');

      // Should delete global intuit cookies (including refresh_token_expires_at)
      expect(mockDeleteCookie).toHaveBeenCalledWith(
        mockEvent,
        'intuit_access_token',
      );
      expect(mockDeleteCookie).toHaveBeenCalledWith(
        mockEvent,
        'intuit_refresh_token',
      );
      expect(mockDeleteCookie).toHaveBeenCalledWith(
        mockEvent,
        'intuit_access_token_expires_at',
      );
      expect(mockDeleteCookie).toHaveBeenCalledWith(
        mockEvent,
        'intuit_refresh_token_expires_at',
      );

      // Should delete intuit:sandbox cookies
      expect(mockDeleteCookie).toHaveBeenCalledWith(
        mockEvent,
        'intuit:sandbox_access_token',
      );
      expect(mockDeleteCookie).toHaveBeenCalledWith(
        mockEvent,
        'intuit:sandbox_refresh_token',
      );
      expect(mockDeleteCookie).toHaveBeenCalledWith(
        mockEvent,
        'intuit:sandbox_access_token_expires_at',
      );
      expect(mockDeleteCookie).toHaveBeenCalledWith(
        mockEvent,
        'intuit:sandbox_refresh_token_expires_at',
      );

      // Total: 4 global + 4 sandbox = 8 cookies
      expect(mockDeleteCookie).toHaveBeenCalledTimes(8);
    });

    it('does nothing when no providers are registered', () => {
      const mockEvent = createMockEvent();

      // Don't register any providers
      deleteProviderCookies(mockEvent, 'clio');

      // Should not delete any cookies
      expect(mockDeleteCookie).not.toHaveBeenCalled();
    });

    it('only deletes cookies for registered instances', () => {
      const mockEvent = createMockEvent();

      // Only register one instance
      providerRegistry.set('clio:smithlaw', {
        clientId: 'smithlaw-clio',
      } as any);

      deleteProviderCookies(mockEvent, 'clio');

      // Should only delete cookies for the registered instance
      expect(mockDeleteCookie).toHaveBeenCalledWith(
        mockEvent,
        'clio:smithlaw_access_token',
      );
      expect(mockDeleteCookie).toHaveBeenCalledWith(
        mockEvent,
        'clio:smithlaw_refresh_token',
      );
      expect(mockDeleteCookie).toHaveBeenCalledWith(
        mockEvent,
        'clio:smithlaw_access_token_expires_at',
      );

      // Should NOT delete global clio cookies (not registered)
      expect(mockDeleteCookie).not.toHaveBeenCalledWith(
        mockEvent,
        'clio_access_token',
      );

      expect(mockDeleteCookie).toHaveBeenCalledTimes(3);
    });
  });
});
