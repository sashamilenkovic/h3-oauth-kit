import type { H3Event } from 'h3';

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { handleOAuthLogout, providerRegistry } from '../src';
import { deleteCookie, sendRedirect } from 'h3';

// Mock h3 functions
vi.mock('h3', () => ({
  deleteCookie: vi.fn(),
  sendRedirect: vi.fn(),
  defineEventHandler: (handler: Function) => handler,
}));

describe('handleOAuthLogout', () => {
  let mockEvent: H3Event;

  beforeEach(() => {
    vi.clearAllMocks();
    mockEvent = {} as H3Event;
    // Clear the provider registry before each test
    providerRegistry.clear();
  });

  describe('as a route handler', () => {
    it('deletes cookies for string-based providers', async () => {
      // Register providers in the registry
      providerRegistry.set('clio', { clientId: 'global-clio' } as any);
      providerRegistry.set('clio:smithlaw', {
        clientId: 'smithlaw-clio',
      } as any);
      providerRegistry.set('azure', { clientId: 'global-azure' } as any);
      providerRegistry.set('azure:dev', { clientId: 'dev-azure' } as any);

      const handler = handleOAuthLogout(['clio', 'azure']);
      const result = await handler(mockEvent);

      // Should delete clio cookies (global + smithlaw instance)
      expect(deleteCookie).toHaveBeenCalledWith(mockEvent, 'clio_access_token');
      expect(deleteCookie).toHaveBeenCalledWith(
        mockEvent,
        'clio_refresh_token',
      );
      expect(deleteCookie).toHaveBeenCalledWith(
        mockEvent,
        'clio_access_token_expires_at',
      );
      expect(deleteCookie).toHaveBeenCalledWith(
        mockEvent,
        'clio:smithlaw_access_token',
      );
      expect(deleteCookie).toHaveBeenCalledWith(
        mockEvent,
        'clio:smithlaw_refresh_token',
      );
      expect(deleteCookie).toHaveBeenCalledWith(
        mockEvent,
        'clio:smithlaw_access_token_expires_at',
      );

      // Should delete azure cookies (global + dev instance)
      expect(deleteCookie).toHaveBeenCalledWith(
        mockEvent,
        'azure_access_token',
      );
      expect(deleteCookie).toHaveBeenCalledWith(
        mockEvent,
        'azure_refresh_token',
      );
      expect(deleteCookie).toHaveBeenCalledWith(
        mockEvent,
        'azure_access_token_expires_at',
      );
      expect(deleteCookie).toHaveBeenCalledWith(
        mockEvent,
        'azure_ext_expires_at',
      );
      expect(deleteCookie).toHaveBeenCalledWith(
        mockEvent,
        'azure:dev_access_token',
      );
      expect(deleteCookie).toHaveBeenCalledWith(
        mockEvent,
        'azure:dev_refresh_token',
      );
      expect(deleteCookie).toHaveBeenCalledWith(
        mockEvent,
        'azure:dev_access_token_expires_at',
      );
      expect(deleteCookie).toHaveBeenCalledWith(
        mockEvent,
        'azure:dev_ext_expires_at',
      );

      // Total: 6 clio + 8 azure = 14 cookies
      expect(deleteCookie).toHaveBeenCalledTimes(14);
      expect(result).toEqual({
        loggedOut: true,
        providers: [{ provider: 'clio' }, { provider: 'azure' }],
      });
    });

    it('deletes cookies for object-based providers', async () => {
      // Register providers for wildcard deletion (clio has no instanceKey)
      providerRegistry.set('clio', { clientId: 'global-clio' } as any);
      providerRegistry.set('clio:smithlaw', {
        clientId: 'smithlaw-clio',
      } as any);

      const handler = handleOAuthLogout([
        { provider: 'clio' }, // No instanceKey -> wildcard deletion
        { provider: 'azure', instanceKey: 'dev' }, // Has instanceKey -> specific deletion
      ]);
      const result = await handler(mockEvent);

      // Clio should use wildcard deletion (all registered clio instances)
      expect(deleteCookie).toHaveBeenCalledWith(mockEvent, 'clio_access_token');
      expect(deleteCookie).toHaveBeenCalledWith(
        mockEvent,
        'clio_refresh_token',
      );
      expect(deleteCookie).toHaveBeenCalledWith(
        mockEvent,
        'clio_access_token_expires_at',
      );
      expect(deleteCookie).toHaveBeenCalledWith(
        mockEvent,
        'clio:smithlaw_access_token',
      );
      expect(deleteCookie).toHaveBeenCalledWith(
        mockEvent,
        'clio:smithlaw_refresh_token',
      );
      expect(deleteCookie).toHaveBeenCalledWith(
        mockEvent,
        'clio:smithlaw_access_token_expires_at',
      );

      // Azure should use specific deletion (only dev instance)
      expect(deleteCookie).toHaveBeenCalledWith(
        mockEvent,
        'azure:dev_access_token',
      );
      expect(deleteCookie).toHaveBeenCalledWith(
        mockEvent,
        'azure:dev_refresh_token',
      );
      expect(deleteCookie).toHaveBeenCalledWith(
        mockEvent,
        'azure:dev_access_token_expires_at',
      );
      expect(deleteCookie).toHaveBeenCalledWith(
        mockEvent,
        'azure:dev_ext_expires_at',
      );

      expect(result).toEqual({
        loggedOut: true,
        providers: [
          { provider: 'clio' },
          { provider: 'azure', instanceKey: 'dev' },
        ],
      });
    });
  });

  describe('as a utility with redirect', () => {
    it('deletes cookies and redirects (string input)', async () => {
      // Register providers for wildcard deletion
      providerRegistry.set('clio', { clientId: 'global-clio' } as any);
      providerRegistry.set('clio:firm', { clientId: 'firm-clio' } as any);

      await handleOAuthLogout(['clio'], { redirectTo: '/login' }, mockEvent);

      expect(deleteCookie).toHaveBeenCalledWith(mockEvent, 'clio_access_token');
      expect(deleteCookie).toHaveBeenCalledWith(
        mockEvent,
        'clio_refresh_token',
      );
      expect(deleteCookie).toHaveBeenCalledWith(
        mockEvent,
        'clio_access_token_expires_at',
      );
      expect(deleteCookie).toHaveBeenCalledWith(
        mockEvent,
        'clio:firm_access_token',
      );
      expect(deleteCookie).toHaveBeenCalledWith(
        mockEvent,
        'clio:firm_refresh_token',
      );
      expect(deleteCookie).toHaveBeenCalledWith(
        mockEvent,
        'clio:firm_access_token_expires_at',
      );

      expect(deleteCookie).toHaveBeenCalledTimes(6);
      expect(sendRedirect).toHaveBeenCalledWith(mockEvent, '/login', 302);
    });

    it('deletes cookies and redirects (scoped input)', async () => {
      await handleOAuthLogout(
        [{ provider: 'clio', instanceKey: 'firm' }],
        { redirectTo: '/firm' },
        mockEvent,
      );

      expect(deleteCookie).toHaveBeenCalledWith(
        mockEvent,
        'clio:firm_access_token',
      );
      expect(sendRedirect).toHaveBeenCalledWith(mockEvent, '/firm', 302);
    });
  });

  describe('as a utility without redirect', () => {
    it('deletes cookies and returns response (scoped)', async () => {
      const result = await handleOAuthLogout(
        [{ provider: 'intuit', instanceKey: 'sandbox' }],
        {},
        mockEvent,
      );

      expect(deleteCookie).toHaveBeenCalledWith(
        mockEvent,
        'intuit:sandbox_access_token',
      );
      expect(result).toEqual({
        loggedOut: true,
        providers: [{ provider: 'intuit', instanceKey: 'sandbox' }],
      });
    });
  });

  describe('edge cases', () => {
    it('handles empty input array', async () => {
      const handler = handleOAuthLogout([]);
      const result = await handler(mockEvent);

      expect(deleteCookie).not.toHaveBeenCalled();
      expect(result).toEqual({
        loggedOut: true,
        providers: [],
      });
    });
  });
});
