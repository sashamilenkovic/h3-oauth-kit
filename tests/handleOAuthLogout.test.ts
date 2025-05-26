import type { H3Event } from 'h3';

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { handleOAuthLogout } from '../src';
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
  });

  describe('as a route handler', () => {
    it('deletes cookies for string-based providers', async () => {
      const handler = handleOAuthLogout(['clio', 'azure']);
      const result = await handler(mockEvent);

      expect(deleteCookie).toHaveBeenCalledTimes(7); // 3 for clio + 4 for azure
      expect(result).toEqual({
        loggedOut: true,
        providers: [{ provider: 'clio' }, { provider: 'azure' }],
      });
    });

    it('deletes cookies for object-based providers', async () => {
      const handler = handleOAuthLogout([
        { provider: 'clio' },
        { provider: 'azure', instanceKey: 'dev' },
      ]);
      const result = await handler(mockEvent);

      expect(deleteCookie).toHaveBeenCalledWith(mockEvent, 'clio_access_token');
      expect(deleteCookie).toHaveBeenCalledWith(
        mockEvent,
        'azure:dev_access_token',
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
      await handleOAuthLogout(['clio'], { redirectTo: '/login' }, mockEvent);

      expect(deleteCookie).toHaveBeenCalledTimes(3);
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
