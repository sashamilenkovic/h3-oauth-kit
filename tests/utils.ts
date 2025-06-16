import type { H3Event } from 'h3';
import { IncomingMessage, ServerResponse } from 'node:http';
import { createEvent } from 'h3';
import { getOAuthProviderConfig, type OAuthProvider } from '../src';

/**
 * Creates a mock H3Event for unit testing.
 * Supports cookies and query parameters.
 *
 * @param options.cookieHeader - Raw cookie string (e.g., "foo=bar; baz=qux")
 * @param options.query - Key-value object to generate query string (?key=value)
 */
export function createMockEvent(options?: {
  cookieHeader?: string;
  query?: Record<string, string>;
}): H3Event {
  const { cookieHeader, query } = options ?? {};

  const req = new IncomingMessage(null as any);
  req.method = 'GET';

  const queryString = query ? '?' + new URLSearchParams(query).toString() : '';

  req.url = '/' + queryString;

  req.headers = {
    ...(cookieHeader ? { cookie: cookieHeader } : {}),
  };

  const res = new ServerResponse(req);
  return createEvent(req, res);
}

/**
 * Test helper: Encrypts the provider's refresh token while preserving type structure.
 */
export async function withEncryptedRefreshToken<
  P extends string,
  T extends Record<string, any>, // ⬅️ changed from string to any
>(provider: P, tokens: T): Promise<T> {
  const config = getOAuthProviderConfig(provider as OAuthProvider);

  const key = `${provider}_refresh_token` as keyof T;
  return {
    ...tokens,
    [key]: await config.encrypt(tokens[key] as string),
  };
}

export function encodeState(state: object): string {
  return encodeURIComponent(
    Buffer.from(JSON.stringify(state)).toString('base64url'),
  );
}
