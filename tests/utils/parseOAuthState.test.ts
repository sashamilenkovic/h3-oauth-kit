import { describe, it, expect } from 'vitest';
import { parseOAuthState } from '../../src/utils';

// Helper to base64url encode a JSON object
function encodeState(obj: object): string {
  return Buffer.from(JSON.stringify(obj)).toString('base64url');
}

describe('parseOAuthState', () => {
  it('parses a valid state with csrf and providerKey', () => {
    const encoded = encodeState({ csrf: 'abc123', providerKey: 'clio' });
    const result = parseOAuthState(encoded);

    expect(result).toEqual({ csrf: 'abc123', providerKey: 'clio' });
  });

  it('throws if csrf is missing', () => {
    const encoded = encodeState({ providerKey: 'clio' });

    expect(() => parseOAuthState(encoded)).toThrowError(
      /Invalid or malformed OAuth state parameter/,
    );
  });

  it('throws if providerKey is missing', () => {
    const encoded = encodeState({ csrf: 'abc123' });

    expect(() => parseOAuthState(encoded)).toThrowError(
      /Invalid or malformed OAuth state parameter/,
    );
  });

  it('throws for invalid base64url string', () => {
    expect(() => parseOAuthState('not-a-valid-base64')).toThrowError(
      /Invalid or malformed OAuth state parameter/,
    );
  });

  it('throws if JSON is not an object', () => {
    const encoded = Buffer.from('"just-a-string"').toString('base64url');

    expect(() => parseOAuthState(encoded)).toThrowError(
      /Invalid or malformed OAuth state parameter/,
    );
  });

  it('throws if input is empty', () => {
    expect(() => parseOAuthState('')).toThrowError(
      /Invalid or malformed OAuth state parameter/,
    );
  });

  it('throws if input is base64url of undefined', () => {
    const encoded = Buffer.from('undefined').toString('base64url');

    expect(() => parseOAuthState(encoded)).toThrowError(
      /Invalid or malformed OAuth state parameter/,
    );
  });

  it('returns a properly typed object', () => {
    const encoded = encodeState({
      csrf: 'csrf-token',
      providerKey: 'intuit:smithlaw',
      returnTo: '/dashboard',
    });

    const result = parseOAuthState(encoded);
    expect(result.csrf).toBe('csrf-token');
    expect(result.providerKey).toBe('intuit:smithlaw');
    expect(result.returnTo).toBe('/dashboard');
  });
});
