import { describe, it, expect, beforeEach, vi } from 'vitest';
import { handleOAuthLogin, useOAuthRegistry } from '../src';
import { createMockEvent } from './utils';
import { setCookie } from 'h3';

vi.mock('h3', async () => {
  const actual = await vi.importActual<typeof import('h3')>('h3');
  return {
    ...actual,
    setCookie: vi.fn(),
    sendRedirect: vi.fn(),
  };
});

vi.mock('../src/utils', async () => {
  const actual = await vi.importActual('../src/utils');
  return {
    ...actual,
    resolveState: vi.fn(() => 'mocked-state'),
  };
});

// Mock PKCE functions
vi.mock('../src/utils/pkce', () => ({
  generateCodeVerifier: vi.fn(() => 'test-verifier'),
  generateCodeChallenge: vi.fn(() => Promise.resolve('test-challenge')),
  base64UrlEncode: vi.fn((input) => Buffer.from(input).toString('base64url')),
}));

const mockSetCookie = vi.mocked(setCookie);
import { generateCodeVerifier, generateCodeChallenge } from '../src/utils/pkce';
const mockGenerateCodeVerifier = vi.mocked(generateCodeVerifier);
const mockGenerateCodeChallenge = vi.mocked(generateCodeChallenge);

describe('handleOAuthLogin with PKCE', () => {
  const { registerOAuthProvider } = useOAuthRegistry('a'.repeat(64));

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should generate and store PKCE parameters when usePKCE is enabled', async () => {
    registerOAuthProvider('azure', {
      clientId: 'test-client-id',
      clientSecret: 'test-client-secret',
      redirectUri: 'http://localhost:3000/callback',
      authorizeEndpoint: 'https://provider.com/authorize',
      tokenEndpoint: 'https://provider.com/token',
      scopes: ['openid', 'profile'],
      usePKCE: true,
    });

    const mockEvent = createMockEvent();
    await handleOAuthLogin('azure', {}, mockEvent);

    // Should have called PKCE functions
    expect(mockGenerateCodeVerifier).toHaveBeenCalledTimes(1);
    expect(mockGenerateCodeChallenge).toHaveBeenCalledWith('test-verifier');

    // Should have set PKCE cookie
    expect(mockSetCookie).toHaveBeenCalledWith(
      mockEvent,
      'oauth_pkce_azure',
      'test-verifier',
      expect.objectContaining({
        httpOnly: true,
        secure: true,
        sameSite: 'lax',
        maxAge: 300,
      }),
    );
  });

  it('should NOT generate PKCE parameters when usePKCE is not set', async () => {
    registerOAuthProvider('clio', {
      clientId: 'test-client-id',
      clientSecret: 'test-client-secret',
      redirectUri: 'http://localhost:3000/callback',
      authorizeEndpoint: 'https://provider.com/authorize',
      tokenEndpoint: 'https://provider.com/token',
      scopes: ['openid'],
      // usePKCE not set (defaults to false/undefined)
    });

    const mockEvent = createMockEvent();
    await handleOAuthLogin('clio', {}, mockEvent);

    // Should NOT call PKCE functions
    expect(mockGenerateCodeVerifier).not.toHaveBeenCalled();
    expect(mockGenerateCodeChallenge).not.toHaveBeenCalled();
  });

  it('should include instance key in PKCE cookie for scoped providers', async () => {
    registerOAuthProvider('azure', 'tenant-a', {
      clientId: 'test-client-id',
      clientSecret: 'test-client-secret',
      redirectUri: 'http://localhost:3000/callback',
      authorizeEndpoint: 'https://provider.com/authorize',
      tokenEndpoint: 'https://provider.com/token',
      scopes: ['openid'],
      usePKCE: true,
    });

    const mockEvent = createMockEvent();
    await handleOAuthLogin('azure', 'tenant-a', {}, mockEvent);

    // PKCE cookie should include the instance key
    expect(mockSetCookie).toHaveBeenCalledWith(
      mockEvent,
      'oauth_pkce_azure:tenant-a',
      'test-verifier',
      expect.any(Object),
    );
  });
});
