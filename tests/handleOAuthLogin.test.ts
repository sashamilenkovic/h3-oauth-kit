import { describe, it, expect, vi, beforeEach } from 'vitest';
import { handleOAuthLogin } from '../src';
import { useOAuthRegistry } from '../src';
import { createMockEvent } from './utils';

import * as utils from '../src/utils';
import { sendRedirect } from 'h3';

vi.mock('h3', async () => {
  const actual = await vi.importActual<typeof import('h3')>('h3');
  return {
    ...actual,
    sendRedirect: vi.fn(),
  };
});

const mockedSendRedirect = sendRedirect as unknown as ReturnType<typeof vi.fn>;

const clioConfig = {
  clientId: 'abc',
  clientSecret: 'secret',
  tokenEndpoint: 'https://example.com/token',
  authorizeEndpoint: 'https://example.com/authorize',
  redirectUri: 'https://myapp.com/callback',
  scopes: ['read', 'write'],
};

describe('handleOAuthLogin', () => {
  const { registerOAuthProvider } = useOAuthRegistry('a'.repeat(64));
  beforeEach(() => {
    vi.resetAllMocks();
    vi.spyOn(utils, 'resolveState').mockReturnValue('mocked-state');
    vi.spyOn(utils, 'buildAuthUrl').mockReturnValue(
      'https://example.com/auth?client_id=abc',
    );
  });

  it('returns URL for manual login flow', async () => {
    registerOAuthProvider('clio', clioConfig);

    const event = createMockEvent();
    const result = await handleOAuthLogin('clio', { redirect: false }, event);

    expect(result).toEqual({ url: 'https://example.com/auth?client_id=abc' });
    expect(utils.resolveState).toHaveBeenCalledWith(event, 'clio', undefined);
    expect(utils.buildAuthUrl).toHaveBeenCalled();
  });

  it('performs redirect when redirect is true', async () => {
    registerOAuthProvider('clio', clioConfig);

    const event = createMockEvent();
    await handleOAuthLogin('clio', { redirect: true }, event);

    expect(mockedSendRedirect).toHaveBeenCalledWith(
      event,
      'https://example.com/auth?client_id=abc',
      302,
    );
  });

  it('returns EventHandler when no event provided', () => {
    registerOAuthProvider('clio', clioConfig);
    const handler = handleOAuthLogin('clio');
    expect(typeof handler).toBe('function');
  });

  it('includes custom string state in URL', async () => {
    registerOAuthProvider('clio', clioConfig);

    const event = createMockEvent();
    vi.spyOn(utils, 'resolveState').mockReturnValue('custom-string');

    const result = await handleOAuthLogin(
      'clio',
      { redirect: false, state: { customValue: 'custom-string' } },
      event,
    );
    expect(result.url).toContain('client_id=abc');
    expect(utils.resolveState).toHaveBeenCalledWith(event, 'clio', {
      customValue: 'custom-string',
    });
  });

  it('includes custom object state in URL', async () => {
    registerOAuthProvider('clio', clioConfig);

    const event = createMockEvent();
    vi.spyOn(utils, 'resolveState').mockReturnValue(
      JSON.stringify({ from: '/dashboard' }),
    );

    const result = await handleOAuthLogin(
      'clio',
      { redirect: false, state: { from: '/dashboard' } },
      event,
    );
    expect(utils.resolveState).toHaveBeenCalledWith(event, 'clio', {
      from: '/dashboard',
    });
    expect(result.url).toContain('client_id=abc');
  });

  it('throws if provider is not registered', async () => {
    const event = createMockEvent();
    await expect(() =>
      handleOAuthLogin('intuit', { redirect: false }, event),
    ).rejects.toThrow('OAuth provider "intuit" is not registered');
  });

  it('uses default empty options when no options provided', async () => {
    registerOAuthProvider('clio', clioConfig);

    const event = createMockEvent();
    // Call with provider, undefined (for instanceKey/options), and event
    // This should trigger the `?? {}` fallback on line 223
    const result = await (handleOAuthLogin as any)('clio', undefined, event);

    expect(result).toEqual({ url: 'https://example.com/auth?client_id=abc' });
    expect(utils.resolveState).toHaveBeenCalledWith(event, 'clio', undefined);
    expect(utils.buildAuthUrl).toHaveBeenCalled();
  });

  it('handles scoped provider with instanceKey (isScoped = true)', async () => {
    // Register a scoped provider
    registerOAuthProvider('clio', 'smithlaw', clioConfig);

    const event = createMockEvent();
    vi.spyOn(utils, 'getProviderKey').mockReturnValue('clio:smithlaw');

    const result = await handleOAuthLogin(
      'clio',
      'smithlaw',
      { redirect: false, state: { from: '/dashboard' } },
      event,
    );

    expect(result).toEqual({ url: 'https://example.com/auth?client_id=abc' });
    expect(utils.resolveState).toHaveBeenCalledWith(event, 'clio:smithlaw', {
      from: '/dashboard',
    });
    expect(utils.buildAuthUrl).toHaveBeenCalled();
  });

  it('handles scoped provider with redirect = true', async () => {
    // Register a scoped provider
    registerOAuthProvider('clio', 'smithlaw', clioConfig);

    const event = createMockEvent();
    vi.spyOn(utils, 'getProviderKey').mockReturnValue('clio:smithlaw');

    await handleOAuthLogin('clio', 'smithlaw', { redirect: true }, event);

    expect(mockedSendRedirect).toHaveBeenCalledWith(
      event,
      'https://example.com/auth?client_id=abc',
      302,
    );
    expect(utils.resolveState).toHaveBeenCalledWith(
      event,
      'clio:smithlaw',
      undefined,
    );
  });
});

describe('handleOAuthLogin - preserveInstance behavior', () => {
  const { registerOAuthProvider } = useOAuthRegistry('a'.repeat(64));
  beforeEach(() => {
    vi.resetAllMocks();
    vi.spyOn(utils, 'resolveState').mockReturnValue('mocked-state');
    vi.spyOn(utils, 'buildAuthUrl').mockReturnValue(
      'https://example.com/auth?client_id=abc',
    );
    registerOAuthProvider('clio', clioConfig);
    registerOAuthProvider('clio', 'smithlaw', clioConfig);
  });

  it('generates normal provider key when preserveInstance is false (default)', async () => {
    const event = createMockEvent();
    const getProviderKeySpy = vi.spyOn(utils, 'getProviderKey');

    await handleOAuthLogin(
      'clio',
      'smithlaw',
      { redirect: false, preserveInstance: false },
      event,
    );

    // Should call getProviderKey with preserveInstance: false
    expect(getProviderKeySpy).toHaveBeenCalledWith('clio', 'smithlaw', false);
  });

  it('generates preserve provider key when preserveInstance is true', async () => {
    const event = createMockEvent();
    const getProviderKeySpy = vi.spyOn(utils, 'getProviderKey');

    await handleOAuthLogin(
      'clio',
      'smithlaw',
      { redirect: false, preserveInstance: true },
      event,
    );

    // Should call getProviderKey with preserveInstance: true
    expect(getProviderKeySpy).toHaveBeenCalledWith('clio', 'smithlaw', true);
  });

  it('generates preserve provider key for global provider when preserveInstance is true', async () => {
    const event = createMockEvent();
    const getProviderKeySpy = vi.spyOn(utils, 'getProviderKey');

    await handleOAuthLogin(
      'clio',
      { redirect: false, preserveInstance: true },
      event,
    );

    // Should call getProviderKey with preserveInstance: true and no instanceKey
    expect(getProviderKeySpy).toHaveBeenCalledWith('clio', undefined, true);
  });

  it('passes preserve provider key to resolveState', async () => {
    const event = createMockEvent();
    const getProviderKeySpy = vi.spyOn(utils, 'getProviderKey');

    await handleOAuthLogin(
      'clio',
      'smithlaw',
      {
        redirect: false,
        preserveInstance: true,
        state: { from: '/dashboard' },
      },
      event,
    );

    // Should call getProviderKey with preserveInstance: true
    expect(getProviderKeySpy).toHaveBeenCalledWith('clio', 'smithlaw', true);

    // Should pass the preserve provider key to resolveState
    // We can't easily test the exact key without complex mocking, but we can verify the call was made
    expect(utils.resolveState).toHaveBeenCalledWith(
      event,
      expect.stringContaining('clio'),
      { from: '/dashboard' },
    );
  });

  it('works with redirect: true and preserveInstance: true', async () => {
    const event = createMockEvent();
    const getProviderKeySpy = vi.spyOn(utils, 'getProviderKey');

    await handleOAuthLogin(
      'clio',
      { redirect: true, preserveInstance: true },
      event,
    );

    // Should call getProviderKey with preserveInstance: true
    expect(getProviderKeySpy).toHaveBeenCalledWith('clio', undefined, true);

    // Should redirect and pass preserve key to resolveState
    expect(mockedSendRedirect).toHaveBeenCalledWith(
      event,
      'https://example.com/auth?client_id=abc',
      302,
    );
    expect(utils.resolveState).toHaveBeenCalledWith(
      event,
      expect.stringContaining('clio'),
      undefined,
    );
  });

  it('defaults to preserveInstance: false when not specified', async () => {
    const event = createMockEvent();
    const getProviderKeySpy = vi.spyOn(utils, 'getProviderKey');

    await handleOAuthLogin(
      'clio',
      'smithlaw',
      { redirect: false }, // preserveInstance not specified
      event,
    );

    // Should call getProviderKey with preserveInstance: undefined (falsy)
    expect(getProviderKeySpy).toHaveBeenCalledWith(
      'clio',
      'smithlaw',
      undefined,
    );
  });
});
