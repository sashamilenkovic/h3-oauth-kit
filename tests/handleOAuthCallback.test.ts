import { describe, it, expect, vi, beforeEach } from 'vitest';
import { handleOAuthCallback } from '../src';
import { useOAuthRegistry } from '../src';
import { createMockEvent } from './utils';
import { getCookie, getQuery, sendRedirect } from 'h3';
import { ofetch } from 'ofetch';
import { encodeState } from './utils';

vi.mock('h3', async () => {
  const actual = await vi.importActual<typeof import('h3')>('h3');
  return {
    ...actual,
    getQuery: vi.fn(),
    sendRedirect: vi.fn(),
    setCookie: vi.fn(),
    getCookie: vi.fn(),
    deleteCookie: vi.fn(),
    createError: actual.createError,
  };
});

vi.mock('ofetch', () => ({
  ofetch: vi.fn(),
}));

// Add this new mock for setProviderCookies
vi.mock('../src/utils', async () => {
  const actual = await vi.importActual('../src/utils');
  return {
    ...actual,
    setProviderCookies: vi.fn(),
    clearNonPreservedCookies: vi.fn(),
  };
});

const mockGetQuery = getQuery as ReturnType<typeof vi.fn>;
const mockSendRedirect = sendRedirect as ReturnType<typeof vi.fn>;
const mockOfetch = ofetch as unknown as ReturnType<typeof vi.fn>;
const mockGetCookie = vi.mocked(getCookie);

// Import the mocked functions
const { setProviderCookies, clearNonPreservedCookies } = await import(
  '../src/utils'
);
const mockSetProviderCookies = vi.mocked(setProviderCookies);
const mockClearNonPreservedCookies = vi.mocked(clearNonPreservedCookies);

function mockOAuthStateCookie(providerKey: string, csrfValue: string) {
  mockGetCookie.mockImplementation((_, key) =>
    key === `oauth_csrf_${providerKey}` ? csrfValue : undefined,
  );
}

describe('handleOAuthCallback', () => {
  const { registerOAuthProvider } = useOAuthRegistry('a'.repeat(64));
  const config = {
    clientId: 'test-client-id',
    clientSecret: 'test-secret',
    tokenEndpoint: 'https://example.com/token',
    authorizeEndpoint: 'https://example.com/auth',
    redirectUri: 'https://example.com/callback',
    scopes: ['read', 'write'],
  };

  beforeEach(() => {
    vi.clearAllMocks();
    registerOAuthProvider('clio', config);

    // Set up default behavior for setProviderCookies mock
    mockSetProviderCookies.mockImplementation(async (_, tokens) => tokens);
  });

  it('returns tokens, state, and providerMetadata when redirect is false', async () => {
    const csrf = 'csrf123';
    const event = createMockEvent();
    const encodedState = encodeState({
      csrf,
      providerKey: 'clio',
      foo: 'bar',
    });

    mockGetQuery.mockReturnValue({
      code: 'auth-code',
      state: encodedState,
    });

    mockOfetch.mockResolvedValue({
      access_token: 'abc',
      refresh_token: 'def',
      expires_in: 3600,
      token_type: 'bearer',
      client_id: 'client-xyz',
    });

    mockOAuthStateCookie('clio', csrf);

    const result = await handleOAuthCallback(
      'clio',
      { redirect: false },
      event,
    );

    expect(result.tokens.access_token).toBe('abc');
    expect(result.state).toMatchObject({
      csrf,
      providerKey: 'clio',
      foo: 'bar',
    });
    expect(result.callbackQueryData).toBeDefined();
  });

  it('performs redirect when redirect is true', async () => {
    const csrf = 'csrf123';
    const event = createMockEvent();
    const encodedState = encodeState({
      csrf,
      providerKey: 'clio',
    });
    mockGetQuery.mockReturnValue({
      code: 'auth-code',
      state: encodedState,
    });

    mockOfetch.mockResolvedValue({
      access_token: 'abc',
      refresh_token: 'def',
      expires_in: 3600,
      token_type: 'bearer',
      client_id: 'client-xyz',
    });

    mockOAuthStateCookie('clio', csrf);

    await handleOAuthCallback('clio', { redirect: true }, event);

    expect(mockSendRedirect).toHaveBeenCalledWith(event, '/', 302);
  });

  it('throws error if code is missing', async () => {
    const event = createMockEvent();
    mockGetQuery.mockReturnValue({ state: 'abc' });

    await expect(
      handleOAuthCallback('clio', { redirect: false }, event),
    ).rejects.toMatchObject({
      statusCode: 400,
      statusMessage: 'Authorization code missing in callback URL',
    });
  });

  it('throws error if state is missing', async () => {
    const event = createMockEvent();
    mockGetQuery.mockReturnValue({ code: 'abc' });

    await expect(
      handleOAuthCallback('clio', { redirect: false }, event),
    ).rejects.toMatchObject({
      statusCode: 400,
      statusMessage: 'State missing in callback URL',
    });
  });

  it('returns an event handler when called without event', () => {
    const handler = handleOAuthCallback('clio');
    expect(typeof handler).toBe('function');
  });

  it('works for scoped provider', async () => {
    const csrf = 'scoped-csrf';
    const instanceKey = 'tenant-a';
    const providerKey = `azure:${instanceKey}`;
    const encodedState = encodeState({
      csrf,
      providerKey,
      instanceKey,
    });
    registerOAuthProvider('azure', instanceKey, {
      ...config,
      redirectUri: 'https://example.com/azure-callback',
      tenantId: 'tenant-id',
    });

    const event = createMockEvent();

    mockGetQuery.mockReturnValue({
      code: 'scoped-code',
      state: encodedState,
    });

    mockOAuthStateCookie('azure:tenant-a', csrf);

    mockOfetch.mockResolvedValue({
      access_token: 'scoped-token',
      refresh_token: 'scoped-refresh',
      expires_in: 3600,
      token_type: 'bearer',
      realm_id: 'abc',
    });

    const result = await handleOAuthCallback(
      'azure',
      { redirect: false },
      event,
    );

    expect(result.tokens.access_token).toBe('scoped-token');
    expect(result.state.instanceKey).toBe(instanceKey);
  });

  it('invokes onError and returns its result if defined', async () => {
    const csrf = 'csrf-fail';
    const event = createMockEvent();
    const encodedState = encodeState({
      csrf,
      providerKey: 'clio',
    });

    mockGetQuery.mockReturnValue({
      code: 'auth-code',
      state: encodedState,
    });

    // Simulate invalid/missing CSRF cookie to trigger failure
    mockGetCookie.mockImplementation(() => undefined);

    const onErrorMock = vi.fn().mockResolvedValue({ custom: 'error-response' });

    const result = await handleOAuthCallback(
      'clio',
      {
        redirect: false,
        onError: onErrorMock,
      },
      event,
    );

    expect(onErrorMock).toHaveBeenCalledWith(expect.anything(), event, 'clio');
    expect(result).toEqual({ custom: 'error-response' });
  });

  it('handles and transforms unknown errors through parseError', async () => {
    const csrf = 'csrf123';
    const event = createMockEvent();
    const encodedState = encodeState({
      csrf,
      providerKey: 'clio',
    });

    mockGetQuery.mockReturnValue({
      code: 'auth-code',
      state: encodedState,
    });

    mockOAuthStateCookie('clio', csrf);

    // Mock ofetch to throw a plain Error object during token exchange
    mockOfetch.mockRejectedValueOnce(new Error('Network error'));

    // Omit onError to ensure we hit the parseError path
    await expect(
      handleOAuthCallback('clio', { redirect: false }, event),
    ).rejects.toMatchObject({
      statusCode: 500,
      message: 'Network error',
    });
  });

  it('handles errors through parseError when onError returns undefined', async () => {
    const csrf = 'csrf123';
    const event = createMockEvent();
    const encodedState = encodeState({
      csrf,
      providerKey: 'clio',
    });

    mockGetQuery.mockReturnValue({
      code: 'auth-code',
      state: encodedState,
    });

    mockOAuthStateCookie('clio', csrf);

    // Mock ofetch to throw a plain Error object during token exchange
    mockOfetch.mockRejectedValueOnce(new Error('Network error'));

    // Provide onError that returns undefined to ensure we hit parseError
    const onErrorMock = vi.fn().mockResolvedValue(undefined);

    await expect(
      handleOAuthCallback(
        'clio',
        { redirect: false, onError: onErrorMock },
        event,
      ),
    ).rejects.toMatchObject({
      statusCode: 500,
      message: 'Network error',
    });

    expect(onErrorMock).toHaveBeenCalledWith(expect.any(Error), event, 'clio');
  });

  it('performs redirect when redirect is not explicitly false but event is provided', async () => {
    const csrf = 'csrf123';
    const event = createMockEvent();
    const encodedState = encodeState({
      csrf,
      providerKey: 'clio',
    });

    mockGetQuery.mockReturnValue({
      code: 'auth-code',
      state: encodedState,
    });

    mockOfetch.mockResolvedValue({
      access_token: 'abc',
      refresh_token: 'def',
      expires_in: 3600,
      token_type: 'bearer',
      client_id: 'client-xyz',
    });

    mockOAuthStateCookie('clio', csrf);

    // Call with event but without explicitly setting redirect to false
    // This should trigger the else branch in the conditional return logic
    await handleOAuthCallback('clio', { redirectTo: '/custom' }, event);

    expect(mockSendRedirect).toHaveBeenCalledWith(event, '/custom', 302);
  });

  it('performs redirect with default redirectTo when redirect is undefined and event is provided', async () => {
    const csrf = 'csrf123';
    const event = createMockEvent();
    const encodedState = encodeState({
      csrf,
      providerKey: 'clio',
    });

    mockGetQuery.mockReturnValue({
      code: 'auth-code',
      state: encodedState,
    });

    mockOfetch.mockResolvedValue({
      access_token: 'abc',
      refresh_token: 'def',
      expires_in: 3600,
      token_type: 'bearer',
      client_id: 'client-xyz',
    });

    mockOAuthStateCookie('clio', csrf);

    // Call with event but without any redirect options
    // This should trigger the else branch and use default redirectTo
    await handleOAuthCallback('clio', {}, event);

    expect(mockSendRedirect).toHaveBeenCalledWith(event, '/', 302);
  });

  it('handles non-H3Error through parseError path when no onError is provided', async () => {
    const csrf = 'csrf123';
    const event = createMockEvent();
    const encodedState = encodeState({
      csrf,
      providerKey: 'clio',
    });

    mockGetQuery.mockReturnValue({
      code: 'auth-code',
      state: encodedState,
    });

    mockOAuthStateCookie('clio', csrf);

    // Mock ofetch to throw a plain object (not an H3Error) during token exchange
    const plainError = { message: 'Plain error object', code: 'CUSTOM_ERROR' };
    mockOfetch.mockRejectedValueOnce(plainError);

    // No onError provided, so it should go through parseError and createError
    await expect(
      handleOAuthCallback('clio', { redirect: false }, event),
    ).rejects.toMatchObject({
      statusCode: 500,
      // The message should come from parseError extracting the message from plainError
      message: 'Plain error object',
    });
  });

  it('handles non-H3Error from setProviderCookies through parseError path', async () => {
    const csrf = 'csrf123';
    const event = createMockEvent();
    const encodedState = encodeState({
      csrf,
      providerKey: 'clio',
    });

    mockGetQuery.mockReturnValue({
      code: 'auth-code',
      state: encodedState,
    });

    mockOAuthStateCookie('clio', csrf);

    // Mock successful token exchange
    mockOfetch.mockResolvedValue({
      access_token: 'abc',
      refresh_token: 'def',
      expires_in: 3600,
      token_type: 'bearer',
      client_id: 'client-xyz',
    });

    // Mock setProviderCookies to throw a non-H3Error
    const cookieError = new TypeError('Cookie setting failed');
    mockSetProviderCookies.mockImplementation(() => {
      throw cookieError;
    });

    // No onError provided, so it should go through parseError and createError
    await expect(
      handleOAuthCallback('clio', { redirect: false }, event),
    ).rejects.toMatchObject({
      statusCode: 500,
      message: 'Cookie setting failed',
    });

    // Verify that setProviderCookies was called
    expect(mockSetProviderCookies).toHaveBeenCalled();
  });
});

describe('handleOAuthCallback as route handler', () => {
  const { registerOAuthProvider } = useOAuthRegistry('a'.repeat(64));
  const config = {
    clientId: 'test-client-id',
    clientSecret: 'test-secret',
    tokenEndpoint: 'https://example.com/token',
    authorizeEndpoint: 'https://example.com/auth',
    redirectUri: 'https://example.com/callback',
    scopes: ['read', 'write'],
  };

  beforeEach(() => {
    vi.clearAllMocks();
    registerOAuthProvider('clio', config);

    // Reset setProviderCookies mock to default behavior
    mockSetProviderCookies.mockImplementation(async (_, tokens) => tokens);
  });

  it('functions as a route handler and performs redirect (event initially undefined)', async () => {
    const routeHandler = handleOAuthCallback('clio', {
      redirectTo: '/custom-redirect',
    });

    const csrf = 'csrf-route-handler';
    const event = createMockEvent();
    const encodedState = encodeState({
      csrf,
      providerKey: 'clio',
    });

    mockGetQuery.mockReturnValue({
      code: 'auth-code-route',
      state: encodedState,
    });
    mockOfetch.mockResolvedValue({
      access_token: 'route-token',
      refresh_token: 'route-refresh',
      expires_in: 3600,
      token_type: 'bearer',
    });
    mockOAuthStateCookie('clio', csrf);

    await routeHandler(event);

    expect(mockSendRedirect).toHaveBeenCalledWith(
      event,
      '/custom-redirect',
      302,
    );
  });

  it('functions as a route handler and returns tokens when redirect is false (event initially undefined)', async () => {
    const routeHandler = handleOAuthCallback('clio', { redirect: false });

    const csrf = 'csrf-route-handler-no-redirect';
    const event = createMockEvent();
    const encodedState = encodeState({
      csrf,
      providerKey: 'clio',
      customData: 'testValue',
    });

    mockGetQuery.mockReturnValue({
      code: 'auth-code-route-no-redirect',
      state: encodedState,
    });
    const mockApiTokens = {
      access_token: 'route-access-token',
      refresh_token: 'route-refresh-token',
      expires_in: 3600,
      token_type: 'bearer',
      id_token: 'route-id-token', // Example additional field
    };
    mockOfetch.mockResolvedValue(mockApiTokens);
    mockOAuthStateCookie('clio', csrf);

    const result = await routeHandler(event);

    expect(result.tokens.access_token).toBe('route-access-token');
    expect(result.tokens.id_token).toBe('route-id-token');
    expect(result.state).toMatchObject({
      csrf,
      providerKey: 'clio',
      customData: 'testValue',
    });
    expect(result.callbackQueryData).toBeDefined();
    expect(mockSendRedirect).not.toHaveBeenCalled();
  });

  it('handles unknown errors via parseError when used as a route handler and onError is not defined', async () => {
    // Get the route handler by calling handleOAuthCallback without an event and no onError
    const routeHandler = handleOAuthCallback('clio', { redirect: false });

    const event = createMockEvent();
    const csrf = 'csrf-unknown-error-route';
    const encodedState = encodeState({
      csrf,
      providerKey: 'clio',
    });

    // Standard setup to allow the handler to proceed to the token exchange point
    mockGetQuery.mockReturnValue({
      code: 'auth-code-unknown-error',
      state: encodedState,
    });
    mockOAuthStateCookie('clio', csrf);

    // Mock ofetch to throw a plain Error object during token exchange
    const genericError = new Error(
      'Generic failure during token exchange in route handler',
    );
    mockOfetch.mockRejectedValueOnce(genericError);

    // Expect the routeHandler to catch the generic error, process it via parseError,
    // and then throw an H3Error created by createError.
    await expect(routeHandler(event)).rejects.toMatchObject({
      statusCode: 500, // Assuming parseError defaults to 500 for generic errors
      message: 'Generic failure during token exchange in route handler',
      // H3 createError wraps the original error in 'cause'
      // We can check if 'cause' exists and matches the original error if needed,
      // but statusCode and message are primary indicators here.
    });

    // Ensure sendRedirect was not called in this error path
    expect(mockSendRedirect).not.toHaveBeenCalled();
  });
});

describe('handleOAuthCallback - scoped provider integration', () => {
  const { registerOAuthProvider } = useOAuthRegistry('a'.repeat(64));
  const config = {
    clientId: 'test-client-id',
    clientSecret: 'test-secret',
    tokenEndpoint: 'https://example.com/token',
    authorizeEndpoint: 'https://example.com/auth',
    redirectUri: 'https://example.com/callback',
    scopes: ['read', 'write'],
    tenantId: 'test-tenant-id',
  };

  beforeEach(() => {
    vi.clearAllMocks();
    registerOAuthProvider('azure', 'smithlaw', config);

    // Reset setProviderCookies mock to default behavior
    mockSetProviderCookies.mockImplementation(async (_, tokens) => tokens);
  });

  it('correctly handles scoped provider state and sets cookies with proper instanceKey', async () => {
    const csrf = 'csrf-scoped-test';
    const event = createMockEvent();

    // Create state that includes instanceKey (as would be created by resolveState)
    const encodedState = encodeState({
      csrf,
      providerKey: 'azure:smithlaw',
      instanceKey: 'smithlaw',
    });

    mockGetQuery.mockReturnValue({
      code: 'auth-code-scoped',
      state: encodedState,
    });

    const mockTokens = {
      access_token: 'Bearer scoped-access-token',
      refresh_token: 'scoped-refresh-token',
      expires_in: 3600,
      token_type: 'Bearer',
      ext_expires_in: 7200,
    };

    mockOfetch.mockResolvedValue(mockTokens);
    mockOAuthStateCookie('azure:smithlaw', csrf);

    const result = await handleOAuthCallback(
      'azure',
      { redirect: false },
      event,
    );

    // Verify that setProviderCookies was called with the correct instanceKey
    expect(mockSetProviderCookies).toHaveBeenCalledWith(
      event,
      mockTokens,
      'azure',
      undefined,
      'smithlaw', // This should be the extracted instanceKey, not undefined
    );

    expect(result.tokens).toEqual(mockTokens);
    expect(result.state.instanceKey).toBe('smithlaw');
    expect(result.state.providerKey).toBe('azure:smithlaw');
  });

  it('correctly handles non-scoped provider state and sets cookies without instanceKey', async () => {
    // Register a non-scoped provider
    registerOAuthProvider('azure', config);

    const csrf = 'csrf-non-scoped-test';
    const event = createMockEvent();

    // Create state without instanceKey (as would be created by resolveState for non-scoped)
    const encodedState = encodeState({
      csrf,
      providerKey: 'azure',
    });

    mockGetQuery.mockReturnValue({
      code: 'auth-code-non-scoped',
      state: encodedState,
    });

    const mockTokens = {
      access_token: 'Bearer non-scoped-access-token',
      refresh_token: 'non-scoped-refresh-token',
      expires_in: 3600,
      token_type: 'Bearer',
      ext_expires_in: 7200,
    };

    mockOfetch.mockResolvedValue(mockTokens);
    mockOAuthStateCookie('azure', csrf);

    const result = await handleOAuthCallback(
      'azure',
      { redirect: false },
      event,
    );

    // Verify that setProviderCookies was called without instanceKey
    expect(mockSetProviderCookies).toHaveBeenCalledWith(
      event,
      mockTokens,
      'azure',
      undefined,
      undefined, // instanceKey should be undefined for non-scoped providers
    );

    expect(result.tokens).toEqual(mockTokens);
    expect(result.state.instanceKey).toBeUndefined();
    expect(result.state.providerKey).toBe('azure');
  });

  it('correctly extracts instanceKey from providerKey even when state is missing instanceKey field', async () => {
    const csrf = 'csrf-malformed-state';
    const event = createMockEvent();

    // Create state that has scoped providerKey but missing instanceKey field
    // The instanceKey should be extracted from the providerKey itself
    const encodedState = encodeState({
      csrf,
      providerKey: 'azure:smithlaw',
      // instanceKey is missing from state - but should be extracted from providerKey
    });

    mockGetQuery.mockReturnValue({
      code: 'auth-code-malformed',
      state: encodedState,
    });

    const mockTokens = {
      access_token: 'Bearer malformed-access-token',
      refresh_token: 'malformed-refresh-token',
      expires_in: 3600,
      token_type: 'Bearer',
      ext_expires_in: 7200,
    };

    mockOfetch.mockResolvedValue(mockTokens);
    mockOAuthStateCookie('azure:smithlaw', csrf);

    const result = await handleOAuthCallback(
      'azure',
      { redirect: false },
      event,
    );

    // setProviderCookies should be called with instanceKey extracted from providerKey
    // The instanceKey in state is redundant - providerKey is the authoritative source
    expect(mockSetProviderCookies).toHaveBeenCalledWith(
      event,
      mockTokens,
      'azure',
      undefined,
      'smithlaw', // instanceKey should be extracted from providerKey 'azure:smithlaw'
    );

    expect(result.tokens).toEqual(mockTokens);
    expect(result.state.instanceKey).toBeUndefined(); // state doesn't have instanceKey
    expect(result.state.providerKey).toBe('azure:smithlaw');
  });
});

describe('handleOAuthCallback - preserveInstance behavior', () => {
  const { registerOAuthProvider } = useOAuthRegistry('a'.repeat(64));
  const config = {
    clientId: 'test-client-id',
    clientSecret: 'test-secret',
    tokenEndpoint: 'https://example.com/token',
    authorizeEndpoint: 'https://example.com/auth',
    redirectUri: 'https://example.com/callback',
    scopes: ['read', 'write'],
  };

  beforeEach(() => {
    vi.clearAllMocks();
    registerOAuthProvider('clio', config);
    registerOAuthProvider('clio', 'smithlaw', config); // Register scoped provider

    // Reset mocked functions to default behavior
    mockSetProviderCookies.mockImplementation(async (_, tokens) => tokens);
    mockClearNonPreservedCookies.mockImplementation(() => {});
  });

  it('clears non-preserved cookies when preserveInstance is false (default behavior)', async () => {
    const csrf = 'csrf-no-preserve';
    const event = createMockEvent();

    // Create state with normal providerKey (no :preserve suffix)
    const encodedState = encodeState({
      csrf,
      providerKey: 'clio:smithlaw', // Normal scoped provider key
    });

    mockGetQuery.mockReturnValue({
      code: 'auth-code-no-preserve',
      state: encodedState,
    });

    const mockTokens = {
      access_token: 'no-preserve-access-token',
      refresh_token: 'no-preserve-refresh-token',
      expires_in: 3600,
      token_type: 'bearer',
      client_id: 'client-xyz',
    };

    mockOfetch.mockResolvedValue(mockTokens);
    mockOAuthStateCookie('clio:smithlaw', csrf);

    await handleOAuthCallback('clio', { redirect: false }, event);

    // Should clear non-preserved cookies since preserveInstance is false
    expect(mockClearNonPreservedCookies).toHaveBeenCalledWith(event, 'clio');
  });

  it('preserves existing cookies when preserveInstance is true', async () => {
    const csrf = 'csrf-preserve';
    const event = createMockEvent();

    // Create state with :preserve suffix in providerKey
    const encodedState = encodeState({
      csrf,
      providerKey: 'clio:smithlaw:preserve', // Provider key with preserve flag
    });

    mockGetQuery.mockReturnValue({
      code: 'auth-code-preserve',
      state: encodedState,
    });

    const mockTokens = {
      access_token: 'preserve-access-token',
      refresh_token: 'preserve-refresh-token',
      expires_in: 3600,
      token_type: 'bearer',
      client_id: 'client-xyz',
    };

    mockOfetch.mockResolvedValue(mockTokens);
    mockOAuthStateCookie('clio:smithlaw:preserve', csrf);

    await handleOAuthCallback('clio', { redirect: false }, event);

    // Should NOT clear non-preserved cookies since preserveInstance is true
    expect(mockClearNonPreservedCookies).not.toHaveBeenCalled();
  });

  it('preserves existing cookies for global provider with preserve flag', async () => {
    const csrf = 'csrf-global-preserve';
    const event = createMockEvent();

    // Create state with :preserve suffix for global provider
    const encodedState = encodeState({
      csrf,
      providerKey: 'clio:preserve', // Global provider with preserve flag
    });

    mockGetQuery.mockReturnValue({
      code: 'auth-code-global-preserve',
      state: encodedState,
    });

    const mockTokens = {
      access_token: 'global-preserve-access-token',
      refresh_token: 'global-preserve-refresh-token',
      expires_in: 3600,
      token_type: 'bearer',
      client_id: 'client-xyz',
    };

    mockOfetch.mockResolvedValue(mockTokens);
    mockOAuthStateCookie('clio:preserve', csrf);

    await handleOAuthCallback('clio', { redirect: false }, event);

    // Should NOT clear non-preserved cookies since preserveInstance is true
    expect(mockClearNonPreservedCookies).not.toHaveBeenCalled();
  });
});
