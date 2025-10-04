import { describe, it, expect, vi, beforeEach } from 'vitest';
import { checkTokenStatus } from '../src';
import { createMockEvent } from './utils';
import { oAuthTokensAreValid } from '../src/utils';
import type { TokenValidationResult } from '../src/types';

vi.mock('../src/utils', async () => {
  const actual = await vi.importActual<typeof import('../src/utils')>(
    '../src/utils',
  );
  return {
    ...actual,
    oAuthTokensAreValid: vi.fn(),
  };
});

const mockTokensValid = vi.mocked(oAuthTokensAreValid);

describe('checkTokenStatus', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should return status for valid tokens', async () => {
    const event = createMockEvent();
    const now = Math.floor(Date.now() / 1000);
    const expiresAt = now + 3600; // 1 hour from now

    mockTokensValid.mockResolvedValue({
      status: 'valid',
      tokens: {
        access_token: 'token',
        refresh_token: 'refresh',
        expires_in: expiresAt,
        token_type: 'bearer',
        client_id: 'client-123',
      },
    } as TokenValidationResult<'clio'>);

    const status = await checkTokenStatus(event, 'clio');

    expect(status.isValid).toBe(true);
    expect(status.hasRefreshToken).toBe(true);
    expect(status.requiresRefresh).toBe(false);
    expect(status.provider).toBe('clio');
    expect(status.expiresIn).toBeGreaterThan(3500); // Approx 1 hour
    expect(status.expiresAt).toBeDefined();
  });

  it('should return status for expired tokens', async () => {
    const event = createMockEvent();
    const now = Math.floor(Date.now() / 1000);
    const expiresAt = now - 100; // Expired 100 seconds ago

    mockTokensValid.mockResolvedValue({
      status: 'expired',
      tokens: {
        access_token: 'token',
        refresh_token: 'refresh',
        expires_in: expiresAt,
        token_type: 'bearer',
        client_id: 'client-123',
      },
    } as TokenValidationResult<'clio'>);

    const status = await checkTokenStatus(event, 'clio');

    expect(status.isValid).toBe(false);
    expect(status.hasRefreshToken).toBe(true);
    expect(status.requiresRefresh).toBe(true);
    expect(status.provider).toBe('clio');
    expect(status.expiresIn).toBe(0);
  });

  it('should return status for missing tokens', async () => {
    const event = createMockEvent();

    mockTokensValid.mockResolvedValue(false);

    const status = await checkTokenStatus(event, 'clio');

    expect(status.isValid).toBe(false);
    expect(status.hasRefreshToken).toBe(false);
    expect(status.requiresRefresh).toBe(false);
    expect(status.provider).toBe('clio');
    expect(status.expiresIn).toBeUndefined();
    expect(status.expiresAt).toBeUndefined();
  });

  it('should include instanceKey when provided', async () => {
    const event = createMockEvent();
    const now = Math.floor(Date.now() / 1000);

    mockTokensValid.mockResolvedValue({
      status: 'valid',
      tokens: {
        access_token: 'token',
        refresh_token: 'refresh',
        expires_in: now + 3600,
        token_type: 'bearer',
        client_id: 'client-123',
      },
    } as TokenValidationResult<'clio'>);

    const status = await checkTokenStatus(event, 'clio', 'smithlaw');

    expect(status.instanceKey).toBe('smithlaw');
  });

  it('should not include instanceKey when not provided', async () => {
    const event = createMockEvent();

    mockTokensValid.mockResolvedValue(false);

    const status = await checkTokenStatus(event, 'clio');

    expect(status.instanceKey).toBeUndefined();
  });

  it('should handle tokens without refresh token', async () => {
    const event = createMockEvent();
    const now = Math.floor(Date.now() / 1000);

    mockTokensValid.mockResolvedValue({
      status: 'valid',
      tokens: {
        access_token: 'token',
        expires_in: now + 3600,
        token_type: 'bearer',
        client_id: 'client-123',
      },
    } as TokenValidationResult<'clio'>);

    const status = await checkTokenStatus(event, 'clio');

    expect(status.isValid).toBe(true);
    expect(status.hasRefreshToken).toBe(false);
  });

  it('should calculate correct expiresAt ISO string', async () => {
    const event = createMockEvent();
    const now = Math.floor(Date.now() / 1000);
    const expiresAt = now + 3600;

    mockTokensValid.mockResolvedValue({
      status: 'valid',
      tokens: {
        access_token: 'token',
        refresh_token: 'refresh',
        expires_in: expiresAt,
        token_type: 'bearer',
        client_id: 'client-123',
      },
    } as TokenValidationResult<'clio'>);

    const status = await checkTokenStatus(event, 'clio');

    expect(status.expiresAt).toBe(new Date(expiresAt * 1000).toISOString());
  });
});
