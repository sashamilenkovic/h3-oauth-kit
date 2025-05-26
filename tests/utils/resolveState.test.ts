import { describe, it, expect, vi, beforeEach } from 'vitest';
import { resolveState } from '../../src/utils';
import { createMockEvent } from '../utils';
import { setCookie } from 'h3';

// Mock `setCookie` from `h3`
vi.mock('h3', async () => {
  const actual = await vi.importActual<typeof import('h3')>('h3');
  return {
    ...actual,
    setCookie: vi.fn(),
  };
});

const mockedSetCookie = setCookie as unknown as ReturnType<typeof vi.fn>;

describe('resolveState', () => {
  const providerKey = 'clio';

  beforeEach(() => {
    mockedSetCookie.mockReset();
  });

  it('encodes a CSRF-protected base64url JSON object when no user state is provided', () => {
    const event = createMockEvent();

    const encoded = resolveState(event, providerKey);

    const decoded = JSON.parse(
      Buffer.from(decodeURIComponent(encoded), 'base64url').toString(),
    );

    expect(decoded).toMatchObject({
      csrf: expect.any(String),
      providerKey: 'clio',
    });

    expect(decoded.csrf).toHaveLength(36); // UUID v4

    expect(mockedSetCookie).toHaveBeenCalledWith(
      event,
      'oauth_csrf_clio',
      decoded.csrf,
      expect.objectContaining({
        httpOnly: true,
        sameSite: 'lax',
        secure: true,
        path: '/',
        maxAge: 300,
      }),
    );
  });

  it('includes custom static state in encoded payload', () => {
    const event = createMockEvent();

    const encoded = resolveState(event, providerKey, {
      returnTo: '/dashboard',
    });

    const decoded = JSON.parse(
      Buffer.from(decodeURIComponent(encoded), 'base64url').toString(),
    );

    expect(decoded).toMatchObject({
      csrf: expect.any(String),
      providerKey: 'clio',
      returnTo: '/dashboard',
    });
  });

  it('resolves userState when passed a function', () => {
    const event = createMockEvent();

    const encoded = resolveState(event, providerKey, () => ({
      from: '/settings',
    }));

    const decoded = JSON.parse(
      Buffer.from(decodeURIComponent(encoded), 'base64url').toString(),
    );

    expect(decoded).toMatchObject({
      csrf: expect.any(String),
      providerKey: 'clio',
      from: '/settings',
    });
  });

  it('throws if state is not an object or function', () => {
    const event = createMockEvent();

    expect(() => resolveState(event, providerKey, 'not-valid' as any)).toThrow(
      /must be a plain object/,
    );
  });

  it('throws if state resolves to an array', () => {
    const event = createMockEvent();

    expect(() =>
      resolveState(event, providerKey, () => ['bad'] as any),
    ).toThrow(/must be a plain object/);
  });

  it('throws if state resolves to null', () => {
    const event = createMockEvent();

    expect(() => resolveState(event, providerKey, () => null as any)).toThrow(
      /must be a plain object/,
    );
  });

  describe('scoped provider keys', () => {
    it('extracts and stores instanceKey separately when providerKey is scoped', () => {
      const event = createMockEvent();
      const scopedProviderKey = 'azure:smithlaw';

      const encoded = resolveState(event, scopedProviderKey);

      const decoded = JSON.parse(
        Buffer.from(decodeURIComponent(encoded), 'base64url').toString(),
      );

      expect(decoded).toMatchObject({
        csrf: expect.any(String),
        providerKey: 'azure:smithlaw',
        instanceKey: 'smithlaw',
      });

      expect(mockedSetCookie).toHaveBeenCalledWith(
        event,
        'oauth_csrf_azure:smithlaw',
        decoded.csrf,
        expect.objectContaining({
          httpOnly: true,
          sameSite: 'lax',
          secure: true,
          path: '/',
          maxAge: 300,
        }),
      );
    });

    it('does not include instanceKey when providerKey is not scoped', () => {
      const event = createMockEvent();
      const unscopedProviderKey = 'azure';

      const encoded = resolveState(event, unscopedProviderKey);

      const decoded = JSON.parse(
        Buffer.from(decodeURIComponent(encoded), 'base64url').toString(),
      );

      expect(decoded).toMatchObject({
        csrf: expect.any(String),
        providerKey: 'azure',
      });

      expect(decoded).not.toHaveProperty('instanceKey');

      expect(mockedSetCookie).toHaveBeenCalledWith(
        event,
        'oauth_csrf_azure',
        decoded.csrf,
        expect.objectContaining({
          httpOnly: true,
          sameSite: 'lax',
          secure: true,
          path: '/',
          maxAge: 300,
        }),
      );
    });

    it('includes custom state along with extracted instanceKey', () => {
      const event = createMockEvent();
      const scopedProviderKey = 'clio:lawfirm123';

      const encoded = resolveState(event, scopedProviderKey, {
        returnTo: '/dashboard',
        customData: 'test',
      });

      const decoded = JSON.parse(
        Buffer.from(decodeURIComponent(encoded), 'base64url').toString(),
      );

      expect(decoded).toMatchObject({
        csrf: expect.any(String),
        providerKey: 'clio:lawfirm123',
        instanceKey: 'lawfirm123',
        returnTo: '/dashboard',
        customData: 'test',
      });
    });

    it('handles complex instanceKey values', () => {
      const event = createMockEvent();
      const complexProviderKey = 'intuit:tenant-123-abc';

      const encoded = resolveState(event, complexProviderKey);

      const decoded = JSON.parse(
        Buffer.from(decodeURIComponent(encoded), 'base64url').toString(),
      );

      expect(decoded).toMatchObject({
        csrf: expect.any(String),
        providerKey: 'intuit:tenant-123-abc',
        instanceKey: 'tenant-123-abc',
      });
    });
  });
});
