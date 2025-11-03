import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  initiateDeviceFlow,
  pollForDeviceToken,
  authenticateDevice,
} from '../src/deviceFlow';
import { useOAuthRegistry } from '../src/index';
import type {
  DeviceAuthorizationResponse,
  DeviceTokenResponse,
} from '../src/types';
import { ofetch } from 'ofetch';

// Mock ofetch
vi.mock('ofetch', () => ({
  ofetch: vi.fn(),
}));

describe('Device Authorization Flow (RFC 8628)', () => {
  const mockEncryptionKey = 'a'.repeat(64);
  let registerOAuthProvider: ReturnType<
    typeof useOAuthRegistry
  >['registerOAuthProvider'];

  beforeEach(() => {
    vi.clearAllMocks();
    const registry = useOAuthRegistry(mockEncryptionKey);
    registerOAuthProvider = registry.registerOAuthProvider;
  });

  describe('initiateDeviceFlow', () => {
    it('should initiate device flow successfully', async () => {
      registerOAuthProvider('azure', {
        clientId: 'test-client-id',
        clientSecret: 'test-client-secret',
        redirectUri: 'http://localhost:3000/callback',
        authorizeEndpoint: 'https://provider.com/authorize',
        tokenEndpoint: 'https://provider.com/token',
        deviceAuthorizationEndpoint: 'https://provider.com/device',
        scopes: ['openid', 'profile'],
      });

      const mockResponse: DeviceAuthorizationResponse = {
        device_code: 'DEVICE-CODE-123',
        user_code: 'ABCD-EFGH',
        verification_uri: 'https://provider.com/activate',
        verification_uri_complete: 'https://provider.com/activate?code=ABCD-EFGH',
        expires_in: 900,
        interval: 5,
      };

      vi.mocked(ofetch).mockResolvedValue(mockResponse);

      const result = await initiateDeviceFlow('azure');

      expect(result).toEqual(mockResponse);
      expect(result.user_code).toBe('ABCD-EFGH');
      expect(vi.mocked(ofetch)).toHaveBeenCalledWith(
        'https://provider.com/device',
        expect.objectContaining({
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            Accept: 'application/json',
          },
        }),
      );

      // Check body params
      const callArgs = vi.mocked(ofetch).mock.calls[0][1];
      const bodyParams = callArgs?.body as URLSearchParams;
      expect(bodyParams.get('client_id')).toBe('test-client-id');
      expect(bodyParams.get('scope')).toBe('openid profile');
    });

    it('should use custom scopes when provided', async () => {
      registerOAuthProvider('azure', {
        clientId: 'test-client-id',
        clientSecret: 'test-client-secret',
        redirectUri: 'http://localhost:3000/callback',
        authorizeEndpoint: 'https://provider.com/authorize',
        tokenEndpoint: 'https://provider.com/token',
        deviceAuthorizationEndpoint: 'https://provider.com/device',
        scopes: ['openid'],
      });

      const mockResponse: DeviceAuthorizationResponse = {
        device_code: 'DEVICE-CODE-123',
        user_code: 'ABCD-EFGH',
        verification_uri: 'https://provider.com/activate',
        expires_in: 900,
      };

      vi.mocked(ofetch).mockResolvedValue(mockResponse);

      await initiateDeviceFlow('azure', {
        scopes: ['User.Read', 'Mail.Send'],
      });

      const callArgs = vi.mocked(ofetch).mock.calls[0][1];
      const bodyParams = callArgs?.body as URLSearchParams;
      expect(bodyParams.get('scope')).toBe('User.Read Mail.Send');
    });

    it('should support multi-tenant with instanceKey', async () => {
      registerOAuthProvider('azure:tenant-a', {
        clientId: 'tenant-a-client-id',
        clientSecret: 'tenant-a-secret',
        redirectUri: 'http://localhost:3000/callback',
        authorizeEndpoint: 'https://provider.com/authorize',
        tokenEndpoint: 'https://provider.com/token',
        deviceAuthorizationEndpoint: 'https://provider.com/device',
        scopes: ['openid'],
      });

      const mockResponse: DeviceAuthorizationResponse = {
        device_code: 'DEVICE-CODE-123',
        user_code: 'ABCD-EFGH',
        verification_uri: 'https://provider.com/activate',
        expires_in: 900,
      };

      vi.mocked(ofetch).mockResolvedValue(mockResponse);

      await initiateDeviceFlow('azure', {
        instanceKey: 'tenant-a',
      });

      const callArgs = vi.mocked(ofetch).mock.calls[0][1];
      const bodyParams = callArgs?.body as URLSearchParams;
      expect(bodyParams.get('client_id')).toBe('tenant-a-client-id');
    });

    it('should throw error if provider is not registered', async () => {
      // Don't register any provider for this test
      await expect(
        initiateDeviceFlow('github' as any),
      ).rejects.toThrow('Provider "github" is not registered');
    });

    it('should throw error if provider has no device authorization endpoint', async () => {
      registerOAuthProvider('azure', {
        clientId: 'test-client-id',
        clientSecret: 'test-client-secret',
        redirectUri: 'http://localhost:3000/callback',
        authorizeEndpoint: 'https://provider.com/authorize',
        tokenEndpoint: 'https://provider.com/token',
        scopes: ['openid'],
        // No deviceAuthorizationEndpoint
      });

      await expect(
        initiateDeviceFlow('azure'),
      ).rejects.toThrow('does not have a device authorization endpoint configured');
    });

    it('should throw error on network failure', async () => {
      registerOAuthProvider('azure', {
        clientId: 'test-client-id',
        clientSecret: 'test-client-secret',
        redirectUri: 'http://localhost:3000/callback',
        authorizeEndpoint: 'https://provider.com/authorize',
        tokenEndpoint: 'https://provider.com/token',
        deviceAuthorizationEndpoint: 'https://provider.com/device',
        scopes: ['openid'],
      });

      vi.mocked(ofetch).mockRejectedValue(
        new Error('Network error'),
      );

      await expect(
        initiateDeviceFlow('azure'),
      ).rejects.toThrow('Failed to initiate device flow');
    });
  });

  describe('pollForDeviceToken', () => {
    it('should successfully get token on first attempt', async () => {
      registerOAuthProvider('azure', {
        clientId: 'test-client-id',
        clientSecret: 'test-client-secret',
        redirectUri: 'http://localhost:3000/callback',
        authorizeEndpoint: 'https://provider.com/authorize',
        tokenEndpoint: 'https://provider.com/token',
        deviceAuthorizationEndpoint: 'https://provider.com/device',
        scopes: ['openid'],
      });

      const mockTokenResponse: DeviceTokenResponse = {
        access_token: 'access-token-123',
        token_type: 'Bearer',
        expires_in: 3600,
        refresh_token: 'refresh-token-456',
        scope: 'openid profile',
      };

      vi.mocked(ofetch).mockResolvedValue(mockTokenResponse);

      const result = await pollForDeviceToken(
        'azure',
        'device-code-123',
        { pollInterval: 1, maxWaitTime: 10 },
      );

      expect(result).toEqual(mockTokenResponse);
      expect(vi.mocked(ofetch)).toHaveBeenCalledTimes(1);

      // Check body params
      const callArgs = vi.mocked(ofetch).mock.calls[0][1];
      const bodyParams = callArgs?.body as URLSearchParams;
      expect(bodyParams.get('grant_type')).toBe('urn:ietf:params:oauth:grant-type:device_code');
      expect(bodyParams.get('device_code')).toBe('device-code-123');
      expect(bodyParams.get('client_id')).toBe('test-client-id');
    });

    it('should handle authorization_pending and keep polling', async () => {
      registerOAuthProvider('azure', {
        clientId: 'test-client-id',
        clientSecret: 'test-client-secret',
        redirectUri: 'http://localhost:3000/callback',
        authorizeEndpoint: 'https://provider.com/authorize',
        tokenEndpoint: 'https://provider.com/token',
        deviceAuthorizationEndpoint: 'https://provider.com/device',
        scopes: ['openid'],
      });

      const mockTokenResponse: DeviceTokenResponse = {
        access_token: 'access-token-123',
        token_type: 'Bearer',
        expires_in: 3600,
      };

      // First two calls return authorization_pending
      vi.mocked(ofetch)
        .mockRejectedValueOnce({
          data: { error: 'authorization_pending' },
        })
        .mockRejectedValueOnce({
          data: { error: 'authorization_pending' },
        })
        .mockResolvedValueOnce(mockTokenResponse);

      const result = await pollForDeviceToken(
        'azure',
        'device-code-123',
        { pollInterval: 0.1, maxWaitTime: 10 }, // Very short interval for testing
      );

      expect(result).toEqual(mockTokenResponse);
      expect(vi.mocked(ofetch)).toHaveBeenCalledTimes(3);
    }, 10000);

    it('should handle slow_down and increase poll interval', async () => {
      registerOAuthProvider('azure', {
        clientId: 'test-client-id',
        clientSecret: 'test-client-secret',
        redirectUri: 'http://localhost:3000/callback',
        authorizeEndpoint: 'https://provider.com/authorize',
        tokenEndpoint: 'https://provider.com/token',
        deviceAuthorizationEndpoint: 'https://provider.com/device',
        scopes: ['openid'],
      });

      const mockTokenResponse: DeviceTokenResponse = {
        access_token: 'access-token-123',
        token_type: 'Bearer',
        expires_in: 3600,
      };

      vi.mocked(ofetch)
        .mockRejectedValueOnce({
          data: { error: 'slow_down' },
        })
        .mockResolvedValueOnce(mockTokenResponse);

      const result = await pollForDeviceToken(
        'azure',
        'device-code-123',
        { pollInterval: 0.1, maxWaitTime: 20 },
      );

      expect(result).toEqual(mockTokenResponse);
      expect(vi.mocked(ofetch)).toHaveBeenCalledTimes(2);
    }, 15000);

    it('should throw error on access_denied', async () => {
      registerOAuthProvider('azure', {
        clientId: 'test-client-id',
        clientSecret: 'test-client-secret',
        redirectUri: 'http://localhost:3000/callback',
        authorizeEndpoint: 'https://provider.com/authorize',
        tokenEndpoint: 'https://provider.com/token',
        deviceAuthorizationEndpoint: 'https://provider.com/device',
        scopes: ['openid'],
      });

      vi.mocked(ofetch).mockRejectedValue({
        data: { error: 'access_denied' },
      });

      await expect(
        pollForDeviceToken(
          'azure',
          'device-code-123',
          { pollInterval: 0.1, maxWaitTime: 10 },
        ),
      ).rejects.toThrow('User denied authorization');
    });

    it('should throw error on expired_token', async () => {
      registerOAuthProvider('azure', {
        clientId: 'test-client-id',
        clientSecret: 'test-client-secret',
        redirectUri: 'http://localhost:3000/callback',
        authorizeEndpoint: 'https://provider.com/authorize',
        tokenEndpoint: 'https://provider.com/token',
        deviceAuthorizationEndpoint: 'https://provider.com/device',
        scopes: ['openid'],
      });

      vi.mocked(ofetch).mockRejectedValue({
        data: { error: 'expired_token' },
      });

      await expect(
        pollForDeviceToken(
          'azure',
          'device-code-123',
          { pollInterval: 0.1, maxWaitTime: 10 },
        ),
      ).rejects.toThrow('Device code expired');
    });

    it('should timeout after maxWaitTime', async () => {
      registerOAuthProvider('azure', {
        clientId: 'test-client-id',
        clientSecret: 'test-client-secret',
        redirectUri: 'http://localhost:3000/callback',
        authorizeEndpoint: 'https://provider.com/authorize',
        tokenEndpoint: 'https://provider.com/token',
        deviceAuthorizationEndpoint: 'https://provider.com/device',
        scopes: ['openid'],
      });

      // Always return authorization_pending
      vi.mocked(ofetch).mockRejectedValue({
        data: { error: 'authorization_pending' },
      });

      await expect(
        pollForDeviceToken(
          'azure',
          'device-code-123',
          { pollInterval: 0.1, maxWaitTime: 1 }, // 1 second timeout
        ),
      ).rejects.toThrow('timed out after 1 seconds');
    }, 5000);

    it('should call onPoll callback on each attempt', async () => {
      registerOAuthProvider('azure', {
        clientId: 'test-client-id',
        clientSecret: 'test-client-secret',
        redirectUri: 'http://localhost:3000/callback',
        authorizeEndpoint: 'https://provider.com/authorize',
        tokenEndpoint: 'https://provider.com/token',
        deviceAuthorizationEndpoint: 'https://provider.com/device',
        scopes: ['openid'],
      });

      const mockTokenResponse: DeviceTokenResponse = {
        access_token: 'access-token-123',
        token_type: 'Bearer',
        expires_in: 3600,
      };

      vi.mocked(ofetch)
        .mockRejectedValueOnce({
          data: { error: 'authorization_pending' },
        })
        .mockResolvedValueOnce(mockTokenResponse);

      const onPollMock = vi.fn();

      await pollForDeviceToken(
        'azure',
        'device-code-123',
        {
          pollInterval: 0.1,
          maxWaitTime: 10,
          onPoll: onPollMock,
        },
      );

      expect(onPollMock).toHaveBeenCalledTimes(2);
      expect(onPollMock).toHaveBeenCalledWith(1, 0);
      expect(onPollMock.mock.calls[1][0]).toBe(2);
    }, 5000);
  });

  describe('authenticateDevice', () => {
    it('should combine initiate and poll into one flow', async () => {
      registerOAuthProvider('azure', {
        clientId: 'test-client-id',
        clientSecret: 'test-client-secret',
        redirectUri: 'http://localhost:3000/callback',
        authorizeEndpoint: 'https://provider.com/authorize',
        tokenEndpoint: 'https://provider.com/token',
        deviceAuthorizationEndpoint: 'https://provider.com/device',
        scopes: ['openid'],
      });

      const mockDeviceResponse: DeviceAuthorizationResponse = {
        device_code: 'DEVICE-CODE-123',
        user_code: 'ABCD-EFGH',
        verification_uri: 'https://provider.com/activate',
        expires_in: 900,
      };

      const mockTokenResponse: DeviceTokenResponse = {
        access_token: 'access-token-123',
        token_type: 'Bearer',
        expires_in: 3600,
      };

      vi.mocked(ofetch)
        .mockResolvedValueOnce(mockDeviceResponse) // initiate
        .mockResolvedValueOnce(mockTokenResponse); // poll

      const onStartMock = vi.fn();
      const onPollMock = vi.fn();

      const result = await authenticateDevice('azure', {
        scopes: ['User.Read'],
        onStart: onStartMock,
        onPoll: onPollMock,
        pollInterval: 0.1,
        maxWaitTime: 10,
      });

      expect(result).toEqual(mockTokenResponse);
      expect(onStartMock).toHaveBeenCalledWith(mockDeviceResponse);
      expect(onPollMock).toHaveBeenCalled();
    }, 5000);
  });
});

