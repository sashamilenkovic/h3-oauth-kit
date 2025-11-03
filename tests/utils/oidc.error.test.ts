import { describe, it, expect, vi, beforeEach } from 'vitest';
import { fetchUserInfo } from '../../src/utils/oidc';
import { ofetch } from 'ofetch';

vi.mock('ofetch');

describe('OIDC Error Handling', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Mock console.error to avoid cluttering test output
    vi.spyOn(console, 'error').mockImplementation(() => {});
  });

  describe('fetchUserInfo error handling', () => {
    it('should return undefined when userInfoEndpoint is not provided', async () => {
      const result = await fetchUserInfo(undefined, 'access-token', 'azure' as any);

      expect(result).toBeUndefined();
      expect(ofetch).not.toHaveBeenCalled();
    });

    it('should return undefined and log error when fetch fails', async () => {
      vi.mocked(ofetch).mockRejectedValueOnce(new Error('Network error'));

      const result = await fetchUserInfo(
        'https://provider.com/userinfo',
        'access-token',
        'azure' as any,
      );

      expect(result).toBeUndefined();
      expect(console.error).toHaveBeenCalledWith(
        expect.stringContaining('Failed to fetch userInfo'),
        expect.any(Error),
      );
    });

    it('should return undefined when API returns 401', async () => {
      const error = new Error('Unauthorized');
      (error as any).status = 401;
      vi.mocked(ofetch).mockRejectedValueOnce(error);

      const result = await fetchUserInfo(
        'https://provider.com/userinfo',
        'access-token',
        'azure' as any,
      );

      expect(result).toBeUndefined();
    });

    it('should return undefined when API returns 403', async () => {
      const error = new Error('Forbidden');
      (error as any).status = 403;
      vi.mocked(ofetch).mockRejectedValueOnce(error);

      const result = await fetchUserInfo(
        'https://provider.com/userinfo',
        'access-token',
        'azure' as any,
      );

      expect(result).toBeUndefined();
    });

    it('should return undefined when API returns 404', async () => {
      const error = new Error('Not Found');
      (error as any).status = 404;
      vi.mocked(ofetch).mockRejectedValueOnce(error);

      const result = await fetchUserInfo(
        'https://provider.com/userinfo',
        'access-token',
        'azure' as any,
      );

      expect(result).toBeUndefined();
    });

    it('should return undefined when API returns 500', async () => {
      const error = new Error('Internal Server Error');
      (error as any).status = 500;
      vi.mocked(ofetch).mockRejectedValueOnce(error);

      const result = await fetchUserInfo(
        'https://provider.com/userinfo',
        'access-token',
        'azure' as any,
      );

      expect(result).toBeUndefined();
    });

    it('should handle timeout errors', async () => {
      const error = new Error('Request timeout');
      (error as any).code = 'ETIMEDOUT';
      vi.mocked(ofetch).mockRejectedValueOnce(error);

      const result = await fetchUserInfo(
        'https://provider.com/userinfo',
        'access-token',
        'azure' as any,
      );

      expect(result).toBeUndefined();
      expect(console.error).toHaveBeenCalled();
    });

    it('should handle network errors gracefully', async () => {
      const error = new Error('Network connection failed');
      (error as any).code = 'ENOTFOUND';
      vi.mocked(ofetch).mockRejectedValueOnce(error);

      const result = await fetchUserInfo(
        'https://invalid-provider.com/userinfo',
        'access-token',
        'azure' as any,
      );

      expect(result).toBeUndefined();
    });

    it('should handle malformed responses', async () => {
      vi.mocked(ofetch).mockRejectedValueOnce(
        new Error('Invalid JSON in response'),
      );

      const result = await fetchUserInfo(
        'https://provider.com/userinfo',
        'access-token',
        'azure' as any,
      );

      expect(result).toBeUndefined();
    });

    it('should log the endpoint that failed', async () => {
      const endpoint = 'https://specific-provider.com/userinfo';
      vi.mocked(ofetch).mockRejectedValueOnce(new Error('Failed'));

      await fetchUserInfo(endpoint, 'access-token', 'azure' as any);

      expect(console.error).toHaveBeenCalledWith(
        expect.stringContaining(endpoint),
        expect.any(Error),
      );
    });

    it('should work correctly when ofetch succeeds', async () => {
      const userInfo = {
        sub: '123456',
        name: 'John Doe',
        email: 'john@example.com',
      };

      vi.mocked(ofetch).mockResolvedValueOnce(userInfo);

      const result = await fetchUserInfo(
        'https://provider.com/userinfo',
        'access-token',
        'azure' as any,
      );

      expect(result).toEqual(userInfo);
      expect(console.error).not.toHaveBeenCalled();
    });

    it('should pass correct headers to ofetch', async () => {
      vi.mocked(ofetch).mockResolvedValueOnce({ sub: '123' });

      await fetchUserInfo(
        'https://provider.com/userinfo',
        'test-access-token',
        'azure' as any,
      );

      expect(ofetch).toHaveBeenCalledWith(
        'https://provider.com/userinfo',
        expect.objectContaining({
          headers: {
            Authorization: 'Bearer test-access-token',
          },
        }),
      );
    });
  });
});

