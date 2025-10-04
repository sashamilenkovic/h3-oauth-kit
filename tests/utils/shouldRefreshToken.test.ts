import { describe, it, expect } from 'vitest';
import { shouldRefreshToken } from '../../src/utils';

describe('shouldRefreshToken', () => {
  it('should return true when token expires within threshold', () => {
    const now = Math.floor(Date.now() / 1000);
    const tokens = {
      expires_in: now + 60, // Expires in 60 seconds
    };

    const result = shouldRefreshToken(tokens, 120); // Threshold: 2 minutes
    expect(result).toBe(true);
  });

  it('should return false when token expires beyond threshold', () => {
    const now = Math.floor(Date.now() / 1000);
    const tokens = {
      expires_in: now + 600, // Expires in 10 minutes
    };

    const result = shouldRefreshToken(tokens, 120); // Threshold: 2 minutes
    expect(result).toBe(false);
  });

  it('should return false when token is already expired', () => {
    const now = Math.floor(Date.now() / 1000);
    const tokens = {
      expires_in: now - 60, // Expired 1 minute ago
    };

    const result = shouldRefreshToken(tokens, 120);
    expect(result).toBe(false);
  });

  it('should return true when token expires exactly at threshold', () => {
    const now = Math.floor(Date.now() / 1000);
    const tokens = {
      expires_in: now + 300, // Expires in 5 minutes
    };

    const result = shouldRefreshToken(tokens, 300); // Threshold: 5 minutes
    expect(result).toBe(true);
  });

  it('should return true when token expires in 1 second with 5 minute threshold', () => {
    const now = Math.floor(Date.now() / 1000);
    const tokens = {
      expires_in: now + 1, // Expires in 1 second
    };

    const result = shouldRefreshToken(tokens, 300);
    expect(result).toBe(true);
  });

  it('should handle large thresholds', () => {
    const now = Math.floor(Date.now() / 1000);
    const tokens = {
      expires_in: now + 3000, // Expires in 50 minutes
    };

    const result = shouldRefreshToken(tokens, 3600); // Threshold: 1 hour
    expect(result).toBe(true);
  });

  it('should handle small thresholds', () => {
    const now = Math.floor(Date.now() / 1000);
    const tokens = {
      expires_in: now + 30, // Expires in 30 seconds
    };

    const result = shouldRefreshToken(tokens, 10); // Threshold: 10 seconds
    expect(result).toBe(false);
  });
});
