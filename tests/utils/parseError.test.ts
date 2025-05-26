import { describe, it, expect } from 'vitest';
import { parseError } from '../../src/utils';

describe('parseError', () => {
  it('returns default message and 500 for unknown error shapes', async () => {
    const result = await parseError(new Error('Something failed'));

    expect(result).toEqual({
      statusCode: 500,
      message: 'Something failed',
    });
  });

  it('extracts status and error_description from structured OAuth error', async () => {
    const error = {
      response: {
        status: 401,
        json: async () => ({
          error: 'invalid_client',
          error_description: 'Client credentials invalid',
        }),
      },
    };

    const result = await parseError(error);

    expect(result).toEqual({
      statusCode: 401,
      message: 'Client credentials invalid',
    });
  });

  it('falls back to `error` field if `error_description` is missing', async () => {
    const error = {
      response: {
        status: 403,
        json: async () => ({
          error: 'unauthorized_scope',
        }),
      },
    };

    const result = await parseError(error);

    expect(result).toEqual({
      statusCode: 403,
      message: 'unauthorized_scope',
    });
  });

  it('falls back to default message if JSON parsing fails', async () => {
    const error = {
      response: {
        status: 400,
        json: async () => {
          throw new Error('Bad JSON');
        },
      },
    };

    const result = await parseError(error);

    expect(result).toEqual({
      statusCode: 400,
      message: 'h3-oauth-kit error',
    });
  });

  it('ignores non-numeric status values and returns default', async () => {
    const error = {
      response: {
        status: 'oops' as unknown as number,
        json: async () => ({
          error_description: 'Something odd happened',
        }),
      },
    };

    const result = await parseError(error);

    expect(result).toEqual({
      statusCode: 500,
      message: 'Something odd happened',
    });
  });

  it('returns fallback message if response.json throws', async () => {
    const error = {
      response: {
        status: 400,
        json: async () => {
          return Promise.reject(new Error('bad json'));
        },
      },
    };

    const result = await parseError(error);

    expect(result).toEqual({
      statusCode: 400,
      message: 'h3-oauth-kit error', // fallback
    });
  });

  it('returns default when error is not an object', async () => {
    const result = await parseError(undefined); // or a string, or number

    expect(result).toEqual({
      statusCode: 500,
      message: 'h3-oauth-kit error',
    });
  });

  it('returns default message if json is not an OAuth error shape', async () => {
    const error = {
      response: {
        status: 502,
        json: async () => ({ unexpected: 'value' }), // missing error keys
      },
    };

    const result = await parseError(error);

    expect(result).toEqual({
      statusCode: 502,
      message: 'h3-oauth-kit error', // fallback to default
    });
  });

  it('falls back to default message when error and error_description are missing', async () => {
    const error = {
      response: {
        status: 502,
        json: async () => ({
          error: undefined,
          error_description: undefined,
        }),
      },
    };

    const result = await parseError(error);

    expect(result).toEqual({
      statusCode: 502,
      message: 'h3-oauth-kit error',
    });
  });

  // Tests for isFetchErrorWithResponse function conditions
  describe('isFetchErrorWithResponse conditions', () => {
    it('processes error when response has only status property', async () => {
      const error = {
        response: {
          status: 429,
          // No json method - testing "status" in maybeResponse condition
        },
      };

      const result = await parseError(error);

      expect(result).toEqual({
        statusCode: 429,
        message: 'h3-oauth-kit error', // fallback since no json method
      });
    });

    it('processes error when response has only json property', async () => {
      const error = {
        response: {
          // No status property - testing "json" in maybeResponse condition
          json: async () => ({
            error: 'rate_limit_exceeded',
            error_description: 'Too many requests',
          }),
        },
      };

      const result = await parseError(error);

      expect(result).toEqual({
        statusCode: 500, // default since no status
        message: 'Too many requests',
      });
    });

    it('processes error when response has both status and json properties', async () => {
      const error = {
        response: {
          status: 422,
          json: async () => ({
            error: 'validation_failed',
            error_description: 'Invalid request parameters',
          }),
        },
      };

      const result = await parseError(error);

      expect(result).toEqual({
        statusCode: 422,
        message: 'Invalid request parameters',
      });
    });

    it('ignores error when response has neither status nor json properties', async () => {
      const error = {
        response: {
          // Neither status nor json - should not match isFetchErrorWithResponse
          someOtherProperty: 'value',
        },
      };

      const result = await parseError(error);

      expect(result).toEqual({
        statusCode: 500,
        message: 'h3-oauth-kit error', // default fallback
      });
    });

    it('ignores error when response is not an object', async () => {
      const error = {
        response: 'not an object', // should not match isFetchErrorWithResponse
      };

      const result = await parseError(error);

      expect(result).toEqual({
        statusCode: 500,
        message: 'h3-oauth-kit error', // default fallback
      });
    });

    it('ignores error when response is null', async () => {
      const error = {
        response: null, // should not match isFetchErrorWithResponse
      };

      const result = await parseError(error);

      expect(result).toEqual({
        statusCode: 500,
        message: 'h3-oauth-kit error', // default fallback
      });
    });
  });
});
