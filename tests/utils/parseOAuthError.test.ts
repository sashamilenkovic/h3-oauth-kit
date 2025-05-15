import { describe, it, expect } from "vitest";
import { parseOAuthError } from "../../src/utils";

describe("parseOAuthError", () => {
  it("returns default message and 500 for unknown error shapes", async () => {
    const result = await parseOAuthError(new Error("Something failed"));

    expect(result).toEqual({
      statusCode: 500,
      message: "Token exchange failed",
    });
  });

  it("extracts status and error_description from structured OAuth error", async () => {
    const error = {
      response: {
        status: 401,
        json: async () => ({
          error: "invalid_client",
          error_description: "Client credentials invalid",
        }),
      },
    };

    const result = await parseOAuthError(error);

    expect(result).toEqual({
      statusCode: 401,
      message: "Client credentials invalid",
    });
  });

  it("falls back to `error` field if `error_description` is missing", async () => {
    const error = {
      response: {
        status: 403,
        json: async () => ({
          error: "unauthorized_scope",
        }),
      },
    };

    const result = await parseOAuthError(error);

    expect(result).toEqual({
      statusCode: 403,
      message: "unauthorized_scope",
    });
  });

  it("falls back to default message if JSON parsing fails", async () => {
    const error = {
      response: {
        status: 400,
        json: async () => {
          throw new Error("Bad JSON");
        },
      },
    };

    const result = await parseOAuthError(error);

    expect(result).toEqual({
      statusCode: 400,
      message: "Token exchange failed",
    });
  });

  it("ignores non-numeric status values and returns default", async () => {
    const error = {
      response: {
        status: "oops" as unknown as number,
        json: async () => ({
          error_description: "Something odd happened",
        }),
      },
    };

    const result = await parseOAuthError(error);

    expect(result).toEqual({
      statusCode: 500,
      message: "Something odd happened",
    });
  });

  it("returns fallback message if response.json throws", async () => {
    const error = {
      response: {
        status: 400,
        json: async () => {
          return Promise.reject(new Error("bad json"));
        },
      },
    };

    const result = await parseOAuthError(error);

    expect(result).toEqual({
      statusCode: 400,
      message: "Token exchange failed", // fallback
    });
  });

  it("returns default when error is not an object", async () => {
    const result = await parseOAuthError(undefined); // or a string, or number

    expect(result).toEqual({
      statusCode: 500,
      message: "Token exchange failed",
    });
  });
});
