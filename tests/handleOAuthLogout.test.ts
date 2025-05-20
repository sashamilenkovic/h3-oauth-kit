import { describe, it, expect, vi, beforeEach } from "vitest";
import { handleOAuthLogout } from "../src";
import { deleteCookie, sendRedirect } from "h3";
import type { H3Event } from "h3";

// Mock h3 functions
vi.mock("h3", () => ({
  deleteCookie: vi.fn(),
  sendRedirect: vi.fn(),
  defineEventHandler: (handler: Function) => handler,
}));

describe("handleOAuthLogout", () => {
  let mockEvent: H3Event;

  beforeEach(() => {
    vi.clearAllMocks();
    mockEvent = {} as H3Event;
  });

  describe("as a route handler", () => {
    it("should delete cookies for all providers", async () => {
      const handler = handleOAuthLogout(["clio", "azure"]);
      await handler(mockEvent);

      expect(deleteCookie).toHaveBeenCalledTimes(7); // 3 for clio + 4 for azure
      // Clio cookies
      expect(deleteCookie).toHaveBeenCalledWith(mockEvent, "clio_access_token");
      expect(deleteCookie).toHaveBeenCalledWith(
        mockEvent,
        "clio_refresh_token"
      );
      expect(deleteCookie).toHaveBeenCalledWith(
        mockEvent,
        "clio_access_token_expires_at"
      );
      // Azure cookies
      expect(deleteCookie).toHaveBeenCalledWith(
        mockEvent,
        "azure_access_token"
      );
      expect(deleteCookie).toHaveBeenCalledWith(
        mockEvent,
        "azure_refresh_token"
      );
      expect(deleteCookie).toHaveBeenCalledWith(
        mockEvent,
        "azure_access_token_expires_at"
      );
      expect(deleteCookie).toHaveBeenCalledWith(
        mockEvent,
        "azure_ext_expires_at"
      );
    });

    it("should return a structured response", async () => {
      const handler = handleOAuthLogout(["clio"]);
      const result = await handler(mockEvent);

      expect(deleteCookie).toHaveBeenCalledTimes(3); // 3 cookies for clio
      expect(result).toEqual({
        loggedOut: true,
        providers: ["clio"],
      });
    });
  });

  describe("as a utility with redirect", () => {
    it("should delete cookies and redirect", async () => {
      await handleOAuthLogout(["clio"], { redirectTo: "/login" }, mockEvent);

      expect(deleteCookie).toHaveBeenCalledTimes(3); // 3 cookies for clio
      expect(sendRedirect).toHaveBeenCalledWith(mockEvent, "/login", 302);
    });

    it("should handle multiple providers with redirect", async () => {
      await handleOAuthLogout(
        ["clio", "azure"],
        { redirectTo: "/dashboard" },
        mockEvent
      );

      expect(deleteCookie).toHaveBeenCalledTimes(7); // 3 for clio + 4 for azure
      expect(sendRedirect).toHaveBeenCalledWith(mockEvent, "/dashboard", 302);
    });
  });

  describe("as a utility without redirect", () => {
    it("should delete cookies and return response", async () => {
      const result = await handleOAuthLogout(["clio"], {}, mockEvent);

      expect(deleteCookie).toHaveBeenCalledTimes(3); // 3 cookies for clio
      expect(sendRedirect).not.toHaveBeenCalled();
      expect(result).toEqual({
        loggedOut: true,
        providers: ["clio"],
      });
    });
  });

  describe("error handling", () => {
    it("should handle empty providers array", async () => {
      const handler = handleOAuthLogout([]);
      const result = await handler(mockEvent);

      expect(deleteCookie).not.toHaveBeenCalled();
      expect(result).toEqual({
        loggedOut: true,
        providers: [],
      });
    });
  });
});
