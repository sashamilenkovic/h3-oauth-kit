import { describe, it, expect, vi } from "vitest";
import { deleteProviderCookies } from "../../src/index";
import { getProviderCookieKeys } from "../../src/utils";
import { deleteCookie } from "h3";

// Mock deleteCookie
vi.mock("h3", async () => {
  const actual = await vi.importActual<typeof import("h3")>("h3");
  return {
    ...actual,
    deleteCookie: vi.fn(),
  };
});

describe("deleteProviderCookies", () => {
  const mockEvent = {} as any;

  it("calls deleteCookie for all azure cookies", () => {
    deleteProviderCookies(mockEvent, "azure");

    const expected = getProviderCookieKeys("azure");
    for (const key of expected) {
      expect(deleteCookie).toHaveBeenCalledWith(mockEvent, key);
    }
  });

  it("calls deleteCookie for all clio cookies", () => {
    deleteProviderCookies(mockEvent, "clio");

    const expected = getProviderCookieKeys("clio");
    for (const key of expected) {
      expect(deleteCookie).toHaveBeenCalledWith(mockEvent, key);
    }
  });

  it("calls deleteCookie for all intuit cookies", () => {
    deleteProviderCookies(mockEvent, "intuit");

    const expected = getProviderCookieKeys("intuit");
    for (const key of expected) {
      expect(deleteCookie).toHaveBeenCalledWith(mockEvent, key);
    }
  });
});
