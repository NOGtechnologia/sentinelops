import { renderHook } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import {
  ApiError,
  buildUrl,
  download,
  getAccessToken,
  request,
  setAccessToken,
  setUnauthorizedHandler,
} from "../api/client";
import { highlight } from "../components/CodeView";
import { markedLines, needlesFor } from "../pages/case/EvidenceTab";
import {
  age,
  formatDateTime,
  formatNumber,
  formatPercent,
  formatTime,
  getDisplayZone,
  parseTime,
  setDisplayZone,
  shortId,
} from "./format";
import { useHotkeys } from "./hotkeys";

describe("format", () => {
  it("formats UTC timestamps in the display zone", () => {
    setDisplayZone("Europe/Berlin");
    expect(getDisplayZone()).toBe("Europe/Berlin");
    expect(formatDateTime("2026-03-12T09:30:00.000000Z", "de-DE")).toBe("12.03.2026, 10:30");
    expect(formatDateTime("2026-03-12T09:30:05.000000Z", "de-DE", true)).toBe("12.03.2026, 10:30:05");
    expect(formatTime("2026-03-29T01:30:00Z", "de-DE")).toBe("03:30:00"); // after the DST change
    expect(formatDateTime(null, "de-DE")).toBe("–");
    expect(formatTime("nonsense", "de-DE")).toBe("–");
    expect(parseTime(undefined)).toBeNull();
  });

  it("formats numbers, percentages, ages and ids", () => {
    expect(formatNumber(14044, "de-DE")).toBe("14.044");
    expect(formatNumber(null, "de-DE")).toBe("–");
    expect(formatPercent(0.25, "en-GB")).toBe("25%");
    expect(formatPercent(undefined, "en-GB")).toBe("–");
    const now = "2026-03-12T10:00:00Z";
    expect(age("2026-03-12T09:30:00Z", now)).toEqual({ unit: "m", value: 30 });
    expect(age("2026-03-11T09:00:00Z", now)).toEqual({ unit: "h", value: 25 });
    expect(age("2026-03-01T10:00:00Z", now)).toEqual({ unit: "d", value: 11 });
    expect(age(null, now)).toEqual({ unit: "m", value: 0 });
    expect(shortId("abcdef0123456789")).toBe("abcdef01");
  });
});

describe("highlight", () => {
  it("splits text into hits and plain parts, case-insensitively and longest first", () => {
    expect(
      highlight("Failed for Jonas.Becker from 203.0.113.45", ["jonas.becker", "203.0.113.4", "203.0.113.45"]),
    ).toEqual([
      { text: "Failed for ", hit: false },
      { text: "Jonas.Becker", hit: true },
      { text: " from ", hit: false },
      { text: "203.0.113.45", hit: true },
    ]);
  });

  it("ignores short or empty needles", () => {
    expect(highlight("abc", ["a", " "])).toEqual([{ text: "abc", hit: false }]);
    expect(highlight("", ["abc"])).toEqual([{ text: "", hit: false }]);
  });
});

describe("evidence helpers", () => {
  it("derives highlight values and marked YAML lines from an explanation", () => {
    const explanation = {
      type: "single",
      matched: [{ field: "group.name", actual: ["Domain Admins", 4728], expected: "x", detection: "selection" }],
      group_by: { "user.name": "jonas.becker", short: "ab" },
    };
    expect(needlesFor(explanation)).toEqual(["Domain Admins", "4728", "jonas.becker"]);
    expect(markedLines(explanation)).toEqual(["condition:", "selection:"]);
    expect(markedLines({ type: "event_count" })).toContain("timespan:");
  });
});

describe("api client", () => {
  it("builds URLs with encoded path parameters and queries", () => {
    expect(buildUrl("/api/v1/cases/{case_id}", { case_id: "a/b" })).toBe("/api/v1/cases/a%2Fb");
    expect(buildUrl("/api/v1/cases", undefined, { status: ["new", "in_progress"], q: "", limit: 5, x: null })).toBe(
      "/api/v1/cases?status=new&status=in_progress&limit=5",
    );
    expect(() => buildUrl("/api/v1/cases/{case_id}", {})).toThrow("missing path parameter case_id");
  });

  it("sends the bearer token, reports errors and calls the 401 handler", async () => {
    const onUnauthorized = vi.fn();
    setUnauthorizedHandler(onUnauthorized);
    setAccessToken("tok");
    expect(getAccessToken()).toBe("tok");
    const fetchMock = vi.fn((_url: string, init?: RequestInit) => {
      const headers = init?.headers as Record<string, string>;
      if (headers.Authorization !== "Bearer tok") return Promise.resolve(new Response("{}", { status: 500 }));
      return Promise.resolve(
        new Response(JSON.stringify({ detail: [{ msg: "field required" }] }), {
          status: 401,
          statusText: "Unauthorized",
        }),
      );
    });
    vi.stubGlobal("fetch", fetchMock);
    const error = await request("/api/v1/auth/me").catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).status).toBe(401);
    expect((error as ApiError).detail).toBe("field required");
    expect(onUnauthorized).toHaveBeenCalled();
    vi.stubGlobal(
      "fetch",
      vi.fn(() => Promise.resolve(new Response("not json", { status: 502, statusText: "Bad Gateway" }))),
    );
    const other = (await request("/api/v1/auth/me").catch((e: unknown) => e)) as ApiError;
    expect(other.detail).toBe("Bad Gateway");
    setUnauthorizedHandler(null);
    setAccessToken(null);
  });

  it("downloads files with the server's file name", async () => {
    const names: string[] = [];
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (this: HTMLAnchorElement) {
      names.push(this.download);
    });
    URL.createObjectURL = vi.fn(() => "blob:x");
    URL.revokeObjectURL = vi.fn();
    vi.stubGlobal(
      "fetch",
      vi.fn(() =>
        Promise.resolve(
          new Response("data", { status: 200, headers: { "Content-Disposition": 'attachment; filename="r.pdf"' } }),
        ),
      ),
    );
    await download("/api/v1/cases/{case_id}/report", { path: { case_id: "c1" }, query: { format: "pdf" } }, "x.pdf");
    expect(click).toHaveBeenCalledTimes(1);
    expect(names).toEqual(["r.pdf"]);
    vi.restoreAllMocks();
  });
});

describe("useHotkeys", () => {
  it("runs single-key shortcuts but not while typing or with modifiers", () => {
    const action = vi.fn();
    const { unmount } = renderHook(() => {
      useHotkeys({ j: action });
    });
    window.dispatchEvent(new KeyboardEvent("keydown", { key: "j" }));
    window.dispatchEvent(new KeyboardEvent("keydown", { key: "j", ctrlKey: true }));
    const input = document.createElement("input");
    document.body.append(input);
    input.dispatchEvent(new KeyboardEvent("keydown", { key: "j", bubbles: true }));
    window.dispatchEvent(new KeyboardEvent("keydown", { key: "k" }));
    expect(action).toHaveBeenCalledTimes(1);
    unmount();
    window.dispatchEvent(new KeyboardEvent("keydown", { key: "j" }));
    expect(action).toHaveBeenCalledTimes(1);
    input.remove();
  });
});
