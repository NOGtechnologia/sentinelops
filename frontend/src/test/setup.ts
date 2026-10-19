import "@testing-library/jest-dom/vitest";
import "../i18n";

import { cleanup } from "@testing-library/react";
import { createElement } from "react";
import { afterEach, vi } from "vitest";

// Canvas-based wrappers (ECharts, Cytoscape) need a real browser; they are covered by the Playwright
// end-to-end and visual regression tests and excluded from unit coverage (vite.config.ts).
vi.mock("../components/Chart", () => ({
  TimeChart: ({ label }: { label: string }) => createElement("div", { role: "img", "aria-label": label }),
}));
vi.mock("../components/EntityGraph", () => ({
  EntityGraph: ({ label, onSelect }: { label: string; onSelect?: (id: string | null) => void }) =>
    createElement(
      "div",
      { role: "img", "aria-label": label },
      createElement("button", { type: "button", onClick: () => onSelect?.("user:jonas.becker") }, "select-node"),
      createElement("button", { type: "button", onClick: () => onSelect?.(null) }, "clear-node"),
    ),
}));

// jsdom lacks these browser APIs used by layout code.
class ResizeObserverStub {
  observe = vi.fn();
  unobserve = vi.fn();
  disconnect = vi.fn();
}
vi.stubGlobal("ResizeObserver", ResizeObserverStub);
Element.prototype.scrollIntoView = vi.fn();
window.scrollTo = vi.fn();
if (!("hasPointerCapture" in Element.prototype)) {
  Object.assign(Element.prototype, { hasPointerCapture: () => false, releasePointerCapture: () => undefined });
}
// Give the virtualised timeline a viewport so rows are rendered.
Object.defineProperty(HTMLElement.prototype, "offsetHeight", { configurable: true, get: () => 600 });
Object.defineProperty(HTMLElement.prototype, "offsetWidth", { configurable: true, get: () => 1000 });
HTMLElement.prototype.getBoundingClientRect = function getBoundingClientRect() {
  return { x: 0, y: 0, top: 0, left: 0, right: 1000, bottom: 600, width: 1000, height: 600, toJSON: () => ({}) };
};

afterEach(() => {
  cleanup();
  sessionStorage.clear();
  localStorage.clear();
  vi.unstubAllGlobals();
  vi.stubGlobal("ResizeObserver", ResizeObserverStub);
});
