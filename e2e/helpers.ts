import AxeBuilder from "@axe-core/playwright";
import { expect, type Page } from "@playwright/test";

export type DemoUser = "analyst" | "senior" | "engineer" | "admin" | "auditor";

/** Log in through the demo login page (only available in demo mode). */
export async function login(page: Page, user: DemoUser = "analyst"): Promise<void> {
  await page.goto("/");
  await page.getByTestId(`demo-login-${user}`).click();
  await expect(page.getByRole("navigation", { name: "Hauptnavigation" }).first()).toBeVisible();
}

/** Open a case from the queue by a fragment of its German title. */
export async function openCase(page: Page, titleFragment: string): Promise<string> {
  await page.getByRole("link", { name: "Fälle" }).first().click();
  await page.getByRole("link", { name: new RegExp(titleFragment) }).first().click();
  await expect(page.getByRole("heading", { level: 1 })).toContainText(titleFragment);
  const match = /\/cases\/([0-9a-f]+)/.exec(page.url());
  if (!match?.[1]) throw new Error(`no case id in ${page.url()}`);
  return match[1];
}

/**
 * Fails the test on any sign of script execution from log data: dialogs (alert/confirm),
 * injected <img onerror>/<script> elements, or the global markers our payloads would set.
 */
export function guardAgainstXss(page: Page): { dialogs: string[] } {
  const state = { dialogs: [] as string[] };
  page.on("dialog", (dialog) => {
    state.dialogs.push(dialog.message());
    void dialog.dismiss();
  });
  return state;
}

export async function expectNoInjectedMarkup(page: Page): Promise<void> {
  expect(await page.locator("img[src='x']").count()).toBe(0);
  expect(await page.locator("script:not([src])").count()).toBe(0);
  expect(await page.locator("a[href^='javascript:']").count()).toBe(0);
}

export async function expectAccessible(page: Page, label: string): Promise<void> {
  const results = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"]).analyze();
  const serious = results.violations.filter((v) => v.impact === "serious" || v.impact === "critical");
  expect(
    serious.map((v) => `${label}: ${v.id} (${v.impact}) ${v.nodes.map((n) => n.target.join(" ")).join(", ")}`),
  ).toEqual([]);
}
