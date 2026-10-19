import { expect, test } from "@playwright/test";

import { login, openCase } from "./helpers";

test("core flow: overview -> queue (keyboard) -> case -> timeline -> evidence -> graph -> report export", async ({
  page,
}) => {
  await login(page, "analyst");
  await expect(page.getByRole("heading", { name: "Lagebild" })).toBeVisible();
  await expect(page.getByText("Events heute")).toBeVisible();

  await page.getByRole("link", { name: "Fälle" }).first().click();
  const table = page.getByRole("table", { name: "Fall-Warteschlange" });
  await expect(table.getByRole("row")).toHaveCount(11); // header + 10 demo cases
  await page.keyboard.press("j");
  await page.keyboard.press("k");
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(/\/cases\/[0-9a-f]+$/);
  await expect(page.getByText("Priorität mit Begründung")).toBeVisible();

  await page.keyboard.press("2");
  await expect(page.getByTestId("timeline-list")).toBeVisible();
  await expect(page.getByTestId("swimlanes")).toBeVisible();
  await page.keyboard.press("3");
  await expect(page.getByTestId("alert-evidence").first()).toBeVisible();
  await page.keyboard.press("4");
  await expect(page.getByRole("img", { name: /Entitätsgraph/ })).toBeVisible();
  await page.keyboard.press("5");
  await expect(page.getByTestId("report-preview")).toBeVisible();
  const download = page.waitForEvent("download");
  await page.getByRole("button", { name: "Markdown" }).click();
  expect((await download).suggestedFilename()).toMatch(/^sentinelops-case-[0-9a-f]+\.md$/);
});

test("demo AI summary is labelled as simulation and separates facts and hypotheses", async ({ page }) => {
  await login(page, "analyst");
  await openCase(page, "Aufnahme in privilegierte Gruppe: jonas.becker");
  const summary = page.getByTestId("case-summary");
  await expect(page.getByText("Demo-Simulation (kein echtes Modell), geprüft gegen Belege")).toBeVisible();
  await expect(summary.getByText("Bestätigte Fakten")).toBeVisible();
  await expect(summary.locator("[data-kind='hypothesis']").first()).toBeVisible();
});

test("language switch and theme toggle", async ({ page }) => {
  await login(page, "analyst");
  await page.getByRole("button", { name: "Sprache wechseln" }).click();
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  await page.getByRole("button", { name: "Change language" }).click();
  await expect(page.getByRole("heading", { name: "Lagebild" })).toBeVisible();
  await page.getByRole("button", { name: "Helles Design" }).click();
  await expect(page.locator("html")).not.toHaveClass(/dark/);
  await page.reload();
  await expect(page.locator("html")).not.toHaveClass(/dark/);
  await expect(page.getByRole("heading", { name: "Lagebild" })).toBeVisible(); // demo session resumed
});

test("strict security headers are sent with the web app", async ({ page }) => {
  const response = await page.goto("/");
  const headers = response?.headers() ?? {};
  expect(headers["content-security-policy"]).toContain("script-src 'self'");
  expect(headers["content-security-policy"]).toContain("frame-ancestors 'none'");
  expect(headers["x-content-type-options"]).toBe("nosniff");
});
