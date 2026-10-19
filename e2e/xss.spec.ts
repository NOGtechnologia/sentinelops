import { expect, test } from "@playwright/test";

import { expectNoInjectedMarkup, guardAgainstXss, login, openCase } from "./helpers";

// Spec 15.6: test data contains <script>, <img onerror> and javascript: links in user names,
// host names, command lines and raw lines (generator scenario 10). No script may ever run.
test("XSS from log data: every view renders hostile values as text", async ({ page }) => {
  const guard = guardAgainstXss(page);
  await login(page, "analyst");

  await page.getByRole("link", { name: "Fälle" }).first().click();
  await expect(page.getByRole("table", { name: "Fall-Warteschlange" })).toBeVisible();
  await expectNoInjectedMarkup(page);

  await openCase(page, "ignore previous instructions");
  await expect(page.getByTestId("injection-notice")).toBeVisible();
  // the payload is visible as text
  await expect(page.getByText("<img src=x onerror=alert(1)>").first()).toBeVisible();
  await expectNoInjectedMarkup(page);

  for (const tab of ["Timeline", "Belege", "Entitätsgraph", "Bericht"]) {
    await page.getByRole("link", { name: new RegExp(`^${tab}`) }).click();
    await page.waitForLoadState("networkidle");
    await expectNoInjectedMarkup(page);
  }

  // sudo command line with <script> and javascript: (Linux part of scenario 10)
  await page.getByRole("link", { name: "Entitäten" }).first().click();
  const entitySearch = page.getByRole("textbox", { name: "Suche", exact: true });
  await entitySearch.fill("<img");
  await entitySearch.press("Enter");
  await expectNoInjectedMarkup(page);

  await page.getByRole("link", { name: "Datenqualität" }).first().click();
  await expect(page.getByTestId("quarantine")).toBeVisible();
  await expectNoInjectedMarkup(page);

  const marker = await page.evaluate(() => (window as unknown as { __xss?: unknown }).__xss);
  expect(marker).toBeUndefined();
  expect(guard.dialogs).toEqual([]);
});

test("XSS: the sudo command line with <script> and javascript: stays text in the event view", async ({ page }) => {
  const guard = guardAgainstXss(page);
  await login(page, "analyst");
  await page.getByRole("link", { name: "Ereignisse" }).first().click();
  await page.getByLabel("Benutzer").fill("www-data");
  await page.getByRole("button", { name: "Suchen" }).click();
  const table = page.getByRole("table", { name: "Ereignisse" });
  const row = table.getByRole("row").filter({ hasText: "sudo" }).first();
  await row.getByRole("button", { name: "Rohzeile" }).click();
  const raw = page.getByTestId("event-raw");
  await expect(raw).toContainText("<script>alert('xss')</script>");
  await expect(raw).toContainText("javascript:alert(document.domain)");
  await expectNoInjectedMarkup(page);
  expect(guard.dialogs).toEqual([]);
});