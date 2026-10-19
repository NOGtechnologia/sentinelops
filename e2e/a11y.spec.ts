import { expect, test } from "@playwright/test";

import { expectAccessible, login, openCase, type DemoUser } from "./helpers";

// Spec 15.6: axe on every page, 0 "serious"/"critical" findings, in dark and light theme.
const PAGES: { path: string; user: DemoUser; ready: string }[] = [
  { path: "/", user: "analyst", ready: "Lagebild" },
  { path: "/cases", user: "analyst", ready: "Fall-Warteschlange" },
  { path: "/entities", user: "analyst", ready: "Entitäten" },
  { path: "/events", user: "analyst", ready: "Ereignisse" },
  { path: "/rules", user: "analyst", ready: "Regeln" },
  { path: "/rules/SO-AUTH-001", user: "engineer", ready: "Brute Force auf ein Konto" },
  { path: "/quality", user: "admin", ready: "Datenqualität" },
  { path: "/audit", user: "auditor", ready: "Audit-Log" },
  { path: "/admin", user: "admin", ready: "Administration" },
];

for (const theme of ["dark", "light"] as const) {
  test.describe(`accessibility (${theme})`, () => {
    test.use({ colorScheme: theme });
    test.beforeEach(async ({ page }) => {
      await page.addInitScript((value) => {
        window.localStorage.setItem("sentinelops.theme", value);
      }, theme);
    });

    test("login page", async ({ page }) => {
      await page.goto("/");
      await expect(page.getByText("Demo-Zugänge")).toBeVisible();
      await expectAccessible(page, `login/${theme}`);
    });

    for (const entry of PAGES) {
      test(`page ${entry.path}`, async ({ page }) => {
        await login(page, entry.user);
        await page.goto(entry.path);
        await expect(page.getByRole("heading", { level: 1 })).toContainText(entry.ready);
        await page.waitForLoadState("networkidle");
        await expectAccessible(page, `${entry.path}/${theme}`);
      });
    }

    test("case detail tabs", async ({ page }) => {
      await login(page, "senior");
      await openCase(page, "Aufnahme in privilegierte Gruppe");
      await expectAccessible(page, `case-overview/${theme}`);
      for (const tab of ["Timeline", "Belege", "Entitätsgraph", "Bericht"]) {
        await page.getByRole("link", { name: new RegExp(`^${tab}`) }).click();
        await page.waitForLoadState("networkidle");
        await expectAccessible(page, `case-${tab}/${theme}`);
      }
    });
  });
}
