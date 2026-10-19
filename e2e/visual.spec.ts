import { existsSync } from "node:fs";
import { join } from "node:path";

import { expect, test } from "@playwright/test";

import { login, openCase } from "./helpers";

const baselines = join(import.meta.dirname, "__screenshots__", process.platform);
// Justification for the conditional skip: baselines are rendered on the CI platform (Linux) by the
// "visual-baselines" workflow; comparing against another OS's font rendering would only produce noise.
// With `--update-snapshots=all` the tests run and create the baselines.
test.beforeEach(({}, testInfo) => {
  test.skip(
    !existsSync(baselines) && testInfo.config.updateSnapshots !== "all",
    `no visual baselines for ${process.platform} yet`,
  );
});

// Visual regression (spec 15.6): diff <= 0.2 % per page, dark and light. Baselines are platform
// specific (font rasterisation) and live in e2e/__screenshots__/<platform>/; CI uses Linux.
// Create or refresh them with `pnpm e2e:update-snapshots` (CI workflow "visual-baselines").
for (const theme of ["dark", "light"] as const) {
  test.describe(`visual (${theme})`, () => {
    test.use({ colorScheme: theme });
    test.beforeEach(async ({ page }) => {
      await page.addInitScript((value) => {
        window.localStorage.setItem("sentinelops.theme", value);
      }, theme);
    });

    test("overview and queue", async ({ page }) => {
      await login(page, "analyst");
      await page.waitForLoadState("networkidle");
      await expect(page).toHaveScreenshot(`dashboard-${theme}.png`, { fullPage: true });
      await page.getByRole("link", { name: "Fälle" }).first().click();
      await page.waitForLoadState("networkidle");
      await expect(page).toHaveScreenshot(`queue-${theme}.png`, { fullPage: true });
    });

    test("case detail", async ({ page }) => {
      await login(page, "analyst");
      await openCase(page, "Aufnahme in privilegierte Gruppe: jonas.becker");
      await page.waitForLoadState("networkidle");
      await expect(page).toHaveScreenshot(`case-overview-${theme}.png`, { fullPage: true });
      await page.getByRole("link", { name: /^Timeline/ }).click();
      await page.waitForLoadState("networkidle");
      await expect(page).toHaveScreenshot(`case-timeline-${theme}.png`);
    });
  });
}
