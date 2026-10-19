import { expect, test } from "@playwright/test";

import { login, openCase } from "./helpers";

// Spec 15.7: a timeline with 5,000 events renders in < 2 s. The API response of a real case is
// replaced by 5,000 synthetic items so the test does not depend on a huge demo case.
test("timeline with 5,000 events renders in under 2 seconds", async ({ page }) => {
  await login(page, "analyst");
  const caseId = await openCase(page, "Password Spraying");
  const base = Date.parse("2026-03-12T02:00:00Z");
  const items = Array.from({ length: 5000 }, (_, i) => ({
    kind: "event",
    time: new Date(base + i * 1000).toISOString().replace("Z", "000Z"),
    id: `ev${String(i).padStart(5, "0")}`,
    action: i % 3 ? "logon-failed" : "logon",
    outcome: i % 3 ? "failure" : "success",
    code: i % 3 ? "4625" : "4624",
    user: `user${String(i % 120)}`,
    target_user: null,
    host: "SRV-GW01.musterfirma.example",
    source_ip: `203.0.113.${String(i % 200)}`,
    time_quality: "exact",
    quality_flags: [],
    rules: i % 50 === 0 ? ["SO-AUTH-002"] : [],
    lanes: [`user:user${String(i % 120)}`, `ip:203.0.113.${String(i % 200)}`],
  }));
  await page.route(`**/api/v1/cases/${caseId}/timeline**`, (route) =>
    route.fulfill({ json: { total: items.length, offset: 0, items } }),
  );
  const started = Date.now();
  await page.getByRole("link", { name: /^Timeline/ }).click();
  await expect(page.getByText("5000 von 5000 Einträgen")).toBeVisible();
  await expect(page.getByTestId("timeline-list").getByRole("listitem").first()).toBeVisible();
  const elapsed = Date.now() - started;
  console.log(`timeline with 5000 events rendered in ${String(elapsed)} ms`);
  expect(elapsed).toBeLessThan(2000);
});
