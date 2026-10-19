import { expect, test } from "@playwright/test";

import { login, openCase } from "./helpers";

// Acceptance test A4 (spec 19): an analyst can check rule and evidence of a false positive,
// mark it with a reason and propose an exception - everything ends up in the audit log.
test("A4: false positive - rule, condition, fields and raw lines; mark and propose exception; audited", async ({
  page,
}) => {
  await login(page, "analyst");
  // Scenario 9 (password typos after a password change) must be at most P4.
  await openCase(page, "Konto gesperrt: lena.hoffmann");
  await expect(page.locator("header [data-priority]").first()).toHaveAttribute("data-priority", "P4");

  await page.getByRole("link", { name: /^Belege/ }).click();
  const alert = page.getByTestId("alert-evidence").first();
  await expect(alert.getByTestId("rule-yaml")).toBeVisible();
  // the rule's condition and the matching detection items are highlighted in the YAML
  await expect(alert.getByTestId("rule-yaml").locator("[data-marked]", { hasText: "condition:" })).toBeVisible();
  // matching fields (single rules) or the evaluated condition (correlations)
  await expect(alert.getByTestId("explanation")).toContainText(/Passende Felder|Bedingung|Feld/);
  const rawLine = alert.locator("li[data-ref] pre.raw-line").first();
  await expect(rawLine).toBeVisible();
  await expect(rawLine).toContainText("lena.hoffmann");

  const reason = "Tippfehler nach Passwortwechsel (Ticket 4711), vom Kontoinhaber bestätigt";
  const markButton = alert.getByRole("button", { name: "Als Fehlalarm markieren" });
  if (await markButton.isVisible()) {
    await markButton.click();
    const dialog = page.getByRole("dialog");
    await dialog.getByLabel("Grund").fill(reason);
    await dialog.getByRole("button", { name: "Als Fehlalarm markieren" }).click();
    await expect(dialog).toBeHidden();
  }
  await expect(alert.getByText("als Fehlalarm markiert")).toBeVisible();

  await alert.getByRole("button", { name: "Ausnahme vorschlagen" }).click();
  const exceptionDialog = page.getByRole("dialog");
  await expect(exceptionDialog.getByLabel("Bedingung (Feld=Wert, eine je Zeile)")).toHaveValue(/lena\.hoffmann/);
  await exceptionDialog.getByLabel("Begründung (mind. 10 Zeichen)").fill("Bekanntes Muster nach Passwortwechsel");
  await exceptionDialog.getByRole("button", { name: "Ausnahme vorschlagen" }).click();
  await expect(exceptionDialog).toBeHidden();

  // Everything is in the audit log (auditor view).
  await page.getByRole("button", { name: /Demo Analyst/ }).click();
  await page.getByRole("menuitem", { name: "Abmelden" }).click();
  await login(page, "auditor");
  await page.getByRole("link", { name: "Audit-Log" }).first().click();
  const table = page.getByRole("table", { name: "Audit-Log" });
  await expect(table.getByRole("row").filter({ hasText: "alert.false_positive" }).first()).toContainText("demo.analyst");
  await expect(table.getByRole("row").filter({ hasText: "exception.proposed" }).first()).toContainText("demo.analyst");
  await page.getByRole("button", { name: "Hash-Kette prüfen" }).click();
  await expect(page.getByText("Hash-Kette vollständig gültig.")).toBeVisible();
});
