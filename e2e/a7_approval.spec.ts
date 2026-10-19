import { expect, test } from "@playwright/test";

import { login, openCase } from "./helpers";

// Acceptance test A7 (UI part): no action without approval. The API part is
// backend/tests/acceptance::test_a7_no_action_without_approval.
test("A7: proposal by L1, approval dialog with simulation notice for L2, simulated execution", async ({ page }) => {
  await login(page, "analyst");
  await openCase(page, "Aufnahme in privilegierte Gruppe: jonas.becker");
  const step = page.locator("li", { hasText: "DISABLE_ACCOUNT" }).first();
  await step.getByRole("button", { name: "Maßnahme vorschlagen" }).click();
  const propose = page.getByRole("dialog");
  await expect(propose.getByTestId("simulation-notice")).toBeVisible();
  await propose.getByLabel("Begründung").fill("Konto nach erfolgreicher Brute-Force-Anmeldung kompromittiert");
  await propose.getByRole("button", { name: "Vorschlag einreichen" }).click();
  await expect(propose).toBeHidden();

  const actions = page.getByTestId("actions-list");
  const proposed = actions.locator("li[data-status='proposed']", { hasText: "DISABLE_ACCOUNT" }).first();
  await expect(proposed).toBeVisible();
  // L1 can neither approve nor execute.
  await expect(proposed.getByRole("button", { name: "Prüfen und entscheiden" })).toHaveCount(0);
  await expect(actions.getByRole("button", { name: "Ausführen (Simulation)" })).toHaveCount(0);

  await page.getByRole("button", { name: /Demo Analyst/ }).click();
  await page.getByRole("menuitem", { name: "Abmelden" }).click();
  await login(page, "senior");
  await openCase(page, "Aufnahme in privilegierte Gruppe: jonas.becker");
  const pending = page.getByTestId("actions-list").locator("li[data-status='proposed']", { hasText: "DISABLE_ACCOUNT" });
  await pending.first().getByRole("button", { name: "Prüfen und entscheiden" }).click();

  const dialog = page.getByTestId("approval-dialog");
  await expect(dialog.getByTestId("simulation-notice")).toBeVisible();
  await expect(dialog).toContainText("jonas.becker");
  await expect(dialog).toContainText("Konto nach erfolgreicher Brute-Force-Anmeldung kompromittiert");
  const approve = dialog.getByRole("button", { name: "Freigeben" });
  await expect(approve).toBeDisabled(); // reason is mandatory
  await dialog.getByLabel("Begründung der Entscheidung (Pflicht)").fill("Belege E41-E43 eindeutig");
  await approve.click();
  await expect(dialog).toBeHidden();

  const approved = page.getByTestId("actions-list").locator("li[data-status='approved']", { hasText: "DISABLE_ACCOUNT" });
  await approved.first().getByRole("button", { name: "Ausführen (Simulation)" }).click();
  const executed = page.getByTestId("actions-list").locator("li[data-status='executed']", { hasText: "DISABLE_ACCOUNT" });
  await expect(executed.first().getByTestId("execution-result")).toContainText("SIMULATION (nothing was changed)");
});

test("A7: four-eyes principle - an approver cannot approve an own proposal", async ({ page }) => {
  await login(page, "senior");
  await openCase(page, "Erfolgreiche Anmeldung nach Brute Force: backup");
  const step = page.locator("li", { hasText: "BLOCK_SOURCE_IP" }).first();
  await step.getByRole("button", { name: "Maßnahme vorschlagen" }).click();
  const propose = page.getByRole("dialog");
  await propose.getByLabel("Begründung").fill("Angreifer-IP sperren");
  await propose.getByRole("button", { name: "Vorschlag einreichen" }).click();
  await expect(propose).toBeHidden();

  const own = page.getByTestId("actions-list").locator("li[data-status='proposed']", { hasText: "BLOCK_SOURCE_IP" });
  await own.first().getByRole("button", { name: "Prüfen und entscheiden" }).click();
  const dialog = page.getByTestId("approval-dialog");
  await expect(dialog).toContainText("Vier-Augen-Prinzip");
  await dialog.getByLabel("Begründung der Entscheidung (Pflicht)").fill("Selbst freigeben");
  await dialog.getByRole("button", { name: "Freigeben" }).click();
  await expect(dialog.getByRole("alert")).toContainText("four-eyes");
  await expect(page.getByTestId("actions-list").locator("li[data-status='approved']", { hasText: "BLOCK_SOURCE_IP" })).toHaveCount(0);
});
