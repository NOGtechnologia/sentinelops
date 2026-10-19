import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { apiError, mockApi, renderApp } from "./harness";
import { caseRow, me } from "./fixtures";

const CASE = caseRow.case_id;

declare global {
  interface Window {
    __xss?: number;
  }
}

describe("case overview", () => {
  it("explains the priority with evidence and separates facts from hypotheses", async () => {
    mockApi();
    renderApp(`/cases/${CASE}`);
    expect(
      await screen.findByRole("heading", { name: "Aufnahme in privilegierte Gruppe: jonas.becker" }),
    ).toBeInTheDocument();
    expect(screen.getByText("+70")).toBeInTheDocument();
    expect(screen.getByText("-10")).toBeInTheDocument();
    expect(screen.getByText("Summe → P1", { exact: false })).toBeInTheDocument();
    expect(screen.getByText("KI-generiert, geprüft gegen Belege")).toBeInTheDocument();
    const summary = screen.getByTestId("case-summary");
    expect(within(summary).getByText(/40 failed logons for jonas.becker\./)).toBeInTheDocument();
    const hypothesis = summary.querySelector("[data-kind='hypothesis']");
    expect(hypothesis).toHaveTextContent("Password was guessed.");
    expect(hypothesis).toHaveTextContent("Konfidenz mittel");
    expect(within(summary).getByText(/Interview the account owner/)).toBeInTheDocument();
    expect(within(summary).getByText("VPN logs")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "1 verworfene KI-Aussage anzeigen" }));
    expect(screen.getByTestId("rejected-statements")).toHaveTextContent("unknown indicator 198.51.100.99");
    expect(screen.getByTestId("injection-notice")).toHaveTextContent("ignore previous instructions");
    expect(screen.getAllByRole("link", { name: "E1" }).length).toBeGreaterThan(0);
  });

  it("proposes an action with a simulation notice and records notes and status", async () => {
    const { calls } = mockApi();
    renderApp(`/cases/${CASE}`);
    await screen.findByText("Empfohlene nächste Schritte");
    await userEvent.click(screen.getByRole("button", { name: "Maßnahme vorschlagen" }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByTestId("simulation-notice")).toBeInTheDocument();
    expect(within(dialog).getByRole("button", { name: "Vorschlag einreichen" })).toBeDisabled();
    await userEvent.type(within(dialog).getByLabelText("Begründung"), "Kompromittiert");
    await userEvent.click(within(dialog).getByRole("button", { name: "Vorschlag einreichen" }));
    await waitFor(() => {
      expect(calls.some((c) => c.path === `/api/v1/cases/${CASE}/actions` && c.method === "POST")).toBe(true);
    });
    const proposal = calls.find((c) => c.path === `/api/v1/cases/${CASE}/actions`);
    expect(proposal?.body).toEqual({
      step_id: "DISABLE_ACCOUNT",
      parameters: { user: "jonas.becker" },
      reason: "Kompromittiert",
      source: "playbook",
    });

    await userEvent.type(screen.getByLabelText("Notiz hinzufügen"), "Rückruf erfolgt");
    await userEvent.click(screen.getByRole("button", { name: "Notiz hinzufügen" }));
    await userEvent.selectOptions(screen.getByLabelText("Status"), "in_progress");
    await userEvent.click(screen.getByRole("button", { name: "Mir zuweisen" }));
    await userEvent.click(screen.getByRole("button", { name: "Neu erzeugen" }));
    await waitFor(() => {
      expect(calls.filter((c) => c.method !== "GET").map((c) => c.path)).toEqual(
        expect.arrayContaining([
          `/api/v1/cases/${CASE}/notes`,
          `/api/v1/cases/${CASE}`,
          `/api/v1/cases/${CASE}/ai-summaries`,
        ]),
      );
    });
    const patches = calls.filter((c) => c.method === "PATCH").map((c) => c.body);
    expect(patches).toEqual([{ status: "in_progress" }, { assignee: me.username }]);
  });

  it("approves only with a reason, executes approved actions in simulation and shows refusals", async () => {
    const { calls } = mockApi({
      "POST /api/v1/actions/a-approved/execute": apiError(403, "approval signature invalid"),
    });
    renderApp(`/cases/${CASE}`);
    const list = await screen.findByTestId("actions-list");
    expect(within(list).getByTestId("execution-result")).toHaveTextContent("SIMULATION (nothing was changed)");
    await userEvent.click(within(list).getByRole("button", { name: "Prüfen und entscheiden" }));
    const dialog = await screen.findByTestId("approval-dialog");
    expect(within(dialog).getByTestId("simulation-notice")).toBeInTheDocument();
    expect(within(dialog).getByText("jonas.becker")).toBeInTheDocument();
    expect(within(dialog).getByRole("button", { name: "Freigeben" })).toBeDisabled();
    await userEvent.type(within(dialog).getByLabelText("Begründung der Entscheidung (Pflicht)"), "Belege eindeutig");
    await userEvent.click(within(dialog).getByRole("button", { name: "Freigeben" }));
    await waitFor(() => {
      expect(calls.find((c) => c.path === "/api/v1/actions/a-proposed/decision")?.body).toEqual({
        decision: "approved",
        reason: "Belege eindeutig",
      });
    });
    await userEvent.click(within(list).getByRole("button", { name: "Ausführen (Simulation)" }));
    expect(await screen.findByText("approval signature invalid")).toBeInTheDocument();
  });

  it("warns about the four-eyes principle for own proposals", async () => {
    mockApi({
      "GET /api/v1/auth/me": { ...me, username: "demo.analyst" },
    });
    renderApp(`/cases/${CASE}`);
    const list = await screen.findByTestId("actions-list");
    await userEvent.click(within(list).getByRole("button", { name: "Prüfen und entscheiden" }));
    expect(
      await screen.findByText(/Vier-Augen-Prinzip: Sie haben diese Maßnahme selbst vorgeschlagen/),
    ).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText("Begründung der Entscheidung (Pflicht)"), "nein");
    await userEvent.click(screen.getByRole("button", { name: "Ablehnen" }));
  });

  it("hides write controls for read-only roles", async () => {
    mockApi({ "GET /api/v1/auth/me": { ...me, roles: ["auditor"], permissions: ["cases:read", "actions:read"] } });
    renderApp(`/cases/${CASE}`);
    await screen.findByText("Empfohlene nächste Schritte");
    expect(screen.queryByRole("button", { name: "Maßnahme vorschlagen" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Prüfen und entscheiden" })).not.toBeInTheDocument();
    expect(screen.getByLabelText("Status")).toBeDisabled();
    expect(screen.queryByLabelText("Notiz hinzufügen")).not.toBeInTheDocument();
  });
});

describe("case timeline", () => {
  it("lists events, alerts, gaps and quality notes; filters by lane and triggers", async () => {
    mockApi();
    renderApp(`/cases/${CASE}/timeline`);
    const list = await screen.findByTestId("timeline-list");
    expect(within(list).getAllByText(/logon-failed/).length).toBeGreaterThan(0);
    expect(within(list).getByText("Zeitlücke von 10 Minuten")).toBeInTheDocument();
    expect(within(list).getByText("Uhrzeitversatz vermutet")).toBeInTheDocument();
    expect(within(list).getByText(/Alarm: SO-PRIV-001/)).toBeInTheDocument();
    expect(screen.getByTestId("swimlanes")).toBeInTheDocument();
    expect(screen.getByText("4 von 4 Einträgen", { exact: false })).toBeInTheDocument();
    await userEvent.click(screen.getByLabelText("Nur auslösende Events"));
    expect(screen.getByText(/3 von 4 Einträgen/)).toBeInTheDocument();
    await userEvent.click(screen.getByLabelText("Nur auslösende Events"));
    await userEvent.selectOptions(screen.getByLabelText("Spur"), "host:dc01");
    expect(screen.getByText(/3 von 4 Einträgen/)).toBeInTheDocument();
    await userEvent.keyboard("1");
  });
});

describe("case evidence", () => {
  it("shows rule YAML, matched fields and raw lines as text (no script execution)", async () => {
    mockApi();
    renderApp(`/cases/${CASE}/evidence`);
    const alerts = await screen.findAllByTestId("alert-evidence");
    expect(alerts).toHaveLength(2);
    const first = alerts[0]!;
    const yaml = within(first).getByTestId("rule-yaml");
    expect(yaml.querySelectorAll("[data-marked]").length).toBeGreaterThan(0);
    expect(within(first).getByTestId("explanation")).toHaveTextContent("gte 15");
    expect(within(first).getByText("logon-failed", { selector: "mark" })).toBeInTheDocument();
    expect(within(first).getByText("jonas.becker", { selector: "mark" })).toBeInTheDocument();
    // hostile content stays text
    expect(first.querySelector("img")).toBeNull();
    expect(first.querySelector("script")).toBeNull();
    expect(within(first).getByText(/<script>window.__xss=2<\/script>/)).toBeInTheDocument();
    expect(window.__xss).toBeUndefined();
    const second = alerts[1]!;
    expect(within(second).getByText("Neues Netz")).toBeInTheDocument();
    expect(within(second).getByText(/Kollege im Urlaub/)).toBeInTheDocument();
    expect(within(second).getByText(/3 weitere nicht angezeigt/)).toBeInTheDocument();
    expect(within(second).getByText("Keine Rohzeile gespeichert.")).toBeInTheDocument();
    expect(within(second).getByText(/Lizenz DRL 1.1/)).toBeInTheDocument();
  });

  it("marks a false positive and proposes an exception (A4 flow)", async () => {
    const { calls } = mockApi();
    renderApp(`/cases/${CASE}/evidence`);
    const first = (await screen.findAllByTestId("alert-evidence"))[0]!;
    await userEvent.click(within(first).getByRole("button", { name: "Als Fehlalarm markieren" }));
    let dialog = await screen.findByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Grund"), "Wartungsfenster");
    await userEvent.click(within(dialog).getByRole("button", { name: "Als Fehlalarm markieren" }));
    await waitFor(() => {
      expect(calls.find((c) => c.path.endsWith("/false-positive"))?.body).toEqual({ reason: "Wartungsfenster" });
    });
    await userEvent.click(within(first).getByRole("button", { name: "Ausnahme vorschlagen" }));
    dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByLabelText("Bedingung (Feld=Wert, eine je Zeile)")).toHaveValue("user.name=jonas.becker");
    const submit = within(dialog).getByRole("button", { name: "Ausnahme vorschlagen" });
    expect(submit).toBeDisabled();
    await userEvent.type(within(dialog).getByLabelText("Begründung (mind. 10 Zeichen)"), "Testkonto der IT-Abteilung");
    await userEvent.click(submit);
    await waitFor(() => {
      expect(calls.find((c) => c.path === "/api/v1/exceptions" && c.method === "POST")?.body).toEqual({
        rule_id: "SO-AUTH-001",
        description: "Testkonto der IT-Abteilung",
        match: { "user.name": "jonas.becker" },
        expires: "2026-06-10",
      });
    });
  });

  it("shows API errors in dialogs", async () => {
    mockApi({
      [`POST /api/v1/alerts/1354f92262121a9db3481caa77742537/false-positive`]: apiError(422, "reason too short"),
    });
    renderApp(`/cases/${CASE}/evidence#E1`);
    const first = (await screen.findAllByTestId("alert-evidence"))[0]!;
    await userEvent.click(within(first).getByRole("button", { name: "Als Fehlalarm markieren" }));
    const dialog = await screen.findByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Grund"), "abc");
    await userEvent.click(within(dialog).getByRole("button", { name: "Als Fehlalarm markieren" }));
    expect(await within(dialog).findByText("reason too short")).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole("button", { name: "Abbrechen" }));
  });
});

describe("case graph and report", () => {
  it("shows node details and links to cases with the entity", async () => {
    mockApi();
    const { router } = renderApp(`/cases/${CASE}/graph`);
    expect(await screen.findByText("Knoten anklicken, um Details zu sehen.")).toBeInTheDocument();
    // the graph component is loaded lazily (components/LazyCanvas.tsx)
    await userEvent.click(await screen.findByRole("button", { name: "select-node" }));
    expect(screen.getByText(/40 Ereignisse/)).toBeInTheDocument();
    expect(screen.getByText("Verbindungen (Ereignisse)")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Fälle mit dieser Entität" }));
    await waitFor(() => {
      expect(router.state.location.search).toMatchObject({ entity: "jonas.becker" });
    });
  });

  it("previews the report (pseudonymised on request) and exports files", async () => {
    const { calls } = mockApi();
    renderApp(`/cases/${CASE}/report`);
    const preview = await screen.findByTestId("report-preview");
    expect(preview.querySelector("img")).toBeNull();
    expect(within(preview).getByText(/und 2 weitere Belege/)).toBeInTheDocument();
    expect(within(preview).getByText(/Apache-2.0/)).toBeInTheDocument();
    await userEvent.click(screen.getByLabelText(/Pseudonymisiert/));
    await waitFor(() => {
      expect(calls.some((c) => c.path.endsWith("/report") && c.query.get("pseudonymize") === "true")).toBe(true);
    });
    expect(
      calls.every(
        (c) => !c.path.endsWith("/report") || c.query.get("preview") === "true" || c.query.get("format") !== "json",
      ),
    ).toBe(true);
    URL.createObjectURL = () => "blob:x";
    URL.revokeObjectURL = () => undefined;
    await userEvent.click(screen.getByRole("button", { name: "PDF" }));
    await waitFor(() => {
      expect(calls.some((c) => c.path.endsWith("/report") && c.query.get("format") === "pdf")).toBe(true);
    });
  });
});
