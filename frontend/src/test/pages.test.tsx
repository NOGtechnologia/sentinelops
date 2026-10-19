import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { apiError, mockApi, renderApp } from "./harness";

describe("rules", () => {
  it("lists rules with hits, false positive rate, maturity and origin; filters", async () => {
    mockApi();
    renderApp("/rules");
    const table = await screen.findByRole("table", { name: "Regeln" });
    expect(within(table).getByText("25 %")).toBeInTheDocument();
    expect(within(table).getByText("experimentell")).toBeInTheDocument();
    expect(within(table).getByText("inaktiv")).toBeInTheDocument();
    expect(within(table).getByText(/SigmaHQ \(Florian Roth\)/)).toBeInTheDocument();
    await userEvent.selectOptions(screen.getByLabelText("Herkunft"), "sigmahq");
    expect(within(table).getAllByRole("row")).toHaveLength(2);
    await userEvent.selectOptions(screen.getByLabelText("Herkunft"), "");
    await userEvent.type(screen.getByLabelText("Regel suchen"), "brute");
    expect(within(table).getAllByRole("row")).toHaveLength(2);
  });

  it("shows a rule with tests, versions and exceptions; toggles with a reason; approves exceptions", async () => {
    const { calls } = mockApi();
    renderApp("/rules/SO-AUTH-001");
    expect(await screen.findByText("SO-AUTH-001 · v1")).toBeInTheDocument();
    expect(screen.getByText("Alarm erwartet")).toBeInTheDocument();
    expect(screen.getByText("kein Alarm erwartet")).toBeInTheDocument();
    expect(screen.getByTestId("rule-yaml")).toHaveTextContent("gte: 15");
    expect(await screen.findByText("Monitoring account svc_monitor")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Ausnahme genehmigen" }));
    await userEvent.click(screen.getByRole("button", { name: "Regel deaktivieren" }));
    const dialog = await screen.findByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Begründung"), "Zu viele Fehlalarme");
    await userEvent.click(within(dialog).getByRole("button", { name: "Speichern" }));
    await waitFor(() => {
      expect(calls.find((c) => c.method === "PATCH" && c.path === "/api/v1/rules/SO-AUTH-001")?.body).toEqual({
        active: false,
        reason: "Zu viele Fehlalarme",
      });
    });
    expect(calls.some((c) => c.path === "/api/v1/exceptions/EXC-1001/approve")).toBe(true);
  });

  it("reports a four-eyes refusal when approving an own exception", async () => {
    mockApi({ "POST /api/v1/exceptions/EXC-1001/approve": apiError(403, "four-eyes principle") });
    renderApp("/rules/SO-AUTH-001");
    await userEvent.click(await screen.findByRole("button", { name: "Ausnahme genehmigen" }));
    expect(await screen.findByText("four-eyes principle")).toBeInTheDocument();
  });
});

describe("data quality", () => {
  it("shows shares, error codes, runs and quarantine (escaped) and reprocesses", async () => {
    const { calls } = mockApi();
    renderApp("/quality");
    expect(await screen.findByText("abgeschnitten", { exact: false })).toBeInTheDocument();
    const quarantine = await screen.findByTestId("quarantine");
    expect(quarantine.querySelector("img")).toBeNull();
    expect(within(quarantine).getByText(/<img src=x/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Neu verarbeiten" }));
    expect(await screen.findByText("5 Datensätze neu verarbeitet.")).toBeInTheDocument();
    await userEvent.selectOptions(screen.getByLabelText("Nach Fehlercode filtern"), "TRUNCATED");
    await waitFor(() => {
      expect(calls.some((c) => c.path === "/api/v1/quality/quarantine" && c.query.get("code") === "TRUNCATED")).toBe(
        true,
      );
    });
  });

  it("uploads a file with source type and time zone", async () => {
    const { calls } = mockApi();
    renderApp("/quality");
    const file = new File(["Mar 12 10:00:00 srv sshd[1]: Accepted password for anna"], "auth.log", {
      type: "text/plain",
    });
    await userEvent.upload(await screen.findByLabelText("Datei"), file);
    await userEvent.selectOptions(screen.getByLabelText("Quelltyp"), "syslog_3164");
    await userEvent.click(screen.getByRole("button", { name: "Hochladen und verarbeiten" }));
    expect(await screen.findByText(/13 übernommen/)).toBeInTheDocument();
    const upload = calls.find((c) => c.path === "/api/v1/uploads");
    expect(upload?.body).toBeInstanceOf(FormData);
    expect((upload?.body as FormData).get("source_type")).toBe("syslog_3164");
  });

  it("shows upload errors", async () => {
    mockApi({ "POST /api/v1/uploads": apiError(422, "unknown source type") });
    renderApp("/quality");
    await userEvent.upload(await screen.findByLabelText("Datei"), new File(["x"], "x.log"));
    await userEvent.click(screen.getByRole("button", { name: "Hochladen und verarbeiten" }));
    expect(await screen.findByText("unknown source type")).toBeInTheDocument();
  });
});

describe("events", () => {
  const hostile = "/usr/bin/echo <script>window.__xss=3</script> javascript:alert(document.domain)";
  const row = {
    "event.id": "ev1",
    "@timestamp": "2026-03-12T08:20:00.000000Z",
    "event.action": "sudo-exec",
    "event.outcome": "success",
    "event.time_quality": "assumed_timezone",
    "user.name": "www-data",
    "host.name": "srv-web01",
    "process.command_line": hostile,
    "log.source_type": "syslog_3164",
    assessment: "normal",
  };

  it("searches by user/host/IP, shows raw lines and command lines as text and exports CSV", async () => {
    const { calls } = mockApi({
      "GET /api/v1/events": {
        offset: 0,
        items: [
          row,
          {
            ...row,
            "event.id": "ev2",
            "event.outcome": "failure",
            assessment: "suspicious",
            "process.command_line": undefined,
          },
        ],
      },
      "GET /api/v1/events/ev1": {
        event: row,
        assessment: "normal",
        raw: { text: `sudo: ${hostile}`, position: 1, run_id: "r" },
      },
      "GET /api/v1/events/export.csv": new Response('"timestamp"\n', {
        status: 200,
        headers: { "Content-Disposition": 'attachment; filename="events.csv"' },
      }),
    });
    const { router } = renderApp("/events?user=www");
    const table = await screen.findByRole("table", { name: "Ereignisse" });
    expect(within(table).getByText("verdächtig")).toBeInTheDocument();
    expect(within(table).getAllByText("Zeitzone angenommen")).toHaveLength(2);
    await userEvent.click(within(table).getAllByRole("button", { name: "Rohzeile" })[0]!);
    const raw = await screen.findByTestId("event-raw");
    expect(raw.querySelector("script")).toBeNull();
    expect(raw.querySelector("a")).toBeNull();
    expect(within(raw).getByText(hostile)).toBeInTheDocument();
    await userEvent.click(within(table).getByRole("button", { name: "Schließen" }));
    await userEvent.type(screen.getByLabelText("IP-Adresse"), "203.0.113.45");
    await userEvent.selectOptions(screen.getByLabelText("Bewertung"), "suspicious");
    await userEvent.click(screen.getByRole("button", { name: "Suchen" }));
    await waitFor(() => {
      expect(router.state.location.search).toMatchObject({ user: "www", ip: "203.0.113.45", assessment: "suspicious" });
    });
    URL.createObjectURL = () => "blob:x";
    URL.revokeObjectURL = () => undefined;
    await userEvent.click(screen.getByRole("button", { name: "CSV exportieren" }));
    await waitFor(() => {
      expect(calls.some((c) => c.path === "/api/v1/events/export.csv")).toBe(true);
    });
  });

  it("shows an empty result and export errors", async () => {
    mockApi({
      "GET /api/v1/events": { offset: 0, items: [] },
      "GET /api/v1/events/export.csv": apiError(403, "forbidden"),
    });
    renderApp("/events");
    expect(await screen.findByText("Keine Ereignisse für diese Suche")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "CSV exportieren" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("forbidden");
  });
});

describe("entities, audit and administration", () => {
  it("pivots entities by type and search and explains hub reasons", async () => {
    const { calls } = mockApi();
    const { router } = renderApp("/entities");
    const table = await screen.findByRole("table", { name: "Entitäten" });
    expect(within(table).getByText(/konfiguriert/)).toBeInTheDocument();
    expect(within(table).getByText(/automatisch: distinct_users>=25 \(40\)/)).toBeInTheDocument();
    expect(within(table).getByText("privilegiert")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Gerät" }));
    await userEvent.type(screen.getByLabelText("Suche"), "dc{Enter}");
    await waitFor(() => {
      expect(
        calls.some((c) => c.path === "/api/v1/entities" && c.query.get("type") === "host" && c.query.get("q") === "dc"),
      ).toBe(true);
    });
    await userEvent.click(within(table).getAllByRole("link", { name: "Fälle anzeigen" })[0]!);
    await waitFor(() => {
      expect(router.state.location.search).toMatchObject({ entity: "dc01" });
    });
  });

  it("filters the audit log and verifies the hash chain", async () => {
    const { calls } = mockApi();
    renderApp("/audit");
    expect(await screen.findByText("report.exported")).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText("Objekt-ID"), "case-1{Enter}");
    await userEvent.click(screen.getByRole("button", { name: "Hash-Kette prüfen" }));
    expect(await screen.findByText("Hash-Kette vollständig gültig.")).toBeInTheDocument();
    expect(calls.some((c) => c.path === "/api/v1/audit" && c.query.get("object_id") === "case-1")).toBe(true);
  });

  it("reports a broken hash chain", async () => {
    mockApi({ "GET /api/v1/audit": { items: [], chain_broken_at: [4] } });
    renderApp("/audit");
    await userEvent.click(await screen.findByRole("button", { name: "Hash-Kette prüfen" }));
    expect(await screen.findByText("Hash-Kette unterbrochen bei Eintrag 4.")).toBeInTheDocument();
  });

  it("creates and revokes ingest tokens, manages sources and runs an analysis", async () => {
    const { calls } = mockApi();
    renderApp("/admin");
    expect(await screen.findByText("Firewall")).toBeInTheDocument();
    expect(screen.getByText("widerrufen")).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText("Name des Tokens"), "Proxy");
    await userEvent.click(screen.getByRole("button", { name: "Token erzeugen" }));
    expect(await screen.findByText("soi_t2_testsecretvalue")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Widerrufen" }));
    await userEvent.type(screen.getByLabelText("Name der Quelle"), "Syslog DMZ");
    await userEvent.click(screen.getByRole("button", { name: "Hinzufügen" }));
    await userEvent.click(screen.getByRole("button", { name: "Entfernen" }));
    await userEvent.click(screen.getByRole("button", { name: "Analyse jetzt starten" }));
    expect(await screen.findByText("Analyse-Job 7 eingereiht.")).toBeInTheDocument();
    expect(screen.getByText(/"provider": "none"/)).toBeInTheDocument();
    expect(screen.getByText("Demo Senior")).toBeInTheDocument();
    const writes = calls.filter((c) => c.method !== "GET").map((c) => `${c.method} ${c.path}`);
    expect(writes).toEqual(
      expect.arrayContaining([
        "POST /api/v1/admin/ingest-tokens",
        "DELETE /api/v1/admin/ingest-tokens/t1",
        "POST /api/v1/admin/sources",
        "DELETE /api/v1/admin/sources/s1",
        "POST /api/v1/admin/analysis",
      ]),
    );
    expect(calls.find((c) => c.path === "/api/v1/admin/sources" && c.method === "POST")?.body).toEqual({
      name: "Syslog DMZ",
      source_type: "syslog_3164",
      timezone: "Europe/Berlin",
    });
  });

  it("shows admin errors", async () => {
    mockApi({
      "POST /api/v1/admin/ingest-tokens": apiError(422, "name too short"),
      "POST /api/v1/admin/sources": apiError(409, "a source with this name exists"),
      "GET /api/v1/admin/sources": { items: [], source_types: ["syslog_3164"] },
    });
    renderApp("/admin");
    await userEvent.type(await screen.findByLabelText("Name des Tokens"), "abc");
    await userEvent.click(screen.getByRole("button", { name: "Token erzeugen" }));
    expect(await screen.findByText("name too short")).toBeInTheDocument();
    expect(screen.getByText("Noch keine Datenquellen angelegt.")).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText("Name der Quelle"), "VPN");
    await userEvent.click(screen.getByRole("button", { name: "Hinzufügen" }));
    expect(await screen.findByText("a source with this name exists")).toBeInTheDocument();
  });
});
