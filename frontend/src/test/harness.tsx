import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, RouterProvider } from "@tanstack/react-router";
import { render } from "@testing-library/react";
import { vi } from "vitest";

import { setAccessToken } from "../api/client";
import { makeRouter } from "../app/router";
import { ThemeProvider } from "../app/theme";
import { AuthProvider } from "../auth/AuthProvider";
import * as f from "./fixtures";

export interface Call {
  method: string;
  path: string;
  query: URLSearchParams;
  body: unknown;
}

type Handler = (call: Call) => unknown;
type Routes = Record<string, unknown>;

const CASE = f.caseRow.case_id;

export function defaultRoutes(): Routes {
  return {
    "GET /api/v1/auth/config": f.authConfig,
    "POST /api/v1/auth/demo-login": { access_token: "test-token", token_type: "bearer" },
    "GET /api/v1/auth/me": f.me,
    "GET /api/v1/version": f.version,
    "GET /api/v1/dashboard": f.dashboard,
    "GET /api/v1/cases": { total: 2, offset: 0, limit: 200, items: [f.caseRow, f.secondCase] },
    "PATCH /api/v1/cases/bulk": { updated: 1 },
    [`GET /api/v1/cases/${CASE}`]: f.caseDetail,
    [`PATCH /api/v1/cases/${CASE}`]: { ok: true },
    [`GET /api/v1/cases/${CASE}/timeline`]: { total: f.timeline.length, offset: 0, items: f.timeline },
    [`GET /api/v1/cases/${CASE}/evidence`]: f.evidence,
    [`GET /api/v1/cases/${CASE}/graph`]: f.graph,
    [`GET /api/v1/cases/${CASE}/report`]: f.report,
    [`POST /api/v1/cases/${CASE}/notes`]: { note_id: "n2" },
    [`POST /api/v1/cases/${CASE}/ai-summaries`]: f.caseDetail.summary,
    [`POST /api/v1/cases/${CASE}/actions`]: f.caseDetail.actions[0],
    "POST /api/v1/actions/a-proposed/decision": { status: "approved" },
    "POST /api/v1/actions/a-approved/execute": { status: "executed" },
    [`POST /api/v1/alerts/${f.alert.alert_id}/false-positive`]: { ok: true },
    "GET /api/v1/rules": f.rules,
    "GET /api/v1/rules/SO-AUTH-001": f.ruleDetail,
    "PATCH /api/v1/rules/SO-AUTH-001": { ok: true },
    "GET /api/v1/exceptions": f.exceptions,
    "POST /api/v1/exceptions": { exception_id: "EXC-1002", status: "proposed" },
    "POST /api/v1/exceptions/EXC-1001/approve": { exception_id: "EXC-1001", status: "active" },
    "GET /api/v1/quality/summary": {
      runs: 3,
      accepted: 1000,
      duplicate: 10,
      malformed: 5,
      error_codes: { TRUNCATED: 3, PARSE_ERROR: 2 },
      by_source: [{ source_type: "syslog_3164", accepted: 1000, duplicate: 10, malformed: 5 }],
    },
    "GET /api/v1/quality/runs": [
      {
        run_id: "r1",
        source_type: "syslog_3164",
        timezone: "Europe/Berlin",
        file_name: "quality/broken_auth.log",
        file_sha256: "aa",
        channel: "demo",
        status: "completed",
        accepted: 5,
        duplicate: 1,
        malformed: 5,
        started_at: "2026-03-12T09:30:00.000000Z",
        finished_at: "2026-03-12T09:30:00.000000Z",
        duration_ms: 156,
        error: null,
        created_by: "cli",
      },
    ],
    "GET /api/v1/quality/quarantine": {
      total: 1,
      items: [
        {
          raw_record_id: "q1",
          run_id: "r1",
          position: 5,
          error_code: "TRUNCATED",
          error_detail: "line ends before message",
          error_position: 25,
          content: f.XSS,
          file_name: "quality/broken_auth.log",
          source_type: "syslog_3164",
        },
      ],
    },
    "POST /api/v1/quality/runs/r1/reprocess": { reprocessed: 5 },
    "POST /api/v1/uploads": {
      run_id: "r9",
      status: "completed",
      accepted: 13,
      duplicate: 0,
      malformed: 0,
      file_sha256: "x",
      duration_ms: 5,
    },
    "GET /api/v1/entities": {
      items: [
        {
          type: "host",
          key: "dc01",
          display: "DC01.musterfirma.example",
          first_seen: "2026-03-09T00:00:00.000000Z",
          last_seen: "2026-03-12T09:00:00.000000Z",
          privileged: false,
          critical: true,
          hub: true,
          hub_reason: "configured",
        },
        {
          type: "ip",
          key: "10.20.0.5",
          display: "10.20.0.5",
          first_seen: "2026-03-09T00:00:00.000000Z",
          last_seen: "2026-03-12T09:00:00.000000Z",
          privileged: false,
          critical: false,
          hub: true,
          hub_reason: "distinct_users>=25 (40)",
        },
        {
          type: "user",
          key: "adm-schulz",
          display: "adm-schulz",
          first_seen: "2026-03-09T00:00:00.000000Z",
          last_seen: "2026-03-12T09:00:00.000000Z",
          privileged: true,
          critical: false,
          hub: false,
          hub_reason: null,
        },
      ],
    },
    "GET /api/v1/audit": (call: Call) => ({
      items: [
        {
          seq: 1,
          ts: "2026-03-12T09:30:00.000000Z",
          actor: "demo.senior",
          action: "report.exported",
          object_type: "case",
          object_id: CASE,
          details: { format: "pdf" },
          prev_hash: "0",
          hash: "1",
        },
      ],
      chain_broken_at: call.query.get("verify") === "true" ? [] : null,
    }),
    "GET /api/v1/admin/ingest-tokens": [
      {
        token_id: "t1",
        name: "Firewall",
        created_by: "demo.admin",
        created_at: "2026-03-12T09:30:00.000000Z",
        revoked_at: null,
      },
      {
        token_id: "t0",
        name: "Old",
        created_by: "demo.admin",
        created_at: "2026-03-10T09:30:00.000000Z",
        revoked_at: "2026-03-11T09:30:00.000000Z",
      },
    ],
    "POST /api/v1/admin/ingest-tokens": { token_id: "t2", token: "soi_t2_testsecretvalue", note: "once" },
    "DELETE /api/v1/admin/ingest-tokens/t1": undefined,
    "GET /api/v1/admin/sources": {
      items: [
        {
          source_id: "s1",
          name: "VPN",
          source_type: "json:musterfirma_vpn",
          timezone: "Europe/Berlin",
          created_at: "2026-03-12T09:30:00.000000Z",
        },
      ],
      source_types: ["syslog_3164", "json:musterfirma_vpn"],
    },
    "POST /api/v1/admin/sources": { source_id: "s2" },
    "DELETE /api/v1/admin/sources/s1": undefined,
    "GET /api/v1/admin/users": [
      {
        subject: "demo-senior",
        username: "demo.senior",
        display_name: "Demo Senior",
        first_login: "2026-03-12T09:30:00.000000Z",
        last_login: "2026-03-12T09:30:00.000000Z",
        roles: ["senior_analyst"],
      },
    ],
    "GET /api/v1/admin/settings": { ai: { provider: "none" }, retention_days: { events: 90 } },
    "POST /api/v1/admin/analysis": { job_id: 7 },
  };
}

export function mockApi(overrides: Routes = {}) {
  const routes: Routes = { ...defaultRoutes(), ...overrides };
  const calls: Call[] = [];
  const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(input instanceof Request ? input.url : input, "http://localhost");
    const method = (init?.method ?? "GET").toUpperCase();
    let body: unknown = undefined;
    if (typeof init?.body === "string") body = JSON.parse(init.body) as unknown;
    else if (init?.body instanceof FormData) body = init.body;
    const call: Call = { method, path: url.pathname, query: url.searchParams, body };
    calls.push(call);
    const key = `${method} ${url.pathname}`;
    if (!(key in routes)) {
      return Promise.resolve(new Response(JSON.stringify({ detail: `no mock for ${key}` }), { status: 404 }));
    }
    const value = routes[key];
    if (value instanceof Response) return Promise.resolve(value);
    const data = typeof value === "function" ? (value as Handler)(call) : value;
    if (data === undefined) return Promise.resolve(new Response(null, { status: 204 }));
    return Promise.resolve(
      new Response(JSON.stringify(data), { status: 200, headers: { "Content-Type": "application/json" } }),
    );
  });
  vi.stubGlobal("fetch", fetchMock);
  return { calls, fetchMock };
}

export function apiError(status: number, detail: string): Response {
  return new Response(JSON.stringify({ detail }), { status, headers: { "Content-Type": "application/json" } });
}

/** Render the whole application at ``path``, logged in as demo user ``user`` (or anonymous). */
export function renderApp(path: string, user: string | null = "senior") {
  setAccessToken(null);
  if (user) sessionStorage.setItem("sentinelops.demoUser", user);
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  const router = makeRouter(createMemoryHistory({ initialEntries: [path] }));
  const result = render(
    <ThemeProvider forced="dark">
      <QueryClientProvider client={queryClient}>
        <AuthProvider>
          <RouterProvider router={router} />
        </AuthProvider>
      </QueryClientProvider>
    </ThemeProvider>,
  );
  return { ...result, router, queryClient };
}
