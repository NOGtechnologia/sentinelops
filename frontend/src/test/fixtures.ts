/* Compact, fictitious API responses (Musterfirma GmbH, RFC 5737 addresses) for component tests. */
import type {
  AuthConfig,
  CaseDetail,
  CaseReport,
  CaseSummaryRow,
  Dashboard,
  Evidence,
  GraphData,
  Me,
  RuleDetail,
  RuleRow,
  TimelineItem,
} from "../api/types";

export const XSS = '<img src=x onerror="window.__xss=1">';

export const authConfig: AuthConfig = {
  demo_mode: true,
  demo_users: [
    { id: "analyst", name: "Demo Analyst (L1)", roles: ["analyst"] },
    { id: "senior", name: "Demo Senior Analyst (L2)", roles: ["senior_analyst"] },
  ],
  oidc_issuer: null,
  oidc_client_id: "sentinelops-web",
  display_timezone: "Europe/Berlin",
};

const ALL = [
  "dashboard:read",
  "cases:read",
  "cases:write",
  "cases:merge",
  "alerts:read",
  "alerts:false_positive",
  "events:read",
  "entities:read",
  "rules:read",
  "rules:write",
  "exceptions:read",
  "exceptions:propose",
  "exceptions:approve",
  "actions:read",
  "actions:propose",
  "actions:decide",
  "actions:execute",
  "reports:export",
  "quality:read",
  "quality:reprocess",
  "ingest:write",
  "audit:read",
  "admin:manage",
  "analysis:run",
  "ai:generate",
];

export const me: Me = {
  subject: "demo-senior",
  username: "demo.senior",
  display_name: "Demo Senior Analyst (L2)",
  roles: ["senior_analyst"],
  permissions: ALL,
};

export const version = {
  product: "SentinelOps",
  version: "1.0.0",
  demo_mode: true,
  demo_now: "2026-03-12T09:30:00.000000Z",
};

export const dashboard: Dashboard = {
  generated_at: "2026-03-12T09:30:00.000000Z",
  data_as_of: "2026-03-12T09:29:00.000000Z",
  last_analysis: "2026-03-12T09:30:00.000000Z",
  kpis: { events_today: 14044, alerts_24h: 9, open_cases: { P1: 3, P2: 2, P3: 4, P4: 1 }, mean_minutes_to_action: 42 },
  series: {
    events_24h: [{ t: "2026-03-11T10:00:00.000000Z", n: 2100 }],
    events_7d: [{ t: "2026-03-09T00:00:00.000000Z", n: 50000 }],
    alerts_24h: [{ t: "2026-03-12T02:00:00.000000Z", n: 3 }],
    alerts_7d: [{ t: "2026-03-12T00:00:00.000000Z", n: 9 }],
  },
  top_rules: [
    {
      rule_id: "SO-AUTH-001",
      title: "Brute force against a single account",
      title_de: "Brute Force auf ein Konto",
      alerts: 4,
    },
  ],
  top_entities: [{ type: "host", display: "DC01.musterfirma.example", cases: 4 }],
  ingestion: [
    {
      source_type: "windows_xml",
      last_run: "2026-03-12T09:30:00.000000Z",
      accepted: 1835,
      duplicate: 0,
      malformed: 4,
      failed_runs: 1,
    },
  ],
  learning_users: 12,
};

export const caseRow: CaseSummaryRow = {
  case_id: "01b71a9b2cca06d6448c5d699a1e0b00",
  title: "Member added to a privileged group: jonas.becker",
  title_de: "Aufnahme in privilegierte Gruppe: jonas.becker",
  status: "new",
  priority: "P1",
  score: 100,
  assignee: null,
  window_start: "2026-03-12T02:10:49.000000Z",
  window_end: "2026-03-12T02:21:17.000000Z",
  related_case_ids: ["0d7316dd9e5bc3f159376a454cc3527b"],
  tactics: ["credential-access", "persistence"],
  rule_ids: ["SO-AUTH-001", "SO-AUTH-003", "SO-PRIV-001", "SO-PRIV-002"],
  created_at: "2026-03-12T09:30:00.000000Z",
  updated_at: "2026-03-12T09:30:00.000000Z",
  first_action_at: null,
  closed_at: null,
  entities: [
    { type: "user", key: "jonas.becker", display: "jonas.becker" },
    { type: "ip", key: "203.0.113.45", display: "203.0.113.45" },
    { type: "host", key: "srv-gw01", display: "SRV-GW01.musterfirma.example" },
    { type: "host", key: "dc01", display: "DC01.musterfirma.example" },
    { type: "host", key: "attacker", display: XSS },
  ],
  alert_count: 5,
  prompt_injection: true,
};

export const secondCase: CaseSummaryRow = {
  ...caseRow,
  case_id: "0d7316dd9e5bc3f159376a454cc3527b",
  title: "Brute force against a single account",
  title_de: "Brute Force auf ein Konto",
  priority: "P3",
  score: 40,
  status: "in_progress",
  assignee: "demo.analyst",
  related_case_ids: [],
  prompt_injection: false,
  entities: [{ type: "user", key: "anna.schmidt", display: "anna.schmidt" }],
  alert_count: 1,
};

const E1 = "380b753c4b04a17cbab8a33b50c4df1f";
const E2 = "253e3412a0f80578279428a1c3e35433";

export const alert = {
  alert_id: "1354f92262121a9db3481caa77742537",
  rule_id: "SO-AUTH-001",
  rule_version: 1,
  rule_hash: "c17b0ec6",
  kind: "correlation",
  title: "Brute force against a single account",
  title_de: "Brute Force auf ein Konto",
  level: "high" as const,
  maturity: "stable",
  tactics: ["credential-access"],
  techniques: ["T1110.001"],
  event_ids: [E1],
  window_start: "2026-03-12T02:10:49.000000Z",
  window_end: "2026-03-12T02:13:25.000000Z",
  group_key: { "user.name": "jonas.becker" },
  entities: caseRow.entities,
  explanation: {
    type: "event_count",
    group_by: { "user.name": "jonas.becker" },
    observed: 40,
    condition: "gte 15",
    matched: [{ field: "event.action", actual: "logon-failed", expected: "logon-failed", detection: "selection" }],
    not_matched_filters: ["filter_service"],
  },
  thresholds: { op: "gte", count: 15 },
  related_alert_ids: [],
  suppressed_by: null,
  privilege_change: false,
  success_after_failures: false,
  false_positive: false,
};

export const baselineAlert = {
  ...alert,
  alert_id: "b2",
  rule_id: "SO-AUTH-005",
  kind: "baseline",
  title: "Unusual logon",
  title_de: "Ungewöhnliche Anmeldung",
  level: "medium" as const,
  event_ids: [E2],
  false_positive: true,
  false_positive_reason: "Kollege im Urlaub",
  explanation: {
    type: "baseline",
    criteria: [
      { criterion: "new_network", detail: "203.0.113.0/24 not in ['198.51.100.0/24']" },
      { criterion: "unusual_hour", detail: "03:13 outside 07:17-17:15" },
    ],
  },
};

export const caseDetail: CaseDetail = {
  case: {
    ...caseRow,
    recommendations: [
      {
        step_id: "VERIFY_ACCOUNT_ACTIVITY",
        title_de: "Kontoaktivität prüfen",
        title_en: "Verify account activity",
        action: false,
        targets: { user: ["jonas.becker"] },
        evidence: [E1],
        reason_rules: ["SO-AUTH-001"],
      },
      {
        step_id: "DISABLE_ACCOUNT",
        title_de: "Konto sperren",
        title_en: "Disable account",
        action: true,
        targets: { user: ["jonas.becker"] },
        evidence: [E1, E2],
        reason_rules: ["SO-AUTH-003"],
      },
    ],
    injection_findings: [
      { event_id: E1, field: "user.name", pattern: "ignore_instructions", excerpt: "ignore previous instructions" },
    ],
  },
  priority: {
    score: 100,
    level: "P1",
    factors: [
      {
        code: "max_severity",
        contribution: 70,
        label_de: "Höchster Regel-Schweregrad: critical",
        label_en: "Highest rule severity: critical",
        evidence: [E2],
      },
      {
        code: "experimental",
        contribution: -10,
        label_de: "Experimentelle Regel",
        label_en: "Experimental rule",
        evidence: [],
      },
    ],
  },
  evidence_refs: { [E1]: "E1", [E2]: "E2" },
  entities: caseRow.entities,
  alerts: [alert, baselineAlert],
  summary: {
    version: 2,
    case_id: caseRow.case_id,
    source: "ai",
    provider: "ollama",
    model: "llama3.1",
    prompt_version: "case-summary/1",
    validation_status: "partially_valid",
    evidence_hash: "abc",
    created_at: "2026-03-12T09:30:00.000000Z",
    pseudonymized: false,
    output: {
      summary: "40 failed logons for jonas.becker from 203.0.113.45, then success.",
      facts: [{ statement: "40 failed logons for jonas.becker.", evidence: ["E1"] }],
      hypotheses: [
        {
          statement: "Password was guessed.",
          confidence: "medium",
          evidence: ["E2"],
          would_confirm: "Interview the account owner",
        },
      ],
      missing_information: [{ item: "VPN logs", why_relevant: "Show the session source" }],
      recommended_steps: [],
    },
    rejected: [
      {
        section: "facts",
        statement: "Host 198.51.100.99 was compromised.",
        reasons: ["unknown indicator 198.51.100.99"],
      },
    ],
    error: null,
    injection_findings: [],
  },
  summary_versions: [
    { version: 2, created_at: "2026-03-12T09:30:00.000000Z", provider: "mock", validation_status: "partially_valid" },
  ],
  actions: [
    {
      action_id: "a-proposed",
      case_id: caseRow.case_id,
      step_id: "DISABLE_ACCOUNT",
      parameters: { user: "jonas.becker" },
      proposed_by: "demo.analyst",
      proposed_at: "2026-03-12T09:31:00.000000Z",
      source: "playbook",
      reason: "Account compromised",
      status: "proposed",
      execution: null,
      approval: null,
    },
    {
      action_id: "a-approved",
      case_id: caseRow.case_id,
      step_id: "BLOCK_SOURCE_IP",
      parameters: { ip: "203.0.113.45" },
      proposed_by: "demo.senior",
      proposed_at: "2026-03-12T09:32:00.000000Z",
      source: "analyst",
      reason: "Attacker address",
      status: "approved",
      execution: null,
      approval: {
        decision: "approved",
        approver: "demo.lead",
        reason: "ok",
        decided_at: "2026-03-12T09:33:00.000000Z",
      },
    },
    {
      action_id: "a-executed",
      case_id: caseRow.case_id,
      step_id: "ISOLATE_HOST",
      parameters: { host: "srv-gw01" },
      proposed_by: "demo.analyst",
      proposed_at: "2026-03-12T09:34:00.000000Z",
      source: "analyst",
      reason: "Contain",
      status: "executed",
      execution: {
        success: true,
        connector: "simulation",
        details: "SIMULATION (nothing was changed): would isolate host srv-gw01",
      },
      approval: {
        decision: "approved",
        approver: "demo.senior2",
        reason: "ok",
        decided_at: "2026-03-12T09:35:00.000000Z",
      },
    },
  ],
  notes: [
    {
      note_id: "n1",
      case_id: caseRow.case_id,
      author: "demo.analyst",
      text: "Owner is on holiday.",
      created_at: "2026-03-12T09:36:00.000000Z",
    },
  ],
  merges: [],
  event_count: 43,
};

export const timeline: TimelineItem[] = [
  {
    kind: "event",
    time: "2026-03-12T02:10:49.000000Z",
    id: E1,
    action: "logon-failed",
    outcome: "failure",
    code: "4625",
    user: "jonas.becker",
    target_user: null,
    host: "SRV-GW01.musterfirma.example",
    source_ip: "203.0.113.45",
    time_quality: "exact",
    quality_flags: [],
    rules: ["SO-AUTH-001"],
    lanes: ["user:jonas.becker", "ip:203.0.113.45"],
  },
  { kind: "gap", time: "2026-03-12T02:11:00.000000Z", seconds: 600, until: "2026-03-12T02:21:00.000000Z" },
  {
    kind: "event",
    time: "2026-03-12T02:20:17.000000Z",
    id: E2,
    action: "user-added-to-group",
    outcome: "success",
    code: "4728",
    user: "jonas.becker",
    target_user: "jonas.becker",
    host: "DC01.musterfirma.example",
    source_ip: null,
    time_quality: "clock_skew_suspected",
    quality_flags: [],
    rules: [],
    lanes: ["user:jonas.becker", "host:dc01"],
  },
  {
    kind: "alert",
    time: "2026-03-12T02:21:00.000000Z",
    rule_id: "SO-PRIV-001",
    title_de: "Aufnahme in privilegierte Gruppe",
    title: "Member added",
  },
];

export const evidence: Evidence = {
  refs: { [E1]: "E1", [E2]: "E2" },
  alerts: [
    {
      ...alert,
      rule: {
        rule_id: "SO-AUTH-001",
        version: 1,
        uuid: "u",
        title: alert.title,
        title_de: alert.title_de,
        description: "d",
        description_de: "d",
        level: "high",
        maturity: "stable",
        tactics: [],
        techniques: [],
        falsepositives: [],
        playbooks: [],
        author: "SentinelOps",
        source: "custom",
        kind: "correlation",
        file: "correlations/so-auth-001.yml",
        content_hash: "c17b",
        yaml: "title: Brute force\ncorrelation:\n  type: event_count\n  condition:\n    gte: 15\n",
      },
      events: [
        {
          ref: "E1",
          event_id: E1,
          time: "2026-03-12T02:10:49.000000Z",
          fields: {
            "event.code": "4625",
            "user.name": "jonas.becker",
            "source.ip": "203.0.113.45",
            "event.category": ["authentication"],
          },
          raw: `Failed logon for jonas.becker from 203.0.113.45 ${XSS} <script>window.__xss=2</script>`,
        },
      ],
      events_truncated: 0,
    },
    {
      ...baselineAlert,
      rule: {
        rule_id: "SO-AUTH-005",
        version: 1,
        uuid: "u5",
        title: "Unusual logon",
        title_de: "Ungewöhnliche Anmeldung",
        description: "d",
        description_de: "d",
        level: "medium",
        maturity: "experimental",
        tactics: [],
        techniques: [],
        falsepositives: [],
        playbooks: [],
        author: "Florian Roth",
        source: "sigmahq",
        kind: "baseline",
        file: "baselines/so-auth-005.yml",
        content_hash: "x",
        yaml: "title: Unusual logon\n",
      },
      events: [{ ref: "E2", event_id: E2, time: "2026-03-12T02:20:17.000000Z", fields: {}, raw: null }],
      events_truncated: 3,
    },
  ],
};

export const graph: GraphData = {
  nodes: [
    { id: "user:jonas.becker", type: "user", label: "jonas.becker", hub: false, events: 40 },
    { id: "ip:203.0.113.45", type: "ip", label: "203.0.113.45", hub: false, events: 41 },
    { id: "host:dc01", type: "host", label: "DC01.musterfirma.example", hub: true, events: 2 },
  ],
  edges: [
    { source: "user:jonas.becker", target: "ip:203.0.113.45", weight: 40 },
    { source: "user:jonas.becker", target: "host:dc01", weight: 2 },
  ],
};

export const report: CaseReport = {
  metadata: { created_at: "2026-03-12T09:30:00.000000Z", events_hash: "e1", report_schema: "case-report/1" },
  case: { ...caseRow },
  priority: caseDetail.priority,
  alerts: [alert],
  timeline,
  evidence: Array.from({ length: 12 }, (_, i) => ({
    ref: `E${i + 1}`,
    event_id: `ev${i}`,
    time: "2026-03-12T02:10:49.000000Z",
    raw: i === 0 ? XSS : `line ${i}`,
  })),
  ai_summary: caseDetail.summary,
  injection_findings: [],
  recommendations: caseDetail.case.recommendations,
  rules: [{ rule_id: "SO-AUTH-001", version: 1, source: "custom", author: "SentinelOps", license: "Apache-2.0" }],
  actions: [],
  notes: [],
};

export const rules: RuleRow[] = [
  {
    ...evidence.alerts[0]!.rule,
    active: true,
    alerts: 4,
    false_positive_alerts: 1,
    false_positive_rate: 0.25,
  },
  {
    ...evidence.alerts[1]!.rule,
    active: false,
    alerts: 0,
    false_positive_alerts: 0,
    false_positive_rate: null,
  },
];

export const ruleDetail: RuleDetail = {
  ...evidence.alerts[0]!.rule,
  active: true,
  versions: [{ version: 1, content_hash: "c17b0ec60f2f3a84", created_at: "2026-03-12T09:30:00.000000Z" }],
  tests: [
    { name: "15 failures", expect: "alert", events: 15 },
    { name: "14 failures", expect: "no_alert", events: 14 },
  ],
  recent_alerts: [
    { alert_id: "x", window_start: "2026-03-12T02:10:49.000000Z", event_count: 40, false_positive: true },
  ],
};

export const exceptions = [
  {
    id: "EXC-1001",
    version: 1,
    rule_id: "SO-AUTH-001",
    description: "Monitoring account svc_monitor",
    match: { "user.name": "svc_monitor" },
    created_by: "demo.engineer",
    approved_by: null,
    expires: "2026-06-30",
    status: "proposed",
    origin: "database",
  },
];
