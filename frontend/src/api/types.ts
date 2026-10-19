/**
 * Response models of the SentinelOps API.
 *
 * Paths, parameters and request bodies are generated from OpenAPI (`schema.d.ts`). Many responses are
 * typed as free-form objects in OpenAPI, so their shape is described here; the end-to-end tests run the
 * UI against the real API, which keeps these types honest.
 */

export type Priority = "P1" | "P2" | "P3" | "P4";
export type CaseStatus =
  "new" | "in_progress" | "resolved_true_positive" | "resolved_false_positive" | "resolved_benign";
export type Level = "informational" | "low" | "medium" | "high" | "critical";
export type EntityType = "user" | "host" | "ip";

export interface Entity {
  type: EntityType;
  key: string;
  display: string;
}

export interface AuthConfig {
  demo_mode: boolean;
  demo_users: { id: string; name: string; roles: string[] }[];
  oidc_issuer: string | null;
  oidc_client_id: string;
  display_timezone: string;
}

export interface Me {
  subject: string;
  username: string;
  display_name: string;
  roles: string[];
  permissions: string[];
}

export interface VersionInfo {
  product: string;
  version: string;
  demo_mode: boolean;
  demo_now: string | null;
}

export interface SeriesPoint {
  t: string;
  n: number;
}

export interface Dashboard {
  generated_at: string;
  data_as_of: string | null;
  last_analysis: string | null;
  kpis: {
    events_today: number;
    alerts_24h: number;
    open_cases: Record<Priority, number>;
    mean_minutes_to_action: number | null;
  };
  series: { events_24h: SeriesPoint[]; events_7d: SeriesPoint[]; alerts_24h: SeriesPoint[]; alerts_7d: SeriesPoint[] };
  top_rules: { rule_id: string; title: string; title_de: string; alerts: number }[];
  top_entities: { type: EntityType; display: string; cases: number }[];
  ingestion: {
    source_type: string;
    last_run: string | null;
    accepted: number;
    duplicate: number;
    malformed: number;
    failed_runs: number;
  }[];
  learning_users: number;
}

export interface CaseSummaryRow {
  case_id: string;
  title: string;
  title_de: string;
  status: CaseStatus;
  priority: Priority;
  score: number;
  assignee: string | null;
  window_start: string;
  window_end: string;
  related_case_ids: string[];
  tactics: string[];
  rule_ids: string[];
  created_at: string;
  updated_at: string;
  first_action_at: string | null;
  closed_at: string | null;
  entities: Entity[];
  alert_count: number;
  prompt_injection: boolean;
}

export interface Page<T> {
  total: number;
  offset: number;
  limit?: number;
  items: T[];
}

export interface PriorityFactor {
  code: string;
  contribution: number;
  label_de: string;
  label_en: string;
  evidence: string[];
}

export interface Recommendation {
  step_id: string;
  title_de: string;
  title_en: string;
  action: boolean;
  targets: Partial<Record<EntityType, string[]>>;
  evidence: string[];
  reason_rules: string[];
}

export interface InjectionFinding {
  event_id: string;
  field: string;
  pattern: string;
  excerpt: string;
}

export interface MatchedItem {
  field: string;
  actual: unknown;
  expected: unknown;
  detection: string;
}

export interface Explanation {
  type: string;
  matched?: MatchedItem[];
  not_matched_filters?: string[];
  group_by?: Record<string, unknown>;
  observed?: number;
  condition?: string;
  criteria?: { criterion: string; detail: string }[];
  [key: string]: unknown;
}

export interface Alert {
  alert_id: string;
  rule_id: string;
  rule_version: number;
  rule_hash: string;
  kind: string;
  title: string;
  title_de: string;
  level: Level;
  maturity: string;
  tactics: string[];
  techniques: string[];
  event_ids: string[];
  window_start: string;
  window_end: string;
  group_key: Record<string, string>;
  entities: Entity[];
  explanation: Explanation;
  thresholds: Record<string, unknown>;
  related_alert_ids: string[];
  suppressed_by: string | null;
  privilege_change: boolean;
  success_after_failures: boolean;
  false_positive: boolean;
  false_positive_reason?: string | null;
  case_id?: string;
}

export interface SummaryOutput {
  summary: string;
  facts: { statement: string; evidence: string[] }[];
  hypotheses: { statement: string; confidence: "low" | "medium" | "high"; evidence: string[]; would_confirm: string }[];
  missing_information: { item: string; why_relevant: string }[];
  recommended_steps: { playbook_step_id: string; rationale: string; evidence: string[] }[];
}

export interface Summary {
  version: number;
  case_id: string;
  source: "template" | "ai";
  provider: string;
  model: string;
  prompt_version: string;
  validation_status: string;
  evidence_hash: string;
  created_at: string;
  pseudonymized: boolean;
  output: SummaryOutput | null;
  rejected: { section: string; statement: string; reasons: string[] }[];
  error: string | null;
  injection_findings: InjectionFinding[];
}

export interface Approval {
  decision: "approved" | "rejected";
  approver: string;
  reason: string;
  decided_at: string;
}

export interface Action {
  action_id: string;
  case_id: string;
  step_id: string;
  parameters: Record<string, string>;
  proposed_by: string;
  proposed_at: string;
  source: "analyst" | "playbook" | "ai";
  reason: string;
  status: "proposed" | "approved" | "rejected" | "executed" | "failed" | "cancelled";
  execution: { success: boolean; connector: string; details: string } | null;
  approval?: Approval | null;
}

export interface Note {
  note_id: string;
  case_id: string;
  author: string;
  text: string;
  created_at: string;
}

export interface CaseDetail {
  case: CaseSummaryRow & { recommendations: Recommendation[]; injection_findings: InjectionFinding[] };
  priority: { score: number; level: Priority; factors: PriorityFactor[] };
  evidence_refs: Record<string, string>;
  entities: Entity[];
  alerts: Alert[];
  summary: Summary | null;
  summary_versions: { version: number; created_at: string; provider: string; validation_status: string }[];
  actions: Action[];
  notes: Note[];
  merges: { merge_id: string; kind: string; source_case_id: string; target_case_id: string; created_at: string }[];
  event_count: number;
}

export interface TimelineItem {
  kind: "event" | "alert" | "gap";
  time: string;
  id?: string;
  action?: string;
  outcome?: string;
  code?: string | null;
  user?: string | null;
  target_user?: string | null;
  host?: string | null;
  source_ip?: string | null;
  time_quality?: string;
  quality_flags?: string[];
  rules?: string[];
  lanes?: string[];
  rule_id?: string;
  title_de?: string;
  title?: string;
  level?: Level;
  seconds?: number;
  until?: string;
}

export interface RuleMeta {
  rule_id: string;
  version: number;
  uuid: string;
  title: string;
  title_de: string;
  description: string;
  description_de: string;
  level: Level;
  maturity: string;
  tactics: string[];
  techniques: string[];
  falsepositives: string[];
  playbooks: string[];
  author: string;
  source: "custom" | "sigmahq";
  kind: string;
  file: string;
  content_hash: string;
}

export interface EvidenceEvent {
  ref: string;
  event_id: string;
  time: string;
  fields: Record<string, unknown>;
  raw: string | null;
}

export interface EvidenceAlert extends Alert {
  rule: RuleMeta & { yaml: string };
  events: EvidenceEvent[];
  events_truncated: number; // evidence events not shown (more than 500)
}

export interface Evidence {
  alerts: EvidenceAlert[];
  refs: Record<string, string>;
}

export interface GraphData {
  nodes: { id: string; type: EntityType; label: string; hub: boolean; events: number }[];
  edges: { source: string; target: string; weight: number }[];
}

export interface RuleRow extends RuleMeta {
  active: boolean;
  alerts: number;
  false_positive_alerts: number;
  false_positive_rate: number | null;
}

export interface RuleDetail extends RuleMeta {
  yaml: string;
  active: boolean;
  versions: { version: number; content_hash: string; created_at: string }[];
  tests: { name: string; expect: string; events: number }[];
  recent_alerts: { alert_id: string; window_start: string; event_count: number; false_positive: boolean }[];
}

export interface RuleException {
  id: string;
  version: number;
  rule_id: string;
  description: string;
  match: Record<string, unknown>;
  created_by: string;
  approved_by: string | null;
  expires: string;
  status: string;
  origin: string;
}

export interface QualitySummary {
  runs: number;
  accepted: number;
  duplicate: number;
  malformed: number;
  error_codes: Record<string, number>;
  by_source: { source_type: string; accepted: number; duplicate: number; malformed: number }[];
}

export interface IngestRun {
  run_id: string;
  source_type: string;
  timezone: string;
  file_name: string;
  file_sha256: string;
  channel: string;
  status: string;
  accepted: number;
  duplicate: number;
  malformed: number;
  started_at: string;
  finished_at: string | null;
  duration_ms: number | null;
  error: string | null;
  created_by: string;
}

export interface QuarantineItem {
  raw_record_id: string;
  run_id: string;
  position: number;
  error_code: string;
  error_detail: string | null;
  error_position: number | null;
  content: string;
  file_name: string;
  source_type: string;
}

export interface AuditEntry {
  seq: number;
  ts: string;
  actor: string;
  action: string;
  object_type: string;
  object_id: string;
  details: Record<string, unknown>;
  prev_hash: string;
  hash: string;
}

export interface EntityRow extends Entity {
  first_seen: string;
  last_seen: string;
  privileged: boolean;
  critical: boolean;
  hub: boolean;
  hub_reason: string | null;
}

export interface IngestToken {
  token_id: string;
  name: string;
  created_by: string;
  created_at: string;
  revoked_at: string | null;
}

export interface SourceRow {
  source_id: string;
  name: string;
  source_type: string;
  timezone: string;
  created_at: string;
}

export interface UserRow {
  subject: string;
  username: string;
  display_name: string;
  first_login: string;
  last_login: string;
  roles: string[];
}

export interface CaseReport {
  metadata: Record<string, unknown>;
  case: CaseSummaryRow & { entities: Entity[] };
  priority: { score: number; level: Priority; factors: PriorityFactor[] };
  alerts: Alert[];
  timeline: TimelineItem[];
  evidence: { ref: string; event_id: string; time: string; raw: string }[];
  ai_summary: Summary | null;
  injection_findings: InjectionFinding[];
  recommendations: Recommendation[];
  rules: { rule_id: string; version: number; source: string; author: string; license: string }[];
  actions: Action[];
  notes: Note[];
}

/** A normalised event as returned by the event search (flat ECS field names). */
export interface EventRow {
  "event.id": string;
  "@timestamp": string;
  "event.action"?: string;
  "event.outcome"?: string;
  "event.code"?: string;
  "event.time_quality"?: string;
  "user.name"?: string;
  "host.name"?: string;
  "source.ip"?: string;
  "process.command_line"?: string;
  "log.source_type": string;
  assessment: "normal" | "suspicious";
  [field: string]: unknown;
}

export interface EventDetail {
  event: Record<string, unknown>;
  assessment: string;
  raw: { text: string; position: number; run_id: string } | null;
}

export interface UploadResult {
  run_id: string;
  status: string;
  accepted: number;
  duplicate: number;
  malformed: number;
  file_sha256: string;
  duration_ms: number;
}
