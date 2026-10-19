import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api } from "./client";
import type {
  Action,
  AuditEntry,
  AuthConfig,
  CaseDetail,
  CaseReport,
  CaseStatus,
  CaseSummaryRow,
  Dashboard,
  EntityRow,
  EventDetail,
  EventRow,
  Evidence,
  GraphData,
  IngestRun,
  IngestToken,
  Me,
  Note,
  Page,
  QualitySummary,
  QuarantineItem,
  RuleDetail,
  RuleException,
  RuleRow,
  SourceRow,
  Summary,
  TimelineItem,
  UploadResult,
  UserRow,
  VersionInfo,
} from "./types";

export const keys = {
  authConfig: ["auth-config"] as const,
  me: ["me"] as const,
  version: ["version"] as const,
  dashboard: ["dashboard"] as const,
  cases: (filters: CaseFilters) => ["cases", filters] as const,
  case: (id: string) => ["case", id] as const,
  timeline: (id: string) => ["case", id, "timeline"] as const,
  evidence: (id: string) => ["case", id, "evidence"] as const,
  graph: (id: string) => ["case", id, "graph"] as const,
  report: (id: string) => ["case", id, "report"] as const,
  rules: ["rules"] as const,
  rule: (id: string) => ["rule", id] as const,
  exceptions: ["exceptions"] as const,
  quality: ["quality"] as const,
  runs: ["quality", "runs"] as const,
  quarantine: (code: string | undefined) => ["quality", "quarantine", code ?? ""] as const,
  entities: (type: string | undefined, q: string | undefined) => ["entities", type ?? "", q ?? ""] as const,
  audit: (objectId: string | undefined, verify: boolean) => ["audit", objectId ?? "", verify] as const,
  tokens: ["admin", "tokens"] as const,
  sources: ["admin", "sources"] as const,
  users: ["admin", "users"] as const,
  settings: ["admin", "settings"] as const,
};

export interface CaseFilters {
  status?: string[] | undefined;
  priority?: string[] | undefined;
  q?: string | undefined;
  entity?: string | undefined;
  assignee?: string | undefined;
}

// --- auth & system ------------------------------------------------------------------------------------

export const useAuthConfig = () =>
  useQuery({ queryKey: keys.authConfig, queryFn: () => api<AuthConfig>("/api/v1/auth/config"), staleTime: Infinity });

export const useMe = (enabled: boolean) =>
  useQuery({ queryKey: keys.me, queryFn: () => api<Me>("/api/v1/auth/me"), enabled, staleTime: 60_000 });

export const useVersion = () =>
  useQuery({ queryKey: keys.version, queryFn: () => api<VersionInfo>("/api/v1/version"), staleTime: Infinity });

export const useDashboard = () =>
  useQuery({ queryKey: keys.dashboard, queryFn: () => api<Dashboard>("/api/v1/dashboard"), refetchInterval: 60_000 });

// --- cases -------------------------------------------------------------------------------------------

export const useCases = (filters: CaseFilters) =>
  useQuery({
    queryKey: keys.cases(filters),
    queryFn: () =>
      api<Page<CaseSummaryRow>>("/api/v1/cases", {
        query: { ...filters, limit: 200 },
      }),
    placeholderData: keepPreviousData,
  });

export const useCase = (id: string) =>
  useQuery({
    queryKey: keys.case(id),
    queryFn: () => api<CaseDetail>("/api/v1/cases/{case_id}", { path: { case_id: id } }),
  });

export const useTimeline = (id: string) =>
  useQuery({
    queryKey: keys.timeline(id),
    queryFn: () =>
      api<Page<TimelineItem>>("/api/v1/cases/{case_id}/timeline", { path: { case_id: id }, query: { limit: 10000 } }),
  });

export const useEvidence = (id: string) =>
  useQuery({
    queryKey: keys.evidence(id),
    queryFn: () => api<Evidence>("/api/v1/cases/{case_id}/evidence", { path: { case_id: id } }),
  });

export const useGraph = (id: string) =>
  useQuery({
    queryKey: keys.graph(id),
    queryFn: () => api<GraphData>("/api/v1/cases/{case_id}/graph", { path: { case_id: id } }),
  });

export const useReport = (id: string, pseudonymize: boolean) =>
  useQuery({
    queryKey: [...keys.report(id), pseudonymize],
    queryFn: () =>
      api<CaseReport>("/api/v1/cases/{case_id}/report", {
        path: { case_id: id },
        query: { format: "json", pseudonymize, preview: true },
      }),
  });

function useInvalidateCase(id: string) {
  const client = useQueryClient();
  return () => {
    void client.invalidateQueries({ queryKey: ["case", id] });
    void client.invalidateQueries({ queryKey: ["cases"] });
    void client.invalidateQueries({ queryKey: keys.dashboard });
  };
}

export const useUpdateCase = (id: string) => {
  const invalidate = useInvalidateCase(id);
  return useMutation({
    mutationFn: (body: { status?: CaseStatus; assignee?: string }) =>
      api<{ status: string }>("/api/v1/cases/{case_id}", { method: "PATCH", path: { case_id: id }, body }),
    onSuccess: invalidate,
  });
};

export const useBulkUpdate = () => {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (body: { case_ids: string[]; status?: CaseStatus; assignee?: string }) =>
      api<{ updated: number }>("/api/v1/cases/bulk", { method: "PATCH", body }),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: ["cases"] });
      void client.invalidateQueries({ queryKey: ["case"] });
    },
  });
};

export const useAddNote = (id: string) => {
  const invalidate = useInvalidateCase(id);
  return useMutation({
    mutationFn: (text: string) =>
      api<Note>("/api/v1/cases/{case_id}/notes", { method: "POST", path: { case_id: id }, body: { text } }),
    onSuccess: invalidate,
  });
};

export const useRegenerateSummary = (id: string) => {
  const invalidate = useInvalidateCase(id);
  return useMutation({
    mutationFn: () => api<Summary>("/api/v1/cases/{case_id}/ai-summaries", { method: "POST", path: { case_id: id } }),
    onSuccess: invalidate,
  });
};

export const useMarkFalsePositive = (caseId: string) => {
  const invalidate = useInvalidateCase(caseId);
  return useMutation({
    mutationFn: ({ alertId, reason }: { alertId: string; reason: string }) =>
      api<unknown>("/api/v1/alerts/{alert_id}/false-positive", {
        method: "POST",
        path: { alert_id: alertId },
        body: { reason },
      }),
    onSuccess: invalidate,
  });
};

// --- actions -----------------------------------------------------------------------------------------

export const useProposeAction = (caseId: string) => {
  const invalidate = useInvalidateCase(caseId);
  return useMutation({
    mutationFn: (body: { step_id: string; parameters: Record<string, string>; reason: string; source?: string }) =>
      api<Action>("/api/v1/cases/{case_id}/actions", { method: "POST", path: { case_id: caseId }, body }),
    onSuccess: invalidate,
  });
};

export const useDecideAction = (caseId: string) => {
  const invalidate = useInvalidateCase(caseId);
  return useMutation({
    mutationFn: ({
      actionId,
      decision,
      reason,
    }: {
      actionId: string;
      decision: "approved" | "rejected";
      reason: string;
    }) =>
      api<Action>("/api/v1/actions/{action_id}/decision", {
        method: "POST",
        path: { action_id: actionId },
        body: { decision, reason },
      }),
    onSuccess: invalidate,
  });
};

export const useExecuteAction = (caseId: string) => {
  const invalidate = useInvalidateCase(caseId);
  return useMutation({
    mutationFn: (actionId: string) =>
      api<Action>("/api/v1/actions/{action_id}/execute", { method: "POST", path: { action_id: actionId } }),
    onSuccess: invalidate,
  });
};

// --- rules & exceptions ------------------------------------------------------------------------------

export const useRules = () => useQuery({ queryKey: keys.rules, queryFn: () => api<RuleRow[]>("/api/v1/rules") });

export const useRule = (id: string) =>
  useQuery({
    queryKey: keys.rule(id),
    queryFn: () => api<RuleDetail>("/api/v1/rules/{rule_id}", { path: { rule_id: id } }),
  });

export const useToggleRule = (id: string) => {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (body: { active: boolean; reason: string }) =>
      api<unknown>("/api/v1/rules/{rule_id}", { method: "PATCH", path: { rule_id: id }, body }),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: keys.rules });
      void client.invalidateQueries({ queryKey: keys.rule(id) });
    },
  });
};

export const useExceptions = () =>
  useQuery({ queryKey: keys.exceptions, queryFn: () => api<RuleException[]>("/api/v1/exceptions") });

export const useProposeException = () => {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (body: { rule_id: string; description: string; match: Record<string, string>; expires: string }) =>
      api<{ exception_id: string; status: string }>("/api/v1/exceptions", { method: "POST", body }),
    onSuccess: () => void client.invalidateQueries({ queryKey: keys.exceptions }),
  });
};

export const useApproveException = () => {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      api<{ exception_id: string; status: string }>("/api/v1/exceptions/{exception_id}/approve", {
        method: "POST",
        path: { exception_id: id },
      }),
    onSuccess: () => void client.invalidateQueries({ queryKey: keys.exceptions }),
  });
};

// --- data quality, entities, audit ---------------------------------------------------------------------

export const useQualitySummary = () =>
  useQuery({ queryKey: keys.quality, queryFn: () => api<QualitySummary>("/api/v1/quality/summary") });

export const useRuns = () =>
  useQuery({ queryKey: keys.runs, queryFn: () => api<IngestRun[]>("/api/v1/quality/runs", { query: { limit: 100 } }) });

export const useQuarantine = (code: string | undefined) =>
  useQuery({
    queryKey: keys.quarantine(code),
    queryFn: () => api<Page<QuarantineItem>>("/api/v1/quality/quarantine", { query: { code, limit: 200 } }),
  });

export const useReprocess = () => {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (runId: string) =>
      api<{ reprocessed: number }>("/api/v1/quality/runs/{run_id}/reprocess", {
        method: "POST",
        path: { run_id: runId },
      }),
    onSuccess: () => void client.invalidateQueries({ queryKey: keys.quality }),
  });
};

export const useUpload = () => {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (form: FormData) => api<UploadResult>("/api/v1/uploads", { method: "POST", form }),
    onSuccess: () => void client.invalidateQueries({ queryKey: keys.quality }),
  });
};

export interface EventFilters {
  q?: string | undefined;
  user?: string | undefined;
  host?: string | undefined;
  ip?: string | undefined;
  action?: string | undefined;
  start?: string | undefined;
  end?: string | undefined;
  assessment?: string | undefined;
}

export const useEvents = (filters: EventFilters) =>
  useQuery({
    queryKey: ["events", filters],
    queryFn: () => api<{ offset: number; items: EventRow[] }>("/api/v1/events", { query: { ...filters, limit: 200 } }),
    placeholderData: keepPreviousData,
  });

export const useEvent = (id: string) =>
  useQuery({
    queryKey: ["event", id],
    queryFn: () => api<EventDetail>("/api/v1/events/{event_id}", { path: { event_id: id } }),
  });

export const useEntities = (type: string | undefined, q: string | undefined) =>
  useQuery({
    queryKey: keys.entities(type, q),
    queryFn: () => api<Page<EntityRow>>("/api/v1/entities", { query: { type, q, limit: 200 } }),
    placeholderData: keepPreviousData,
  });

export const useAudit = (objectId: string | undefined, verify: boolean, enabled = true) =>
  useQuery({
    queryKey: keys.audit(objectId, verify),
    queryFn: () =>
      api<{ items: AuditEntry[]; chain_broken_at: number[] | null }>("/api/v1/audit", {
        query: { object_id: objectId, verify, limit: 200 },
      }),
    enabled,
  });

// --- administration ----------------------------------------------------------------------------------

export const useTokens = () =>
  useQuery({ queryKey: keys.tokens, queryFn: () => api<IngestToken[]>("/api/v1/admin/ingest-tokens") });

export const useCreateToken = () => {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (name: string) =>
      api<{ token_id: string; token: string; note: string }>("/api/v1/admin/ingest-tokens", {
        method: "POST",
        body: { name },
      }),
    onSuccess: () => void client.invalidateQueries({ queryKey: keys.tokens }),
  });
};

export const useRevokeToken = () => {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      api<undefined>("/api/v1/admin/ingest-tokens/{token_id}", { method: "DELETE", path: { token_id: id } }),
    onSuccess: () => void client.invalidateQueries({ queryKey: keys.tokens }),
  });
};

export const useSources = () =>
  useQuery({
    queryKey: keys.sources,
    queryFn: () => api<{ items: SourceRow[]; source_types: string[] }>("/api/v1/admin/sources"),
  });

export const useCreateSource = () => {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (body: { name: string; source_type: string; timezone: string }) =>
      api<SourceRow>("/api/v1/admin/sources", { method: "POST", body }),
    onSuccess: () => void client.invalidateQueries({ queryKey: keys.sources }),
  });
};

export const useDeleteSource = () => {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      api<undefined>("/api/v1/admin/sources/{source_id}", { method: "DELETE", path: { source_id: id } }),
    onSuccess: () => void client.invalidateQueries({ queryKey: keys.sources }),
  });
};

export const useUsers = () => useQuery({ queryKey: keys.users, queryFn: () => api<UserRow[]>("/api/v1/admin/users") });

export const useSettings = () =>
  useQuery({ queryKey: keys.settings, queryFn: () => api<Record<string, unknown>>("/api/v1/admin/settings") });

export const useTriggerAnalysis = () =>
  useMutation({ mutationFn: () => api<{ job_id: number }>("/api/v1/admin/analysis", { method: "POST" }) });
