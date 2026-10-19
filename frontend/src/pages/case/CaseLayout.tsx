import { Link, Outlet, useNavigate, useParams, useRouterState } from "@tanstack/react-router";
import { ChevronLeft } from "lucide-react";
import { useTranslation } from "react-i18next";

import { useCase, useUpdateCase } from "../../api/hooks";
import type { CaseDetail, CaseStatus } from "../../api/types";
import { useAuth } from "../../auth/AuthProvider";
import { EntityChip, Tag } from "../../components/Badges";
import { PriorityBadge } from "../../components/Priority";
import { QueryView } from "../../components/States";
import { Time } from "../../components/Time";
import { cn } from "../../lib/cn";
import { useHotkeys } from "../../lib/hotkeys";

const STATUSES: CaseStatus[] = [
  "new",
  "in_progress",
  "resolved_true_positive",
  "resolved_false_positive",
  "resolved_benign",
];
const TABS = [
  { to: "/cases/$caseId", key: "overview" },
  { to: "/cases/$caseId/timeline", key: "timeline" },
  { to: "/cases/$caseId/evidence", key: "evidence" },
  { to: "/cases/$caseId/graph", key: "graph" },
  { to: "/cases/$caseId/report", key: "report" },
] as const;

export function CaseLayout() {
  const { caseId } = useParams({ from: "/cases/$caseId" });
  const query = useCase(caseId);
  return <QueryView query={query}>{(data) => <CaseFrame data={data} />}</QueryView>;
}

function CaseFrame({ data }: { data: CaseDetail }) {
  const { t, i18n } = useTranslation();
  const { me, can } = useAuth();
  const navigate = useNavigate();
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  const update = useUpdateCase(data.case.case_id);
  const c = data.case;
  const caseId = c.case_id;

  useHotkeys(
    Object.fromEntries(
      TABS.map((tab, index) => [String(index + 1), () => void navigate({ to: tab.to, params: { caseId } })]),
    ),
  );

  const activeTab =
    TABS.find((tab) => tab.to !== "/cases/$caseId" && pathname.endsWith(tab.to.split("/").pop() ?? ""))?.key ??
    "overview";

  return (
    <>
      <Link to="/cases" className="link mb-3 inline-flex items-center gap-1 text-sm">
        <ChevronLeft aria-hidden className="size-4" />
        {t("case.backToQueue")}
      </Link>
      <header className="card mb-4 p-4">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0 flex-1">
            <div className="mb-2 flex flex-wrap items-center gap-2">
              <PriorityBadge level={data.priority.level} large />
              <span className="tabular text-sm text-muted">
                {t("case.score")} <strong className="text-text">{data.priority.score}</strong>/100
              </span>
              <span className="font-mono text-xs text-muted">{caseId}</span>
            </div>
            <h1 className="text-xl font-bold tracking-tight">{i18n.language === "de" ? c.title_de : c.title}</h1>
            <p className="mt-1 text-sm text-muted">
              <Time value={c.window_start} seconds /> – <Time value={c.window_end} seconds /> ·{" "}
              {t("case.alerts", { count: data.alerts.length })} · {t("case.events", { count: data.event_count })}
            </p>
            <div className="mt-2 flex flex-wrap gap-1">
              {data.entities.map((e) => (
                <EntityChip
                  key={`${e.type}:${e.key}`}
                  entity={e}
                  onClick={(entity) => void navigate({ to: "/cases", search: { entity: entity.key } })}
                />
              ))}
            </div>
            {c.tactics.length > 0 && (
              <div className="mt-2 flex flex-wrap gap-1">
                {c.tactics.map((tactic) => (
                  <Tag key={tactic} tone="accent">
                    {t(`tactics.${tactic}`, { defaultValue: tactic })}
                  </Tag>
                ))}
              </div>
            )}
          </div>
          <div className="flex w-full flex-col gap-2 sm:w-64">
            <label htmlFor="case-status" className="label">
              {t("case.status")}
            </label>
            <select
              id="case-status"
              className="input"
              value={c.status}
              disabled={!can("cases:write") || update.isPending}
              onChange={(event) => {
                update.mutate({ status: event.target.value as CaseStatus });
              }}
            >
              {STATUSES.map((s) => (
                <option key={s} value={s}>
                  {t(`status.${s}`)}
                </option>
              ))}
            </select>
            <p className="text-xs text-muted">
              {t("case.assignee")}: <span className="text-text">{c.assignee ?? t("queue.unassigned")}</span>
            </p>
            {can("cases:write") && me && c.assignee !== me.username && (
              <button
                type="button"
                className="btn btn-sm"
                disabled={update.isPending}
                onClick={() => {
                  update.mutate({ assignee: me.username });
                }}
              >
                {t("queue.assignToMe")}
              </button>
            )}
          </div>
        </div>
      </header>

      <nav aria-label={t("case.sections")} className="mb-4 flex gap-1 overflow-x-auto overflow-y-hidden border-b border-border">
        {TABS.map((tab, index) => (
          <Link
            key={tab.key}
            to={tab.to}
            params={{ caseId }}
            className={cn(
              "-mb-px border-b-2 px-3 py-2 text-sm whitespace-nowrap",
              activeTab === tab.key
                ? "border-accent font-semibold text-accent"
                : "border-transparent text-muted hover:text-text",
            )}
            aria-current={activeTab === tab.key ? "page" : undefined}
          >
            {t(`case.tab.${tab.key}`)} <kbd className="ml-1 hidden text-[10px] text-muted lg:inline">{index + 1}</kbd>
          </Link>
        ))}
      </nav>
      <Outlet />
    </>
  );
}
