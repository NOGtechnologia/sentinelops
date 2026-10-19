import { Link, useNavigate, useSearch } from "@tanstack/react-router";
import { AlertTriangle, Bot } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import { useBulkUpdate, useCases } from "../api/hooks";
import type { CaseStatus, CaseSummaryRow, Priority } from "../api/types";
import { useAuth } from "../auth/AuthProvider";
import { EntityChip, StatusBadge, Tag } from "../components/Badges";
import { PageHeader } from "../components/Layout";
import { PriorityBadge } from "../components/Priority";
import { SearchField } from "../components/SearchField";
import { Empty, QueryView } from "../components/States";
import { cn } from "../lib/cn";
import { age } from "../lib/format";
import { useHotkeys } from "../lib/hotkeys";
import { useNow } from "../lib/now";

export interface QueueSearch {
  status?: string[] | undefined;
  priority?: string[] | undefined;
  q?: string | undefined;
  entity?: string | undefined;
}

const PRIORITIES: Priority[] = ["P1", "P2", "P3", "P4"];
const STATUSES: CaseStatus[] = [
  "new",
  "in_progress",
  "resolved_true_positive",
  "resolved_false_positive",
  "resolved_benign",
];

function toggle(list: string[] | undefined, value: string): string[] | undefined {
  const current = new Set(list ?? []);
  if (current.has(value)) current.delete(value);
  else current.add(value);
  return current.size ? [...current] : undefined;
}

export function CaseQueuePage() {
  const { t } = useTranslation();
  const search = useSearch({ from: "/cases" });
  const navigate = useNavigate({ from: "/cases" });
  const query = useCases(search);

  const update = (patch: Partial<QueueSearch>) => void navigate({ search: (prev) => ({ ...prev, ...patch }) });

  return (
    <>
      <PageHeader title={t("queue.title")} subtitle={t("queue.subtitle")} />
      <div className="card mb-4 flex flex-wrap items-end gap-4 p-3">
        <SearchField
          key={search.q ?? ""}
          id="queue-q"
          className="min-w-56 flex-1"
          label={t("queue.searchTitle")}
          placeholder={t("queue.searchPlaceholder")}
          initial={search.q ?? ""}
          onSubmit={(value) => {
            update({ q: value || undefined });
          }}
        />
        <fieldset>
          <legend className="label">{t("queue.priority")}</legend>
          <div className="flex gap-1">
            {PRIORITIES.map((p) => (
              <button
                key={p}
                type="button"
                aria-pressed={search.priority?.includes(p) ?? false}
                className={cn(
                  "rounded-md border p-0.5",
                  search.priority?.includes(p) ? "border-accent" : "border-transparent",
                )}
                onClick={() => {
                  update({ priority: toggle(search.priority, p) });
                }}
              >
                <PriorityBadge level={p} />
              </button>
            ))}
          </div>
        </fieldset>
        <fieldset>
          <legend className="label">{t("queue.status")}</legend>
          <div className="flex flex-wrap gap-1">
            {STATUSES.map((s) => (
              <button
                key={s}
                type="button"
                aria-pressed={search.status?.includes(s) ?? false}
                className={cn(
                  "rounded-md border px-2 py-1 text-xs",
                  search.status?.includes(s) ? "border-accent bg-accent-soft text-accent" : "border-border text-muted",
                )}
                onClick={() => {
                  update({ status: toggle(search.status, s) });
                }}
              >
                {t(`status.${s}`)}
              </button>
            ))}
          </div>
        </fieldset>
        {(search.entity ?? search.q ?? search.status ?? search.priority) && (
          <button type="button" className="btn btn-sm" onClick={() => void navigate({ search: {} })}>
            {t("queue.resetFilters")}
          </button>
        )}
      </div>
      {search.entity && (
        <p className="mb-3 text-sm">
          {t("queue.filteredByEntity")} <span className="font-mono">{search.entity}</span>
        </p>
      )}
      <QueryView query={query}>{(data) => <CaseTable rows={data.items} total={data.total} />}</QueryView>
    </>
  );
}

function CaseTable({ rows, total }: { rows: CaseSummaryRow[]; total: number }) {
  const { t, i18n } = useTranslation();
  const { me, can } = useAuth();
  const navigate = useNavigate();
  const now = useNow();
  const bulk = useBulkUpdate();
  const [cursor, setCursor] = useState(0);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const rowRefs = useRef<(HTMLTableRowElement | null)[]>([]);
  const canWrite = can("cases:write");

  useEffect(() => {
    rowRefs.current[cursor]?.scrollIntoView({ block: "nearest" });
  }, [cursor]);

  const current = rows[cursor];
  const toggleSelected = (id: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };
  const assignToMe = (ids: string[]) => {
    if (!me || ids.length === 0) return;
    bulk.mutate({ case_ids: ids, assignee: me.username });
  };

  useHotkeys({
    j: () => {
      setCursor((c) => Math.min(rows.length - 1, c + 1));
    },
    k: () => {
      setCursor((c) => Math.max(0, c - 1));
    },
    Enter: () => {
      if (current) void navigate({ to: "/cases/$caseId", params: { caseId: current.case_id } });
    },
    x: () => {
      if (current) toggleSelected(current.case_id);
    },
    a: () => {
      if (canWrite && current) assignToMe(selected.size ? [...selected] : [current.case_id]);
    },
  });

  if (rows.length === 0) return <Empty title={t("queue.empty")} />;

  return (
    <div className="card overflow-x-auto">
      <div className="flex flex-wrap items-center gap-2 border-b border-border px-3 py-2 text-sm">
        <span className="text-muted">{t("queue.count", { shown: rows.length, total })}</span>
        {canWrite && selected.size > 0 && (
          <>
            <span className="ml-2 font-semibold">{t("queue.selected", { count: selected.size })}</span>
            <button
              type="button"
              className="btn btn-sm"
              onClick={() => {
                assignToMe([...selected]);
              }}
            >
              {t("queue.assignToMe")}
            </button>
            <button
              type="button"
              className="btn btn-sm"
              onClick={() => {
                bulk.mutate({ case_ids: [...selected], status: "in_progress" });
              }}
            >
              {t("queue.markInProgress")}
            </button>
            <button
              type="button"
              className="btn btn-sm"
              onClick={() => {
                setSelected(new Set());
              }}
            >
              {t("queue.clearSelection")}
            </button>
          </>
        )}
        <span className="ml-auto text-xs text-muted">{t("queue.keyboardHint")}</span>
      </div>
      <table className="table" aria-label={t("queue.title")}>
        <thead>
          <tr>
            {canWrite && (
              <th scope="col" className="w-8">
                <span className="sr-only">{t("queue.select")}</span>
              </th>
            )}
            <th scope="col">{t("queue.priority")}</th>
            <th scope="col">{t("queue.case")}</th>
            <th scope="col">{t("queue.entities")}</th>
            <th scope="col">{t("queue.rules")}</th>
            <th scope="col">{t("queue.tactics")}</th>
            <th scope="col">{t("queue.age")}</th>
            <th scope="col">{t("queue.assignee")}</th>
            <th scope="col">{t("queue.status")}</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row, index) => {
            const a = age(row.window_start, now);
            return (
              <tr
                key={row.case_id}
                ref={(el) => {
                  rowRefs.current[index] = el;
                }}
                data-selected={index === cursor}
                className="hover:bg-surface-2"
                onClick={() => {
                  setCursor(index);
                }}
              >
                {canWrite && (
                  <td>
                    <input
                      type="checkbox"
                      aria-label={t("queue.selectCase", { id: row.case_id.slice(0, 8) })}
                      checked={selected.has(row.case_id)}
                      onChange={() => {
                        toggleSelected(row.case_id);
                      }}
                    />
                  </td>
                )}
                <td>
                  <PriorityBadge level={row.priority} score={row.score} />
                </td>
                <td className="min-w-60">
                  <Link to="/cases/$caseId" params={{ caseId: row.case_id }} className="link font-semibold text-text">
                    {i18n.language === "de" ? row.title_de : row.title}
                  </Link>
                  <div className="mt-1 flex flex-wrap items-center gap-1.5 text-xs text-muted">
                    <span className="font-mono">{row.case_id.slice(0, 8)}</span>
                    <span>· {t("queue.alerts", { count: row.alert_count })}</span>
                    {row.prompt_injection && (
                      <span className="inline-flex items-center gap-1 text-warn">
                        <Bot aria-hidden className="size-3" />
                        {t("queue.promptInjection")}
                      </span>
                    )}
                    {row.related_case_ids.length > 0 && (
                      <span className="inline-flex items-center gap-1">
                        <AlertTriangle aria-hidden className="size-3" />
                        {t("queue.related", { count: row.related_case_ids.length })}
                      </span>
                    )}
                  </div>
                </td>
                <td>
                  <div className="flex max-w-64 flex-wrap gap-1">
                    {row.entities.slice(0, 3).map((e) => (
                      <EntityChip key={`${e.type}:${e.key}`} entity={e} />
                    ))}
                    {row.entities.length > 3 && <Tag>+{row.entities.length - 3}</Tag>}
                  </div>
                </td>
                <td>
                  <div className="flex max-w-36 flex-wrap gap-1">
                    {row.rule_ids.slice(0, 3).map((r) => (
                      <Tag key={r}>{r}</Tag>
                    ))}
                    {row.rule_ids.length > 3 && <Tag>+{row.rule_ids.length - 3}</Tag>}
                  </div>
                </td>
                <td>
                  <div className="flex max-w-40 flex-wrap gap-1">
                    {row.tactics.map((tactic) => (
                      <Tag key={tactic} tone="accent">
                        {t(`tactics.${tactic}`, { defaultValue: tactic })}
                      </Tag>
                    ))}
                  </div>
                </td>
                <td className="tabular whitespace-nowrap">{t(`common.age_${a.unit}`, { count: a.value })}</td>
                <td className="text-xs">
                  {row.assignee ?? <span className="text-muted">{t("queue.unassigned")}</span>}
                </td>
                <td>
                  <StatusBadge status={row.status} />
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
