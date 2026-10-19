import { useNavigate, useSearch } from "@tanstack/react-router";
import { Download } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { download } from "../api/client";
import { useEvent, useEvents, type EventFilters } from "../api/hooks";
import type { EventRow } from "../api/types";
import { Tag } from "../components/Badges";
import { RawLine } from "../components/CodeView";
import { PageHeader } from "../components/Layout";
import { Empty, QueryView } from "../components/States";
import { Time } from "../components/Time";
import { cn } from "../lib/cn";

const FIELDS = ["q", "user", "host", "ip", "action"] as const;

/** Event search - pivot by user, host, IP and time (spec 7.2) with CSV export (spec 10). */
export function EventsPage() {
  const { t } = useTranslation();
  const search = useSearch({ from: "/events" });
  const navigate = useNavigate({ from: "/events" });
  const query = useEvents(search);
  const [draft, setDraft] = useState<EventFilters>(search);
  const [error, setError] = useState<string | null>(null);

  const apply = () => {
    const next: EventFilters = {};
    for (const key of [...FIELDS, "start", "end", "assessment"] as const) {
      const value = draft[key]?.trim();
      if (value) next[key] = value;
    }
    void navigate({ search: next });
  };

  return (
    <>
      <PageHeader
        title={t("events.title")}
        subtitle={t("events.subtitle")}
        actions={
          <button
            type="button"
            className="btn"
            onClick={() => {
              setError(null);
              download("/api/v1/events/export.csv", { query: { ...search, limit: 10000 } }, "events.csv").catch(
                (exc: unknown) => {
                  setError(exc instanceof Error ? exc.message : String(exc));
                },
              );
            }}
          >
            <Download aria-hidden className="size-4" />
            {t("events.exportCsv")}
          </button>
        }
      />
      {error && (
        <p role="alert" className="mb-3 text-sm text-danger">
          {error}
        </p>
      )}
      <form
        className="card mb-4 grid gap-3 p-3 sm:grid-cols-2 lg:grid-cols-4 xl:grid-cols-8"
        onSubmit={(event) => {
          event.preventDefault();
          apply();
        }}
      >
        {FIELDS.map((key) => (
          <div key={key} className={key === "q" ? "xl:col-span-2" : undefined}>
            <label htmlFor={`event-${key}`} className="label">
              {t(`events.filter.${key}`)}
            </label>
            <input
              id={`event-${key}`}
              className="input"
              value={draft[key] ?? ""}
              onChange={(e) => {
                setDraft((prev) => ({ ...prev, [key]: e.target.value }));
              }}
            />
          </div>
        ))}
        <div>
          <label htmlFor="event-assessment" className="label">
            {t("events.filter.assessment")}
          </label>
          <select
            id="event-assessment"
            className="input"
            value={draft.assessment ?? ""}
            onChange={(e) => {
              setDraft((prev) => ({ ...prev, assessment: e.target.value }));
            }}
          >
            <option value="">{t("common.all")}</option>
            <option value="suspicious">{t("events.assessment.suspicious")}</option>
            <option value="normal">{t("events.assessment.normal")}</option>
          </select>
        </div>
        <div className="flex items-end">
          <button type="submit" className="btn btn-primary w-full">
            {t("events.search")}
          </button>
        </div>
      </form>
      <QueryView query={query}>
        {(data) => (data.items.length === 0 ? <Empty title={t("events.empty")} /> : <EventsTable rows={data.items} />)}
      </QueryView>
    </>
  );
}

function EventsTable({ rows }: { rows: EventRow[] }) {
  const { t } = useTranslation();
  const [open, setOpen] = useState<string | null>(null);
  return (
    <div className="card overflow-x-auto">
      <p className="border-b border-border px-3 py-2 text-xs text-muted">{t("events.count", { count: rows.length })}</p>
      <table className="table text-xs" aria-label={t("events.title")}>
        <thead>
          <tr>
            <th scope="col">{t("events.col.time")}</th>
            <th scope="col">{t("events.col.action")}</th>
            <th scope="col">{t("entity.user")}</th>
            <th scope="col">{t("entity.host")}</th>
            <th scope="col">{t("entity.ip")}</th>
            <th scope="col">{t("events.col.source")}</th>
            <th scope="col">{t("events.col.assessment")}</th>
            <th scope="col">
              <span className="sr-only">{t("events.col.raw")}</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => {
            const id = row["event.id"];
            const expanded = open === id;
            return (
              <EventRowView
                key={id}
                row={row}
                expanded={expanded}
                onToggle={() => {
                  setOpen(expanded ? null : id);
                }}
              />
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function EventRowView({ row, expanded, onToggle }: { row: EventRow; expanded: boolean; onToggle: () => void }) {
  const { t } = useTranslation();
  return (
    <>
      <tr className={cn(row.assessment === "suspicious" && "bg-p2/5")}>
        <td className="whitespace-nowrap">
          <Time value={row["@timestamp"]} seconds />
          {row["event.time_quality"] && row["event.time_quality"] !== "exact" && (
            <div>
              <Tag tone="warn">
                {t(`timeQuality.${row["event.time_quality"]}`, { defaultValue: row["event.time_quality"] })}
              </Tag>
            </div>
          )}
        </td>
        <td className={cn("font-mono", row["event.outcome"] === "failure" && "text-danger")}>
          {row["event.action"]}
          {row["event.code"] ? ` (${row["event.code"]})` : ""}
        </td>
        <td className="max-w-48 font-mono break-all">{row["user.name"] ?? ""}</td>
        <td className="max-w-56 font-mono break-all">{row["host.name"] ?? ""}</td>
        <td className="font-mono">{row["source.ip"] ?? ""}</td>
        <td className="font-mono">{row["log.source_type"]}</td>
        <td>
          {row.assessment === "suspicious" ? (
            <Tag tone="warn">{t("events.assessment.suspicious")}</Tag>
          ) : (
            <Tag>{t("events.assessment.normal")}</Tag>
          )}
        </td>
        <td>
          <button type="button" className="btn btn-sm" aria-expanded={expanded} onClick={onToggle}>
            {expanded ? t("events.hideRaw") : t("events.showRaw")}
          </button>
        </td>
      </tr>
      {expanded && (
        <tr>
          <td colSpan={8}>
            <RawEvent id={row["event.id"]} commandLine={row["process.command_line"]} />
          </td>
        </tr>
      )}
    </>
  );
}

function RawEvent({ id, commandLine }: { id: string; commandLine: string | undefined }) {
  const { t } = useTranslation();
  const query = useEvent(id);
  return (
    <div className="flex flex-col gap-2 py-1" data-testid="event-raw">
      {commandLine && (
        <p className="text-xs">
          <span className="text-muted">{t("events.commandLine")}:</span>{" "}
          <code className="rounded bg-code px-1 font-mono break-all">{commandLine}</code>
        </p>
      )}
      <QueryView query={query}>{(data) => <RawLine text={data.raw?.text ?? ""} />}</QueryView>
    </div>
  );
}
