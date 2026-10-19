import { Link } from "@tanstack/react-router";
import { useCallback, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";

import { useDashboard } from "../api/hooks";
import type { Dashboard, Priority } from "../api/types";
import { EntityIcon } from "../components/Badges";
import type { ChartSeries } from "../components/Chart";
import { TimeChart } from "../components/LazyCanvas";
import { Kpi, PageHeader, Section } from "../components/Layout";
import { PriorityBadge } from "../components/Priority";
import { QueryView } from "../components/States";
import { Time } from "../components/Time";
import { locale } from "../i18n";
import { formatDateTime, formatNumber } from "../lib/format";

const PRIORITIES: Priority[] = ["P1", "P2", "P3", "P4"];

export function DashboardPage() {
  const query = useDashboard();
  return <QueryView query={query}>{(data) => <DashboardView data={data} />}</QueryView>;
}

function DashboardView({ data }: { data: Dashboard }) {
  const { t, i18n } = useTranslation();
  const loc = locale(i18n.language);
  const [range, setRange] = useState<"24h" | "7d">("24h");

  const series = useMemo<ChartSeries[]>(() => {
    const events = range === "24h" ? data.series.events_24h : data.series.events_7d;
    const alerts = range === "24h" ? data.series.alerts_24h : data.series.alerts_7d;
    return [
      { name: t("dashboard.events"), type: "line", color: "--accent", data: events.map((p) => [p.t, p.n]) },
      { name: t("dashboard.alerts"), type: "bar", color: "--p2", axis: 1, data: alerts.map((p) => [p.t, p.n]) },
    ];
  }, [data, range, t]);

  const formatAxis = useCallback(
    (iso: string) => (range === "24h" ? formatDateTime(iso, loc).slice(-5) : formatDateTime(iso, loc).slice(0, 6)),
    [range, loc],
  );

  const openTotal = PRIORITIES.reduce((sum, p) => sum + data.kpis.open_cases[p], 0);
  const asOf = (
    <>
      {t("common.dataAsOf")} <Time value={data.data_as_of} />
    </>
  );

  return (
    <>
      <PageHeader
        title={t("dashboard.title")}
        subtitle={
          <>
            {asOf} · {t("dashboard.lastAnalysis")} <Time value={data.last_analysis} />
          </>
        }
      />

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Kpi
          label={t("dashboard.eventsToday")}
          value={formatNumber(data.kpis.events_today, loc)}
          hint={t("dashboard.periodToday")}
        />
        <Kpi
          label={t("dashboard.alerts24h")}
          value={formatNumber(data.kpis.alerts_24h, loc)}
          hint={t("dashboard.period24h")}
        />
        <div className="card p-4">
          <p className="text-xs font-semibold text-muted uppercase">{t("dashboard.openCases")}</p>
          <p className="tabular mt-1 text-2xl font-bold">{formatNumber(openTotal, loc)}</p>
          <ul className="mt-2 flex flex-wrap gap-1.5" aria-label={t("dashboard.openByPriority")}>
            {PRIORITIES.map((p) => (
              <li key={p}>
                <Link
                  to="/cases"
                  search={{ priority: [p], status: ["new", "in_progress"] }}
                  className="inline-flex items-center gap-1"
                >
                  <PriorityBadge level={p} />
                  <span className="tabular text-sm font-semibold">{data.kpis.open_cases[p]}</span>
                </Link>
              </li>
            ))}
          </ul>
        </div>
        <Kpi
          label={t("dashboard.meanTimeToAction")}
          value={
            data.kpis.mean_minutes_to_action === null
              ? "–"
              : t("dashboard.minutes", { count: Math.round(data.kpis.mean_minutes_to_action) })
          }
          hint={t("dashboard.allCases")}
        />
      </div>

      <Section
        className="mt-4"
        title={t("dashboard.trend")}
        aside={
          <div role="group" aria-label={t("dashboard.range")} className="flex gap-1">
            {(["24h", "7d"] as const).map((r) => (
              <button
                key={r}
                type="button"
                className={range === r ? "btn btn-sm btn-primary" : "btn btn-sm"}
                aria-pressed={range === r}
                onClick={() => {
                  setRange(r);
                }}
              >
                {t(`dashboard.range_${r}`)}
              </button>
            ))}
          </div>
        }
      >
        <TimeChart series={series} label={t("dashboard.trendLabel")} formatTime={formatAxis} />
        <p className="mt-2 flex gap-4 text-xs text-muted">
          <span className="flex items-center gap-1.5">
            <span aria-hidden className="inline-block h-0.5 w-4 bg-accent" />
            {t("dashboard.events")}
          </span>
          <span className="flex items-center gap-1.5">
            <span aria-hidden className="inline-block size-2.5 bg-p2" />
            {t("dashboard.alerts")}
          </span>
        </p>
      </Section>

      <div className="mt-4 grid gap-4 lg:grid-cols-3">
        <Section title={t("dashboard.topRules")} aside={t("dashboard.period7d")}>
          <ol className="flex flex-col gap-2">
            {data.top_rules.map((rule) => (
              <li key={rule.rule_id} className="flex items-center justify-between gap-2 text-sm">
                <Link to="/rules/$ruleId" params={{ ruleId: rule.rule_id }} className="link min-w-0 truncate">
                  <span className="font-mono text-xs text-muted">{rule.rule_id}</span>{" "}
                  {i18n.language === "de" ? rule.title_de : rule.title}
                </Link>
                <span className="tabular font-semibold">{rule.alerts}</span>
              </li>
            ))}
          </ol>
        </Section>
        <Section title={t("dashboard.topEntities")} aside={t("dashboard.openCasesOnly")}>
          <ol className="flex flex-col gap-2">
            {data.top_entities.map((entity) => (
              <li key={`${entity.type}:${entity.display}`} className="flex items-center justify-between gap-2 text-sm">
                <Link
                  to="/cases"
                  search={{ entity: entity.display }}
                  className="link flex min-w-0 items-center gap-1.5"
                >
                  <EntityIcon type={entity.type} className="text-muted" />
                  <span className="truncate font-mono text-xs">{entity.display}</span>
                </Link>
                <span className="tabular text-xs text-muted">{t("dashboard.cases", { count: entity.cases })}</span>
              </li>
            ))}
          </ol>
        </Section>
        <Section title={t("dashboard.ingestion")} aside={asOf}>
          <table className="table text-xs [&_td]:px-2 [&_th]:px-2">
            <thead>
              <tr>
                <th scope="col">{t("quality.source")}</th>
                <th scope="col" className="text-right">
                  {t("quality.accepted")}
                </th>
                <th scope="col" className="text-right">
                  {t("quality.malformed")}
                </th>
              </tr>
            </thead>
            <tbody>
              {data.ingestion.map((row) => (
                <tr key={row.source_type}>
                  <td className="break-all">
                    <span className="font-mono">{row.source_type}</span>
                    {row.failed_runs > 0 && (
                      <span className="ml-1 text-danger">
                        ({t("dashboard.failedRuns", { count: row.failed_runs })})
                      </span>
                    )}
                  </td>
                  <td className="tabular text-right">{formatNumber(row.accepted, loc)}</td>
                  <td className={`tabular text-right ${row.malformed > 0 ? "text-warn" : ""}`}>
                    {formatNumber(row.malformed, loc)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {data.learning_users > 0 && (
            <p className="mt-3 text-xs text-muted">{t("dashboard.baselineLearning", { count: data.learning_users })}</p>
          )}
        </Section>
      </div>
    </>
  );
}
