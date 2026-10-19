import { useParams } from "@tanstack/react-router";
import { Download } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { download } from "../../api/client";
import { useReport } from "../../api/hooks";
import type { CaseReport } from "../../api/types";
import { useAuth } from "../../auth/AuthProvider";
import { RawLine } from "../../components/CodeView";
import { PriorityBadge } from "../../components/Priority";
import { QueryView } from "../../components/States";
import { Time } from "../../components/Time";

export function ReportTab() {
  const { t } = useTranslation();
  const { caseId } = useParams({ from: "/cases/$caseId/report" });
  const { can } = useAuth();
  const [pseudonymize, setPseudonymize] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const query = useReport(caseId, pseudonymize);

  if (!can("reports:export")) return <p className="text-sm text-muted">{t("errors.forbidden")}</p>;

  const exportAs = (format: "md" | "pdf" | "json") => {
    setError(null);
    download(
      "/api/v1/cases/{case_id}/report",
      { path: { case_id: caseId }, query: { format, pseudonymize } },
      `sentinelops-case-${caseId.slice(0, 12)}.${format}`,
    ).catch((exc: unknown) => {
      setError(exc instanceof Error ? exc.message : String(exc));
    });
  };

  return (
    <div className="flex flex-col gap-4">
      <div className="card flex flex-wrap items-center gap-3 p-3">
        <label className="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={pseudonymize}
            onChange={(event) => {
              setPseudonymize(event.target.checked);
            }}
          />
          {t("report.pseudonymize")}
        </label>
        <div className="ml-auto flex flex-wrap gap-2">
          {(["md", "pdf", "json"] as const).map((format) => (
            <button
              key={format}
              type="button"
              className="btn btn-sm"
              onClick={() => {
                exportAs(format);
              }}
            >
              <Download aria-hidden className="size-3.5" />
              {t(`report.export_${format}`)}
            </button>
          ))}
        </div>
        {error && (
          <p role="alert" className="w-full text-sm text-danger">
            {error}
          </p>
        )}
      </div>
      <p className="text-xs text-muted">{t("report.auditHint")}</p>
      <QueryView query={query}>{(report) => <ReportPreview report={report} />}</QueryView>
    </div>
  );
}

export function ReportPreview({ report }: { report: CaseReport }) {
  const { t, i18n } = useTranslation();
  const de = i18n.language === "de";
  const summary = report.ai_summary?.output;
  return (
    <article className="card mx-auto w-full max-w-4xl p-6 leading-relaxed" data-testid="report-preview">
      <header className="border-b border-border pb-4">
        <p className="text-xs font-semibold text-muted uppercase">{t("report.caseReport")}</p>
        <h2 className="mt-1 text-xl font-bold">{de ? report.case.title_de : report.case.title}</h2>
        <div className="mt-2 flex flex-wrap items-center gap-3 text-sm text-muted">
          <PriorityBadge level={report.priority.level} score={report.priority.score} />
          <span className="font-mono">{report.case.case_id}</span>
          <span>
            <Time value={report.case.window_start} /> – <Time value={report.case.window_end} />
          </span>
        </div>
        <p className="mt-2 text-xs text-muted">{t("app.complements")}</p>
      </header>

      <h3 className="mt-5 mb-2 font-semibold">{t("report.summary")}</h3>
      <p className="text-xs text-muted">
        {report.ai_summary?.source === "ai" ? t("case.aiGenerated") : t("case.templateSummary")} ·{" "}
        {t("report.validation")}: {report.ai_summary?.validation_status ?? "–"}
      </p>
      <p className="mt-2 text-sm">{summary?.summary ?? "–"}</p>
      {summary && summary.facts.length > 0 && (
        <ul className="mt-2 list-disc pl-5 text-sm">
          {summary.facts.map((fact, i) => (
            <li key={i}>
              {fact.statement} <span className="font-mono text-xs text-muted">({fact.evidence.join(", ")})</span>
            </li>
          ))}
        </ul>
      )}
      {summary && summary.hypotheses.length > 0 && (
        <>
          <h4 className="mt-3 text-sm font-semibold">{t("case.hypotheses")}</h4>
          <ul className="mt-1 list-disc pl-5 text-sm italic">
            {summary.hypotheses.map((hyp, i) => (
              <li key={i}>
                [{t(`case.confidence.${hyp.confidence}`)}] {hyp.statement}
              </li>
            ))}
          </ul>
        </>
      )}

      <h3 className="mt-5 mb-2 font-semibold">{t("case.priorityReason")}</h3>
      <table className="table text-sm">
        <tbody>
          {report.priority.factors.map((factor) => (
            <tr key={factor.code}>
              <td className="tabular w-16 text-right font-mono">
                {factor.contribution > 0 ? `+${factor.contribution}` : factor.contribution}
              </td>
              <td>{de ? factor.label_de : factor.label_en}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <h3 className="mt-5 mb-2 font-semibold">{t("case.alertsTitle")}</h3>
      <table className="table text-sm">
        <thead>
          <tr>
            <th scope="col">{t("report.rule")}</th>
            <th scope="col">{t("report.title")}</th>
            <th scope="col">{t("report.window")}</th>
          </tr>
        </thead>
        <tbody>
          {report.alerts.map((alert) => (
            <tr key={alert.alert_id}>
              <td className="font-mono text-xs">
                {alert.rule_id} v{alert.rule_version}
              </td>
              <td>{de ? alert.title_de : alert.title}</td>
              <td className="text-xs">
                <Time value={alert.window_start} seconds />
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {report.rules.length > 0 && (
        <>
          <h3 className="mt-5 mb-2 font-semibold">{t("report.rulesOrigin")}</h3>
          <ul className="text-sm">
            {report.rules.map((rule) => (
              <li key={rule.rule_id} className="font-mono text-xs">
                {rule.rule_id} v{rule.version} · {rule.source} · {rule.author} · {rule.license}
              </li>
            ))}
          </ul>
        </>
      )}

      <h3 className="mt-5 mb-2 font-semibold">{t("case.nextSteps")}</h3>
      <ol className="list-decimal pl-5 text-sm">
        {report.recommendations.map((step) => (
          <li key={step.step_id}>
            {de ? step.title_de : step.title_en}
            {step.action && <span className="text-warn"> – {t("case.requiresApproval")}</span>}
          </li>
        ))}
      </ol>

      <h3 className="mt-5 mb-2 font-semibold">{t("report.evidenceExcerpts")}</h3>
      <ul className="flex flex-col gap-2">
        {report.evidence.slice(0, 10).map((ev) => (
          <li key={ev.event_id}>
            <p className="text-xs text-muted">
              <span className="font-mono font-semibold text-accent">{ev.ref}</span> · <Time value={ev.time} seconds />
            </p>
            <RawLine text={ev.raw} className="mt-1" />
          </li>
        ))}
      </ul>
      {report.evidence.length > 10 && (
        <p className="mt-2 text-xs text-muted">{t("report.moreEvidence", { count: report.evidence.length - 10 })}</p>
      )}

      <h3 className="mt-5 mb-2 font-semibold">{t("report.metadata")}</h3>
      <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-0.5 font-mono text-xs">
        {Object.entries(report.metadata).map(([key, value]) => (
          <div key={key} className="contents">
            <dt className="text-muted">{key}</dt>
            <dd className="break-all">{String(value)}</dd>
          </div>
        ))}
      </dl>
    </article>
  );
}
