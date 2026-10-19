import { Upload } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { ApiError } from "../api/client";
import { useQualitySummary, useQuarantine, useReprocess, useRuns, useUpload } from "../api/hooks";
import type { QualitySummary } from "../api/types";
import { useAuth } from "../auth/AuthProvider";
import { Tag } from "../components/Badges";
import { Kpi, PageHeader, Section } from "../components/Layout";
import { Empty, QueryView } from "../components/States";
import { Time } from "../components/Time";
import { locale } from "../i18n";
import { formatNumber, formatPercent } from "../lib/format";

export function QualityPage() {
  const { t } = useTranslation();
  const { can } = useAuth();
  const summary = useQualitySummary();
  return (
    <>
      <PageHeader title={t("quality.title")} subtitle={t("quality.subtitle")} />
      <QueryView query={summary}>{(data) => <SummaryView data={data} />}</QueryView>
      <div className="mt-4 grid gap-4 2xl:grid-cols-2">
        <RunsSection />
        <QuarantineSection />
      </div>
      {can("ingest:write") && <UploadSection />}
    </>
  );
}

function SummaryView({ data }: { data: QualitySummary }) {
  const { t, i18n } = useTranslation();
  const loc = locale(i18n.language);
  const total = Math.max(1, data.accepted + data.duplicate + data.malformed);
  const share = (n: number) => formatPercent(n / total, loc);
  return (
    <>
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Kpi label={t("quality.runs")} value={formatNumber(data.runs, loc)} />
        <Kpi label={t("quality.accepted")} value={formatNumber(data.accepted, loc)} hint={share(data.accepted)} />
        <Kpi label={t("quality.duplicate")} value={formatNumber(data.duplicate, loc)} hint={share(data.duplicate)} />
        <Kpi label={t("quality.malformed")} value={formatNumber(data.malformed, loc)} hint={share(data.malformed)} />
      </div>
      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <Section title={t("quality.bySource")}>
          <table className="table text-sm">
            <thead>
              <tr>
                <th scope="col">{t("quality.source")}</th>
                <th scope="col">{t("quality.distribution")}</th>
                <th scope="col" className="text-right">
                  {t("quality.accepted")}
                </th>
                <th scope="col" className="text-right">
                  {t("quality.duplicate")}
                </th>
                <th scope="col" className="text-right">
                  {t("quality.malformed")}
                </th>
              </tr>
            </thead>
            <tbody>
              {data.by_source.map((row) => {
                const sum = Math.max(1, row.accepted + row.duplicate + row.malformed);
                return (
                  <tr key={row.source_type}>
                    <td className="font-mono text-xs">{row.source_type}</td>
                    <td className="w-40">
                      <div className="flex h-2 overflow-hidden rounded bg-surface-2" aria-hidden>
                        <div className="bg-ok" style={{ width: `${(100 * row.accepted) / sum}%` }} />
                        <div className="bg-p3" style={{ width: `${(100 * row.duplicate) / sum}%` }} />
                        <div className="bg-danger" style={{ width: `${(100 * row.malformed) / sum}%` }} />
                      </div>
                    </td>
                    <td className="tabular text-right">{formatNumber(row.accepted, loc)}</td>
                    <td className="tabular text-right">{formatNumber(row.duplicate, loc)}</td>
                    <td className="tabular text-right">{formatNumber(row.malformed, loc)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </Section>
        <Section title={t("quality.errorCodes")}>
          {Object.keys(data.error_codes).length === 0 ? (
            <p className="text-sm text-muted">{t("common.none")}</p>
          ) : (
            <ul className="flex flex-col gap-2 text-sm">
              {Object.entries(data.error_codes).map(([code, count]) => (
                <li key={code} className="flex items-center justify-between gap-2">
                  <span>
                    <span className="font-mono text-xs">{code}</span>{" "}
                    <span className="text-muted">– {t(`quality.code.${code}`, { defaultValue: code })}</span>
                  </span>
                  <span className="tabular font-semibold">{count}</span>
                </li>
              ))}
            </ul>
          )}
        </Section>
      </div>
    </>
  );
}

function RunsSection() {
  const { t, i18n } = useTranslation();
  const loc = locale(i18n.language);
  const { can } = useAuth();
  const query = useRuns();
  const reprocess = useReprocess();
  return (
    <Section title={t("quality.runsTitle")}>
      <QueryView query={query} empty={(rows) => rows.length === 0}>
        {(rows) => (
          <div className="max-h-[480px] overflow-auto">
            <table className="table text-xs">
              <thead>
                <tr>
                  <th scope="col">{t("quality.file")}</th>
                  <th scope="col">{t("quality.channel")}</th>
                  <th scope="col" className="text-right">
                    {t("quality.accepted")}
                  </th>
                  <th scope="col" className="text-right">
                    {t("quality.duplicate")}
                  </th>
                  <th scope="col" className="text-right">
                    {t("quality.malformed")}
                  </th>
                  <th scope="col">{t("quality.status")}</th>
                  <th scope="col">
                    <span className="sr-only">{t("quality.actions")}</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {rows.map((run) => (
                  <tr key={run.run_id}>
                    <td className="max-w-64">
                      <p className="truncate font-mono" title={run.file_name}>
                        {run.file_name}
                      </p>
                      <p className="text-muted">
                        {run.source_type} · <Time value={run.started_at} />
                        {run.duration_ms !== null && ` · ${formatNumber(run.duration_ms, loc)} ms`}
                      </p>
                    </td>
                    <td>{run.channel}</td>
                    <td className="tabular text-right">{formatNumber(run.accepted, loc)}</td>
                    <td className="tabular text-right">{formatNumber(run.duplicate, loc)}</td>
                    <td className={`tabular text-right ${run.malformed ? "text-warn" : ""}`}>
                      {formatNumber(run.malformed, loc)}
                    </td>
                    <td>
                      <Tag tone={run.status === "failed" ? "warn" : "default"}>
                        {t(`quality.runStatus.${run.status}`, { defaultValue: run.status })}
                      </Tag>
                    </td>
                    <td>
                      {run.malformed > 0 && can("quality:reprocess") && (
                        <button
                          type="button"
                          className="btn btn-sm"
                          disabled={reprocess.isPending}
                          onClick={() => {
                            reprocess.mutate(run.run_id);
                          }}
                        >
                          {t("quality.reprocess")}
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </QueryView>
      {reprocess.data && (
        <p className="mt-2 text-sm text-ok">{t("quality.reprocessed", { count: reprocess.data.reprocessed })}</p>
      )}
    </Section>
  );
}

function QuarantineSection() {
  const { t } = useTranslation();
  const [code, setCode] = useState("");
  const query = useQuarantine(code || undefined);
  return (
    <Section
      title={t("quality.quarantine")}
      aside={
        <select
          aria-label={t("quality.filterCode")}
          className="input py-1 text-xs"
          value={code}
          onChange={(event) => {
            setCode(event.target.value);
          }}
        >
          <option value="">{t("quality.allCodes")}</option>
          {["PARSE_ERROR", "MISSING_TIMESTAMP", "INVALID_ENCODING", "SCHEMA_VIOLATION", "TRUNCATED", "OVERSIZED"].map(
            (c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ),
          )}
        </select>
      }
    >
      <QueryView query={query}>
        {(data) =>
          data.items.length === 0 ? (
            <Empty title={t("quality.quarantineEmpty")} />
          ) : (
            <div
              role="region"
              aria-label={t("quality.quarantine")}
              tabIndex={0}
              className="max-h-[480px] overflow-auto"
            >
              <ul className="flex flex-col gap-2" data-testid="quarantine">
                {data.items.map((item) => (
                  <li key={item.raw_record_id} className="rounded-md border border-border p-2.5">
                    <div className="flex flex-wrap items-center gap-2 text-xs">
                      <Tag tone="warn">{item.error_code}</Tag>
                      <span className="font-mono text-muted">
                        {item.file_name} · {t("quality.position", { position: item.position })}
                        {item.error_position !== null && ` · ${t("quality.offset", { offset: item.error_position })}`}
                      </span>
                    </div>
                    {item.error_detail && <p className="mt-1 text-xs">{item.error_detail}</p>}
                    <pre tabIndex={0} className="raw-line mt-1.5 max-h-32 overflow-auto rounded bg-code p-2">
                      {item.content}
                    </pre>
                  </li>
                ))}
              </ul>
            </div>
          )
        }
      </QueryView>
    </Section>
  );
}

function UploadSection() {
  const { t } = useTranslation();
  const upload = useUpload();
  const [sourceType, setSourceType] = useState("windows_xml");
  const [timezone, setTimezone] = useState("Europe/Berlin");
  const [file, setFile] = useState<File | null>(null);
  const types = [
    "windows_evtx",
    "windows_xml",
    "windows_json",
    "syslog_3164",
    "syslog_5424",
    "journald_json",
    "json:generic",
    "json:musterfirma_vpn",
  ];
  return (
    <Section className="mt-4" title={t("quality.upload")}>
      <form
        className="flex flex-wrap items-end gap-3"
        onSubmit={(event) => {
          event.preventDefault();
          if (!file) return;
          const form = new FormData();
          form.append("file", file);
          form.append("source_type", sourceType);
          form.append("timezone", timezone);
          upload.mutate(form);
        }}
      >
        <div>
          <label htmlFor="upload-file" className="label">
            {t("quality.file")}
          </label>
          <input
            id="upload-file"
            type="file"
            className="input"
            onChange={(event) => {
              setFile(event.target.files?.[0] ?? null);
            }}
          />
        </div>
        <div>
          <label htmlFor="upload-type" className="label">
            {t("quality.sourceType")}
          </label>
          <select
            id="upload-type"
            className="input font-mono"
            value={sourceType}
            onChange={(event) => {
              setSourceType(event.target.value);
            }}
          >
            {types.map((type) => (
              <option key={type} value={type}>
                {type}
              </option>
            ))}
          </select>
        </div>
        <div>
          <label htmlFor="upload-tz" className="label">
            {t("quality.timezone")}
          </label>
          <input
            id="upload-tz"
            className="input"
            value={timezone}
            onChange={(event) => {
              setTimezone(event.target.value);
            }}
          />
        </div>
        <button type="submit" className="btn btn-primary" disabled={!file || upload.isPending}>
          <Upload aria-hidden className="size-4" />
          {t("quality.uploadSubmit")}
        </button>
      </form>
      {upload.data && (
        <p className="mt-3 text-sm text-ok">
          {t("quality.uploadResult", {
            accepted: upload.data.accepted,
            duplicate: upload.data.duplicate,
            malformed: upload.data.malformed,
          })}
        </p>
      )}
      {upload.error && (
        <p role="alert" className="mt-3 text-sm text-danger">
          {upload.error instanceof ApiError ? upload.error.detail : String(upload.error)}
        </p>
      )}
    </Section>
  );
}
