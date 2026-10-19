import { useParams, useRouterState } from "@tanstack/react-router";
import { Flag, ShieldOff } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";

import { ApiError } from "../../api/client";
import { useEvidence, useMarkFalsePositive, useProposeException, useVersion } from "../../api/hooks";
import type { EvidenceAlert, EvidenceEvent, Explanation } from "../../api/types";
import { useAuth } from "../../auth/AuthProvider";
import { LevelBadge, Tag } from "../../components/Badges";
import { RawLine, YamlView } from "../../components/CodeView";
import { Dialog } from "../../components/Dialog";
import { QueryView } from "../../components/States";
import { Time } from "../../components/Time";

const KEY_FIELDS = [
  "@timestamp",
  "event.code",
  "event.action",
  "event.outcome",
  "user.name",
  "user.target.name",
  "group.name",
  "host.name",
  "source.ip",
  "logon.type",
  "process.command_line",
  "event.time_quality",
  "log.source_type",
];

export function EvidenceTab() {
  const { caseId } = useParams({ from: "/cases/$caseId/evidence" });
  const query = useEvidence(caseId);
  const hash = useRouterState({ select: (s) => s.location.hash });

  useEffect(() => {
    if (!hash || !query.data) return;
    const target = document.getElementById(`evidence-${hash}`);
    target?.scrollIntoView({ block: "center" });
    target?.focus();
  }, [hash, query.data]);

  return (
    <QueryView query={query}>
      {(data) => (
        <div className="flex flex-col gap-6">
          {data.alerts.map((alert) => (
            <AlertEvidence key={alert.alert_id} alert={alert} caseId={caseId} />
          ))}
        </div>
      )}
    </QueryView>
  );
}

function stringValues(value: unknown): string[] {
  if (typeof value === "string") return [value];
  if (typeof value === "number") return [String(value)];
  if (Array.isArray(value)) return value.flatMap(stringValues);
  return [];
}

/** Values to highlight in raw lines: matched field values and grouping values of the explanation. */
export function needlesFor(explanation: Explanation): string[] {
  const values = [
    ...(explanation.matched ?? []).flatMap((m) => stringValues(m.actual)),
    ...Object.values(explanation.group_by ?? {}).flatMap(stringValues),
  ];
  return [...new Set(values)].filter((v) => v.length >= 3);
}

/** YAML lines to emphasise: the condition and the detection items that matched. */
export function markedLines(explanation: Explanation): string[] {
  const marks = ["condition:"];
  for (const m of explanation.matched ?? []) {
    marks.push(`${m.detection}:`);
  }
  if (explanation.type !== "single") marks.push("group-by:", "timespan:", "gte:", "rules:");
  return marks;
}

function AlertEvidence({ alert, caseId }: { alert: EvidenceAlert; caseId: string }) {
  const { t, i18n } = useTranslation();
  const { can } = useAuth();
  const [fpOpen, setFpOpen] = useState(false);
  const [excOpen, setExcOpen] = useState(false);
  const needles = useMemo(() => needlesFor(alert.explanation), [alert.explanation]);
  const marks = useMemo(() => markedLines(alert.explanation), [alert.explanation]);
  const rule = alert.rule;
  const license = rule.source === "sigmahq" ? "DRL 1.1" : "Apache-2.0";

  return (
    <article className="card" aria-labelledby={`alert-${alert.alert_id}`} data-testid="alert-evidence">
      <header className="flex flex-wrap items-start justify-between gap-3 border-b border-border p-4">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <Tag>{alert.rule_id}</Tag>
            <span className="text-xs text-muted">v{alert.rule_version}</span>
            <LevelBadge level={alert.level} />
            <Tag>{t(`evidence.kind.${alert.kind}`, { defaultValue: alert.kind })}</Tag>
            {alert.false_positive && <Tag tone="warn">{t("evidence.markedFalsePositive")}</Tag>}
          </div>
          <h2 id={`alert-${alert.alert_id}`} className="mt-1 text-base font-semibold">
            {i18n.language === "de" ? alert.title_de : alert.title}
          </h2>
          <p className="mt-0.5 text-xs text-muted">
            <Time value={alert.window_start} seconds /> – <Time value={alert.window_end} seconds /> ·{" "}
            {t("evidence.origin", { author: rule.author, source: rule.source, license })}
          </p>
          {alert.false_positive_reason && (
            <p className="mt-1 text-xs text-warn">
              {t("evidence.fpReason")}: {alert.false_positive_reason}
            </p>
          )}
        </div>
        <div className="flex flex-wrap gap-2">
          {can("alerts:false_positive") && !alert.false_positive && (
            <button
              type="button"
              className="btn btn-sm"
              onClick={() => {
                setFpOpen(true);
              }}
            >
              <Flag aria-hidden className="size-3.5" />
              {t("evidence.markFalsePositive")}
            </button>
          )}
          {can("exceptions:propose") && (
            <button
              type="button"
              className="btn btn-sm"
              onClick={() => {
                setExcOpen(true);
              }}
            >
              <ShieldOff aria-hidden className="size-3.5" />
              {t("evidence.proposeException")}
            </button>
          )}
        </div>
      </header>

      <div className="grid gap-4 p-4 xl:grid-cols-2">
        <section aria-label={t("evidence.ruleSource")}>
          <h3 className="label">{t("evidence.ruleSource")}</h3>
          <YamlView yaml={rule.yaml} markLines={marks} />
        </section>
        <section aria-label={t("evidence.explanation")}>
          <h3 className="label">{t("evidence.explanation")}</h3>
          <ExplanationView explanation={alert.explanation} />
        </section>
      </div>

      <section className="border-t border-border p-4" aria-label={t("evidence.events")}>
        <h3 className="label">
          {t("evidence.eventsTitle", { count: alert.events.length })}
          {alert.events_truncated > 0 ? ` · ${t("evidence.truncated", { count: alert.events_truncated })}` : null}
        </h3>
        <ul className="flex flex-col gap-3">
          {alert.events.map((event) => (
            <EventEvidence key={`${alert.alert_id}-${event.event_id}`} event={event} needles={needles} />
          ))}
        </ul>
      </section>

      {fpOpen && (
        <FalsePositiveDialog
          caseId={caseId}
          alertId={alert.alert_id}
          onClose={() => {
            setFpOpen(false);
          }}
        />
      )}
      {excOpen && (
        <ExceptionDialog
          alert={alert}
          onClose={() => {
            setExcOpen(false);
          }}
        />
      )}
    </article>
  );
}

function ExplanationView({ explanation }: { explanation: Explanation }) {
  const { t } = useTranslation();
  return (
    <div className="flex flex-col gap-3 text-sm" data-testid="explanation">
      {explanation.condition && (
        <p>
          <span className="text-muted">{t("evidence.condition")}:</span>{" "}
          <code className="rounded bg-code px-1.5 py-0.5 font-mono text-xs">{explanation.condition}</code>
          {explanation.observed !== undefined && (
            <>
              {" "}
              · {t("evidence.observed")}: <strong className="tabular">{explanation.observed}</strong>
            </>
          )}
        </p>
      )}
      {explanation.group_by && Object.keys(explanation.group_by).length > 0 && (
        <p>
          <span className="text-muted">{t("evidence.groupBy")}:</span>{" "}
          {Object.entries(explanation.group_by).map(([field, value]) => (
            <code key={field} className="mr-2 rounded bg-code px-1.5 py-0.5 font-mono text-xs break-all">
              {field}={stringValues(value).join(",")}
            </code>
          ))}
        </p>
      )}
      {(explanation.matched ?? []).length > 0 && (
        <table className="table text-xs" aria-label={t("evidence.matchedFields")}>
          <thead>
            <tr>
              <th scope="col">{t("evidence.detection")}</th>
              <th scope="col">{t("evidence.field")}</th>
              <th scope="col">{t("evidence.expected")}</th>
              <th scope="col">{t("evidence.actual")}</th>
            </tr>
          </thead>
          <tbody>
            {(explanation.matched ?? []).map((m, i) => (
              <tr key={i}>
                <td className="font-mono">{m.detection}</td>
                <td className="font-mono">{m.field}</td>
                <td className="font-mono break-all">{stringValues(m.expected).join(", ")}</td>
                <td className="font-mono break-all">
                  <mark className="rounded-sm bg-mark px-0.5 text-mark-fg">{stringValues(m.actual).join(", ")}</mark>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {(explanation.not_matched_filters ?? []).length > 0 && (
        <p className="text-xs">
          <span className="text-muted">{t("evidence.filtersNotMatched")}:</span>{" "}
          {(explanation.not_matched_filters ?? []).map((f) => (
            <code key={f} className="mr-1 rounded bg-code px-1 font-mono">
              {f}
            </code>
          ))}
        </p>
      )}
      {(explanation.criteria ?? []).length > 0 && (
        <ul className="flex flex-col gap-1">
          {(explanation.criteria ?? []).map((c) => (
            <li key={c.criterion} className="text-xs">
              <Tag tone="accent">{t(`evidence.criterion.${c.criterion}`, { defaultValue: c.criterion })}</Tag>{" "}
              <span className="font-mono">{c.detail}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function EventEvidence({ event, needles }: { event: EvidenceEvent; needles: string[] }) {
  const { t } = useTranslation();
  const fields = KEY_FIELDS.filter((f) => event.fields[f] !== undefined && event.fields[f] !== null);
  return (
    <li
      id={`evidence-${event.ref}`}
      tabIndex={-1}
      className="rounded-md border border-border p-3 focus:border-accent"
      data-ref={event.ref}
    >
      <div className="mb-2 flex flex-wrap items-center gap-2 text-xs">
        <span className="rounded bg-accent-soft px-1.5 font-mono font-semibold text-accent">{event.ref}</span>
        <Time value={event.time} seconds />
        <span className="font-mono text-muted">{event.event_id}</span>
      </div>
      <dl className="mb-2 grid grid-cols-[max-content_1fr] gap-x-3 gap-y-0.5 font-mono text-xs sm:grid-cols-[max-content_1fr_max-content_1fr]">
        {fields.map((field) => (
          <div key={field} className="contents">
            <dt className="text-muted">{field}</dt>
            <dd className="break-all">{stringValues(event.fields[field]).join(", ")}</dd>
          </div>
        ))}
      </dl>
      {event.raw ? (
        <>
          <p className="sr-only">{t("evidence.rawLine")}</p>
          <RawLine text={event.raw} needles={needles} />
        </>
      ) : (
        <p className="text-xs text-muted">{t("evidence.noRaw")}</p>
      )}
    </li>
  );
}

function FalsePositiveDialog({ caseId, alertId, onClose }: { caseId: string; alertId: string; onClose: () => void }) {
  const { t } = useTranslation();
  const mark = useMarkFalsePositive(caseId);
  const [reason, setReason] = useState("");
  return (
    <Dialog
      open
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
      title={t("evidence.fpTitle")}
      description={t("evidence.fpDescription")}
    >
      <form
        className="flex flex-col gap-3"
        onSubmit={(event) => {
          event.preventDefault();
          mark.mutate({ alertId, reason: reason.trim() }, { onSuccess: onClose });
        }}
      >
        <label htmlFor="fp-reason" className="label">
          {t("evidence.fpReason")}
        </label>
        <textarea
          id="fp-reason"
          className="input min-h-24"
          required
          minLength={3}
          maxLength={2000}
          value={reason}
          onChange={(event) => {
            setReason(event.target.value);
          }}
        />
        {mark.error && (
          <p role="alert" className="text-sm text-danger">
            {mark.error instanceof ApiError ? mark.error.detail : String(mark.error)}
          </p>
        )}
        <div className="flex justify-end gap-2">
          <button type="button" className="btn" onClick={onClose}>
            {t("common.cancel")}
          </button>
          <button type="submit" className="btn btn-primary" disabled={reason.trim().length < 3 || mark.isPending}>
            {t("evidence.fpSubmit")}
          </button>
        </div>
      </form>
    </Dialog>
  );
}

function addDays(iso: string, days: number): string {
  const date = new Date(iso);
  date.setUTCDate(date.getUTCDate() + days);
  return date.toISOString().slice(0, 10);
}

function ExceptionDialog({ alert, onClose }: { alert: EvidenceAlert; onClose: () => void }) {
  const { t } = useTranslation();
  const propose = useProposeException();
  const version = useVersion();
  const today = version.data?.demo_now ?? new Date().toISOString();
  const initialMatch = Object.entries(alert.group_key)
    .map(([k, v]) => `${k}=${v}`)
    .join("\n");
  const [match, setMatch] = useState(initialMatch);
  const [description, setDescription] = useState("");
  const [expires, setExpires] = useState(() => addDays(today, 90));
  const parsed = Object.fromEntries(
    match
      .split("\n")
      .map((line) => line.split("="))
      .filter((parts) => parts.length >= 2 && parts[0]?.trim())
      .map(([key, ...rest]) => [key?.trim() ?? "", rest.join("=").trim()]),
  );
  const valid =
    description.trim().length >= 10 && Object.keys(parsed).length > 0 && /^\d{4}-\d{2}-\d{2}$/.test(expires);
  return (
    <Dialog
      open
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
      title={t("evidence.exceptionTitle", { rule: alert.rule_id })}
      description={t("evidence.exceptionDescription")}
    >
      <form
        className="flex flex-col gap-3"
        onSubmit={(event) => {
          event.preventDefault();
          propose.mutate(
            { rule_id: alert.rule_id, description: description.trim(), match: parsed, expires },
            { onSuccess: onClose },
          );
        }}
      >
        <div>
          <label htmlFor="exc-match" className="label">
            {t("evidence.exceptionMatch")}
          </label>
          <textarea
            id="exc-match"
            className="input min-h-20 font-mono"
            value={match}
            onChange={(event) => {
              setMatch(event.target.value);
            }}
          />
          <p className="mt-1 text-xs text-muted">{t("evidence.exceptionMatchHint")}</p>
        </div>
        <div>
          <label htmlFor="exc-desc" className="label">
            {t("evidence.exceptionReason")}
          </label>
          <textarea
            id="exc-desc"
            className="input min-h-20"
            required
            minLength={10}
            maxLength={2000}
            value={description}
            onChange={(event) => {
              setDescription(event.target.value);
            }}
          />
        </div>
        <div>
          <label htmlFor="exc-expires" className="label">
            {t("evidence.exceptionExpires")}
          </label>
          <input
            id="exc-expires"
            type="date"
            className="input"
            value={expires}
            onChange={(event) => {
              setExpires(event.target.value);
            }}
          />
        </div>
        <p className="text-xs text-muted">{t("evidence.exceptionApprovalHint")}</p>
        {propose.error && (
          <p role="alert" className="text-sm text-danger">
            {propose.error instanceof ApiError ? propose.error.detail : String(propose.error)}
          </p>
        )}
        {propose.isSuccess && <p className="text-sm text-ok">{t("evidence.exceptionProposed")}</p>}
        <div className="flex justify-end gap-2">
          <button type="button" className="btn" onClick={onClose}>
            {t("common.cancel")}
          </button>
          <button type="submit" className="btn btn-primary" disabled={!valid || propose.isPending}>
            {t("evidence.exceptionSubmit")}
          </button>
        </div>
      </form>
    </Dialog>
  );
}
