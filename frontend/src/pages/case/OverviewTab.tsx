import { useParams } from "@tanstack/react-router";
import { Bot, CheckCircle2, FileText, HelpCircle, RefreshCw, ShieldAlert } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { useAddNote, useCase, useRegenerateSummary } from "../../api/hooks";
import type { CaseDetail, Recommendation, Summary } from "../../api/types";
import { useAuth } from "../../auth/AuthProvider";
import { Tag } from "../../components/Badges";
import { Section } from "../../components/Layout";
import { QueryView } from "../../components/States";
import { Time } from "../../components/Time";
import { cn } from "../../lib/cn";
import { ActionsPanel, ProposeActionDialog } from "./Actions";
import { EvidenceRefs } from "./EvidenceRef";

export function OverviewTab() {
  const { caseId } = useParams({ from: "/cases/$caseId/" });
  const query = useCase(caseId);
  return <QueryView query={query}>{(data) => <Overview data={data} />}</QueryView>;
}

function Overview({ data }: { data: CaseDetail }) {
  const { t, i18n } = useTranslation();
  const caseId = data.case.case_id;
  const toRefs = (eventIds: string[]) =>
    eventIds.map((id) => data.evidence_refs[id]).filter((r): r is string => r !== undefined);

  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
      <div className="flex min-w-0 flex-col gap-4">
        {data.case.injection_findings.length > 0 && <InjectionNotice data={data} />}
        <Section title={t("case.priorityReason")} aside={t("case.priorityAside")}>
          <ul className="flex flex-col divide-y divide-border">
            {data.priority.factors.map((factor) => (
              <li key={factor.code} className="flex items-start gap-3 py-2">
                <span
                  className={cn(
                    "tabular w-12 shrink-0 text-right font-mono text-sm font-semibold",
                    factor.contribution >= 0 ? "text-text" : "text-ok",
                  )}
                >
                  {factor.contribution > 0 ? `+${factor.contribution}` : factor.contribution}
                </span>
                <div className="min-w-0 flex-1 text-sm">
                  <p>{i18n.language === "de" ? factor.label_de : factor.label_en}</p>
                  {factor.evidence.length > 0 && (
                    <p className="mt-1 text-xs text-muted">
                      {t("case.evidence")}: <EvidenceRefs caseId={caseId} refs={toRefs(factor.evidence)} />
                    </p>
                  )}
                </div>
              </li>
            ))}
            <li className="flex items-center gap-3 py-2 font-semibold">
              <span className="tabular w-12 text-right font-mono">{data.priority.score}</span>
              <span>
                {t("case.sum")} → {data.priority.level}
              </span>
            </li>
          </ul>
        </Section>
        <SummarySection data={data} />
        <Section title={t("case.alertsTitle")}>
          <ul className="flex flex-col gap-2 text-sm">
            {data.alerts.map((alert) => (
              <li key={alert.alert_id} className="flex flex-wrap items-center gap-2">
                <Tag>{alert.rule_id}</Tag>
                <span className="font-semibold">{i18n.language === "de" ? alert.title_de : alert.title}</span>
                <span className="text-xs text-muted">
                  <Time value={alert.window_start} seconds /> · {t("case.events", { count: alert.event_ids.length })}
                </span>
                {alert.false_positive && <Tag tone="warn">{t("evidence.markedFalsePositive")}</Tag>}
              </li>
            ))}
          </ul>
        </Section>
      </div>
      <div className="flex min-w-0 flex-col gap-4">
        <RecommendationsSection data={data} />
        <ActionsPanel data={data} />
        <NotesSection data={data} />
      </div>
    </div>
  );
}

function InjectionNotice({ data }: { data: CaseDetail }) {
  const { t } = useTranslation();
  return (
    <section role="note" className="rounded-lg border border-warn/60 bg-warn/10 p-4" data-testid="injection-notice">
      <h2 className="flex items-center gap-2 font-semibold text-warn">
        <ShieldAlert aria-hidden className="size-4" />
        {t("case.injectionTitle")}
      </h2>
      <p className="mt-1 text-sm text-muted">{t("case.injectionText")}</p>
      <ul className="mt-2 flex flex-col gap-1 text-sm">
        {data.case.injection_findings.map((finding, i) => (
          <li key={i}>
            <span className="text-muted">{finding.field}:</span>{" "}
            <code className="rounded bg-code px-1 font-mono text-xs break-all">{finding.excerpt}</code>
          </li>
        ))}
      </ul>
    </section>
  );
}

function SummarySection({ data }: { data: CaseDetail }) {
  const { t } = useTranslation();
  const { can } = useAuth();
  const regenerate = useRegenerateSummary(data.case.case_id);
  const [showRejected, setShowRejected] = useState(false);
  const summary: Summary | null = data.summary;
  const output = summary?.output;
  const caseId = data.case.case_id;
  const isAi = summary?.source === "ai";

  return (
    <Section
      title={t("case.summaryTitle")}
      aside={
        summary && (
          <span className="flex flex-wrap items-center gap-2">
            {isAi ? (
              <span className="inline-flex items-center gap-1 text-accent">
                <Bot aria-hidden className="size-3.5" />
                {summary.provider === "mock" ? t("case.demoSimulation") : t("case.aiGenerated")}
              </span>
            ) : (
              <span className="inline-flex items-center gap-1">
                <FileText aria-hidden className="size-3.5" />
                {t("case.templateSummary")}
              </span>
            )}
            <span>
              {t("case.summaryMeta", {
                version: summary.version,
                provider: summary.provider,
                model: summary.model,
                status: summary.validation_status,
              })}
            </span>
          </span>
        )
      }
    >
      {!output ? (
        <p className="text-sm text-muted">{t("case.noSummary")}</p>
      ) : (
        <div className="flex flex-col gap-4 text-sm" data-testid="case-summary">
          <p>{output.summary}</p>
          <div>
            <h3 className="mb-1.5 flex items-center gap-1.5 text-xs font-semibold text-muted uppercase">
              <CheckCircle2 aria-hidden className="size-3.5 text-ok" />
              {t("case.facts")}
            </h3>
            {output.facts.length === 0 ? (
              <p className="text-muted">{t("common.none")}</p>
            ) : (
              <ul className="flex flex-col gap-1.5">
                {output.facts.map((fact, i) => (
                  <li key={i} className="border-l-2 border-ok pl-3">
                    {fact.statement} <EvidenceRefs caseId={caseId} refs={fact.evidence} />
                  </li>
                ))}
              </ul>
            )}
          </div>
          <div>
            <h3 className="mb-1.5 flex items-center gap-1.5 text-xs font-semibold text-muted uppercase">
              <HelpCircle aria-hidden className="size-3.5 text-hypothesis" />
              {t("case.hypotheses")}
            </h3>
            {output.hypotheses.length === 0 ? (
              <p className="text-muted">{t("common.none")}</p>
            ) : (
              <ul className="flex flex-col gap-2">
                {output.hypotheses.map((hyp, i) => (
                  <li
                    key={i}
                    className="rounded-md border border-dashed border-hypothesis/60 p-2.5"
                    data-kind="hypothesis"
                  >
                    <p className="italic">
                      <span className="mr-1 not-italic">
                        <Tag>{t(`case.confidence.${hyp.confidence}`)}</Tag>
                      </span>
                      {hyp.statement} <EvidenceRefs caseId={caseId} refs={hyp.evidence} />
                    </p>
                    <p className="mt-1 text-xs text-muted">
                      {t("case.wouldConfirm")}: {hyp.would_confirm}
                    </p>
                  </li>
                ))}
              </ul>
            )}
          </div>
          <div>
            <h3 className="mb-1.5 text-xs font-semibold text-muted uppercase">{t("case.missingInformation")}</h3>
            {output.missing_information.length === 0 ? (
              <p className="text-muted">{t("common.none")}</p>
            ) : (
              <ul className="list-disc pl-5">
                {output.missing_information.map((item, i) => (
                  <li key={i}>
                    <span className="font-semibold">{item.item}</span> –{" "}
                    <span className="text-muted">{item.why_relevant}</span>
                  </li>
                ))}
              </ul>
            )}
          </div>
          {summary.rejected.length > 0 && (
            <div>
              <button
                type="button"
                className="link text-xs"
                aria-expanded={showRejected}
                onClick={() => {
                  setShowRejected((v) => !v);
                }}
              >
                {t("case.rejectedToggle", { count: summary.rejected.length })}
              </button>
              {showRejected && (
                <ul className="mt-2 flex flex-col gap-1.5" data-testid="rejected-statements">
                  {summary.rejected.map((item, i) => (
                    <li key={i} className="rounded-md bg-surface-2 p-2 text-xs">
                      <p className="line-through decoration-danger/70">{item.statement}</p>
                      <p className="mt-1 text-danger">{item.reasons.join("; ")}</p>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )}
        </div>
      )}
      {can("ai:generate") && (
        <div className="mt-4 flex flex-wrap items-center gap-2 border-t border-border pt-3">
          <button
            type="button"
            className="btn btn-sm"
            disabled={regenerate.isPending}
            onClick={() => {
              regenerate.mutate();
            }}
          >
            <RefreshCw aria-hidden className={cn("size-3.5", regenerate.isPending && "animate-spin")} />
            {t("case.regenerate")}
          </button>
          <span className="text-xs text-muted">{t("case.regenerateHint")}</span>
        </div>
      )}
    </Section>
  );
}

function RecommendationsSection({ data }: { data: CaseDetail }) {
  const { t, i18n } = useTranslation();
  const { can } = useAuth();
  const [proposing, setProposing] = useState<Recommendation | null>(null);
  const toRefs = (ids: string[]) => ids.map((id) => data.evidence_refs[id]).filter((r): r is string => r !== undefined);
  return (
    <Section title={t("case.nextSteps")}>
      <ol className="flex flex-col gap-2">
        {data.case.recommendations.map((step, index) => (
          <li key={step.step_id} className="rounded-md border border-border p-3 text-sm">
            <div className="flex flex-wrap items-start justify-between gap-2">
              <div className="min-w-0">
                <p className="font-semibold">
                  {index + 1}. {i18n.language === "de" ? step.title_de : step.title_en}
                </p>
                <p className="mt-0.5 font-mono text-[11px] text-muted">{step.step_id}</p>
              </div>
              {step.action && <Tag tone="warn">{t("case.requiresApproval")}</Tag>}
            </div>
            <p className="mt-1 text-xs text-muted">
              {t("case.because", { rules: step.reason_rules.join(", ") })}{" "}
              <EvidenceRefs caseId={data.case.case_id} refs={toRefs(step.evidence)} />
            </p>
            {step.action && can("actions:propose") && (
              <button
                type="button"
                className="btn btn-sm mt-2"
                onClick={() => {
                  setProposing(step);
                }}
              >
                {t("actions.propose")}
              </button>
            )}
          </li>
        ))}
      </ol>
      {proposing && (
        <ProposeActionDialog
          caseId={data.case.case_id}
          step={proposing}
          onClose={() => {
            setProposing(null);
          }}
        />
      )}
    </Section>
  );
}

function NotesSection({ data }: { data: CaseDetail }) {
  const { t } = useTranslation();
  const { can } = useAuth();
  const add = useAddNote(data.case.case_id);
  const [text, setText] = useState("");
  return (
    <Section title={t("case.notes")}>
      {data.notes.length === 0 ? (
        <p className="text-sm text-muted">{t("case.noNotes")}</p>
      ) : (
        <ul className="flex flex-col gap-2 text-sm">
          {data.notes.map((note) => (
            <li key={note.note_id} className="rounded-md bg-surface-2 p-2.5">
              <p className="text-xs text-muted">
                {note.author} · <Time value={note.created_at} />
              </p>
              <p className="mt-1 whitespace-pre-wrap">{note.text}</p>
            </li>
          ))}
        </ul>
      )}
      {can("cases:write") && (
        <form
          className="mt-3 flex flex-col gap-2"
          onSubmit={(event) => {
            event.preventDefault();
            if (!text.trim()) return;
            add.mutate(text.trim(), {
              onSuccess: () => {
                setText("");
              },
            });
          }}
        >
          <label htmlFor="note-text" className="sr-only">
            {t("case.addNote")}
          </label>
          <textarea
            id="note-text"
            className="input min-h-20"
            value={text}
            onChange={(event) => {
              setText(event.target.value);
            }}
            placeholder={t("case.notePlaceholder")}
            maxLength={10000}
          />
          <button type="submit" className="btn btn-sm self-end" disabled={add.isPending || !text.trim()}>
            {t("case.addNote")}
          </button>
        </form>
      )}
    </Section>
  );
}
