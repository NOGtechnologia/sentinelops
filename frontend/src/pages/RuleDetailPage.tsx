import { Link, useParams } from "@tanstack/react-router";
import { ChevronLeft } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { ApiError } from "../api/client";
import { useApproveException, useExceptions, useRule, useToggleRule } from "../api/hooks";
import type { RuleDetail } from "../api/types";
import { useAuth } from "../auth/AuthProvider";
import { LevelBadge, Tag } from "../components/Badges";
import { YamlView } from "../components/CodeView";
import { Dialog } from "../components/Dialog";
import { PageHeader, Section } from "../components/Layout";
import { QueryView } from "../components/States";
import { Time } from "../components/Time";

export function RuleDetailPage() {
  const { ruleId } = useParams({ from: "/rules/$ruleId" });
  const query = useRule(ruleId);
  return <QueryView query={query}>{(rule) => <RuleView rule={rule} />}</QueryView>;
}

function RuleView({ rule }: { rule: RuleDetail }) {
  const { t, i18n } = useTranslation();
  const { can } = useAuth();
  const [toggling, setToggling] = useState(false);
  const de = i18n.language === "de";
  return (
    <>
      <Link to="/rules" className="link mb-3 inline-flex items-center gap-1 text-sm">
        <ChevronLeft aria-hidden className="size-4" />
        {t("rules.back")}
      </Link>
      <PageHeader
        title={de ? rule.title_de : rule.title}
        subtitle={
          <span className="flex flex-wrap items-center gap-2">
            <span className="font-mono">{`${rule.rule_id} · v${String(rule.version)}`}</span>
            <LevelBadge level={rule.level} />
            <Tag>{t(`rules.maturityValue.${rule.maturity}`, { defaultValue: rule.maturity })}</Tag>
            {rule.active ? <Tag tone="accent">{t("rules.active")}</Tag> : <Tag tone="warn">{t("rules.inactive")}</Tag>}
          </span>
        }
        actions={
          can("rules:write") && (
            <button
              type="button"
              className="btn"
              onClick={() => {
                setToggling(true);
              }}
            >
              {rule.active ? t("rules.deactivate") : t("rules.activate")}
            </button>
          )
        }
      />
      <div className="grid gap-4 xl:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
        <div className="flex min-w-0 flex-col gap-4">
          <Section title={t("rules.description")}>
            <p className="text-sm">{de ? rule.description_de : rule.description}</p>
            <dl className="mt-3 grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-sm">
              <dt className="text-muted">{t("rules.origin")}</dt>
              <dd>
                {rule.source === "sigmahq"
                  ? t("rules.originSigmaHq", { author: rule.author })
                  : t("rules.originCustom")}
              </dd>
              <dt className="text-muted">{t("rules.attack")}</dt>
              <dd className="flex flex-wrap gap-1">
                {rule.tactics.map((x) => (
                  <Tag key={x} tone="accent">
                    {t(`tactics.${x}`, { defaultValue: x })}
                  </Tag>
                ))}
                {rule.techniques.map((x) => (
                  <Tag key={x}>{x}</Tag>
                ))}
              </dd>
              <dt className="text-muted">{t("rules.falsePositives")}</dt>
              <dd>{rule.falsepositives.join("; ") || "–"}</dd>
              <dt className="text-muted">{t("rules.playbooks")}</dt>
              <dd className="font-mono text-xs">{rule.playbooks.join(", ")}</dd>
              <dt className="text-muted">{t("rules.file")}</dt>
              <dd className="font-mono text-xs">{rule.file}</dd>
            </dl>
          </Section>
          <Section title={t("rules.yaml")}>
            <YamlView yaml={rule.yaml} markLines={["condition:"]} />
          </Section>
        </div>
        <div className="flex min-w-0 flex-col gap-4">
          <Section title={t("rules.tests")} aside={t("rules.testsCount", { count: rule.tests.length })}>
            <ul className="flex flex-col gap-1 text-sm">
              {rule.tests.map((test, i) => (
                <li key={i} className="flex items-start justify-between gap-2">
                  <span>{test.name}</span>
                  <Tag tone={test.expect === "alert" ? "accent" : "default"}>
                    {t(`rules.expect.${test.expect}`, { defaultValue: test.expect })}
                  </Tag>
                </li>
              ))}
            </ul>
          </Section>
          <ExceptionsSection ruleId={rule.rule_id} />
          <Section title={t("rules.versions")}>
            <ul className="flex flex-col gap-1 text-xs">
              {rule.versions.map((v) => (
                <li key={`${v.version}-${v.content_hash}`} className="flex justify-between gap-2 font-mono">
                  <span>
                    v{v.version} · {v.content_hash.slice(0, 12)}
                  </span>
                  <Time value={v.created_at} />
                </li>
              ))}
            </ul>
          </Section>
          <Section title={t("rules.recentAlerts")}>
            {rule.recent_alerts.length === 0 ? (
              <p className="text-sm text-muted">{t("common.none")}</p>
            ) : (
              <ul className="flex flex-col gap-1 text-xs">
                {rule.recent_alerts.map((a) => (
                  <li key={a.alert_id} className="flex justify-between gap-2">
                    <Time value={a.window_start} />
                    <span>
                      {t("case.events", { count: a.event_count })}
                      {a.false_positive && ` · ${t("evidence.markedFalsePositive")}`}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </Section>
        </div>
      </div>
      {toggling && (
        <ToggleDialog
          rule={rule}
          onClose={() => {
            setToggling(false);
          }}
        />
      )}
    </>
  );
}

function ExceptionsSection({ ruleId }: { ruleId: string }) {
  const { t } = useTranslation();
  const { can } = useAuth();
  const query = useExceptions();
  const approve = useApproveException();
  const items = (query.data ?? []).filter((e) => e.rule_id === ruleId);
  return (
    <Section title={t("rules.exceptions")}>
      {items.length === 0 ? (
        <p className="text-sm text-muted">{t("common.none")}</p>
      ) : (
        <ul className="flex flex-col gap-2 text-sm">
          {items.map((exc) => (
            <li key={`${exc.id}-${exc.version}`} className="rounded-md border border-border p-2.5">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-xs">{exc.id}</span>
                <Tag tone={exc.status === "active" ? "accent" : "warn"}>
                  {t(`rules.exceptionStatus.${exc.status}`, { defaultValue: exc.status })}
                </Tag>
                <span className="text-xs text-muted">
                  {t("rules.expires")} {exc.expires}
                </span>
              </div>
              <p className="mt-1">{exc.description}</p>
              <p className="mt-1 font-mono text-xs break-all text-muted">{JSON.stringify(exc.match)}</p>
              <p className="mt-1 text-xs text-muted">
                {t("rules.createdBy", { user: exc.created_by })}
                {exc.approved_by && ` · ${t("rules.approvedBy", { user: exc.approved_by })}`}
              </p>
              {exc.status === "proposed" && can("exceptions:approve") && (
                <button
                  type="button"
                  className="btn btn-sm mt-2"
                  disabled={approve.isPending}
                  onClick={() => {
                    approve.mutate(exc.id);
                  }}
                >
                  {t("rules.approveException")}
                </button>
              )}
            </li>
          ))}
        </ul>
      )}
      {approve.error && (
        <p role="alert" className="mt-2 text-sm text-danger">
          {approve.error instanceof ApiError ? approve.error.detail : String(approve.error)}
        </p>
      )}
    </Section>
  );
}

function ToggleDialog({ rule, onClose }: { rule: RuleDetail; onClose: () => void }) {
  const { t } = useTranslation();
  const toggle = useToggleRule(rule.rule_id);
  const [reason, setReason] = useState("");
  return (
    <Dialog
      open
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
      title={rule.active ? t("rules.deactivate") : t("rules.activate")}
      description={t("rules.toggleHint")}
    >
      <form
        className="flex flex-col gap-3"
        onSubmit={(event) => {
          event.preventDefault();
          toggle.mutate({ active: !rule.active, reason: reason.trim() }, { onSuccess: onClose });
        }}
      >
        <label htmlFor="toggle-reason" className="label">
          {t("actions.reason")}
        </label>
        <textarea
          id="toggle-reason"
          className="input min-h-20"
          required
          minLength={3}
          maxLength={1000}
          value={reason}
          onChange={(event) => {
            setReason(event.target.value);
          }}
        />
        <div className="flex justify-end gap-2">
          <button type="button" className="btn" onClick={onClose}>
            {t("common.cancel")}
          </button>
          <button type="submit" className="btn btn-primary" disabled={reason.trim().length < 3 || toggle.isPending}>
            {t("common.save")}
          </button>
        </div>
      </form>
    </Dialog>
  );
}
