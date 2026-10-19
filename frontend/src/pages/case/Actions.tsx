import { FlaskConical, ShieldCheck } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { ApiError } from "../../api/client";
import { useDecideAction, useExecuteAction, useProposeAction } from "../../api/hooks";
import type { Action, CaseDetail, EntityType, Recommendation } from "../../api/types";
import { useAuth } from "../../auth/AuthProvider";
import { Tag } from "../../components/Badges";
import { Dialog } from "../../components/Dialog";
import { Section } from "../../components/Layout";
import { Time } from "../../components/Time";

const PARAMETERS: Record<string, EntityType[]> = {
  DISABLE_ACCOUNT: ["user"],
  RESET_PASSWORD: ["user"],
  ISOLATE_HOST: ["host"],
  BLOCK_SOURCE_IP: ["ip"],
};

function errorText(error: unknown): string | null {
  if (!error) return null;
  if (error instanceof ApiError) return error.detail;
  return error instanceof Error ? error.message : JSON.stringify(error);
}

function SimulationNotice() {
  const { t } = useTranslation();
  return (
    <p
      className="flex items-start gap-2 rounded-md border border-accent/50 bg-accent-soft p-3 text-sm"
      data-testid="simulation-notice"
    >
      <FlaskConical aria-hidden className="mt-0.5 size-4 shrink-0 text-accent" />
      <span>{t("actions.simulationNotice")}</span>
    </p>
  );
}

export function ProposeActionDialog({
  caseId,
  step,
  onClose,
}: {
  caseId: string;
  step: Recommendation;
  onClose: () => void;
}) {
  const { t, i18n } = useTranslation();
  const propose = useProposeAction(caseId);
  const params = PARAMETERS[step.step_id] ?? [];
  const [values, setValues] = useState<Record<string, string>>(() =>
    Object.fromEntries(params.map((p) => [p, step.targets[p]?.[0] ?? ""])),
  );
  const [reason, setReason] = useState("");
  const valid = reason.trim().length > 0 && params.every((p) => values[p]);

  return (
    <Dialog
      open
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
      title={t("actions.proposeTitle", { step: i18n.language === "de" ? step.title_de : step.title_en })}
      description={t("actions.proposeDescription")}
    >
      <form
        className="flex flex-col gap-3"
        onSubmit={(event) => {
          event.preventDefault();
          propose.mutate(
            { step_id: step.step_id, parameters: values, reason: reason.trim(), source: "playbook" },
            { onSuccess: onClose },
          );
        }}
      >
        {params.map((param) => (
          <div key={param}>
            <label htmlFor={`param-${param}`} className="label">
              {t(`entity.${param}`)}
            </label>
            <select
              id={`param-${param}`}
              className="input font-mono"
              value={values[param] ?? ""}
              onChange={(event) => {
                setValues((prev) => ({ ...prev, [param]: event.target.value }));
              }}
            >
              {(step.targets[param] ?? []).map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
            </select>
          </div>
        ))}
        <div>
          <label htmlFor="propose-reason" className="label">
            {t("actions.reason")}
          </label>
          <textarea
            id="propose-reason"
            className="input min-h-20"
            value={reason}
            required
            maxLength={2000}
            onChange={(event) => {
              setReason(event.target.value);
            }}
          />
        </div>
        <SimulationNotice />
        {propose.error && (
          <p role="alert" className="text-sm text-danger">
            {errorText(propose.error)}
          </p>
        )}
        <div className="flex justify-end gap-2">
          <button type="button" className="btn" onClick={onClose}>
            {t("common.cancel")}
          </button>
          <button type="submit" className="btn btn-primary" disabled={!valid || propose.isPending}>
            {t("actions.submitProposal")}
          </button>
        </div>
      </form>
    </Dialog>
  );
}

export function ApprovalDialog({ action, caseId, onClose }: { action: Action; caseId: string; onClose: () => void }) {
  const { t } = useTranslation();
  const { me } = useAuth();
  const decide = useDecideAction(caseId);
  const [reason, setReason] = useState("");
  const ownProposal = me?.username === action.proposed_by;
  const submit = (decision: "approved" | "rejected") => {
    decide.mutate({ actionId: action.action_id, decision, reason: reason.trim() }, { onSuccess: onClose });
  };
  return (
    <Dialog
      open
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
      title={t("actions.approvalTitle")}
      description={t("actions.approvalDescription")}
      wide
    >
      <div className="flex flex-col gap-3" data-testid="approval-dialog">
        <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1.5 text-sm">
          <dt className="text-muted">{t("actions.step")}</dt>
          <dd className="font-mono">{action.step_id}</dd>
          <dt className="text-muted">{t("actions.parameters")}</dt>
          <dd className="font-mono break-all">
            {Object.entries(action.parameters).map(([key, value]) => (
              <span key={key} className="mr-3">
                {key}=<strong>{value}</strong>
              </span>
            ))}
          </dd>
          <dt className="text-muted">{t("actions.proposedBy")}</dt>
          <dd>
            {action.proposed_by} · <Time value={action.proposed_at} /> · {t(`actions.source.${action.source}`)}
          </dd>
          <dt className="text-muted">{t("actions.proposalReason")}</dt>
          <dd className="whitespace-pre-wrap">{action.reason}</dd>
        </dl>
        <SimulationNotice />
        {ownProposal && (
          <p className="rounded-md border border-warn/50 bg-warn/10 p-3 text-sm text-warn">
            {t("actions.fourEyesHint")}
          </p>
        )}
        <div>
          <label htmlFor="decision-reason" className="label">
            {t("actions.decisionReason")}
          </label>
          <textarea
            id="decision-reason"
            className="input min-h-20"
            value={reason}
            required
            maxLength={2000}
            onChange={(event) => {
              setReason(event.target.value);
            }}
          />
        </div>
        {decide.error && (
          <p role="alert" className="text-sm text-danger">
            {errorText(decide.error)}
          </p>
        )}
        <div className="flex justify-end gap-2">
          <button
            type="button"
            className="btn btn-danger"
            disabled={!reason.trim() || decide.isPending}
            onClick={() => {
              submit("rejected");
            }}
          >
            {t("actions.reject")}
          </button>
          <button
            type="button"
            className="btn btn-primary"
            disabled={!reason.trim() || decide.isPending}
            onClick={() => {
              submit("approved");
            }}
          >
            <ShieldCheck aria-hidden className="size-4" />
            {t("actions.approve")}
          </button>
        </div>
      </div>
    </Dialog>
  );
}

const STATUS_TONE: Record<Action["status"], "default" | "accent" | "warn"> = {
  proposed: "warn",
  approved: "accent",
  rejected: "default",
  executed: "accent",
  failed: "warn",
  cancelled: "default",
};

export function ActionsPanel({ data }: { data: CaseDetail }) {
  const { t } = useTranslation();
  const { can } = useAuth();
  const execute = useExecuteAction(data.case.case_id);
  const [deciding, setDeciding] = useState<Action | null>(null);

  return (
    <Section title={t("actions.title")} aside={t("actions.simulationShort")}>
      {data.actions.length === 0 ? (
        <p className="text-sm text-muted">{t("actions.none")}</p>
      ) : (
        <ul className="flex flex-col gap-2" data-testid="actions-list">
          {data.actions.map((action) => (
            <li
              key={action.action_id}
              className="rounded-md border border-border p-3 text-sm"
              data-status={action.status}
            >
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-mono font-semibold">{action.step_id}</span>
                <Tag tone={STATUS_TONE[action.status]}>{t(`actions.status.${action.status}`)}</Tag>
              </div>
              <p className="mt-1 font-mono text-xs break-all text-muted">
                {Object.entries(action.parameters)
                  .map(([k, v]) => `${k}=${v}`)
                  .join(" ")}
              </p>
              <p className="mt-1 text-xs text-muted">
                {t("actions.proposedBy")} {action.proposed_by} · <Time value={action.proposed_at} />
              </p>
              {action.approval && (
                <p className="mt-1 text-xs">
                  {t(`actions.decision.${action.approval.decision}`)} {action.approval.approver} ·{" "}
                  <Time value={action.approval.decided_at} />: {action.approval.reason}
                </p>
              )}
              {action.execution && (
                <p
                  className="mt-1 rounded bg-surface-2 p-2 font-mono text-xs break-words"
                  data-testid="execution-result"
                >
                  {action.execution.details}
                </p>
              )}
              <div className="mt-2 flex gap-2">
                {action.status === "proposed" && can("actions:decide") && (
                  <button
                    type="button"
                    className="btn btn-sm"
                    onClick={() => {
                      setDeciding(action);
                    }}
                  >
                    {t("actions.review")}
                  </button>
                )}
                {action.status === "approved" && can("actions:execute") && (
                  <button
                    type="button"
                    className="btn btn-sm btn-primary"
                    disabled={execute.isPending}
                    onClick={() => {
                      execute.mutate(action.action_id);
                    }}
                  >
                    {t("actions.executeSimulation")}
                  </button>
                )}
              </div>
            </li>
          ))}
        </ul>
      )}
      {execute.error && (
        <p role="alert" className="mt-2 text-sm text-danger">
          {errorText(execute.error)}
        </p>
      )}
      {deciding && (
        <ApprovalDialog
          action={deciding}
          caseId={data.case.case_id}
          onClose={() => {
            setDeciding(null);
          }}
        />
      )}
    </Section>
  );
}
