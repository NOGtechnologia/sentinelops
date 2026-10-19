import { CheckCircle2, ShieldX } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { useAudit } from "../api/hooks";
import { PageHeader } from "../components/Layout";
import { QueryView } from "../components/States";
import { Time } from "../components/Time";

export function AuditPage() {
  const { t } = useTranslation();
  const [objectId, setObjectId] = useState("");
  const [applied, setApplied] = useState<string | undefined>(undefined);
  const [verify, setVerify] = useState(false);
  const query = useAudit(applied, verify);

  return (
    <>
      <PageHeader title={t("audit.title")} subtitle={t("audit.subtitle")} />
      <div className="card mb-4 flex flex-wrap items-end gap-3 p-3">
        <form
          className="min-w-56 flex-1"
          onSubmit={(event) => {
            event.preventDefault();
            setApplied(objectId.trim() || undefined);
          }}
        >
          <label htmlFor="audit-object" className="label">
            {t("audit.objectId")}
          </label>
          <input
            id="audit-object"
            className="input font-mono"
            value={objectId}
            onChange={(event) => {
              setObjectId(event.target.value);
            }}
          />
        </form>
        <button
          type="button"
          className="btn"
          onClick={() => {
            setVerify(true);
          }}
        >
          {t("audit.verify")}
        </button>
      </div>
      <QueryView query={query}>
        {(data) => (
          <>
            {verify && data.chain_broken_at !== null && (
              <p
                role="status"
                className={`mb-3 flex items-center gap-2 text-sm ${data.chain_broken_at.length ? "text-danger" : "text-ok"}`}
              >
                {data.chain_broken_at.length ? (
                  <ShieldX aria-hidden className="size-4" />
                ) : (
                  <CheckCircle2 aria-hidden className="size-4" />
                )}
                {data.chain_broken_at.length
                  ? t("audit.chainBroken", { seqs: data.chain_broken_at.join(", ") })
                  : t("audit.chainOk")}
              </p>
            )}
            <div className="card overflow-x-auto">
              <table className="table text-xs" aria-label={t("audit.title")}>
                <thead>
                  <tr>
                    <th scope="col">#</th>
                    <th scope="col">{t("audit.time")}</th>
                    <th scope="col">{t("audit.actor")}</th>
                    <th scope="col">{t("audit.action")}</th>
                    <th scope="col">{t("audit.object")}</th>
                    <th scope="col">{t("audit.details")}</th>
                  </tr>
                </thead>
                <tbody>
                  {data.items.map((entry) => (
                    <tr key={entry.seq}>
                      <td className="tabular">{entry.seq}</td>
                      <td>
                        <Time value={entry.ts} seconds />
                      </td>
                      <td>{entry.actor}</td>
                      <td className="font-mono">{entry.action}</td>
                      <td className="font-mono break-all">
                        {entry.object_type}:{entry.object_id.slice(0, 16)}
                      </td>
                      <td className="max-w-md font-mono break-all text-muted">{JSON.stringify(entry.details)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}
      </QueryView>
    </>
  );
}
