import { Link, useNavigate, useSearch } from "@tanstack/react-router";
import { useTranslation } from "react-i18next";

import { useEntities } from "../api/hooks";
import { EntityIcon, Tag } from "../components/Badges";
import { PageHeader } from "../components/Layout";
import { SearchField } from "../components/SearchField";
import { QueryView } from "../components/States";
import { Time } from "../components/Time";

/** Pivot view (spec 7.2): users, hosts and IPs with their flags; each opens the cases that contain it. */
export function EntitiesPage() {
  const { t } = useTranslation();
  const search = useSearch({ from: "/entities" });
  const navigate = useNavigate({ from: "/entities" });
  const query = useEntities(search.type, search.q);

  return (
    <>
      <PageHeader title={t("entities.title")} subtitle={t("entities.subtitle")} />
      <div className="card mb-4 flex flex-wrap items-end gap-3 p-3">
        <SearchField
          key={search.q ?? ""}
          id="entity-q"
          className="min-w-56 flex-1"
          label={t("entities.search")}
          initial={search.q ?? ""}
          onSubmit={(value) => void navigate({ search: (prev) => ({ ...prev, q: value || undefined }) })}
        />
        <div role="group" aria-label={t("entities.type")} className="flex gap-1">
          {(["", "user", "host", "ip"] as const).map((type) => (
            <button
              key={type || "all"}
              type="button"
              aria-pressed={(search.type ?? "") === type}
              className={(search.type ?? "") === type ? "btn btn-sm btn-primary" : "btn btn-sm"}
              onClick={() => void navigate({ search: (prev) => ({ ...prev, type: type || undefined }) })}
            >
              {type ? t(`entity.${type}`) : t("common.all")}
            </button>
          ))}
        </div>
      </div>
      <QueryView query={query}>
        {(data) => (
          <div className="card overflow-x-auto">
            <table className="table" aria-label={t("entities.title")}>
              <thead>
                <tr>
                  <th scope="col">{t("entities.entity")}</th>
                  <th scope="col">{t("entities.flags")}</th>
                  <th scope="col">{t("entities.firstSeen")}</th>
                  <th scope="col">{t("entities.lastSeen")}</th>
                  <th scope="col">
                    <span className="sr-only">{t("entities.cases")}</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((row) => (
                  <tr key={`${row.type}:${row.key}`}>
                    <td>
                      <span className="flex items-center gap-2 font-mono text-xs break-all">
                        <EntityIcon type={row.type} className="text-muted" />
                        {row.display}
                      </span>
                    </td>
                    <td>
                      <div className="flex flex-wrap gap-1">
                        {row.privileged && <Tag tone="warn">{t("entities.privileged")}</Tag>}
                        {row.critical && <Tag tone="warn">{t("entities.critical")}</Tag>}
                        {row.hub && (
                          <Tag>
                            {t("entities.hub")}
                            {row.hub_reason &&
                              ` (${
                                row.hub_reason === "configured"
                                  ? t("entities.hubConfigured")
                                  : t("entities.hubAuto", { detail: row.hub_reason })
                              })`}
                          </Tag>
                        )}
                      </div>
                    </td>
                    <td className="text-xs">
                      <Time value={row.first_seen} />
                    </td>
                    <td className="text-xs">
                      <Time value={row.last_seen} />
                    </td>
                    <td>
                      <Link to="/cases" search={{ entity: row.key }} className="link text-xs">
                        {t("entities.showCases")}
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </QueryView>
    </>
  );
}
