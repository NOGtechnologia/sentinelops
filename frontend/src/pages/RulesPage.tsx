import { Link } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";

import { useRules } from "../api/hooks";
import type { RuleRow } from "../api/types";
import { LevelBadge, Tag } from "../components/Badges";
import { PageHeader } from "../components/Layout";
import { QueryView } from "../components/States";
import { locale } from "../i18n";
import { formatPercent } from "../lib/format";

export function RulesPage() {
  const { t } = useTranslation();
  const query = useRules();
  return (
    <>
      <PageHeader title={t("rules.title")} subtitle={t("rules.subtitle")} />
      <QueryView query={query}>{(rows) => <RulesTable rows={rows} />}</QueryView>
    </>
  );
}

function RulesTable({ rows }: { rows: RuleRow[] }) {
  const { t, i18n } = useTranslation();
  const loc = locale(i18n.language);
  const [filter, setFilter] = useState("");
  const [source, setSource] = useState("");
  const shown = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    return rows
      .filter((r) => !source || r.source === source)
      .filter(
        (r) =>
          !needle ||
          r.rule_id.toLowerCase().includes(needle) ||
          r.title.toLowerCase().includes(needle) ||
          r.title_de.toLowerCase().includes(needle),
      )
      .sort((a, b) => a.rule_id.localeCompare(b.rule_id));
  }, [rows, filter, source]);

  return (
    <div className="card overflow-x-auto">
      <div className="flex flex-wrap items-end gap-3 border-b border-border p-3">
        <div className="min-w-56 flex-1">
          <label htmlFor="rule-filter" className="label">
            {t("rules.filter")}
          </label>
          <input
            id="rule-filter"
            className="input"
            value={filter}
            onChange={(event) => {
              setFilter(event.target.value);
            }}
          />
        </div>
        <div>
          <label htmlFor="rule-source" className="label">
            {t("rules.source")}
          </label>
          <select
            id="rule-source"
            className="input"
            value={source}
            onChange={(event) => {
              setSource(event.target.value);
            }}
          >
            <option value="">{t("common.all")}</option>
            <option value="custom">{t("rules.sourceCustom")}</option>
            <option value="sigmahq">{t("rules.sourceSigmaHq")}</option>
          </select>
        </div>
      </div>
      <table className="table" aria-label={t("rules.title")}>
        <thead>
          <tr>
            <th scope="col">{t("rules.rule")}</th>
            <th scope="col">{t("rules.level")}</th>
            <th scope="col">{t("rules.maturity")}</th>
            <th scope="col">{t("rules.kind")}</th>
            <th scope="col">{t("rules.attack")}</th>
            <th scope="col" className="text-right">
              {t("rules.hits")}
            </th>
            <th scope="col" className="text-right">
              {t("rules.fpRate")}
            </th>
            <th scope="col">{t("rules.state")}</th>
          </tr>
        </thead>
        <tbody>
          {shown.map((rule) => (
            <tr key={rule.rule_id}>
              <td className="min-w-72">
                <Link to="/rules/$ruleId" params={{ ruleId: rule.rule_id }} className="link font-semibold text-text">
                  {i18n.language === "de" ? rule.title_de : rule.title}
                </Link>
                <p className="font-mono text-xs text-muted">
                  {`${rule.rule_id} · v${rule.version} · ${rule.source === "sigmahq" ? `SigmaHQ (${rule.author})` : rule.author}`}
                </p>
              </td>
              <td>
                <LevelBadge level={rule.level} />
              </td>
              <td>
                <Tag tone={rule.maturity === "experimental" ? "warn" : "default"}>
                  {t(`rules.maturityValue.${rule.maturity}`, { defaultValue: rule.maturity })}
                </Tag>
              </td>
              <td className="text-xs">{t(`evidence.kind.${rule.kind}`, { defaultValue: rule.kind })}</td>
              <td>
                <div className="flex flex-wrap gap-1">
                  {rule.techniques.map((tech) => (
                    <Tag key={tech}>{tech}</Tag>
                  ))}
                </div>
              </td>
              <td className="tabular text-right">{rule.alerts}</td>
              <td className="tabular text-right">
                {rule.false_positive_rate === null ? "–" : formatPercent(rule.false_positive_rate, loc)}
              </td>
              <td>
                {rule.active ? (
                  <Tag tone="accent">{t("rules.active")}</Tag>
                ) : (
                  <Tag tone="warn">{t("rules.inactive")}</Tag>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
