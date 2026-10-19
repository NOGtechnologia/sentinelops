import { useNavigate, useParams } from "@tanstack/react-router";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { useGraph } from "../../api/hooks";
import type { GraphData } from "../../api/types";
import { EntityIcon } from "../../components/Badges";
import { EntityGraph } from "../../components/LazyCanvas";
import { Section } from "../../components/Layout";
import { QueryView } from "../../components/States";

export function GraphTab() {
  const { caseId } = useParams({ from: "/cases/$caseId/graph" });
  const query = useGraph(caseId);
  return (
    <QueryView query={query} empty={(d) => d.nodes.length === 0}>
      {(data) => <GraphView data={data} />}
    </QueryView>
  );
}

function GraphView({ data }: { data: GraphData }) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const [selected, setSelected] = useState<string | null>(null);
  const node = data.nodes.find((n) => n.id === selected);
  const neighbours = selected
    ? data.edges
        .filter((e) => e.source === selected || e.target === selected)
        .map((e) => ({ id: e.source === selected ? e.target : e.source, weight: e.weight }))
        .sort((a, b) => b.weight - a.weight)
    : [];
  const byId = new Map(data.nodes.map((n) => [n.id, n]));

  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_320px]">
      <div>
        <EntityGraph
          data={data}
          label={t("graph.label", { nodes: data.nodes.length, edges: data.edges.length })}
          onSelect={setSelected}
        />
        <ul className="mt-2 flex flex-wrap gap-4 text-xs text-muted" aria-label={t("graph.legend")}>
          <li className="flex items-center gap-1.5">
            <span aria-hidden className="inline-block size-3 rounded-full bg-accent" />
            {t("entity.user")}
          </li>
          <li className="flex items-center gap-1.5">
            <span aria-hidden className="inline-block size-3 rounded-sm bg-p3" />
            {t("entity.host")}
          </li>
          <li className="flex items-center gap-1.5">
            <span aria-hidden className="inline-block size-3 rotate-45 bg-p2" />
            {t("entity.ip")}
          </li>
          <li className="flex items-center gap-1.5">
            <span aria-hidden className="inline-block size-3 rounded-full border-2 border-dashed border-muted" />
            {t("graph.hub")}
          </li>
        </ul>
      </div>
      <Section title={t("graph.details")}>
        {!node ? (
          <p className="text-sm text-muted">{t("graph.selectHint")}</p>
        ) : (
          <div className="flex flex-col gap-3 text-sm">
            <p className="flex items-center gap-2 font-mono break-all">
              <EntityIcon type={node.type} />
              {node.label}
            </p>
            <p className="text-muted">
              {t(`entity.${node.type}`)} · {t("graph.events", { count: node.events })}
              {node.hub && ` · ${t("graph.hub")}`}
            </p>
            <button
              type="button"
              className="btn btn-sm self-start"
              onClick={() => void navigate({ to: "/cases", search: { entity: node.id.split(":").slice(1).join(":") } })}
            >
              {t("graph.casesWithEntity")}
            </button>
            {neighbours.length > 0 && (
              <div>
                <h3 className="label">{t("graph.connections")}</h3>
                <ul className="flex flex-col gap-1">
                  {neighbours.map((n) => {
                    const other = byId.get(n.id);
                    return (
                      <li key={n.id} className="flex items-center justify-between gap-2 text-xs">
                        <span className="flex min-w-0 items-center gap-1.5 font-mono">
                          {other && <EntityIcon type={other.type} className="text-muted" />}
                          <span className="truncate">{other?.label ?? n.id}</span>
                        </span>
                        <span className="tabular text-muted">{n.weight}</span>
                      </li>
                    );
                  })}
                </ul>
              </div>
            )}
          </div>
        )}
      </Section>
    </div>
  );
}
