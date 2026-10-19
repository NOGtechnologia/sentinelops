import cytoscape from "cytoscape";
import { useEffect, useRef } from "react";

import type { GraphData } from "../api/types";
import { useTheme } from "../app/theme";

function cssVar(name: string): string {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || "#888";
}

const SHAPES = { user: "ellipse", host: "round-rectangle", ip: "diamond" } as const;

/** User-host-IP relations of a case. Labels are drawn on canvas - never interpreted as markup. */
export function EntityGraph({
  data,
  label,
  onSelect,
  height = 520,
}: {
  data: GraphData;
  label: string;
  onSelect?: (id: string | null) => void;
  height?: number;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const { theme } = useTheme();
  const selectRef = useRef(onSelect);
  useEffect(() => {
    selectRef.current = onSelect;
  });

  useEffect(() => {
    const element = ref.current;
    if (!element) return undefined;
    const maxEvents = Math.max(1, ...data.nodes.map((n) => n.events));
    const colors = { user: cssVar("--accent"), host: cssVar("--p3"), ip: cssVar("--p2") };
    const cy = cytoscape({
      container: element,
      elements: [
        ...data.nodes.map((node) => ({
          data: {
            id: node.id,
            label: node.label,
            type: node.type,
            hub: node.hub ? 1 : 0,
            size: 22 + 26 * Math.sqrt(node.events / maxEvents),
          },
        })),
        ...data.edges.map((edge, i) => ({
          data: { id: `e${i}`, source: edge.source, target: edge.target, weight: edge.weight },
        })),
      ],
      style: [
        {
          selector: "node",
          style: {
            "background-color": (n: cytoscape.NodeSingular) => colors[n.data("type") as keyof typeof colors],
            shape: (n: cytoscape.NodeSingular) => SHAPES[n.data("type") as keyof typeof SHAPES],
            width: "data(size)",
            height: "data(size)",
            label: "data(label)",
            color: cssVar("--text"),
            "font-size": 11,
            "font-family": "JetBrains Mono, monospace",
            "text-valign": "bottom",
            "text-margin-y": 4,
            "text-wrap": "ellipsis",
            "text-max-width": "160px",
          },
        },
        {
          selector: "node[hub = 1]",
          style: { "border-width": 2, "border-style": "dashed", "border-color": cssVar("--muted"), opacity: 0.7 },
        },
        { selector: "node:selected", style: { "border-width": 3, "border-color": cssVar("--text") } },
        {
          selector: "edge",
          style: {
            width: (e: cytoscape.EdgeSingular) => 1 + Math.min(5, Math.log2(1 + (e.data("weight") as number))),
            "line-color": cssVar("--border"),
            "curve-style": "bezier",
          },
        },
      ],
      // Deterministic layout (no random placement): stable screenshots and a stable mental map.
      layout: {
        name: "concentric",
        animate: false,
        padding: 32,
        minNodeSpacing: 36,
        concentric: (node: cytoscape.NodeSingular) => node.degree(false),
        levelWidth: () => 1,
      },
      wheelSensitivity: 0.3,
    });
    cy.on("tap", "node", (event) => selectRef.current?.((event.target as cytoscape.NodeSingular).id()));
    cy.on("tap", (event) => {
      if (event.target === cy) selectRef.current?.(null);
    });
    return () => {
      cy.destroy();
    };
  }, [data, theme]);

  return (
    <div
      ref={ref}
      role="img"
      aria-label={label}
      className="w-full rounded-lg border border-border bg-code"
      style={{ height }}
    />
  );
}
