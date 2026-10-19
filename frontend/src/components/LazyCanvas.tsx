import { lazy, Suspense, type ComponentProps } from "react";

// ECharts (~500 kB) and Cytoscape (~420 kB) are only downloaded when a chart or graph is shown,
// not with the login page or the case queue (Lighthouse performance budget, spec 15.6).
// While loading, the placeholder keeps the final size so the layout does not shift.
const TimeChartImpl = lazy(() => import("./Chart").then((m) => ({ default: m.TimeChart })));
const EntityGraphImpl = lazy(() => import("./EntityGraph").then((m) => ({ default: m.EntityGraph })));

function Placeholder({ label, height, className }: { label: string; height: number; className?: string }) {
  return <div role="img" aria-label={label} aria-busy="true" className={className} style={{ height }} />;
}

export function TimeChart(props: ComponentProps<typeof TimeChartImpl>) {
  return (
    <Suspense fallback={<Placeholder label={props.label} height={props.height ?? 180} className="w-full" />}>
      <TimeChartImpl {...props} />
    </Suspense>
  );
}

export function EntityGraph(props: ComponentProps<typeof EntityGraphImpl>) {
  return (
    <Suspense
      fallback={
        <Placeholder
          label={props.label}
          height={props.height ?? 520}
          className="w-full rounded-lg border border-border bg-code"
        />
      }
    >
      <EntityGraphImpl {...props} />
    </Suspense>
  );
}
