import { BarChart, LineChart } from "echarts/charts";
import { GridComponent, TooltipComponent } from "echarts/components";
import * as echarts from "echarts/core";
import { CanvasRenderer } from "echarts/renderers";
import { useEffect, useRef } from "react";

import { useTheme } from "../app/theme";

echarts.use([LineChart, BarChart, GridComponent, TooltipComponent, CanvasRenderer]);

export interface ChartSeries {
  name: string;
  data: [string, number][];
  type: "line" | "bar";
  color: string; // CSS variable name, e.g. "--accent"
  axis?: 0 | 1; // 1 = secondary axis on the right (different magnitude)
}

function cssVar(name: string): string {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || "#888";
}

/** Time-series chart; data points are rendered on a canvas (log values never become DOM markup). */
export function TimeChart({
  series,
  label,
  height = 180,
  formatTime,
}: {
  series: ChartSeries[];
  label: string;
  height?: number;
  formatTime: (iso: string) => string;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const { theme } = useTheme();

  useEffect(() => {
    const element = ref.current;
    if (!element) return undefined;
    const chart = echarts.init(element, undefined, { renderer: "canvas" });
    const text = cssVar("--muted");
    const grid = cssVar("--border");
    chart.setOption({
      animation: false,
      grid: { left: 48, right: series.some((s) => s.axis === 1) ? 36 : 12, top: 12, bottom: 28 },
      tooltip: {
        trigger: "axis",
        renderMode: "richText",
        backgroundColor: cssVar("--surface"),
        borderColor: grid,
        textStyle: { color: cssVar("--text") },
      },
      xAxis: {
        type: "time",
        axisLabel: { color: text, formatter: (value: number) => formatTime(new Date(value).toISOString()) },
        axisLine: { lineStyle: { color: grid } },
      },
      yAxis: [
        { type: "value", minInterval: 1, axisLabel: { color: text }, splitLine: { lineStyle: { color: grid } } },
        { type: "value", minInterval: 1, axisLabel: { color: text }, splitLine: { show: false } },
      ],
      series: series.map((s) => ({
        name: s.name,
        type: s.type,
        yAxisIndex: s.axis ?? 0,
        data: s.data,
        showSymbol: false,
        smooth: false,
        barMaxWidth: 12,
        itemStyle: { color: cssVar(s.color) },
        lineStyle: { color: cssVar(s.color), width: 2 },
        areaStyle: s.type === "line" ? { color: cssVar(s.color), opacity: 0.12 } : undefined,
      })),
    });
    const observer = new ResizeObserver(() => {
      chart.resize();
    });
    observer.observe(element);
    return () => {
      observer.disconnect();
      chart.dispose();
    };
  }, [series, theme, formatTime]);

  return <div ref={ref} role="img" aria-label={label} className="w-full" style={{ height }} />;
}
