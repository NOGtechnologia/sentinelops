import { useParams } from "@tanstack/react-router";
import { useVirtualizer } from "@tanstack/react-virtual";
import { Clock, Siren, ZoomOut } from "lucide-react";
import { useMemo, useRef, useState, type PointerEvent as ReactPointerEvent } from "react";
import { useTranslation } from "react-i18next";

import { useCase, useTimeline } from "../../api/hooks";
import type { TimelineItem } from "../../api/types";
import { Tag } from "../../components/Badges";
import { Section } from "../../components/Layout";
import { QueryView } from "../../components/States";
import { Time } from "../../components/Time";
import { locale } from "../../i18n";
import { cn } from "../../lib/cn";
import { formatTime, parseTime } from "../../lib/format";

const MAX_LANES = 8;

export function TimelineTab() {
  const { caseId } = useParams({ from: "/cases/$caseId/timeline" });
  const query = useTimeline(caseId);
  const detail = useCase(caseId);
  return (
    <QueryView query={query}>
      {(data) => <Timeline items={data.items} refs={detail.data?.evidence_refs ?? {}} />}
    </QueryView>
  );
}

interface Range {
  start: number;
  end: number;
}

export function Timeline({ items, refs }: { items: TimelineItem[]; refs: Record<string, string> }) {
  const { t, i18n } = useTranslation();
  const [lane, setLane] = useState<string>("");
  const [triggersOnly, setTriggersOnly] = useState(false);
  const [range, setRange] = useState<Range | null>(null);

  const lanes = useMemo(() => {
    const counts = new Map<string, number>();
    for (const item of items) for (const l of item.lanes ?? []) counts.set(l, (counts.get(l) ?? 0) + 1);
    return [...counts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).map(([l]) => l);
  }, [items]);

  const filtered = useMemo(
    () =>
      items.filter((item) => {
        const ts = parseTime(item.time)?.getTime() ?? 0;
        if (range && (ts < range.start || ts > range.end)) return false;
        if (lane && item.kind === "event" && !(item.lanes ?? []).includes(lane)) return false;
        if (triggersOnly && item.kind === "event" && (item.rules ?? []).length === 0) return false;
        return true;
      }),
    [items, lane, triggersOnly, range],
  );

  const quality = items.filter((i) => i.time_quality && i.time_quality !== "exact").length;

  return (
    <div className="flex flex-col gap-4">
      <Section
        title={t("timeline.lanesTitle")}
        aside={
          range ? (
            <button
              type="button"
              className="btn btn-sm"
              onClick={() => {
                setRange(null);
              }}
            >
              <ZoomOut aria-hidden className="size-3.5" />
              {t("timeline.resetZoom")}
            </button>
          ) : (
            t("timeline.zoomHint")
          )
        }
      >
        <Swimlanes items={items} lanes={lanes.slice(0, MAX_LANES)} range={range} onZoom={setRange} />
      </Section>

      <div className="card flex flex-wrap items-end gap-4 p-3">
        <div>
          <label htmlFor="lane-filter" className="label">
            {t("timeline.lane")}
          </label>
          <select
            id="lane-filter"
            className="input font-mono"
            value={lane}
            onChange={(event) => {
              setLane(event.target.value);
            }}
          >
            <option value="">{t("timeline.allLanes")}</option>
            {lanes.map((l) => (
              <option key={l} value={l}>
                {l}
              </option>
            ))}
          </select>
        </div>
        <label className="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={triggersOnly}
            onChange={(event) => {
              setTriggersOnly(event.target.checked);
            }}
          />
          {t("timeline.triggersOnly")}
        </label>
        <p className="ml-auto text-xs text-muted">
          {t("timeline.count", { shown: filtered.length, total: items.length })}
          {quality > 0 && <> · {t("timeline.qualityCount", { count: quality })}</>}
        </p>
      </div>

      <VirtualList items={filtered} refs={refs} locale={locale(i18n.language)} />
    </div>
  );
}

function VirtualList({
  items,
  refs,
  locale: loc,
}: {
  items: TimelineItem[];
  refs: Record<string, string>;
  locale: string;
}) {
  const { t } = useTranslation();
  const parent = useRef<HTMLElement>(null);
  const virtualizer = useVirtualizer({
    count: items.length,
    getScrollElement: () => parent.current,
    estimateSize: () => 44,
    overscan: 12,
  });
  return (
    // A scrollable region must be reachable by keyboard (axe: scrollable-region-focusable).
    <section
      ref={parent}
      className="card h-[60vh] min-h-80 overflow-auto"
      aria-label={t("timeline.listLabel")}
      // eslint-disable-next-line jsx-a11y/no-noninteractive-tabindex -- scrollable region needs keyboard focus
      tabIndex={0}
      data-testid="timeline-list"
    >
      <div role="list" className="relative w-full" style={{ height: virtualizer.getTotalSize() }}>
        {virtualizer.getVirtualItems().map((row) => {
          const item = items[row.index];
          if (!item) return null;
          return (
            <div
              key={row.key}
              role="listitem"
              className="absolute top-0 left-0 w-full"
              style={{ transform: `translateY(${row.start}px)` }}
              ref={virtualizer.measureElement}
              data-index={row.index}
            >
              <TimelineRow item={item} refId={item.id ? refs[item.id] : undefined} loc={loc} />
            </div>
          );
        })}
      </div>
    </section>
  );
}

function TimelineRow({ item, refId, loc }: { item: TimelineItem; refId: string | undefined; loc: string }) {
  const { t, i18n } = useTranslation();
  if (item.kind === "gap") {
    return (
      <div className="flex items-center gap-2 border-b border-dashed border-border px-4 py-2 text-xs text-muted">
        <Clock aria-hidden className="size-3.5" />
        {t("timeline.gap", { minutes: Math.round((item.seconds ?? 0) / 60) })}
      </div>
    );
  }
  if (item.kind === "alert") {
    return (
      <div
        className="flex flex-wrap items-center gap-3 border-b border-border bg-p2/10 px-4 py-2 text-sm"
        data-kind="alert"
      >
        <span className="tabular w-20 font-mono text-xs">{formatTime(item.time, loc)}</span>
        <Siren aria-hidden className="size-4 text-p2" />
        <span className="font-semibold">
          {t("timeline.alert")}: {item.rule_id} –{" "}
          {i18n.language === "de" ? item.title_de : (item.title ?? item.title_de)}
        </span>
      </div>
    );
  }
  const trigger = (item.rules ?? []).length > 0;
  return (
    <div
      className={cn(
        "flex flex-wrap items-center gap-x-3 gap-y-1 border-b border-border/60 px-4 py-2 text-sm",
        trigger && "border-l-2 border-l-accent bg-accent-soft/40",
      )}
      data-trigger={trigger || undefined}
    >
      <span className="tabular w-20 font-mono text-xs">
        <Time value={item.time} timeOnly />
      </span>
      {refId && <span className="w-10 font-mono text-[11px] font-semibold text-accent">{refId}</span>}
      <span className={cn("min-w-28 font-mono text-xs", item.outcome === "failure" ? "text-danger" : "text-text")}>
        {item.action} {item.code ? `(${item.code})` : ""}
      </span>
      <span className="font-mono text-xs break-all">
        {item.user && (
          <span>
            <span className="text-muted">{t("entity.user")}=</span>
            {item.user}{" "}
          </span>
        )}
        {item.target_user && (
          <span>
            <span className="text-muted">{t("timeline.target")}=</span>
            {item.target_user}{" "}
          </span>
        )}
        {item.host && (
          <span>
            <span className="text-muted">{t("entity.host")}=</span>
            {item.host}{" "}
          </span>
        )}
        {item.source_ip && (
          <span>
            <span className="text-muted">{t("entity.ip")}=</span>
            {item.source_ip}
          </span>
        )}
      </span>
      <span className="ml-auto flex flex-wrap gap-1">
        {item.time_quality && item.time_quality !== "exact" && (
          <Tag tone="warn">{t(`timeQuality.${item.time_quality}`, { defaultValue: item.time_quality })}</Tag>
        )}
        {(item.rules ?? []).map((r) => (
          <Tag key={r} tone="accent">
            {r}
          </Tag>
        ))}
      </span>
    </div>
  );
}

/** Lanes per entity; events as ticks, triggering events emphasised, alerts as diamonds. Drag to zoom. */
function Swimlanes({
  items,
  lanes,
  range,
  onZoom,
}: {
  items: TimelineItem[];
  lanes: string[];
  range: Range | null;
  onZoom: (range: Range) => void;
}) {
  const { t, i18n } = useTranslation();
  const loc = locale(i18n.language);
  const svgRef = useRef<SVGSVGElement>(null);
  const [drag, setDrag] = useState<{ from: number; to: number } | null>(null);
  const times = items.map((i) => parseTime(i.time)?.getTime() ?? 0).filter((v) => v > 0);
  const min = range?.start ?? Math.min(...times);
  const max = range?.end ?? Math.max(...times);
  const span = Math.max(1, max - min);
  const width = 1000;
  const labelWidth = 180;
  const rowHeight = 26;
  const height = Math.max(1, lanes.length) * rowHeight + 24;
  const x = (ts: number) => labelWidth + ((ts - min) / span) * (width - labelWidth - 10);

  if (times.length === 0 || lanes.length === 0) return <p className="text-sm text-muted">{t("common.empty")}</p>;

  const toTime = (clientX: number) => {
    const rect = svgRef.current?.getBoundingClientRect();
    if (!rect) return min;
    const px = ((clientX - rect.left) / rect.width) * width;
    return min + ((Math.max(labelWidth, Math.min(width - 10, px)) - labelWidth) / (width - labelWidth - 10)) * span;
  };
  const onDown = (event: ReactPointerEvent<SVGSVGElement>) => {
    const ts = toTime(event.clientX);
    setDrag({ from: ts, to: ts });
  };
  const onMove = (event: ReactPointerEvent<SVGSVGElement>) => {
    if (drag) setDrag({ ...drag, to: toTime(event.clientX) });
  };
  const onUp = () => {
    if (drag && Math.abs(drag.to - drag.from) > span / 100) {
      onZoom({ start: Math.min(drag.from, drag.to), end: Math.max(drag.from, drag.to) });
    }
    setDrag(null);
  };

  return (
    <svg
      ref={svgRef}
      viewBox={`0 0 ${width} ${height}`}
      className="w-full cursor-crosshair touch-none select-none"
      role="img"
      aria-label={t("timeline.lanesLabel", { lanes: lanes.length })}
      onPointerDown={onDown}
      onPointerMove={onMove}
      onPointerUp={onUp}
      onPointerLeave={onUp}
      data-testid="swimlanes"
    >
      {lanes.map((laneName, row) => {
        const y = row * rowHeight + 4;
        return (
          <g key={laneName}>
            <rect
              x={0}
              y={y}
              width={width}
              height={rowHeight - 4}
              className={row % 2 ? "fill-surface" : "fill-surface-2"}
            />
            <text x={6} y={y + 15} className="fill-muted font-mono text-[11px]">
              {laneName.length > 26 ? `${laneName.slice(0, 25)}…` : laneName}
            </text>
            {items.map((item, i) => {
              if (!(item.lanes ?? []).includes(laneName) || item.kind !== "event") return null;
              const ts = parseTime(item.time)?.getTime() ?? 0;
              if (ts < min || ts > max) return null;
              const trigger = (item.rules ?? []).length > 0;
              return (
                <rect
                  key={i}
                  x={x(ts) - 1}
                  y={y + (trigger ? 2 : 6)}
                  width={trigger ? 3 : 2}
                  height={trigger ? rowHeight - 8 : rowHeight - 16}
                  className={trigger ? "fill-accent" : "fill-muted"}
                />
              );
            })}
          </g>
        );
      })}
      {items
        .filter((item) => item.kind === "alert")
        .map((item, i) => {
          const ts = parseTime(item.time)?.getTime() ?? 0;
          if (ts < min || ts > max) return null;
          const cx = x(ts);
          const y = height - 14;
          return (
            <polygon
              key={`a${i}`}
              points={`${cx},${y - 6} ${cx + 6},${y} ${cx},${y + 6} ${cx - 6},${y}`}
              className="fill-p2"
            />
          );
        })}
      {drag && (
        <rect
          x={x(Math.min(drag.from, drag.to))}
          y={0}
          width={Math.abs(x(drag.to) - x(drag.from))}
          height={height}
          className="fill-accent/20"
        />
      )}
      <text x={labelWidth} y={height - 2} className="fill-muted text-[10px]">
        {formatTime(new Date(min).toISOString(), loc)}
      </text>
      <text x={width - 10} y={height - 2} textAnchor="end" className="fill-muted text-[10px]">
        {formatTime(new Date(max).toISOString(), loc)}
      </text>
    </svg>
  );
}
