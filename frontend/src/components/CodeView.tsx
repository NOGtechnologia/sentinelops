import { useMemo } from "react";

import { cn } from "../lib/cn";

export interface Segment {
  text: string;
  hit: boolean;
}

/**
 * Split ``text`` into plain and highlighted segments for the given needles (case-insensitive).
 * Pure string work - the result is rendered as React text nodes, so log content can never become markup.
 */
export function highlight(text: string, needles: readonly string[]): Segment[] {
  const terms = [...new Set(needles.map((n) => n.trim()).filter((n) => n.length >= 2))].sort(
    (a, b) => b.length - a.length,
  );
  if (terms.length === 0 || !text) return [{ text, hit: false }];
  const lower = text.toLowerCase();
  const lowerTerms = terms.map((term) => term.toLowerCase());
  const segments: Segment[] = [];
  let index = 0;
  let plainStart = 0;
  while (index < text.length) {
    const match = lowerTerms.find((term) => lower.startsWith(term, index));
    if (match) {
      if (plainStart < index) segments.push({ text: text.slice(plainStart, index), hit: false });
      segments.push({ text: text.slice(index, index + match.length), hit: true });
      index += match.length;
      plainStart = index;
    } else {
      index += 1;
    }
  }
  if (plainStart < text.length) segments.push({ text: text.slice(plainStart), hit: false });
  return segments;
}

export function Highlighted({ text, needles }: { text: string; needles: readonly string[] }) {
  const segments = useMemo(() => highlight(text, needles), [text, needles]);
  return (
    <>
      {segments.map((segment, i) =>
        segment.hit ? (
          <mark key={i} className="rounded-sm bg-mark px-0.5 text-mark-fg">
            {segment.text}
          </mark>
        ) : (
          <span key={i}>{segment.text}</span>
        ),
      )}
    </>
  );
}

/** A raw log line: monospace text in <pre>, never parsed as HTML (spec 16.1). */
export function RawLine({
  text,
  needles = [],
  className,
}: {
  text: string;
  needles?: readonly string[];
  className?: string;
}) {
  return (
    <pre className={cn("raw-line rounded-md border border-border bg-code p-3 text-text", className)}>
      <Highlighted text={text} needles={needles} />
    </pre>
  );
}

/** YAML (rule source) with line numbers; lines containing one of ``markLines`` are emphasised. */
export function YamlView({ yaml, markLines = [] }: { yaml: string; markLines?: readonly string[] }) {
  const lines = yaml.replace(/\n$/, "").split("\n");
  return (
    <pre
      tabIndex={0}
      className="raw-line overflow-x-auto rounded-md border border-border bg-code py-2 text-text"
      data-testid="rule-yaml"
    >
      {lines.map((line, i) => {
        const marked = markLines.some((m) => m && line.includes(m));
        return (
          <div key={i} className={cn("flex px-3", marked && "bg-mark/40")} data-marked={marked || undefined}>
            <span aria-hidden className="mr-3 inline-block w-6 shrink-0 text-right text-muted select-none">
              {i + 1}
            </span>
            <span>{line}</span>
          </div>
        );
      })}
    </pre>
  );
}
