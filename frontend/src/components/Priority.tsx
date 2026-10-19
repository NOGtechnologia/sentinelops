import { useTranslation } from "react-i18next";

import type { Priority } from "../api/types";
import { cn } from "../lib/cn";

/** Colour-blind safe: every priority has its own shape and text (P1 octagon, P2 triangle, P3 circle, P4 dot). */
function Shape({ level }: { level: Priority }) {
  const common = { width: 12, height: 12, viewBox: "0 0 12 12", "aria-hidden": true, focusable: false } as const;
  switch (level) {
    case "P1":
      return (
        <svg {...common}>
          <polygon points="3.5,0.5 8.5,0.5 11.5,3.5 11.5,8.5 8.5,11.5 3.5,11.5 0.5,8.5 0.5,3.5" fill="currentColor" />
        </svg>
      );
    case "P2":
      return (
        <svg {...common}>
          <polygon points="6,0.5 11.5,11 0.5,11" fill="currentColor" />
        </svg>
      );
    case "P3":
      return (
        <svg {...common}>
          <circle cx="6" cy="6" r="5" fill="currentColor" />
        </svg>
      );
    default:
      return (
        <svg {...common}>
          <circle cx="6" cy="6" r="2.5" fill="currentColor" />
        </svg>
      );
  }
}

const TEXT: Record<Priority, string> = { P1: "text-p1", P2: "text-p2", P3: "text-p3", P4: "text-p4" };
const RING: Record<Priority, string> = {
  P1: "border-p1/50 bg-p1/10",
  P2: "border-p2/50 bg-p2/10",
  P3: "border-p3/50 bg-p3/10",
  P4: "border-p4/40 bg-p4/10",
};

export function PriorityBadge({ level, score, large = false }: { level: Priority; score?: number; large?: boolean }) {
  const { t } = useTranslation();
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md border font-semibold whitespace-nowrap",
        TEXT[level],
        RING[level],
        large ? "px-2.5 py-1 text-base" : "px-1.5 py-0.5 text-xs",
      )}
      data-priority={level}
    >
      <Shape level={level} />
      <span>{level}</span>
      <span className={cn("font-normal", large ? "text-sm" : "sr-only sm:not-sr-only")}>{t(`priority.${level}`)}</span>
      {score !== undefined && <span className="tabular font-normal text-muted">· {score}</span>}
    </span>
  );
}
