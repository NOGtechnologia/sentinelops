import { Globe, Monitor, User } from "lucide-react";
import { useTranslation } from "react-i18next";

import type { CaseStatus, Entity, EntityType, Level } from "../api/types";
import { cn } from "../lib/cn";

const STATUS_STYLE: Record<CaseStatus, string> = {
  new: "border-accent/60 text-accent",
  in_progress: "border-warn/60 text-warn",
  resolved_true_positive: "border-danger/50 text-danger",
  resolved_false_positive: "border-border text-muted",
  resolved_benign: "border-ok/50 text-ok",
};

export function StatusBadge({ status }: { status: CaseStatus }) {
  const { t } = useTranslation();
  return (
    <span className={cn("rounded border px-1.5 py-0.5 text-xs whitespace-nowrap", STATUS_STYLE[status])}>
      {t(`status.${status}`)}
    </span>
  );
}

const LEVEL_STYLE: Record<Level, string> = {
  critical: "text-p1",
  high: "text-p2",
  medium: "text-p3",
  low: "text-p4",
  informational: "text-muted",
};

export function LevelBadge({ level }: { level: Level }) {
  const { t } = useTranslation();
  return <span className={cn("text-xs font-semibold uppercase", LEVEL_STYLE[level])}>{t(`level.${level}`)}</span>;
}

const ENTITY_ICON: Record<EntityType, typeof User> = { user: User, host: Monitor, ip: Globe };

export function EntityIcon({ type, className }: { type: EntityType; className?: string }) {
  const Icon = ENTITY_ICON[type];
  return <Icon aria-hidden className={cn("size-3.5 shrink-0", className)} />;
}

/** Entity values come from logs: rendered as text only. */
export function EntityChip({ entity, onClick }: { entity: Entity; onClick?: (entity: Entity) => void }) {
  const { t } = useTranslation();
  const content = (
    <>
      <EntityIcon type={entity.type} className="text-muted" />
      <span className="sr-only">{t(`entity.${entity.type}`)}: </span>
      <span className="max-w-56 truncate font-mono text-xs">{entity.display}</span>
    </>
  );
  const base = "inline-flex items-center gap-1 rounded border border-border bg-surface-2 px-1.5 py-0.5";
  if (onClick) {
    return (
      <button
        type="button"
        className={cn(base, "hover:border-accent")}
        onClick={() => {
          onClick(entity);
        }}
        title={entity.display}
      >
        {content}
      </button>
    );
  }
  return (
    <span className={base} title={entity.display}>
      {content}
    </span>
  );
}

export function Tag({
  children,
  tone = "default",
}: {
  children: React.ReactNode;
  tone?: "default" | "accent" | "warn";
}) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded px-1.5 py-0.5 text-xs whitespace-nowrap",
        tone === "accent" && "bg-accent-soft text-accent",
        tone === "warn" && "bg-warn/15 text-warn",
        tone === "default" && "bg-surface-2 text-muted",
      )}
    >
      {children}
    </span>
  );
}
