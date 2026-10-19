import { AlertTriangle, Inbox, Loader2 } from "lucide-react";
import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";

import { ApiError } from "../api/client";

export function Loading({ label }: { label?: string }) {
  const { t } = useTranslation();
  return (
    <div role="status" aria-live="polite" className="flex items-center gap-2 p-6 text-muted">
      <Loader2 aria-hidden className="size-4 animate-spin" />
      <span>{label ?? t("common.loading")}</span>
    </div>
  );
}

export function Empty({ title, children }: { title?: string; children?: ReactNode }) {
  const { t } = useTranslation();
  return (
    <div className="flex flex-col items-center gap-2 rounded-lg border border-dashed border-border p-8 text-center text-muted">
      <Inbox aria-hidden className="size-6" />
      <p className="font-semibold text-text">{title ?? t("common.empty")}</p>
      {children}
    </div>
  );
}

export function ErrorState({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const { t } = useTranslation();
  let message = t("errors.generic");
  if (error instanceof ApiError) {
    if (error.status === 403) message = t("errors.forbidden");
    else if (error.status === 404) message = t("errors.notFound");
    else message = `${t("errors.generic")} (${error.status}: ${error.detail})`;
  }
  return (
    <div role="alert" className="flex flex-col items-start gap-3 rounded-lg border border-danger/40 bg-danger/5 p-4">
      <div className="flex items-center gap-2 text-danger">
        <AlertTriangle aria-hidden className="size-4" />
        <span className="font-semibold">{message}</span>
      </div>
      {onRetry && (
        <button type="button" className="btn" onClick={onRetry}>
          {t("common.retry")}
        </button>
      )}
    </div>
  );
}

/** Renders loading/error states of a query and the content once data is there. */
export function QueryView<T>({
  query,
  children,
  empty,
}: {
  query: { data: T | undefined; error: unknown; isLoading: boolean; refetch: () => unknown };
  children: (data: T) => ReactNode;
  empty?: (data: T) => boolean;
}) {
  if (query.isLoading) return <Loading />;
  if (query.error) return <ErrorState error={query.error} onRetry={() => void query.refetch()} />;
  if (query.data === undefined) return <Loading />;
  if (empty?.(query.data)) return <Empty />;
  return <>{children(query.data)}</>;
}
