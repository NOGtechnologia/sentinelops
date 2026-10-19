/** Formatting helpers. All timestamps from the API are UTC (ISO 8601); display uses the configured zone. */

let displayZone = "Europe/Berlin";

export function setDisplayZone(zone: string): void {
  displayZone = zone;
}

export function getDisplayZone(): string {
  return displayZone;
}

const cache = new Map<string, Intl.DateTimeFormat>();

function formatter(locale: string, options: Intl.DateTimeFormatOptions): Intl.DateTimeFormat {
  const key = `${locale}|${displayZone}|${JSON.stringify(options)}`;
  let fmt = cache.get(key);
  if (!fmt) {
    fmt = new Intl.DateTimeFormat(locale, { timeZone: displayZone, ...options });
    cache.set(key, fmt);
  }
  return fmt;
}

export function parseTime(value: string | null | undefined): Date | null {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

export function formatDateTime(value: string | null | undefined, locale: string, seconds = false): string {
  const date = parseTime(value);
  if (!date) return "–";
  return formatter(locale, {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    ...(seconds ? { second: "2-digit" } : {}),
  }).format(date);
}

export function formatTime(value: string | null | undefined, locale: string): string {
  const date = parseTime(value);
  if (!date) return "–";
  return formatter(locale, { hour: "2-digit", minute: "2-digit", second: "2-digit" }).format(date);
}

export function formatNumber(value: number | null | undefined, locale: string): string {
  if (value === null || value === undefined) return "–";
  return new Intl.NumberFormat(locale).format(value);
}

export function formatPercent(value: number | null | undefined, locale: string): string {
  if (value === null || value === undefined) return "–";
  return new Intl.NumberFormat(locale, { style: "percent", maximumFractionDigits: 1 }).format(value);
}

/** Age in whole minutes/hours/days between two instants (``now`` comes from the server clock). */
export function age(
  from: string | null | undefined,
  now: string | null | undefined,
): { unit: "m" | "h" | "d"; value: number } {
  const start = parseTime(from);
  const end = parseTime(now);
  if (!start || !end) return { unit: "m", value: 0 };
  const minutes = Math.max(0, Math.floor((end.getTime() - start.getTime()) / 60000));
  if (minutes < 60) return { unit: "m", value: minutes };
  if (minutes < 48 * 60) return { unit: "h", value: Math.floor(minutes / 60) };
  return { unit: "d", value: Math.floor(minutes / 1440) };
}

export function shortId(id: string, length = 8): string {
  return id.slice(0, length);
}
