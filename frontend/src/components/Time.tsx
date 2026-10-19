import { useTranslation } from "react-i18next";

import { locale } from "../i18n";
import { formatDateTime, formatTime, getDisplayZone } from "../lib/format";

export function Time({
  value,
  seconds = false,
  timeOnly = false,
}: {
  value: string | null | undefined;
  seconds?: boolean;
  timeOnly?: boolean;
}) {
  const { i18n } = useTranslation();
  const loc = locale(i18n.language);
  const text = timeOnly ? formatTime(value, loc) : formatDateTime(value, loc, seconds);
  if (!value) return <span>{text}</span>;
  return (
    <time dateTime={value} title={`${value} (UTC) · ${getDisplayZone()}`} className="tabular whitespace-nowrap">
      {text}
    </time>
  );
}
