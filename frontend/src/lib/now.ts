import { useVersion } from "../api/hooks";

/** Reference "now": the fixed demo clock in demo mode (stable screenshots), otherwise the browser clock. */
export function useNow(): string {
  const version = useVersion();
  return version.data?.demo_now ?? new Date().toISOString();
}
