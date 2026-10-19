/** Own, simple logo: a shield with two log lines and a check mark (no third-party marks). */
export function Logo({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 32 32" className={className} aria-hidden focusable="false">
      <path
        className="fill-accent/20 stroke-accent"
        strokeWidth="2"
        d="M16 2 4 6.5v8.8C4 23 9.2 28.3 16 30c6.8-1.7 12-7 12-14.7V6.5Z"
      />
      <rect className="fill-accent" x="9" y="10" width="14" height="2" rx="1" />
      <rect className="fill-accent" x="9" y="14.5" width="9" height="2" rx="1" />
      <path
        className="fill-none stroke-accent"
        d="m12.5 21 2.6 2.6 5.4-5.6"
        strokeWidth="2.2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}
