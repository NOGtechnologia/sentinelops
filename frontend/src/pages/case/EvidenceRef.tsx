import { Link } from "@tanstack/react-router";

/** Link to a numbered piece of evidence (E1 ... En) in the evidence tab. */
export function EvidenceRef({ caseId, refId }: { caseId: string; refId: string }) {
  return (
    <Link
      to="/cases/$caseId/evidence"
      params={{ caseId }}
      hash={refId}
      className="rounded bg-accent-soft px-1 font-mono text-[11px] font-semibold text-accent hover:underline"
    >
      {refId}
    </Link>
  );
}

export function EvidenceRefs({ caseId, refs }: { caseId: string; refs: string[] }) {
  if (refs.length === 0) return null;
  const shown = refs.slice(0, 12);
  return (
    <span className="inline-flex flex-wrap gap-1 align-middle">
      {shown.map((r) => (
        <EvidenceRef key={r} caseId={caseId} refId={r} />
      ))}
      {refs.length > shown.length && <span className="text-xs text-muted">+{refs.length - shown.length}</span>}
    </span>
  );
}
