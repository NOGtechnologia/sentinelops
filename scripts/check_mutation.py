"""Mutation score gate (spec 15.2): killed / (killed + survived) >= 85 % on the core logic.

Reads ``backend/mutants/mutmut-cicd-stats.json`` written by ``mutmut export-cicd-stats``.
Timeouts count as killed (the mutant was detected); skipped/suspicious mutants are reported.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

MIN_SCORE = 0.85


def main(path: str) -> int:
    stats = json.loads(Path(path).read_text(encoding="utf-8"))
    killed = int(stats.get("killed", 0)) + int(stats.get("timeout", 0))
    survived = int(stats.get("survived", 0))
    total = killed + survived
    score = killed / total if total else 0.0
    print(f"mutation score {score:.1%} ({killed} killed, {survived} survived; stats: {stats})")
    if total == 0:
        print("no mutants were evaluated", file=sys.stderr)
        return 1
    if score < MIN_SCORE:
        print(f"mutation score below {MIN_SCORE:.0%}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "backend/mutants/mutmut-cicd-stats.json"))
