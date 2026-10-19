"""Coverage gates (spec 15.2): >= 90 % overall and 100 % lines + branches in
the core modules. Reads a Cobertura ``coverage.xml``."""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET  # trusted, locally generated file
from pathlib import Path

OVERALL_MIN = 0.90
FULL_COVERAGE = (
    "sentinelops/normalize/",
    "sentinelops/detection/matcher.py",
    "sentinelops/detection/correlation.py",
    "sentinelops/correlation/",
    "sentinelops/ai/validator.py",
    "sentinelops/response/approvals.py",
)


def main(path: str) -> int:
    root = ET.parse(path).getroot()  # noqa: S314 - coverage.xml is produced by our own test run
    lines_valid = int(root.get("lines-valid", "0"))
    lines_covered = int(root.get("lines-covered", "0"))
    branches_valid = int(root.get("branches-valid", "0"))
    branches_covered = int(root.get("branches-covered", "0"))
    total = (lines_covered + branches_covered) / max(1, lines_valid + branches_valid)
    problems: list[str] = []
    if total < OVERALL_MIN:
        problems.append(f"overall coverage {total:.1%} < {OVERALL_MIN:.0%}")
    for cls in root.iter("class"):
        filename = cls.get("filename", "").replace("\\", "/")
        if not any(filename.endswith(p) or f"/{p}" in f"/{filename}" for p in FULL_COVERAGE):
            continue
        line_rate = float(cls.get("line-rate", "1"))
        branch_rate = float(cls.get("branch-rate", "1"))
        if line_rate < 1.0 or branch_rate < 1.0:
            problems.append(f"{filename}: lines {line_rate:.1%}, branches {branch_rate:.1%} (100 % required)")
    print(f"overall coverage (lines + branches): {total:.2%}")
    for problem in problems:
        print(f"FAIL {problem}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else str(Path("backend") / "coverage.xml")))
