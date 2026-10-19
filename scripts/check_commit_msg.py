"""commit-msg hook: Conventional Commits (CLAUDE.md rule 11), comparable to commitlint's config-conventional."""

from __future__ import annotations

import re
import sys
from pathlib import Path

TYPES = ("build", "chore", "ci", "docs", "feat", "fix", "perf", "refactor", "revert", "style", "test")
HEADER = re.compile(rf"^(?:{'|'.join(TYPES)})(?:\([a-z0-9][a-z0-9/_-]*\))?!?: \S.{{0,99}}$")
EXEMPT = re.compile(r"^(?:Merge |Revert \"|fixup! |squash! )")


def check(message: str) -> str | None:
    lines = [line for line in message.splitlines() if not line.startswith("#")]
    header = lines[0].strip() if lines else ""
    if EXEMPT.match(header):
        return None
    if not HEADER.match(header):
        return (
            f"commit header {header!r} is not a Conventional Commit: "
            f"<type>(<scope>)?: <subject> with type in {', '.join(TYPES)}, at most 100 characters"
        )
    if len(lines) > 1 and lines[1].strip():
        return "the second line of the commit message must be empty"
    return None


def main(argv: list[str]) -> int:
    message = Path(argv[1]).read_text(encoding="utf-8-sig") if len(argv) > 1 else sys.stdin.read()
    problem = check(message)
    if problem:
        print(problem, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
