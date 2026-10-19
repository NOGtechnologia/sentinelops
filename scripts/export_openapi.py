"""Write (or ``--check``) the OpenAPI document of the API."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path


def render() -> str:
    os.environ.setdefault("SENTINELOPS_DEMO_MODE", "false")
    from sentinelops.api.app import create_app  # noqa: PLC0415 - settings are read at import time

    spec = create_app().openapi()
    return json.dumps(spec, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def main(argv: list[str]) -> int:
    check = "--check" in argv
    target = Path(next(a for a in argv if not a.startswith("--")))
    text = render()
    if check:
        if not target.exists() or target.read_text(encoding="utf-8") != text:
            print(f"{target} is outdated - run `make openapi`", file=sys.stderr)
            return 1
        return 0
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {target}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
