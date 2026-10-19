"""Generate docs/permissions.md from api/permissions.yaml (``--check`` verifies it is current)."""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "backend" / "src" / "sentinelops" / "api" / "permissions.yaml"
TARGET = ROOT / "docs" / "permissions.md"
ROLE_ORDER = ("analyst", "senior_analyst", "detection_engineer", "admin", "auditor")


def render() -> str:
    data = yaml.safe_load(SOURCE.read_text(encoding="utf-8"))
    roles: dict[str, list[str]] = data["roles"]
    routes: dict[str, str] = data["routes"]
    permissions = sorted({p for perms in roles.values() for p in perms} | {p for p in routes.values()})
    lines = [
        "# Rollen und Berechtigungen",
        "",
        "<!-- generiert aus backend/src/sentinelops/api/permissions.yaml - nicht von Hand bearbeiten -->",
        "",
        "## Rechte je Rolle",
        "",
        "| Recht | " + " | ".join(ROLE_ORDER) + " |",
        "|---|" + ":-:|" * len(ROLE_ORDER),
    ]
    for permission in permissions:
        if permission in ("public", "authenticated"):
            continue
        marks = ["✓" if permission in roles.get(role, []) else "" for role in ROLE_ORDER]
        lines.append(f"| `{permission}` | " + " | ".join(marks) + " |")
    lines += ["", "## Routen", "", "| Methode und Pfad | Recht |", "|---|---|"]
    lines += [f"| `{route}` | `{permission}` |" for route, permission in routes.items()]
    return "\n".join(lines) + "\n"


def main(argv: list[str]) -> int:
    text = render()
    if "--check" in argv:
        if not TARGET.exists() or TARGET.read_text(encoding="utf-8") != text:
            print(f"{TARGET} is outdated - run scripts/gen_permissions_doc.py", file=sys.stderr)
            return 1
        return 0
    TARGET.write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {TARGET}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
