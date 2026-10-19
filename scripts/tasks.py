"""Cross-platform task runner behind the Makefile (``make check`` etc.).

Usage: ``uv run python scripts/tasks.py <task> [<task> ...]``.
Every task exits non-zero on failure; ``check`` runs the full gate of spec 15.1.
Tasks that need tools which are not installed locally (gitleaks, semgrep,
oasdiff, pnpm) fail with a clear message instead of being skipped silently;
use ``--allow-missing-tools`` only for local convenience - CI never does.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
FRONTEND = ROOT / "frontend"
ALLOW_MISSING = "--allow-missing-tools" in sys.argv


class TaskError(RuntimeError):
    pass


def run(cmd: Sequence[str], cwd: Path = ROOT, env: dict[str, str] | None = None) -> None:
    print(f"$ {' '.join(cmd)}  (in {cwd.relative_to(ROOT) if cwd != ROOT else '.'})", flush=True)
    merged = {**os.environ, **(env or {})}
    result = subprocess.run(list(cmd), cwd=cwd, env=merged, check=False)  # noqa: S603 - fixed argument lists
    if result.returncode != 0:
        raise TaskError(f"command failed ({result.returncode}): {' '.join(cmd)}")


def tool(name: str) -> str | None:
    found = shutil.which(name)
    if found is None:
        message = f"required tool '{name}' not found"
        if ALLOW_MISSING:
            print(f"WARNING: {message} - skipped because of --allow-missing-tools", flush=True)
            return None
        raise TaskError(message)
    return found


def uv(*args: str, cwd: Path = BACKEND, env: dict[str, str] | None = None) -> None:
    run(["uv", "run", *args], cwd=cwd, env=env)


def pnpm(*args: str) -> None:
    exe = tool("pnpm")
    if exe:
        run([exe, *args], cwd=FRONTEND)


# --- tasks -----------------------------------------------------------------------------


def lint() -> None:
    uv("ruff", "format", "--check", "src", "tests", "migrations", "../generator/src", "../scripts")
    uv("ruff", "check", "src", "tests", "migrations", "../generator/src", "../scripts")
    if FRONTEND.joinpath("package.json").exists():
        pnpm("run", "lint")


def typecheck() -> None:
    uv("mypy")
    if FRONTEND.joinpath("package.json").exists():
        pnpm("run", "typecheck")


def arch_check() -> None:
    uv("lint-imports")


def rules_check() -> None:
    uv("sentinelops", "rules", "check")
    uv("sentinelops", "rules", "test")
    uv("sentinelops", "rules", "catalog-check")


def test_unit() -> None:
    uv("pytest", "tests/unit", "-q", "--cov=sentinelops", "--cov-report=", "--cov-branch")


def test_property() -> None:
    uv("pytest", "tests/property", "-q", "--cov=sentinelops", "--cov-append", "--cov-report=")


def test_integration() -> None:
    uv("pytest", "tests/integration", "-q", "--cov=sentinelops", "--cov-append", "--cov-report=")


def test_acceptance() -> None:
    uv("pytest", "tests/acceptance", "-q", "--cov=sentinelops", "--cov-append", "--cov-report=")


def test_benchmark() -> None:
    uv(
        "pytest",
        "tests/benchmark",
        "-q",
        "--cov=sentinelops",
        "--cov-append",
        "--cov-report=xml:coverage.xml",
        env={"SENTINELOPS_BENCHMARK_REPORT": str(BACKEND / "benchmark-report.md")},
    )
    run(
        ["uv", "run", "python", str(ROOT / "scripts" / "check_coverage.py"), str(BACKEND / "coverage.xml")], cwd=BACKEND
    )


def test_frontend() -> None:
    if FRONTEND.joinpath("package.json").exists():
        pnpm("run", "test:coverage")
        pnpm("run", "i18n:check")


def build() -> None:
    run(["uv", "build", "--package", "sentinelops", "--out-dir", str(ROOT / "dist")], cwd=ROOT)
    if FRONTEND.joinpath("package.json").exists():
        pnpm("run", "build")


def openapi() -> None:
    uv("python", str(ROOT / "scripts" / "export_openapi.py"), str(ROOT / "docs" / "api" / "openapi.json"))
    if FRONTEND.joinpath("package.json").exists():
        pnpm("run", "api:types")


def openapi_diff() -> None:
    uv("python", str(ROOT / "scripts" / "export_openapi.py"), "--check", str(ROOT / "docs" / "api" / "openapi.json"))
    if FRONTEND.joinpath("package.json").exists():
        pnpm("run", "api:check")
    base = os.environ.get("OPENAPI_BASE")
    if base:  # CI: compare against the spec of the target branch
        exe = tool("oasdiff")
        if exe:
            run([exe, "breaking", base, str(ROOT / "docs" / "api" / "openapi.json"), "--fail-on", "ERR"])


#: Accepted advisories - each one is justified in docs/security/accepted-risks.md.
PIP_AUDIT_IGNORED = ("PYSEC-2026-2447",)  # diskcache via pySigma, no fixed release; needs write access to cache dir


def security() -> None:
    requirements = ROOT / "dist" / "requirements-audit.txt"
    requirements.parent.mkdir(exist_ok=True)
    run(["uv", "export", "--format", "requirements-txt", "--no-emit-workspace", "--all-packages", "--all-groups",
         "--frozen", "-q", "-o", str(requirements)])
    ignored = [arg for vuln in PIP_AUDIT_IGNORED for arg in ("--ignore-vuln", vuln)]
    uv("pip-audit", "-r", str(requirements), "--require-hashes", "--disable-pip", "--strict", "--progress-spinner",
       "off", *ignored)
    exe = tool("semgrep")
    if exe:
        run(
            [
                exe,
                "scan",
                "--error",
                "--metrics=off",
                "--config",
                str(ROOT / ".semgrep.yml"),
                "backend/src",
                "frontend/src",
            ]
        )
    exe = tool("gitleaks")
    if exe:
        run([exe, "detect", "--redact", "--no-banner", "--source", str(ROOT)])
    if FRONTEND.joinpath("package.json").exists():
        pnpm("audit", "--prod")
    uv("python", str(ROOT / "scripts" / "check_fixtures.py"))


def docs_check() -> None:
    uv("sentinelops", "rules", "catalog-check")
    run(
        ["uv", "run", "--package", "sentinelops", "mkdocs", "build", "--strict", "--site-dir", str(ROOT / "site")],
        cwd=ROOT,
    )


def check() -> None:
    for task in (
        lint,
        typecheck,
        arch_check,
        rules_check,
        test_unit,
        test_property,
        test_integration,
        test_acceptance,
        test_benchmark,
        test_frontend,
        build,
        security,
        openapi_diff,
        docs_check,
    ):
        print(f"\n=== {task.__name__} ===", flush=True)
        task()


def e2e() -> None:
    pnpm("--dir", str(ROOT / "e2e"), "exec", "playwright", "test")


def screenshots() -> None:
    pnpm("--dir", str(ROOT / "e2e"), "run", "screenshots")


def nightly() -> None:
    uv("pytest", "tests/benchmark", "tests/property", "-q", env={"HYPOTHESIS_PROFILE": "nightly"})
    uv("mutmut", "run")


TASKS: dict[str, Callable[[], None]] = {
    f.__name__.replace("_", "-"): f
    for f in (
        lint,
        typecheck,
        arch_check,
        rules_check,
        test_unit,
        test_property,
        test_integration,
        test_acceptance,
        test_benchmark,
        test_frontend,
        build,
        openapi,
        openapi_diff,
        security,
        docs_check,
        check,
        e2e,
        screenshots,
        nightly,
    )
}


def main(argv: list[str]) -> int:
    names = [a for a in argv if not a.startswith("--")]
    if not names or any(n not in TASKS for n in names):
        print("usage: tasks.py <task>...  tasks: " + ", ".join(sorted(TASKS)), file=sys.stderr)
        return 2
    try:
        for name in names:
            TASKS[name]()
    except TaskError as exc:
        print(f"\nFAILED: {exc}", file=sys.stderr)
        return 1
    print("\nOK", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
