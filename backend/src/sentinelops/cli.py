"""``sentinelops`` command line interface."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from sentinelops.settings import REPO_ROOT, RULES_DIR, Settings


def _runtime() -> Any:
    from sentinelops.runtime import Runtime

    return Runtime(Settings())


def cmd_migrate(args: argparse.Namespace) -> int:
    from alembic import command
    from alembic.config import Config

    backend = Path(__file__).resolve().parents[2]
    cfg = Config(str(backend / "alembic.ini"))
    cfg.set_main_option("script_location", str(backend / "migrations"))
    cfg.set_main_option("sqlalchemy.url", Settings().database_url)
    if args.down:
        command.downgrade(cfg, "base")
    else:
        command.upgrade(cfg, "head")
    return 0


async def _ingest_dataset(rt: Any, root: Path, channel: str) -> list[dict[str, Any]]:
    from sentinelops.ingest.runs import ingest_path

    truth = json.loads(await asyncio.to_thread((root / "ground_truth.json").read_text, encoding="utf-8"))
    results = []
    for entry in truth["files"]:
        result = await ingest_path(
            rt.engine,
            root / entry["path"],
            source_type=entry["source_type"],
            timezone=entry["timezone"],
            file_name=entry["path"],
            channel=channel,
            actor="cli",
            profiles=rt.profiles,
            now=rt.clock.now(),
        )
        results.append(result.to_dict())
    return results


def cmd_ingest(args: argparse.Namespace) -> int:
    from sentinelops.ingest.runs import ingest_path

    async def run() -> list[dict[str, Any]]:
        rt = _runtime()
        path = Path(args.path)
        is_dir = await asyncio.to_thread(path.is_dir)
        try:
            if is_dir:
                return await _ingest_dataset(rt, path, "cli")
            if not args.source_type:
                raise SystemExit("--source-type is required for single files")
            result = await ingest_path(
                rt.engine,
                path,
                source_type=args.source_type,
                timezone=args.timezone,
                channel="cli",
                actor="cli",
                profiles=rt.profiles,
                now=rt.clock.now(),
            )
            return [result.to_dict()]
        finally:
            await rt.engine.dispose()

    print(json.dumps(asyncio.run(run()), indent=1))
    return 0


def cmd_analyze(_: argparse.Namespace) -> int:
    from sentinelops.worker.analysis import run_analysis
    from sentinelops.worker.main import effective_exceptions

    async def run() -> dict[str, Any]:
        rt = _runtime()
        try:
            return await run_analysis(
                rt.engine, rt.analysis_context(await effective_exceptions(rt)), rt.clock.now(), "cli"
            )
        finally:
            await rt.engine.dispose()

    print(json.dumps(asyncio.run(run())))
    return 0


def cmd_worker(_: argparse.Namespace) -> int:
    from sentinelops.worker.main import run_forever

    asyncio.run(run_forever(_runtime()))
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    uvicorn.run("sentinelops.api.app:create_app", factory=True, host=args.host, port=args.port, proxy_headers=True)
    return 0


def cmd_demo_load(args: argparse.Namespace) -> int:
    from musterfirma.generate import GeneratorConfig, generate

    from sentinelops.worker.analysis import run_analysis
    from sentinelops.worker.main import effective_exceptions

    out = Path(args.out)
    if not (out / "ground_truth.json").exists():
        out.mkdir(parents=True, exist_ok=True)
        generate(GeneratorConfig(seed=args.seed, events_per_day=args.events_per_day), out)

    async def run() -> dict[str, Any]:
        rt = _runtime()
        try:
            runs = await _ingest_dataset(rt, out, "demo")
            analysis = await run_analysis(
                rt.engine, rt.analysis_context(await effective_exceptions(rt)), rt.clock.now(), "demo"
            )
            return {"runs": len(runs), "accepted": sum(r["accepted"] for r in runs), "analysis": analysis}
        finally:
            await rt.engine.dispose()

    print(json.dumps(asyncio.run(run())))
    return 0


def cmd_benchmark(args: argparse.Namespace) -> int:
    from sentinelops.evaluation.benchmark import evaluate, evaluate_normal_only

    report, _ = evaluate(Path(args.dataset))
    text = report.markdown()
    failures = report.failures()
    if args.normal:
        normal = evaluate_normal_only(Path(args.normal))
        high = normal.normal_cases["P1"] + normal.normal_cases["P2"]
        low = normal.normal_cases["P3"] + normal.normal_cases["P4"]
        text += (
            f"\n| Normalverhalten ({normal.events} Events): Fälle P1/P2 | {high} | 0 |\n"
            f"| Normalverhalten: Fälle P3/P4 | {low} | ≤ 5 |\n"
        )
        if high > 0 or low > 5:
            failures.append(f"normal-only dataset: {high} P1/P2 and {low} P3/P4 cases")
    if args.markdown:
        Path(args.markdown).write_text(text, encoding="utf-8")
    if args.json:
        Path(args.json).write_text(json.dumps(report.to_dict(), indent=1, default=str), encoding="utf-8")
    print(text)
    for failure in failures:
        print(f"FAIL: {failure}", file=sys.stderr)
    return 1 if failures else 0


def cmd_rules(args: argparse.Namespace) -> int:
    from sentinelops.detection.catalog_doc import render_catalog
    from sentinelops.detection.config import DetectionConfig
    from sentinelops.detection.exceptions import load_exceptions
    from sentinelops.detection.rule_tests import run_rule_tests
    from sentinelops.detection.sigma_loader import load_ruleset
    from sentinelops.investigation.catalog import catalog_ids

    cfg = DetectionConfig()
    ruleset = load_ruleset(RULES_DIR, cfg, catalog_ids())
    if args.action == "check":
        print(f"{len(ruleset.metas)} alerting rules, {len(ruleset.base_rules)} Sigma detection rules - OK")
        return 0
    if args.action == "test":
        results, problems = run_rule_tests(RULES_DIR / "tests", ruleset, cfg, load_exceptions(RULES_DIR / "exceptions"))
        failed = [r for r in results if not r.passed]
        for r in failed:
            print(f"FAIL {r.rule_id}: {r.name}", file=sys.stderr)
        for p in problems:
            print(f"FAIL {p}", file=sys.stderr)
        print(f"{len(results) - len(failed)}/{len(results)} rule test cases passed")
        return 1 if failed or problems else 0
    doc = render_catalog(ruleset)
    target = REPO_ROOT / "docs" / "detection-catalog.md"
    if args.action == "catalog-check":
        if not target.exists() or target.read_text(encoding="utf-8") != doc:
            print("docs/detection-catalog.md is outdated - run `sentinelops rules catalog`", file=sys.stderr)
            return 1
        return 0
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(doc, encoding="utf-8", newline="\n")
    print(f"wrote {target}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sentinelops")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("migrate", help="apply database migrations")
    p.add_argument("--down", action="store_true")
    p.set_defaults(func=cmd_migrate)
    p = sub.add_parser("ingest", help="ingest a file or a generated dataset directory")
    p.add_argument("path")
    p.add_argument("--source-type")
    p.add_argument("--timezone", default="UTC")
    p.set_defaults(func=cmd_ingest)
    sub.add_parser("analyze", help="run detection and case building").set_defaults(func=cmd_analyze)
    sub.add_parser("worker", help="run the job worker").set_defaults(func=cmd_worker)
    p = sub.add_parser("serve", help="run the API server")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    p.set_defaults(func=cmd_serve)
    p = sub.add_parser("demo-load", help="generate (if needed), ingest and analyze demo data")
    p.add_argument("--seed", default="dev")
    p.add_argument("--events-per-day", type=int, default=50_000)
    p.add_argument("--out", default=str(REPO_ROOT / "data" / "demo"))
    p.set_defaults(func=cmd_demo_load)
    p = sub.add_parser("benchmark", help="detection benchmark against ground truth")
    p.add_argument("dataset")
    p.add_argument("--normal", help="dataset generated with --no-scenarios")
    p.add_argument("--markdown")
    p.add_argument("--json")
    p.set_defaults(func=cmd_benchmark)
    p = sub.add_parser("rules", help="rule checks")
    p.add_argument("action", choices=["check", "test", "catalog", "catalog-check"])
    p.set_defaults(func=cmd_rules)
    args = parser.parse_args(argv)
    result: int = args.func(args)
    return result


if __name__ == "__main__":
    sys.exit(main())


_ = datetime  # keep import for type users of the module
