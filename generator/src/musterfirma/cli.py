"""Command line interface: ``musterfirma-gen --seed dev --out data/dev``."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path

from musterfirma.generate import SEEDS, GeneratorConfig, generate, summary
from musterfirma.ground_truth import GroundTruth


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="musterfirma-gen", description="Generate SentinelOps test data (Musterfirma GmbH).")
    parser.add_argument("--seed", default="dev", help=f"seed name ({', '.join(SEEDS)} or any string)")
    parser.add_argument("--out", type=Path, required=False, help="output directory")
    parser.add_argument("--events-per-day", type=int, default=50_000)
    parser.add_argument("--start", type=date.fromisoformat, default=date(2026, 3, 9))
    parser.add_argument("--no-scenarios", action="store_true", help="normal behaviour only")
    parser.add_argument("--no-quality", action="store_true", help="no data quality cases")
    parser.add_argument("--schema", action="store_true", help="print the ground truth JSON schema and exit")
    args = parser.parse_args(argv)
    if args.schema:
        print(json.dumps(GroundTruth.model_json_schema(), indent=1))
        return 0
    if args.out is None:
        parser.error("--out is required")
    cfg = GeneratorConfig(
        seed=args.seed,
        start=args.start,
        events_per_day=args.events_per_day,
        scenarios=not args.no_scenarios,
        quality=not args.no_quality,
    )
    args.out.mkdir(parents=True, exist_ok=True)
    truth = generate(cfg, args.out)
    print(json.dumps(summary(truth)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
