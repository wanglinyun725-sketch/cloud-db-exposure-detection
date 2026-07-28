"""Generate cluster-aware main tables from frozen JSONL run records."""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
import sys

import yaml


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.experiments.statistics import analyze_frozen_runs  # noqa: E402


DEFAULT_CONFIG = ROOT / "configs" / "ec_react_main_v1.yaml"
DEFAULT_RUNS = ROOT / "output" / "ec_react_main_v1" / "runs.jsonl"
DEFAULT_OUTPUT = (
    ROOT / "output" / "ec_react_main_v1" / "analysis.json"
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--runs", type=Path, default=DEFAULT_RUNS)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    config = yaml.safe_load(
        args.config.resolve().read_text(encoding="utf-8")
    )
    records = _read_jsonl(args.runs.resolve())
    report = analyze_frozen_runs(records, config)
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    summary_csv = output.with_name("main_summary.csv")
    comparisons_csv = output.with_name("paired_comparisons.csv")
    slices_csv = output.with_name("slice_summaries.csv")
    source_gains_csv = output.with_name("source_gain_summaries.csv")
    heterogeneity_csv = output.with_name(
        "source_heterogeneity_tests.csv"
    )
    _write_csv(summary_csv, report["summaries"])
    _write_csv(comparisons_csv, report["paired_comparisons"])
    _write_csv(slices_csv, report["slice_summaries"])
    _write_csv(
        source_gains_csv,
        report["source_heterogeneity"]["source_gain_summaries"],
    )
    _write_csv(
        heterogeneity_csv,
        report["source_heterogeneity"]["heterogeneity_tests"],
    )
    print(json.dumps(
        {
            "run_records": report["run_records"],
            "independence_groups": report[
                "unique_independence_groups"
            ],
            "summaries": len(report["summaries"]),
            "paired_comparisons": len(report["paired_comparisons"]),
            "slice_summaries": len(report["slice_summaries"]),
            "source_heterogeneity_tests": len(
                report["source_heterogeneity"]["heterogeneity_tests"]
            ),
            "analysis": str(output),
            "summary_csv": str(summary_csv),
            "comparisons_csv": str(comparisons_csv),
            "slices_csv": str(slices_csv),
            "source_gains_csv": str(source_gains_csv),
            "source_heterogeneity_csv": str(heterogeneity_csv),
        },
        ensure_ascii=False,
    ))
    return 0


def _read_jsonl(path: Path) -> list[dict]:
    if not path.is_file():
        raise FileNotFoundError(f"run file is missing: {path}")
    rows = []
    for line_number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(),
        start=1,
    ):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"invalid JSONL at {path}:{line_number}"
            ) from exc
        if not isinstance(value, dict):
            raise ValueError(
                f"JSONL row must be an object at {path}:{line_number}"
            )
        rows.append(value)
    return rows


def _write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fields = sorted({key for row in rows for key in row})
    with path.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


if __name__ == "__main__":
    sys.exit(main())
