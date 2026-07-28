#!/usr/bin/env python3
"""Run semantic C1/C2 experiments on dataset_v1 splits."""
from __future__ import annotations

import json
import os
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(ROOT))

from scripts.experiments.run_semantic_experiments import (  # noqa: E402
    MAX_D,
    MIN_D,
    evaluate_method,
    evaluate_path_labels,
    full_constrained,
    plain_dfs,
    rank_by_gatescore,
    type_dfs,
)
from src.graph.refute_aware_search import refute_aware_beam_search  # noqa: E402

DATA = ROOT / "output" / "dataset_v1" / "dataset_v1_corpus.json"
MANIFEST = ROOT / "output" / "dataset_v1" / "dataset_v1_manifest.json"
OUT = ROOT / "output" / "dataset_v1" / "semantic_experiments_by_split.json"
SPLIT_ORDER = ("dev", "validation", "test", "hard_test")


def main() -> None:
    samples = json.loads(DATA.read_text(encoding="utf-8"))
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8")) if MANIFEST.exists() else {}
    by_split = _samples_by_split(samples)
    methods = _methods()
    results = {
        "dataset": DATA.relative_to(ROOT).as_posix(),
        "manifest": MANIFEST.relative_to(ROOT).as_posix(),
        "n_samples": len(samples),
        "split_summary": _split_summary(by_split),
        "metric_notes": {
            "semantic_consistency_check": "Implementation consistency between path_labels and verify_path, not real-cloud generalization accuracy.",
            "retrieval_metrics": "Computed only on samples with at least one Valid path_label.",
            "main_report_splits": ["test", "hard_test"],
        },
        "dataset_notes": manifest.get("notes", []),
        "splits": {},
    }
    for split in SPLIT_ORDER:
        split_samples = by_split.get(split, [])
        print(f"split={split} samples={len(split_samples)}")
        split_result = {
            "n_samples": len(split_samples),
            "semantic_consistency_check": evaluate_path_labels(split_samples),
            "methods": {},
        }
        for name, (runner, ranker) in methods.items():
            res = evaluate_method(split_samples, name, runner, ranker)
            split_result["methods"][name] = res
            console_res = {key: value for key, value in res.items() if key != "sample_metrics"}
            print(split, name, json.dumps(console_res, ensure_ascii=False))
        results["splits"][split] = split_result
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"wrote {OUT}")


def _methods() -> dict:
    return {
        "plain_dfs_gatescore": (lambda G, e, t: plain_dfs(G, e, t), rank_by_gatescore),
        "type_dfs_gatescore": (lambda G, e, t: type_dfs(G, e, t), rank_by_gatescore),
        "full_constrained_gatescore": (lambda G, e, t: full_constrained(G, e, t), rank_by_gatescore),
        "refute_aware_beam": (lambda G, e, t: refute_aware_beam_search(G, e, t, MIN_D, MAX_D, beam_width=4, top_k=20), None),
    }


def _samples_by_split(samples: list[dict]) -> dict[str, list[dict]]:
    by_split: dict[str, list[dict]] = defaultdict(list)
    for sample in samples:
        by_split[sample.get("split", "unknown")].append(sample)
    unknown = set(by_split) - set(SPLIT_ORDER)
    if unknown:
        raise SystemExit(f"unknown split values: {sorted(unknown)}")
    return dict(by_split)


def _split_summary(by_split: dict[str, list[dict]]) -> dict:
    out = {}
    for split in SPLIT_ORDER:
        samples = by_split.get(split, [])
        out[split] = {
            "samples": len(samples),
            "groups": len({sample.get("group_id") for sample in samples}),
            "sources": dict(sorted(Counter(sample.get("source_dataset", "unknown") for sample in samples).items())),
            "variants": dict(sorted(Counter(sample.get("variant_type", "base") for sample in samples).items())),
            "sample_labels": dict(sorted(Counter(sample.get("sample_label", sample.get("expected_state", "Unknown")) for sample in samples).items())),
            "retrieval_samples": sum(1 for sample in samples if any(label.get("state") == "Valid" for label in sample.get("path_labels", []))),
        }
    return out


if __name__ == "__main__":
    main()
