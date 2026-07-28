#!/usr/bin/env python3
"""Independent, reproducible audit of the current research prototype.

This script does not call an LLM. It evaluates:

- effective dataset size and source coverage;
- held-out metrics broken down by source;
- random and shortest-path sanity baselines;
- SDDP slice compatibility with the production search/verification code;
- ambiguity introduced by parallel edge types on node-only paths.
"""
from __future__ import annotations

import json
import random
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path


ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(ROOT))
DATASET = ROOT / "output" / "dataset_v1" / "dataset_v1_corpus.json"
SPLIT_RESULTS = ROOT / "output" / "dataset_v1" / "semantic_experiments_by_split.json"
SDDP_DIR = ROOT / "output" / "sddp_slices"
OUT = ROOT / "output" / "objective_project_audit.json"
REPORT_SPLITS = ("test", "hard_test")
METRICS = ("recall@1", "recall@3", "recall@5", "mrr", "precision@3")


def main() -> None:
    samples = _load(DATASET)
    split_results = _load(SPLIT_RESULTS)
    sample_by_id = {sample["sample_id"]: sample for sample in samples}
    heldout_retrieval = [
        sample
        for sample in samples
        if sample.get("split") in REPORT_SPLITS
        and any(label.get("state") == "Valid" for label in sample.get("path_labels", []))
    ]

    output = {
        "dataset_composition": dataset_composition(samples),
        "heldout_source_metrics": heldout_source_metrics(split_results, sample_by_id),
        "sanity_baselines": sanity_baselines(heldout_retrieval),
        "sddp_compatibility": sddp_compatibility(),
        "parallel_edge_ambiguity": parallel_edge_ambiguity(samples),
        "claim_boundaries": {
            "heldout_splits": list(REPORT_SPLITS),
            "heldout_retrieval_samples": len(heldout_retrieval),
            "cloudgoat_retrieval_gold_paths": sum(
                len(sample.get("gold_paths", []))
                for sample in samples
                if sample.get("source_dataset") == "data:pathbench_cloudgoat"
            ),
            "notes": [
                "dataset_v1 is derived from three in-repository sources, not an external benchmark",
                "missing/refuted/temporal_conflict samples are controlled variants of base graphs",
                "CloudGoat samples currently have no retrieval gold paths",
                "SDDP slices are compatibility/case-study inputs, not validated attack ground truth",
            ],
        },
    }
    OUT.write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(_console_summary(output), ensure_ascii=False, indent=2))
    print(f"wrote {OUT.relative_to(ROOT).as_posix()}")


def dataset_composition(samples: list[dict]) -> dict:
    base = [sample for sample in samples if sample.get("variant_type") == "base"]
    variants = [sample for sample in samples if sample.get("variant_type") != "base"]
    sources = {}
    for source in sorted({sample.get("source_dataset", "unknown") for sample in samples}):
        rows = [sample for sample in samples if sample.get("source_dataset") == source]
        sources[source] = {
            "samples": len(rows),
            "groups": len({sample.get("group_id") for sample in rows}),
            "base_samples": sum(sample.get("variant_type") == "base" for sample in rows),
            "derived_variants": sum(sample.get("variant_type") != "base" for sample in rows),
            "samples_with_gold_paths": sum(bool(sample.get("gold_paths")) for sample in rows),
            "valid_retrieval_samples": sum(
                any(label.get("state") == "Valid" for label in sample.get("path_labels", []))
                for sample in rows
            ),
            "split_counts": dict(Counter(sample.get("split") for sample in rows)),
        }
    return {
        "samples": len(samples),
        "groups": len({sample.get("group_id") for sample in samples}),
        "base_samples": len(base),
        "derived_variants": len(variants),
        "derived_variant_fraction": len(variants) / max(len(samples), 1),
        "path_labels": sum(len(sample.get("path_labels", [])) for sample in samples),
        "sources": sources,
    }


def heldout_source_metrics(results: dict, sample_by_id: dict[str, dict]) -> dict:
    output = {}
    for split in REPORT_SPLITS:
        methods = results["splits"][split]["methods"]
        for method_name, method in methods.items():
            for row in method.get("sample_metrics", []):
                source = sample_by_id[row["sample_id"]]["source_dataset"]
                output.setdefault(source, {}).setdefault(method_name, []).append(row)
    return {
        source: {
            method: {
                "n": len(rows),
                **{
                    metric: statistics.fmean(float(row[metric]) for row in rows)
                    for metric in METRICS
                },
            }
            for method, rows in methods.items()
        }
        for source, methods in output.items()
    }


def sanity_baselines(samples: list[dict], random_repeats: int = 1000) -> dict:
    from scripts.experiments.run_semantic_experiments import plain_dfs
    from src.eval.metrics import summarize_path_ranking
    from src.graph.graph_builder import build_graph, get_entry_nodes, get_target_nodes

    cached = []
    shortest_rows = []
    for sample in samples:
        graph = build_graph(sample)
        result = plain_dfs(graph, get_entry_nodes(graph), get_target_nodes(graph))
        paths = result["paths"]
        gold = [
            label["path"]
            for label in sample.get("path_labels", [])
            if label.get("state") == "Valid" and label.get("path")
        ]
        shortest = sorted(paths, key=lambda path: (len(path), tuple(path)))
        shortest_rows.append(summarize_path_ranking(shortest, gold))
        cached.append((sample["sample_id"], paths, gold))

    random_repeat_means = {metric: [] for metric in METRICS}
    rng = random.Random(20260725)
    for _ in range(random_repeats):
        rows = []
        for _, paths, gold in cached:
            ranked = list(paths)
            rng.shuffle(ranked)
            rows.append(summarize_path_ranking(ranked, gold))
        for metric in METRICS:
            random_repeat_means[metric].append(
                statistics.fmean(float(row[metric]) for row in rows)
            )

    return {
        "candidate_universe": "plain DFS paths with the production depth bounds",
        "n_samples": len(samples),
        "shortest_path": _mean_metrics(shortest_rows),
        "random_ranking": {
            "repeats": random_repeats,
            **{
                metric: {
                    "mean": statistics.fmean(values),
                    "ci_lower": _percentile(sorted(values), 0.025),
                    "ci_upper": _percentile(sorted(values), 0.975),
                }
                for metric, values in random_repeat_means.items()
            },
        },
    }


def sddp_compatibility() -> dict:
    from src.graph.constrained_search import constrained_dfs
    from src.graph.gate_score import load_config, verify_path
    from src.graph.graph_builder import build_graph, get_entry_nodes, get_target_nodes
    from src.graph.path_utils import edge_aware_path_key, path_from_label

    config = load_config()
    cases = []
    total_gold = 0
    correct_gold = 0
    detected_gold = 0
    for path in sorted(SDDP_DIR.glob("*.json")):
        if path.name.endswith("_stats.json"):
            continue
        sample = _load(path)
        if not isinstance(sample, dict) or "nodes" not in sample:
            continue
        graph = build_graph(sample)
        candidates = constrained_dfs(
            graph,
            get_entry_nodes(graph),
            get_target_nodes(graph),
            config["search"]["min_depth"],
            config["search"]["max_depth"],
        )
        candidate_keys = {edge_aware_path_key(candidate) for candidate in candidates}
        gold_states = []
        labels = sample.get("path_labels", [])
        if labels:
            labeled_gold = [
                (path_from_label(label), label.get("state", sample.get("expected_state")))
                for label in labels
            ]
        else:
            labeled_gold = [
                (gold, sample.get("expected_state"))
                for gold in sample.get("gold_paths", [])
            ]
        for gold, expected in labeled_gold:
            got = verify_path(graph, gold, config)["state"]
            gold_states.append(got)
            total_gold += 1
            correct_gold += got == expected
            detected_gold += edge_aware_path_key(gold) in candidate_keys
        cases.append({
            "file": path.name,
            "expected_state": sample.get("expected_state"),
            "gold_paths": len(labeled_gold),
            "candidate_paths": len(candidates),
            "gold_states_from_current_verifier": gold_states,
            "gold_paths_retrieved": sum(
                edge_aware_path_key(gold) in candidate_keys
                for gold, _ in labeled_gold
            ),
        })
    return {
        "cases": cases,
        "total_gold_paths": total_gold,
        "gold_state_agreement": correct_gold / max(total_gold, 1),
        "gold_retrieval_rate": detected_gold / max(total_gold, 1),
    }


def parallel_edge_ambiguity(samples: list[dict]) -> dict:
    base_samples = [sample for sample in samples if sample.get("variant_type") == "base"]
    pairs_total = 0
    ambiguous_pairs = 0
    labeled_paths_total = 0
    labeled_paths_affected = 0
    labeled_paths_with_edge_refs = 0
    affected_paths_without_edge_refs = 0
    by_source = defaultdict(lambda: {"pairs": 0, "ambiguous_pairs": 0})
    for sample in base_samples:
        pair_types = defaultdict(set)
        for edge in sample.get("edges", []):
            pair_types[(edge["source"], edge["target"])].add(edge["type"])
        ambiguous = {pair for pair, types in pair_types.items() if len(types) > 1}
        pairs_total += len(pair_types)
        ambiguous_pairs += len(ambiguous)
        source = sample.get("source_dataset", "unknown")
        by_source[source]["pairs"] += len(pair_types)
        by_source[source]["ambiguous_pairs"] += len(ambiguous)
        for label in sample.get("path_labels", []):
            path = label.get("path", [])
            labeled_paths_total += 1
            has_refs = (
                len(label.get("edge_ids", [])) == max(len(path) - 1, 0)
                and len(label.get("edge_types", [])) == max(len(path) - 1, 0)
            )
            labeled_paths_with_edge_refs += int(has_refs)
            affected = any(pair in ambiguous for pair in zip(path[:-1], path[1:]))
            if affected:
                labeled_paths_affected += 1
                affected_paths_without_edge_refs += int(not has_refs)
    return {
        "base_samples": len(base_samples),
        "node_pairs_with_edges": pairs_total,
        "parallel_type_pairs": ambiguous_pairs,
        "parallel_type_pair_fraction": ambiguous_pairs / max(pairs_total, 1),
        "labeled_paths": labeled_paths_total,
        "labeled_paths_touching_ambiguous_pair": labeled_paths_affected,
        "labeled_paths_with_edge_refs": labeled_paths_with_edge_refs,
        "ambiguous_labeled_paths_without_edge_refs": affected_paths_without_edge_refs,
        "by_source": dict(by_source),
        "risk": (
            "Parallel edges require edge-aware paths. Regenerated labels and search "
            "results carry edge_ids/edge_types; any remaining node-only affected "
            "labels are reported by ambiguous_labeled_paths_without_edge_refs."
        ),
    }


def _mean_metrics(rows: list[dict]) -> dict:
    return {
        metric: statistics.fmean(float(row[metric]) for row in rows)
        for metric in METRICS
    }


def _percentile(sorted_values: list[float], q: float) -> float:
    position = (len(sorted_values) - 1) * q
    lower = int(position)
    upper = min(lower + 1, len(sorted_values) - 1)
    fraction = position - lower
    return sorted_values[lower] * (1 - fraction) + sorted_values[upper] * fraction


def _load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _console_summary(output: dict) -> dict:
    return {
        "dataset": output["dataset_composition"],
        "sanity_baselines": output["sanity_baselines"],
        "sddp": {
            key: value
            for key, value in output["sddp_compatibility"].items()
            if key != "cases"
        },
        "parallel_edge_ambiguity": output["parallel_edge_ambiguity"],
    }


if __name__ == "__main__":
    main()
