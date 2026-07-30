"""Evaluate CP-Cert only on reviewed/adjudicated human annotations.

This runner intentionally refuses pending or AI/script-origin labels.  It
recomputes edge four-values and path verdicts before measuring certificate
size/cost, so a human label cannot silently disagree with the deterministic
verification inputs.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import random
import statistics
import sys
from typing import Any

import jsonschema

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.verification.cp_cert import (
    EvidenceItem,
    build_negative_certificate,
    build_positive_certificate,
    fuse_claims,
    verify_certificate,
    verify_path_claims,
)


SCHEMA_PATH = ROOT / "data" / "real_sources" / "realpathbench_v2_schema.json"
DEFAULT_OUTPUT = ROOT / "output" / "cp_cert_experiment_results.json"
ALLOWED_STATUSES = {"reviewed", "adjudicated"}
ALLOWED_ORIGINS = {"human_reviewed", "human_adjudicated"}


def load_cases(path: Path) -> list[dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict) and isinstance(payload.get("cases"), list):
        return payload["cases"]
    raise ValueError("input must be a case array or an object containing cases")


def case_evidence(case: dict[str, Any]) -> list[EvidenceItem]:
    evidence = []
    for edge in case["edges"]:
        edge_id = edge["edge_id"]
        for raw_item in edge["evidence_items"]:
            evidence.append(
                EvidenceItem(
                    evidence_id=raw_item["evidence_id"],
                    polarity=raw_item["polarity"],
                    claim_ids=(edge_id,),
                    raw_ref=raw_item["raw_ref"],
                    cost=float(raw_item["query_cost"]),
                    source=raw_item["source"],
                )
            )
    return evidence


def validate_case_for_experiment(
    case: dict[str, Any],
    schema: dict[str, Any],
) -> None:
    jsonschema.validate(
        case,
        schema,
        format_checker=jsonschema.FormatChecker(),
    )
    annotation = case["annotation"]
    if annotation["status"] not in ALLOWED_STATUSES:
        raise ValueError(
            f"{case['case_id']}: annotation status "
            f"{annotation['status']!r} is not reviewed/adjudicated"
        )
    if annotation["label_origin"] not in ALLOWED_ORIGINS:
        raise ValueError(
            f"{case['case_id']}: non-human-reviewed label origin is forbidden"
        )
    if not case["path_labels"]:
        raise ValueError(f"{case['case_id']}: no human path labels")
    _independence_group(case)


def evaluate_case(case: dict[str, Any]) -> dict[str, Any]:
    evidence = case_evidence(case)
    declared_edges = {edge["edge_id"]: edge for edge in case["edges"]}
    fused = fuse_claims(evidence, declared_edges)
    edge_mismatches = []
    for edge_id, edge in declared_edges.items():
        recomputed = fused[edge_id].value
        if recomputed != edge["evidence_state"]:
            edge_mismatches.append(
                {
                    "edge_id": edge_id,
                    "declared": edge["evidence_state"],
                    "recomputed": recomputed,
                }
            )
    if edge_mismatches:
        raise ValueError(
            f"{case['case_id']}: edge evidence-state mismatch: "
            f"{edge_mismatches}"
        )

    paths = {
        label["path_id"]: tuple(label["edge_ids"])
        for label in case["path_labels"]
    }
    path_results = []
    for label in case["path_labels"]:
        unknown_edges = set(label["edge_ids"]) - set(declared_edges)
        if unknown_edges:
            raise ValueError(
                f"{case['case_id']}/{label['path_id']}: unknown edge IDs "
                f"{sorted(unknown_edges)}"
            )
        verdict = verify_path_claims(
            label["path_id"],
            label["edge_ids"],
            evidence,
        )
        if verdict.state != label["state"]:
            raise ValueError(
                f"{case['case_id']}/{label['path_id']}: declared path state "
                f"{label['state']} != recomputed {verdict.state}"
            )
        path_results.append(verdict.to_dict())

    certificates = []
    valid_labels = [
        label for label in case["path_labels"] if label["state"] == "Valid"
    ]
    for label in valid_labels:
        relevant = [
            item
            for item in evidence
            if item.polarity == "support"
            and set(item.claim_ids).intersection(label["edge_ids"])
        ]
        baseline_ids = sorted({item.evidence_id for item in relevant})
        for method in ("exact", "greedy"):
            certificate = build_positive_certificate(
                label["path_id"],
                label["edge_ids"],
                evidence,
                method=method,
            )
            coverage = {
                item.evidence_id: set(item.claim_ids).intersection(
                    label["edge_ids"]
                )
                for item in relevant
            }
            audit = verify_certificate(certificate, relevant, coverage)
            _require_valid_certificate(
                case["case_id"],
                label["path_id"],
                method,
                audit,
            )
            certificates.append(
                _certificate_row(
                    case,
                    label["path_id"],
                    certificate,
                    audit,
                    baseline_ids,
                    relevant,
                )
            )

    states = {label["state"] for label in case["path_labels"]}
    if states and states.issubset({"Invalid", "Conflict"}):
        relevant = [
            item
            for item in evidence
            if item.polarity == "refute"
            and any(
                set(item.claim_ids).intersection(premises)
                for premises in paths.values()
            )
        ]
        baseline_ids = sorted({item.evidence_id for item in relevant})
        coverage = {
            item.evidence_id: {
                path_id
                for path_id, premises in paths.items()
                if set(item.claim_ids).intersection(premises)
            }
            for item in relevant
        }
        for method in ("exact", "greedy"):
            certificate = build_negative_certificate(
                paths,
                evidence,
                method=method,
            )
            audit = verify_certificate(certificate, relevant, coverage)
            _require_valid_certificate(
                case["case_id"],
                "all-candidate-paths",
                method,
                audit,
            )
            certificates.append(
                _certificate_row(
                    case,
                    "all-candidate-paths",
                    certificate,
                    audit,
                    baseline_ids,
                    relevant,
                )
            )

    return {
        "case_id": case["case_id"],
        "independence_group": _independence_group(case),
        "source_id": case["source"]["source_id"],
        "provenance_level": case["source"]["provenance_level"],
        "annotation_status": case["annotation"]["status"],
        "label_origin": case["annotation"]["label_origin"],
        "path_verdicts": path_results,
        "certificates": certificates,
    }


def _independence_group(case: dict[str, Any]) -> str:
    value = (
        (case.get("candidate_metadata") or {}).get(
            "independence_group"
        )
        or case.get("independence_group")
    )
    if not isinstance(value, str) or not value.strip():
        raise ValueError(
            f"{case.get('case_id')}: independence_group is required "
            "for CP-Cert inference"
        )
    return value


def _require_valid_certificate(
    case_id: str,
    target: str,
    method: str,
    audit: dict[str, Any],
) -> None:
    if audit.get("valid") is not True:
        raise ValueError(
            f"{case_id}/{target}/{method}: generated certificate failed "
            f"independent audit: {audit}"
        )


def _certificate_row(
    case: dict[str, Any],
    target: str,
    certificate,
    audit: dict[str, Any],
    baseline_ids: list[str],
    relevant: list[EvidenceItem],
) -> dict[str, Any]:
    cost_by_id = {item.evidence_id: item.cost for item in relevant}
    baseline_cost = sum(cost_by_id[evidence_id] for evidence_id in baseline_ids)
    baseline_size = len(baseline_ids)
    return {
        "case_id": case["case_id"],
        "independence_group": _independence_group(case),
        "target": target,
        "kind": certificate.kind,
        "method": certificate.method,
        "certificate": certificate.to_dict(),
        "audit": audit,
        "baseline_all_relevant_evidence_size": baseline_size,
        "baseline_all_relevant_evidence_cost": baseline_cost,
        "size_reduction": (
            1.0 - len(certificate.evidence_ids) / baseline_size
            if baseline_size
            else 0.0
        ),
        "cost_reduction": (
            1.0 - certificate.total_cost / baseline_cost
            if baseline_cost
            else 0.0
        ),
    }


def summarize(case_results: list[dict[str, Any]]) -> dict[str, Any]:
    rows = [
        row
        for case in case_results
        for row in case["certificates"]
    ]
    by_method = {}
    metric_extractors = {
        "evidence_count": lambda row: len(
            row["certificate"]["evidence_ids"]
        ),
        "total_cost": lambda row: row["certificate"]["total_cost"],
        "size_reduction": lambda row: row["size_reduction"],
        "cost_reduction": lambda row: row["cost_reduction"],
        "valid_certificate": lambda row: row["audit"]["valid"],
        "sufficient": lambda row: row["audit"]["sufficient"],
        "irreducible": lambda row: row["audit"]["irreducible"],
        "raw_ref_complete": lambda row: row["audit"][
            "raw_refs_complete"
        ] and row["audit"]["raw_refs_match"],
        "optimality_verified": lambda row: row["audit"][
            "optimality_verified"
        ],
        "approximation_bound_satisfied": lambda row: row["audit"][
            "approximation_bound_satisfied"
        ],
    }
    for method in ("exact", "greedy"):
        selected = [row for row in rows if row["method"] == method]
        if not selected:
            continue
        metric_summaries = {}
        for metric, extractor in metric_extractors.items():
            values = _collapse_certificate_metric(
                selected,
                extractor,
            )
            if values:
                metric_summaries[metric] = _summarize_group_values(
                    values,
                    seed_key=(method, metric),
                )
        by_method[method] = {
            "n_certificates": len(selected),
            "independence_groups": len({
                row["independence_group"] for row in selected
            }),
            "group_level_metrics": metric_summaries,
        }
    paired = _paired_method_summaries(rows)
    return {
        "analysis_version": "1.0",
        "statistical_unit": "independence_group",
        "independent_cases": len(case_results),
        "independence_groups": len({
            case["independence_group"] for case in case_results
        }),
        "certificates": len(rows),
        "by_method": by_method,
        "paired_exact_minus_greedy": paired,
        "pseudo_replication_guard": True,
        "warning": (
            "Certificate rows and paths are not independent. Means and "
            "bootstrap intervals first collapse targets within case and "
            "cases within independence_group."
        ),
    }


def _collapse_certificate_metric(
    rows: list[dict[str, Any]],
    extractor,
) -> dict[str, float]:
    case_values: dict[tuple[str, str], list[float]] = {}
    for row in rows:
        value = extractor(row)
        if value is None:
            continue
        key = (row["independence_group"], row["case_id"])
        case_values.setdefault(key, []).append(float(value))
    group_cases: dict[str, list[float]] = {}
    for (group, _), values in case_values.items():
        group_cases.setdefault(group, []).append(statistics.fmean(values))
    return {
        group: statistics.fmean(values)
        for group, values in group_cases.items()
    }


def _paired_method_summaries(
    rows: list[dict[str, Any]],
) -> dict[str, Any]:
    indexed = {
        (
            row["independence_group"],
            row["case_id"],
            row["target"],
            row["kind"],
            row["method"],
        ): row
        for row in rows
    }
    pair_keys = {
        key[:4]
        for key in indexed
        if (
            (*key[:4], "exact") in indexed
            and (*key[:4], "greedy") in indexed
        )
    }
    extractors = {
        "evidence_count": lambda row: len(
            row["certificate"]["evidence_ids"]
        ),
        "total_cost": lambda row: row["certificate"]["total_cost"],
        "size_reduction": lambda row: row["size_reduction"],
        "cost_reduction": lambda row: row["cost_reduction"],
    }
    output = {}
    for metric, extractor in extractors.items():
        case_differences: dict[tuple[str, str], list[float]] = {}
        for group, case_id, target, kind in pair_keys:
            exact = indexed[(group, case_id, target, kind, "exact")]
            greedy = indexed[(group, case_id, target, kind, "greedy")]
            case_differences.setdefault((group, case_id), []).append(
                float(extractor(exact)) - float(extractor(greedy))
            )
        group_cases: dict[str, list[float]] = {}
        for (group, _), values in case_differences.items():
            group_cases.setdefault(group, []).append(
                statistics.fmean(values)
            )
        group_values = {
            group: statistics.fmean(values)
            for group, values in group_cases.items()
        }
        if group_values:
            output[metric] = _summarize_group_values(
                group_values,
                seed_key=("exact-minus-greedy", metric),
            )
    return {
        "pairing": "same independence_group/case/target/kind",
        "difference": "exact minus greedy",
        "metrics": output,
    }


def _summarize_group_values(
    values: dict[str, float],
    *,
    seed_key: tuple[str, str],
    resamples: int = 5000,
    confidence: float = 0.95,
) -> dict[str, Any]:
    ordered = [values[group] for group in sorted(values)]
    low, high = _bootstrap_mean_ci(
        ordered,
        resamples=resamples,
        confidence=confidence,
        seed=_seed(seed_key),
    )
    return {
        "independence_groups": len(ordered),
        "mean": statistics.fmean(ordered),
        "ci_low": low,
        "ci_high": high,
        "confidence_level": confidence,
        "cluster_bootstrap_resamples": resamples,
    }


def _bootstrap_mean_ci(
    values: list[float],
    *,
    resamples: int,
    confidence: float,
    seed: int,
) -> tuple[float, float]:
    if not values:
        raise ValueError("bootstrap requires values")
    if len(values) == 1:
        return values[0], values[0]
    rng = random.Random(seed)
    estimates = sorted(
        statistics.fmean(rng.choice(values) for _ in values)
        for _ in range(resamples)
    )
    alpha = 1.0 - confidence
    return (
        _quantile(estimates, alpha / 2),
        _quantile(estimates, 1 - alpha / 2),
    )


def _quantile(values: list[float], probability: float) -> float:
    position = probability * (len(values) - 1)
    lower = int(position)
    upper = min(lower + 1, len(values) - 1)
    fraction = position - lower
    return values[lower] * (1 - fraction) + values[upper] * fraction


def _seed(value: Any) -> int:
    return int(sha256(
        json.dumps(value, sort_keys=True).encode("utf-8")
    ).hexdigest()[:16], 16)


def run(
    input_path: Path,
    output_path: Path,
    *,
    split_manifest_path: Path | None = None,
) -> dict[str, Any]:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    payload = json.loads(input_path.read_text(encoding="utf-8"))
    cases = load_cases(input_path)
    selected_splits = None
    split_bound = split_manifest_path is not None
    if split_manifest_path is not None:
        manifest = json.loads(
            split_manifest_path.read_text(encoding="utf-8")
        )
        cases, selected_splits = _select_frozen_test_cases(
            payload,
            cases,
            manifest,
        )
    elif isinstance(payload, dict):
        cases = [
            case
            for case in cases
            if (
                (case.get("admission_screen") or {}).get("decision")
                in {None, "accept"}
            )
        ]
    if not cases:
        raise ValueError("no eligible CP-Cert cases")
    for case in cases:
        validate_case_for_experiment(case, schema)
    results = [evaluate_case(case) for case in cases]
    summary = summarize(results)
    claim_gate = _cp_cert_claim_gate(
        summary,
        split_bound=split_bound,
    )
    report = {
        "experiment": "cp_cert_reviewed_human_gold",
        "input": str(input_path),
        "split_manifest": (
            str(split_manifest_path)
            if split_manifest_path is not None
            else None
        ),
        "selected_splits": selected_splits,
        "schema": str(SCHEMA_PATH.relative_to(ROOT)),
        "research_effectiveness_result": claim_gate["eligible"],
        "summary": summary,
        "cp_cert_claim_gate": claim_gate,
        "cases": results,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return report


def _select_frozen_test_cases(
    release: Any,
    cases: list[dict[str, Any]],
    manifest: Any,
) -> tuple[list[dict[str, Any]], list[str]]:
    if not isinstance(release, dict):
        raise ValueError(
            "split-bound CP-Cert input must be a reviewed release object"
        )
    if not isinstance(manifest, dict):
        raise ValueError("split manifest root must be an object")
    if manifest.get("packet_sha256") != release.get("packet_sha256"):
        raise ValueError("split manifest packet hash differs from release")
    if manifest.get("gold_release_sha256") != _stable_hash(release):
        raise ValueError("split manifest gold release hash mismatch")
    assignments = manifest.get("assignments")
    if not isinstance(assignments, list):
        raise ValueError("split manifest assignments must be an array")
    by_case = {}
    for item in assignments:
        if not isinstance(item, dict):
            raise ValueError("split manifest assignment must be an object")
        case_id = item.get("case_id")
        if not isinstance(case_id, str) or case_id in by_case:
            raise ValueError("split manifest has duplicate/invalid case IDs")
        if item.get("split") not in {
            "development",
            "validation",
            "test",
            "external_test",
            "excluded",
            "execution_queue",
        }:
            raise ValueError(
                f"{case_id}: split manifest has an invalid split"
            )
        by_case[case_id] = item
    case_ids = {case["case_id"] for case in cases}
    if set(by_case) != case_ids:
        raise ValueError("split manifest case set differs from release")
    selected = []
    target_splits = {"test", "external_test"}
    for case in cases:
        assignment = by_case[case["case_id"]]
        group = (
            (case.get("candidate_metadata") or {}).get(
                "independence_group"
            )
            or case.get("independence_group")
            or f"nonanalytic:{case['case_id']}"
        )
        if (
            assignment.get("independence_group")
            != group
        ):
            raise ValueError(
                f"{case['case_id']}: split independence_group mismatch"
            )
        if assignment.get("split") in target_splits:
            if (
                (case.get("admission_screen") or {}).get("decision")
                not in {None, "accept"}
            ):
                raise ValueError(
                    f"{case['case_id']}: non-accepted case entered test split"
                )
            selected.append(case)
    if not selected:
        raise ValueError("split manifest has no held-out CP-Cert cases")
    return selected, sorted({
        by_case[case["case_id"]]["split"] for case in selected
    })


def _cp_cert_claim_gate(
    summary: dict[str, Any],
    *,
    split_bound: bool,
    minimum_independence_groups: int = 15,
) -> dict[str, Any]:
    exact = (summary.get("by_method") or {}).get("exact") or {}
    metrics = exact.get("group_level_metrics") or {}

    def mean_value(name: str) -> float | None:
        item = metrics.get(name) or {}
        value = item.get("mean")
        return float(value) if value is not None else None

    valid_rate = mean_value("valid_certificate")
    trace_rate = mean_value("raw_ref_complete")
    optimality_rate = mean_value("optimality_verified")
    size = metrics.get("size_reduction") or {}
    cost = metrics.get("cost_reduction") or {}
    size_useful = (
        size.get("mean") is not None
        and float(size["mean"]) > 0
        and float(size.get("ci_low", -1)) > 0
    )
    cost_useful = (
        cost.get("mean") is not None
        and float(cost["mean"]) > 0
        and float(cost.get("ci_low", -1)) > 0
    )
    groups = int(summary.get("independence_groups") or 0)

    def complete_rate(name: str, value: float | None) -> bool:
        metric = metrics.get(name) or {}
        return (
            int(metric.get("independence_groups") or 0) == groups
            and value == 1.0
        )

    gates = {
        "frozen_held_out_split_bound": split_bound,
        "minimum_independence_groups": (
            groups >= minimum_independence_groups
        ),
        "all_certificates_valid": complete_rate(
            "valid_certificate",
            valid_rate,
        ),
        "all_raw_references_verified": complete_rate(
            "raw_ref_complete",
            trace_rate,
        ),
        "exact_optimality_oracle_verified": complete_rate(
            "optimality_verified",
            optimality_rate,
        ),
        "positive_ci_lower_bound_for_compression": (
            size_useful or cost_useful
        ),
    }
    return {
        "gate_version": "1.0",
        "claim": (
            "CP-Cert emits valid, traceable, exact-minimal certificates "
            "that reduce evidence size or cost on held-out human gold"
        ),
        "minimum_independence_groups": minimum_independence_groups,
        "observed_independence_groups": groups,
        "gates": gates,
        "eligible": all(gates.values()),
        "posthoc_threshold_change_allowed": False,
    }


def _stable_hash(value: Any) -> str:
    return sha256(json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--split-manifest", type=Path)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    try:
        report = run(
            args.input,
            args.output,
            split_manifest_path=args.split_manifest,
        )
    except (ValueError, jsonschema.ValidationError) as exc:
        print(f"CP-Cert experiment refused: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report["summary"], ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
