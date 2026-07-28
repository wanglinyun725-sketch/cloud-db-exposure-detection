"""Evaluate CP-Cert only on reviewed/adjudicated human annotations.

This runner intentionally refuses pending or AI/script-origin labels.  It
recomputes edge four-values and path verdicts before measuring certificate
size/cost, so a human label cannot silently disagree with the deterministic
verification inputs.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
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
        "source_id": case["source"]["source_id"],
        "provenance_level": case["source"]["provenance_level"],
        "annotation_status": case["annotation"]["status"],
        "label_origin": case["annotation"]["label_origin"],
        "path_verdicts": path_results,
        "certificates": certificates,
    }


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
    for method in ("exact", "greedy"):
        selected = [row for row in rows if row["method"] == method]
        if not selected:
            continue
        by_method[method] = {
            "n_certificates": len(selected),
            "mean_evidence_count": statistics.fmean(
                len(row["certificate"]["evidence_ids"])
                for row in selected
            ),
            "mean_total_cost": statistics.fmean(
                row["certificate"]["total_cost"] for row in selected
            ),
            "mean_size_reduction": statistics.fmean(
                row["size_reduction"] for row in selected
            ),
            "mean_cost_reduction": statistics.fmean(
                row["cost_reduction"] for row in selected
            ),
            "sufficiency_rate": statistics.fmean(
                row["audit"]["sufficient"] for row in selected
            ),
            "irreducibility_rate": statistics.fmean(
                row["audit"]["irreducible"] for row in selected
            ),
            "raw_ref_completeness": statistics.fmean(
                row["audit"]["raw_refs_complete"] for row in selected
            ),
        }
    return {
        "independent_cases": len(case_results),
        "certificates": len(rows),
        "by_method": by_method,
        "warning": (
            "Descriptive results only. Statistical inference must use "
            "independence_group/case-level units after the dataset split is frozen."
        ),
    }


def run(input_path: Path, output_path: Path) -> dict[str, Any]:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    cases = load_cases(input_path)
    for case in cases:
        validate_case_for_experiment(case, schema)
    results = [evaluate_case(case) for case in cases]
    report = {
        "experiment": "cp_cert_reviewed_human_gold",
        "input": str(input_path),
        "schema": str(SCHEMA_PATH.relative_to(ROOT)),
        "summary": summarize(results),
        "cases": results,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    try:
        report = run(args.input, args.output)
    except (ValueError, jsonschema.ValidationError) as exc:
        print(f"CP-Cert experiment refused: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report["summary"], ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
