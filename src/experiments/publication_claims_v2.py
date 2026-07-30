"""Deterministic, fail-closed publication claim ledger for Goal v2."""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
from typing import Any, Mapping

import yaml

from src.data.executable_lineage_inventory import (
    build_executable_lineage_inventory,
)
from src.experiments.artifact_chain_v2 import (
    read_jsonl,
    validate_decision_binding,
)
from src.experiments.confirmatory_decision import (
    evaluate_confirmatory_decision,
)
from src.experiments.frozen_splits import (
    ANALYTIC_SPLITS,
    build_frozen_split_manifest,
)
from src.experiments.statistics import analyze_frozen_runs


REQUIRED_CP_CERT_GATES = {
    "frozen_held_out_split_bound",
    "minimum_independence_groups",
    "all_certificates_valid",
    "all_raw_references_verified",
    "exact_optimality_oracle_verified",
    "positive_ci_lower_bound_for_compression",
}


def build_publication_claim_ledger(
    root: str | Path,
    *,
    inventory_path: str | Path,
    confirmatory_freeze_path: str | Path,
    decision_path: str | Path,
    cp_cert_result_path: str | Path,
) -> dict[str, Any]:
    """Derive every publishable innovation claim from frozen evidence."""
    root = Path(root).resolve()
    inventory_path = _resolve(root, inventory_path)
    confirmatory_freeze_path = _resolve(
        root,
        confirmatory_freeze_path,
    )
    decision_path = _resolve(root, decision_path)
    cp_cert_result_path = _resolve(root, cp_cert_result_path)
    inventory = _read_json(inventory_path)
    confirmatory = _read_json(confirmatory_freeze_path)
    decision = _read_json(decision_path)
    cp_cert = _read_json(cp_cert_result_path)

    inventory_summary = _validate_inventory(root, inventory)
    decision_binding = _validate_recomputed_decision(
        root,
        decision,
    )
    config_path = _resolve(
        root,
        decision_binding["config"]["path"],
    )
    config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    if not isinstance(config, Mapping):
        raise ValueError("frozen config root must be an object")
    cp_allowed, gold_path, split_path = _validate_cp_cert_result(
        root,
        cp_cert,
        config,
    )
    human_gold = _validate_human_gold(
        confirmatory,
        _read_json(gold_path),
        _read_json(split_path),
    )

    candidate_gate = bool(
        inventory_summary["conservative_independence_groups"] >= 40
        and inventory_summary["source_count"] >= 6
        and {"AWS", "AZURE", "GCP"}
        <= set(inventory_summary["platforms"])
    )
    benchmark_allowed = bool(
        candidate_gate
        and human_gold["analytic_independence_groups"] >= 30
        and confirmatory.get("ready_to_publish") is True
    )
    ec_allowed = bool(decision.get("claim_allowed") is True)
    mandatory_allowed = benchmark_allowed and ec_allowed
    claims = [
        {
            "claim_id": "realpathbench_cd",
            "claim_class": "mandatory_innovation",
            "status": "allowed" if benchmark_allowed else "blocked",
            "allowed_wording": (
                "RealPathBench-CD is a real, traceable cross-cloud "
                "benchmark satisfying the frozen candidate and "
                "double-human-gold gates."
                if benchmark_allowed
                else (
                    "A real-source candidate corpus exists, but the "
                    "published benchmark claim is blocked until the "
                    "double-human-gold gate passes."
                )
            ),
            "prohibited_wording": (
                []
                if benchmark_allowed
                else [
                    "human-validated benchmark",
                    "30-lineage human gold completed",
                ]
            ),
            "metrics": {
                "conservative_candidate_lineages": inventory_summary[
                    "conservative_independence_groups"
                ],
                "independent_sources": inventory_summary["source_count"],
                "platforms": inventory_summary["platforms"],
                "human_gold_independence_groups": human_gold[
                    "independence_groups"
                ],
                "analytic_gold_independence_groups": human_gold[
                    "analytic_independence_groups"
                ],
                "human_finalized_cases": human_gold["cases"],
                "analytic_gold_cases": human_gold[
                    "analytic_cases"
                ],
                "excluded_or_pending_cases": human_gold[
                    "excluded_or_pending_cases"
                ],
            },
            "evidence": [
                {
                    "input": "inventory",
                    "json_pointer": "/minimum_candidate_gate",
                },
                {
                    "input": "confirmatory_freeze",
                    "json_pointer": "/human_gold_independence_groups",
                },
                {
                    "input": "gold_release",
                    "json_pointer": "/cases",
                },
                {
                    "input": "split_manifest",
                    "json_pointer": "/summary/analytic_independence_groups",
                },
            ],
        },
        {
            "claim_id": "ec_react_effectiveness",
            "claim_class": "mandatory_innovation",
            "status": "allowed" if ec_allowed else "blocked",
            "allowed_wording": (
                decision.get("claim")
                if ec_allowed
                else (
                    "EC-ReAct was evaluated under the frozen protocol, "
                    "but its effectiveness claim did not pass."
                )
            ),
            "prohibited_wording": (
                []
                if ec_allowed
                else [
                    "EC-ReAct outperforms vanilla ReAct",
                    "EC-ReAct satisfies the preregistered success gates",
                ]
            ),
            "metrics": {
                "primary_metric": decision.get("primary_metric"),
                "confirmatory_budget": decision.get(
                    "confirmatory_budget"
                ),
                "overall_status": decision.get("overall_status"),
                "model_decisions": deepcopy(
                    decision.get("model_decisions") or []
                ),
            },
            "evidence": [
                {
                    "input": "confirmatory_decision",
                    "json_pointer": "/model_decisions",
                },
            ],
        },
        {
            "claim_id": "cp_cert_empirical_innovation",
            "claim_class": "conditional_innovation",
            "status": (
                "allowed" if cp_allowed else "conditional_failed"
            ),
            "allowed_wording": (
                cp_cert["cp_cert_claim_gate"]["claim"]
                if cp_allowed
                else (
                    "CP-Cert is implemented and independently audited, "
                    "but its held-out empirical innovation gate did not "
                    "pass and no effectiveness innovation is claimed."
                )
            ),
            "prohibited_wording": (
                []
                if cp_allowed
                else [
                    "CP-Cert is an empirically validated innovation",
                    "CP-Cert significantly compresses held-out evidence",
                ]
            ),
            "metrics": {
                "research_effectiveness_result": cp_allowed,
                "observed_independence_groups": cp_cert[
                    "cp_cert_claim_gate"
                ].get("observed_independence_groups"),
                "gates": deepcopy(
                    cp_cert["cp_cert_claim_gate"]["gates"]
                ),
            },
            "evidence": [
                {
                    "input": "cp_cert_result",
                    "json_pointer": "/cp_cert_claim_gate",
                },
            ],
        },
    ]
    inputs = {
        "inventory": _binding(root, inventory_path),
        "confirmatory_freeze": _binding(
            root,
            confirmatory_freeze_path,
        ),
        "confirmatory_decision": _binding(root, decision_path),
        "cp_cert_result": _binding(root, cp_cert_result_path),
        "gold_release": _binding(root, gold_path),
        "split_manifest": _binding(root, split_path),
    }
    return {
        "ledger_version": "2.0",
        "status": "complete",
        "derivation": "deterministic_from_hash_bound_evidence",
        "inputs": inputs,
        "mandatory_innovations_claim_allowed": mandatory_allowed,
        "cp_cert_innovation_claim_allowed": cp_allowed,
        "thesis_claim_status": (
            "allowed" if mandatory_allowed else "blocked"
        ),
        "posthoc_claim_substitution_allowed": False,
        "claims": claims,
        "summary": {
            "claims": len(claims),
            "allowed": sum(
                item["status"] == "allowed" for item in claims
            ),
            "blocked": sum(
                item["status"] == "blocked" for item in claims
            ),
            "conditional_failed": sum(
                item["status"] == "conditional_failed"
                for item in claims
            ),
        },
    }


def validate_publication_claim_ledger(
    root: str | Path,
    ledger: Mapping[str, Any],
) -> dict[str, Any]:
    """Rebuild the ledger from its bound inputs and reject any drift."""
    root = Path(root).resolve()
    if not isinstance(ledger, Mapping):
        raise ValueError("publication claim ledger root must be an object")
    inputs = ledger.get("inputs")
    if not isinstance(inputs, Mapping):
        raise ValueError("publication claim ledger lacks input bindings")
    required = {
        "inventory",
        "confirmatory_freeze",
        "confirmatory_decision",
        "cp_cert_result",
        "gold_release",
        "split_manifest",
    }
    if set(inputs) != required:
        raise ValueError("publication claim ledger input set changed")
    for name, item in inputs.items():
        if not isinstance(item, Mapping):
            raise ValueError(f"claim ledger {name} binding is malformed")
        path = _resolve(root, str(item.get("path", "")))
        if item.get("sha256") != _file_hash(path):
            raise ValueError(f"claim ledger {name} hash mismatch")
    expected = build_publication_claim_ledger(
        root,
        inventory_path=inputs["inventory"]["path"],
        confirmatory_freeze_path=inputs["confirmatory_freeze"]["path"],
        decision_path=inputs["confirmatory_decision"]["path"],
        cp_cert_result_path=inputs["cp_cert_result"]["path"],
    )
    if dict(ledger) != expected:
        raise ValueError(
            "publication claim ledger differs from deterministic derivation"
        )
    return expected


def _validate_inventory(
    root: Path,
    inventory: Mapping[str, Any],
) -> Mapping[str, Any]:
    inputs = inventory.get("inputs")
    if not isinstance(inputs, Mapping):
        raise ValueError("lineage inventory lacks source input paths")
    recomputed = build_executable_lineage_inventory(
        root,
        runtime_queue_path=inputs["runtime_queue"],
        configuration_queue_path=inputs["configuration_queue"],
        admission_audit_path=inputs["lineage_admission_audit"],
    )
    observed = deepcopy(dict(inventory))
    expected = deepcopy(recomputed)
    observed.pop("generated_at", None)
    expected.pop("generated_at", None)
    if observed != expected:
        raise ValueError("lineage inventory differs from source recomputation")
    gate = inventory.get("minimum_candidate_gate")
    if not isinstance(gate, Mapping) or gate.get("passes") is not True:
        raise ValueError("real-source candidate inventory gate did not pass")
    summary = inventory.get("summary")
    if not isinstance(summary, Mapping):
        raise ValueError("lineage inventory summary is malformed")
    return summary


def _validate_recomputed_decision(
    root: Path,
    decision: Mapping[str, Any],
) -> dict[str, Mapping[str, Any]]:
    binding = validate_decision_binding(root, decision)
    config = yaml.safe_load(
        _resolve(root, binding["config"]["path"]).read_text(
            encoding="utf-8"
        )
    )
    analysis = _read_json(
        _resolve(root, binding["analysis"]["path"])
    )
    records = read_jsonl(
        _resolve(root, binding["runs"]["path"])
    )
    expected_analysis = analyze_frozen_runs(records, config)
    observed_analysis = {
        key: value
        for key, value in analysis.items()
        if key != "artifact_binding"
    }
    if observed_analysis != expected_analysis:
        raise ValueError(
            "analysis differs from deterministic runs recomputation"
        )
    expected = evaluate_confirmatory_decision(analysis, config)
    observed = {
        key: value
        for key, value in decision.items()
        if key != "artifact_binding"
    }
    if observed != expected:
        raise ValueError(
            "confirmatory decision differs from preregistered recomputation"
        )
    return binding


def _validate_cp_cert_result(
    root: Path,
    report: Mapping[str, Any],
    config: Mapping[str, Any],
) -> tuple[bool, Path, Path]:
    if report.get("experiment") != "cp_cert_reviewed_human_gold":
        raise ValueError("unexpected CP-Cert experiment ID")
    selected = report.get("selected_splits")
    if (
        not isinstance(selected, list)
        or not selected
        or not set(selected) <= {"test", "external_test"}
    ):
        raise ValueError("CP-Cert result is not held-out split bound")
    gate = report.get("cp_cert_claim_gate")
    if not isinstance(gate, Mapping):
        raise ValueError("CP-Cert result lacks claim gate")
    gates = gate.get("gates")
    if (
        not isinstance(gates, Mapping)
        or set(gates) != REQUIRED_CP_CERT_GATES
        or any(not isinstance(value, bool) for value in gates.values())
    ):
        raise ValueError("CP-Cert claim sub-gates are malformed")
    eligible = gate.get("eligible")
    if not isinstance(eligible, bool) or eligible is not all(
        gates.values()
    ):
        raise ValueError("CP-Cert eligibility differs from sub-gates")
    if report.get("research_effectiveness_result") is not eligible:
        raise ValueError("CP-Cert result differs from claim gate")
    if gate.get("posthoc_threshold_change_allowed") is not False:
        raise ValueError("CP-Cert permits post-hoc threshold changes")
    if eligible and (
        not isinstance(gate.get("claim"), str)
        or not gate["claim"].strip()
    ):
        raise ValueError("eligible CP-Cert result lacks claim wording")
    data = config.get("data")
    artifact_binding = report.get("artifact_binding")
    if (
        not isinstance(data, Mapping)
        or not isinstance(artifact_binding, Mapping)
    ):
        raise ValueError("CP-Cert frozen input binding is malformed")
    paths = {}
    for field in ("gold_release", "split_manifest"):
        configured = data.get(field)
        bound = artifact_binding.get(field)
        if not isinstance(configured, str) or not isinstance(
            bound,
            Mapping,
        ):
            raise ValueError(f"CP-Cert lacks {field} binding")
        path = _resolve(root, configured)
        if _resolve(root, str(bound.get("path", ""))) != path:
            raise ValueError(f"CP-Cert {field} path mismatch")
        if bound.get("sha256") != _file_hash(path):
            raise ValueError(f"CP-Cert {field} hash mismatch")
        paths[field] = path
    release = _read_json(paths["gold_release"])
    split = _read_json(paths["split_manifest"])
    if split.get("packet_sha256") != release.get("packet_sha256"):
        raise ValueError("CP-Cert split packet hash mismatch")
    if split.get("gold_release_sha256") != _stable_hash(release):
        raise ValueError("CP-Cert split gold hash mismatch")
    _validate_split_manifest(release, split)
    return eligible, paths["gold_release"], paths["split_manifest"]


def _validate_human_gold(
    report: Mapping[str, Any],
    release: Mapping[str, Any],
    split: Mapping[str, Any],
) -> dict[str, int]:
    if (
        report.get("stage") != "frozen"
        or report.get("ready_to_publish") is not True
    ):
        return {
            "independence_groups": 0,
            "analytic_independence_groups": 0,
            "cases": 0,
            "analytic_cases": 0,
            "excluded_or_pending_cases": 0,
        }
    if report.get("release_sha256") != _stable_hash(release):
        raise ValueError("confirmatory release hash differs from freeze report")
    if report.get("split_manifest_sha256") != _stable_hash(split):
        raise ValueError("confirmatory split hash differs from freeze report")
    cases = release.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("human gold release has no cases")
    groups = set()
    for case in cases:
        annotation = case.get("annotation") or {}
        decision = (case.get("admission_screen") or {}).get("decision")
        expected_statuses = {
            "accept": {"reviewed", "adjudicated"},
            "reject": {"rejected"},
            "needs_execution": {"needs_execution"},
        }
        if (
            decision not in expected_statuses
            or annotation.get("status") not in expected_statuses[decision]
        ):
            raise ValueError("human gold contains a non-finalized case")
        if annotation.get("label_origin") not in {
            "human_reviewed",
            "human_adjudicated",
        }:
            raise ValueError("human gold contains a non-human label")
        primary = annotation.get("primary_annotator")
        reviewer = annotation.get("reviewer")
        if (
            not isinstance(primary, str)
            or not isinstance(reviewer, str)
            or primary == reviewer
        ):
            raise ValueError("human gold annotator identities are invalid")
        audit = case.get("annotation_audit")
        if not isinstance(audit, Mapping):
            raise ValueError("human gold case lacks annotation audit hashes")
        for field in (
            "primary_submission_sha256",
            "reviewer_submission_sha256",
        ):
            if not _is_sha256(audit.get(field)):
                raise ValueError(
                    f"human gold case has invalid {field}"
                )
        if (
            annotation.get("label_origin") == "human_adjudicated"
            and not _is_sha256(
                audit.get("adjudicator_submission_sha256")
            )
        ):
            raise ValueError(
                "adjudicated human gold lacks adjudicator audit hash"
            )
        group = (case.get("candidate_metadata") or {}).get(
            "independence_group"
        )
        if not isinstance(group, str) or not group:
            raise ValueError("human gold case lacks independence_group")
        groups.add(group)
    if report.get("human_gold_independence_groups") != len(groups):
        raise ValueError("human gold group count differs from freeze report")
    assignments = split.get("assignments")
    if not isinstance(assignments, list):
        raise ValueError("human gold split assignments are malformed")
    analytic = [
        item
        for item in assignments
        if isinstance(item, Mapping)
        and item.get("split") in ANALYTIC_SPLITS
    ]
    analytic_groups = {
        item.get("independence_group") for item in analytic
    }
    if None in analytic_groups or "" in analytic_groups:
        raise ValueError("analytic gold split lacks independence groups")
    return {
        "independence_groups": len(groups),
        "analytic_independence_groups": len(analytic_groups),
        "cases": len(cases),
        "analytic_cases": len(analytic),
        "excluded_or_pending_cases": len(cases) - len(analytic),
    }


def _validate_split_manifest(
    release: Mapping[str, Any],
    split: Mapping[str, Any],
) -> None:
    policy = split.get("policy")
    seed = split.get("seed")
    if not isinstance(policy, Mapping) or not isinstance(seed, int):
        raise ValueError("frozen split policy is malformed")
    ratios = policy.get("target_ratios")
    external_source_ids = policy.get("external_source_ids")
    if (
        not isinstance(ratios, Mapping)
        or not isinstance(external_source_ids, list)
        or any(
            not isinstance(value, str)
            for value in external_source_ids
        )
    ):
        raise ValueError("frozen split parameters are malformed")
    expected = build_frozen_split_manifest(
        release,
        seed=seed,
        ratios=ratios,
        external_source_ids=set(external_source_ids),
    )
    if dict(split) != expected:
        raise ValueError(
            "split manifest differs from deterministic gold recomputation"
        )


def _binding(root: Path, path: Path) -> dict[str, str]:
    return {
        "path": _portable(root, path),
        "sha256": _file_hash(path),
    }


def _read_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ValueError(f"required claim evidence is missing: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"claim evidence root must be an object: {path}")
    return value


def _file_hash(path: Path) -> str:
    if not path.is_file():
        raise ValueError(f"required claim evidence is missing: {path}")
    return sha256(path.read_bytes()).hexdigest()


def _stable_hash(value: Any) -> str:
    return sha256(json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")).hexdigest()


def _is_sha256(value: Any) -> bool:
    return bool(
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _resolve(root: Path, value: str | Path) -> Path:
    path = Path(value)
    return (path if path.is_absolute() else root / path).resolve()


def _portable(root: Path, path: Path) -> str:
    try:
        return str(path.resolve().relative_to(root)).replace("\\", "/")
    except ValueError:
        return str(path.resolve()).replace("\\", "/")
