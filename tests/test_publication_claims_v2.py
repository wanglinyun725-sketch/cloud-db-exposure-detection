from hashlib import sha256
import json
from pathlib import Path

import pytest
import yaml

from src.experiments.artifact_chain_v2 import (
    build_analysis_binding,
    build_decision_binding,
)
from src.experiments.confirmatory_decision import (
    evaluate_confirmatory_decision,
)
from src.experiments.frozen_splits import build_frozen_split_manifest
from src.experiments.publication_claims_v2 import (
    build_publication_claim_ledger,
    validate_publication_claim_ledger,
)


ROOT = Path(__file__).resolve().parents[1]
INVENTORY = (
    ROOT / "output" / "research_design"
    / "executable_lineage_inventory_v1.json"
)


def _write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def _stable_hash(value):
    return sha256(json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")).hexdigest()


def _fixture(tmp_path, *, ec_pass=True, cp_pass=False):
    packet_sha = "a" * 64
    gold = {
        "release_version": "human-annotation-0.1",
        "packet_sha256": packet_sha,
        "cases": [
            {
                "case_id": f"case-{index:02d}",
                "candidate_metadata": {
                    "independence_group": f"group-{index:02d}",
                },
                "source": {
                    "source_id": f"source-{index % 6}",
                    "provenance_level": "A",
                },
                "admission_screen": {
                    "decision": "accept",
                },
                "annotation": {
                    "status": "reviewed",
                    "label_origin": "human_reviewed",
                    "primary_annotator": "human-a",
                    "reviewer": "human-b",
                    "adjudication": None,
                },
                "annotation_audit": {
                    "primary_submission_sha256": "b" * 64,
                    "reviewer_submission_sha256": "c" * 64,
                    "adjudicator_submission_sha256": None,
                    "agreement": {},
                },
            }
            for index in range(30)
        ],
    }
    gold_path = tmp_path / "gold.json"
    _write_json(gold_path, gold)
    split = build_frozen_split_manifest(
        gold,
        seed=20260730,
    )
    split_path = tmp_path / "split.json"
    _write_json(split_path, split)
    confirmatory = {
        "stage": "frozen",
        "ready_to_publish": True,
        "human_gold_independence_groups": 30,
        "release_sha256": _stable_hash(gold),
        "split_manifest_sha256": _stable_hash(split),
    }
    confirmatory_path = tmp_path / "confirmatory.json"
    _write_json(confirmatory_path, confirmatory)

    config = {
        "freeze_status": "FROZEN",
        "data": {
            "gold_release": str(gold_path),
            "split_manifest": str(split_path),
        },
        "schedule_arms": [{
            "role": "confirmatory_primary",
            "model_ids": ["local", "strong"],
        }],
        "reporting": {
            "confirmatory_primary_metric": "exact_edge_f1",
            "confirmatory_budget": 20,
            "success_gates": {
                "two_sided_p_below": 0.05,
                "minimum_mean_f1_gain": 0.03,
                "minimum_absolute_f1": 0.60,
                "relative_improvement_rule": (
                    "material_or_holm_significant"
                ),
            },
        },
    }
    config_path = tmp_path / "frozen.yaml"
    config_path.write_text(
        yaml.safe_dump(config, sort_keys=False),
        encoding="utf-8",
    )
    config_hash = sha256(config_path.read_bytes()).hexdigest()
    run_manifest = tmp_path / "run_manifest.json"
    _write_json(run_manifest, {
        "config_sha256": config_hash,
        "scheduled_runs": 1,
        "schedule": [{"schedule_id": "s1"}],
        "secrets_in_manifest": False,
    })
    runs_path = tmp_path / "runs.jsonl"
    record = {"schedule_id": "s1", "config_sha256": config_hash}
    runs_path.write_text(json.dumps(record) + "\n", encoding="utf-8")

    mean = 0.70 if ec_pass else 0.55
    gain = 0.05 if ec_pass else 0.0
    summaries = []
    comparisons = []
    safety = []
    for model in ("local", "strong"):
        summaries.append({
            "method_id": "ec_react_full",
            "model_id": model,
            "budget": 20,
            "split": "test",
            "metric": "exact_edge_f1",
            "mean": mean,
            "ci_low": mean - 0.05,
            "ci_high": mean + 0.05,
            "confidence_level": 0.95,
        })
        comparisons.append({
            "primary_method_id": "ec_react_full",
            "primary_model_id": model,
            "baseline_method_id": "vanilla_react",
            "baseline_model_id": model,
            "budget": 20,
            "split": "test",
            "metric": "exact_edge_f1",
            "favorable_effect": gain,
            "favorable_effect_ci_low": gain - 0.02,
            "favorable_effect_ci_high": gain + 0.02,
            "confidence_level": 0.95,
            "paired_standardized_effect": 0.5,
            "minimum_detectable_paired_dz": 0.4,
            "paired_independence_groups": 20,
            "p_holm": 0.10,
        })
        safety.append({
            "primary_method_id": "ec_react_full",
            "primary_model_id": model,
            "baseline_method_id": "vanilla_react",
            "budget": 20,
            "split": "external_negative_control",
            "rate_difference_primary_minus_baseline": (
                0.0 if ec_pass else 0.1
            ),
            "rate_difference_ci_low": -0.05,
            "rate_difference_ci_high": 0.05,
            "confidence_level": 0.95,
            "unsafe_false_reachable_must_not_increase_pass": ec_pass,
        })
    analysis_semantic = {
        "run_records": 1,
        "summaries": summaries,
        "paired_comparisons": comparisons,
        "safety_gate_evaluations": {"evaluations": safety},
    }
    analysis = {
        **analysis_semantic,
        "artifact_binding": build_analysis_binding(
            ROOT,
            config_path=config_path,
            run_manifest_path=run_manifest,
            runs_path=runs_path,
            records=[record],
        ),
    }
    analysis_path = tmp_path / "analysis.json"
    _write_json(analysis_path, analysis)
    decision = {
        **evaluate_confirmatory_decision(analysis, config),
        "artifact_binding": build_decision_binding(
            ROOT,
            config_path=config_path,
            analysis_path=analysis_path,
            analysis=analysis,
        ),
    }
    decision_path = tmp_path / "decision.json"
    _write_json(decision_path, decision)

    gates = {
        "frozen_held_out_split_bound": True,
        "minimum_independence_groups": cp_pass,
        "all_certificates_valid": True,
        "all_raw_references_verified": True,
        "exact_optimality_oracle_verified": True,
        "positive_ci_lower_bound_for_compression": True,
    }
    cp = {
        "experiment": "cp_cert_reviewed_human_gold",
        "selected_splits": ["test"],
        "artifact_binding": {
            "gold_release": {
                "path": str(gold_path),
                "sha256": sha256(gold_path.read_bytes()).hexdigest(),
            },
            "split_manifest": {
                "path": str(split_path),
                "sha256": sha256(split_path.read_bytes()).hexdigest(),
            },
        },
        "research_effectiveness_result": cp_pass,
        "cp_cert_claim_gate": {
            "claim": "CP-Cert passes its held-out empirical gate.",
            "eligible": cp_pass,
            "observed_independence_groups": 20,
            "gates": gates,
            "posthoc_threshold_change_allowed": False,
        },
    }
    cp_path = tmp_path / "cp.json"
    _write_json(cp_path, cp)
    return {
        "inventory": INVENTORY,
        "confirmatory": confirmatory_path,
        "decision": decision_path,
        "cp": cp_path,
        "analysis": analysis_path,
        "analysis_semantic": analysis_semantic,
        "config": config,
        "config_path": config_path,
    }


def _build(paths):
    return build_publication_claim_ledger(
        ROOT,
        inventory_path=paths["inventory"],
        confirmatory_freeze_path=paths["confirmatory"],
        decision_path=paths["decision"],
        cp_cert_result_path=paths["cp"],
    )


def test_claim_ledger_allows_mandatory_and_blocks_failed_conditional(
    tmp_path,
    monkeypatch,
):
    paths = _fixture(tmp_path, ec_pass=True, cp_pass=False)
    monkeypatch.setattr(
        "src.experiments.publication_claims_v2.analyze_frozen_runs",
        lambda records, config: paths["analysis_semantic"],
    )

    ledger = _build(paths)

    assert ledger["mandatory_innovations_claim_allowed"] is True
    assert ledger["cp_cert_innovation_claim_allowed"] is False
    assert ledger["summary"] == {
        "claims": 3,
        "allowed": 2,
        "blocked": 0,
        "conditional_failed": 1,
    }
    assert validate_publication_claim_ledger(ROOT, ledger) == ledger


def test_failed_ec_gate_blocks_thesis_claim_without_metric_substitution(
    tmp_path,
    monkeypatch,
):
    paths = _fixture(tmp_path, ec_pass=False, cp_pass=True)
    monkeypatch.setattr(
        "src.experiments.publication_claims_v2.analyze_frozen_runs",
        lambda records, config: paths["analysis_semantic"],
    )

    ledger = _build(paths)
    by_id = {item["claim_id"]: item for item in ledger["claims"]}

    assert ledger["mandatory_innovations_claim_allowed"] is False
    assert ledger["thesis_claim_status"] == "blocked"
    assert by_id["ec_react_effectiveness"]["status"] == "blocked"
    assert by_id["ec_react_effectiveness"]["prohibited_wording"]
    assert ledger["posthoc_claim_substitution_allowed"] is False


def test_rejected_candidate_cannot_count_as_analytic_gold(
    tmp_path,
    monkeypatch,
):
    paths = _fixture(tmp_path, ec_pass=True, cp_pass=False)
    monkeypatch.setattr(
        "src.experiments.publication_claims_v2.analyze_frozen_runs",
        lambda records, config: paths["analysis_semantic"],
    )
    gold_path = Path(paths["config"]["data"]["gold_release"])
    split_path = Path(paths["config"]["data"]["split_manifest"])
    gold = json.loads(gold_path.read_text(encoding="utf-8"))
    gold["cases"][0]["admission_screen"]["decision"] = "reject"
    gold["cases"][0]["annotation"]["status"] = "rejected"
    _write_json(gold_path, gold)
    split = build_frozen_split_manifest(gold, seed=20260730)
    _write_json(split_path, split)
    freeze = json.loads(
        paths["confirmatory"].read_text(encoding="utf-8")
    )
    freeze["release_sha256"] = _stable_hash(gold)
    freeze["split_manifest_sha256"] = _stable_hash(split)
    _write_json(paths["confirmatory"], freeze)
    cp = json.loads(paths["cp"].read_text(encoding="utf-8"))
    cp["artifact_binding"]["gold_release"]["sha256"] = sha256(
        gold_path.read_bytes()
    ).hexdigest()
    cp["artifact_binding"]["split_manifest"]["sha256"] = sha256(
        split_path.read_bytes()
    ).hexdigest()
    _write_json(paths["cp"], cp)

    ledger = _build(paths)
    by_id = {item["claim_id"]: item for item in ledger["claims"]}

    assert (
        by_id["realpathbench_cd"]["metrics"][
            "human_gold_independence_groups"
        ]
        == 30
    )
    assert (
        by_id["realpathbench_cd"]["metrics"][
            "analytic_gold_independence_groups"
        ]
        == 29
    )
    assert by_id["realpathbench_cd"]["status"] == "blocked"


def test_ledger_tampering_is_rejected(tmp_path, monkeypatch):
    paths = _fixture(tmp_path, ec_pass=True, cp_pass=False)
    monkeypatch.setattr(
        "src.experiments.publication_claims_v2.analyze_frozen_runs",
        lambda records, config: paths["analysis_semantic"],
    )
    ledger = _build(paths)
    ledger["claims"][2]["status"] = "allowed"

    with pytest.raises(ValueError, match="deterministic derivation"):
        validate_publication_claim_ledger(ROOT, ledger)


def test_analysis_must_match_deterministic_runs_recomputation(
    tmp_path,
    monkeypatch,
):
    paths = _fixture(tmp_path, ec_pass=True, cp_pass=False)
    monkeypatch.setattr(
        "src.experiments.publication_claims_v2.analyze_frozen_runs",
        lambda records, config: paths["analysis_semantic"],
    )
    analysis = json.loads(paths["analysis"].read_text(encoding="utf-8"))
    analysis["summaries"][0]["mean"] = 0.99
    _write_json(paths["analysis"], analysis)
    decision = {
        **evaluate_confirmatory_decision(
            analysis,
            paths["config"],
        ),
        "artifact_binding": build_decision_binding(
            ROOT,
            config_path=paths["config_path"],
            analysis_path=paths["analysis"],
            analysis=analysis,
        ),
    }
    _write_json(paths["decision"], decision)

    with pytest.raises(ValueError, match="analysis differs"):
        _build(paths)
