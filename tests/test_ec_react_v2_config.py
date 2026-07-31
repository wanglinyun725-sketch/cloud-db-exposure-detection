from copy import deepcopy
from pathlib import Path

import yaml

from src.experiments.ec_react_preflight import _validate_method_fairness
from src.experiments.ec_react_execution import (
    planned_runs_per_instance,
    planned_runs_per_instance_for_selection,
    schedule_design_errors,
)


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs" / "ec_react_main_v2_draft.yaml"
COMPONENTS = {
    "pareto_guard",
    "external_rule_prior",
    "four_value_memory",
    "budget_stop",
    "provider_scope_gate",
    "evidence_citation_guard",
}


def test_v2_draft_has_one_confirmatory_metric_and_budget():
    config = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))

    assert config["freeze_status"].startswith("DRAFT_BLOCKED")
    assert config["shared_execution"]["confirmatory_budget"] == 20
    assert config["reporting"]["confirmatory_budget"] == 20
    assert config["reporting"]["primary_metrics"] == [
        "certified_fine_edge_f1_at_5"
    ]
    assert config["reporting"]["success_gates"] == {
        "two_sided_p_below": 0.05,
        "minimum_mean_f1_gain": 0.10,
        "minimum_absolute_f1": 0.60,
        "relative_improvement_rule": (
            "material_or_holm_significant"
        ),
        "unsafe_false_reachable_must_not_increase": True,
    }


def test_each_v2_ablation_changes_exactly_one_full_method_component():
    config = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    methods = {item["method_id"]: item for item in config["methods"]}
    full = methods["ec_react_full"]
    expected_component = {
        "ablate_pareto": "pareto_guard",
        "ablate_provider_scope_gate": "provider_scope_gate",
        "ablate_external_rule_prior": "external_rule_prior",
        "ablate_four_value_memory": "four_value_memory",
        "ablate_budget_stop": "budget_stop",
        "ablate_evidence_cert": "evidence_citation_guard",
    }

    for method_id, changed_component in expected_component.items():
        ablated = methods[method_id]
        differences = {
            component
            for component in COMPONENTS
            if ablated[component] != full[component]
        }
        assert differences == {changed_component}

    assert full["finish_guard_mode"] == "strict"
    assert methods["ablate_evidence_cert"]["finish_guard_mode"] == "record"
    assert all(
        isinstance(method[component], bool)
        for method in methods.values()
        for component in COMPONENTS
    )
    blockers = []
    _validate_method_fairness(
        config["methods"],
        config["shared_execution"],
        blockers,
    )
    assert blockers == []


def test_v2_model_layer_is_honest_about_what_is_and_is_not_frozen():
    config = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    models = {item["model_id"]: item for item in config["models"]}

    assert models["qwen2_5_7b_local"]["default_model"] == "qwen2.5:7b"
    assert models["qwen2_5_7b_local"]["require_runtime_digest"] is True
    assert models["qwen2_5_7b_local"]["api_key_required"] is False
    assert models["qwen2_5_7b_local"]["client_kind"] == "ollama_native"
    assert models["qwen2_5_7b_local"]["frozen_runtime_digest"] == (
        "845dbda0ea48ed749caafd9e6037047aa19acfcfd82e704d7ca97d631a0b697e"
    )
    strong = models["gpt_5_4_snapshot"]
    assert strong["default_model"] == "gpt-5.4-2026-03-05"
    assert strong["require_exact_version"] is True
    assert strong["api_key_required"] is True
    assert strong["client_kind"] == "openai_chat"
    assert strong["reasoning_effort"] == "medium"
    assert strong["temperature"] is None


def test_v2_data_gate_uses_executable_oracle_protocol():
    config = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    data = config["data"]

    assert data["source_packet"].endswith(
        "runtime_confirmatory_30_unlabeled.json"
    )
    assert data["gold_protocol"] == "executable_oracle_v1"
    assert data["oracle_registry"].endswith(
        "executable_oracle_registry_v1.json"
    )
    assert data["minimum_finalized_cases"] == 30
    assert data["minimum_independence_groups"] == 30
    assert data["minimum_external_negative_controls"] == 10
    assert "annotation_pilot_packet" not in data


def test_v2_uses_an_explicit_non_cartesian_schedule():
    config = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))

    assert schedule_design_errors(config) == []
    assert planned_runs_per_instance(config) == 77
    assert planned_runs_per_instance_for_selection(
        config,
        model_ids={"qwen2_5_7b_local"},
    ) == 67
    assert planned_runs_per_instance_for_selection(
        config,
        model_ids={"gpt_5_4_snapshot"},
    ) == 17
    assert planned_runs_per_instance_for_selection(
        config,
        method_ids={"ec_react_full"},
    ) == 20
    arms = {item["arm_id"]: item for item in config["schedule_arms"]}
    primary = arms["confirmatory_dual_model_b20"]
    assert primary["role"] == "confirmatory_primary"
    assert primary["budgets"] == [20]
    assert primary["repeats"] == 5
    assert set(primary["method_ids"]) == {
        "ec_react_full",
        "vanilla_react",
    }
    assert set(primary["model_ids"]) == {
        "qwen2_5_7b_local",
        "gpt_5_4_snapshot",
    }
    ablation = arms["qwen_component_ablations_b20"]
    assert ablation["model_ids"] == ["qwen2_5_7b_local"]
    assert ablation["budgets"] == [20]


def test_explicit_schedule_rejects_duplicate_conditions():
    config = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    duplicate = deepcopy(config["schedule_arms"][0])
    duplicate["arm_id"] = "duplicate_primary"
    config["schedule_arms"].append(duplicate)

    errors = schedule_design_errors(config)

    assert any("duplicate condition" in item for item in errors)
