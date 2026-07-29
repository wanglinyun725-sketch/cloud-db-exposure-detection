from pathlib import Path

import yaml

from src.experiments.ec_react_preflight import _validate_method_fairness


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
    assert models["qwen2_5_7b_local"]["frozen_runtime_digest"] == (
        "845dbda0ea48ed749caafd9e6037047aa19acfcfd82e704d7ca97d631a0b697e"
    )
    assert "default_model" not in models["stronger_fixed"]
    assert models["stronger_fixed"]["require_exact_version"] is True
    assert models["stronger_fixed"]["freeze_blocker"]
