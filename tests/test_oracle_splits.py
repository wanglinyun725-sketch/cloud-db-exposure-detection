import json
from pathlib import Path

from src.oracle_gold.splits import build_oracle_split


ROOT = Path(__file__).resolve().parents[1]
REGISTRY = (
    "data/real_sources/oracle/executable_oracle_registry_v1.json"
)
POLICY = "configs/oracle_split_policy_v1.json"
COMMITTED = (
    ROOT / "data" / "real_sources" / "oracle" / "releases"
    / "executable_oracle_gold_v1_splits.json"
)


def _build():
    return build_oracle_split(
        ROOT,
        registry_path=REGISTRY,
        policy_path=POLICY,
    )


def test_committed_oracle_split_is_reproducible():
    assert json.loads(COMMITTED.read_text(encoding="utf-8")) == _build()


def test_split_is_frozen_before_gold_and_excludes_unknowns():
    manifest = _build()

    assert manifest["status"] == "blocked_on_oracle_gold"
    assert manifest["assignments"] == []
    assert len(manifest["excluded"]) == 40
    assert manifest["summary"] == {
        "qualifying_groups": 0,
        "excluded_or_pending_groups": 40,
        "split_counts": {},
        "minimum_oracle_gold_groups": 30,
        "minimum_test_and_external_test_groups": 15,
        "gold_gate_passes": False,
        "test_size_passes": False,
    }
