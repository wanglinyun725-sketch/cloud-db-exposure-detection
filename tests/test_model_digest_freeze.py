import json
from unittest.mock import patch

import pytest

from scripts.experiments.run_ec_react_main import (
    _verify_frozen_runtime_digest,
)
from src.experiments.ec_react_preflight import _model_status


DIGEST = "a" * 64


class _FakeResponse:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def read(self):
        return json.dumps({
            "models": [{
                "name": "qwen2.5:7b",
                "digest": DIGEST,
            }]
        }).encode("utf-8")


@patch(
    "scripts.experiments.run_ec_react_main.urllib.request.urlopen",
    return_value=_FakeResponse(),
)
def test_ollama_runtime_digest_must_match_the_frozen_artifact(mocked):
    model = {
        "model_id": "local",
        "require_runtime_digest": True,
        "frozen_runtime_digest": DIGEST,
    }

    actual = _verify_frozen_runtime_digest(
        model,
        "qwen2.5:7b",
        "http://127.0.0.1:11434/v1",
    )

    assert actual == DIGEST
    assert mocked.call_args.args[0] == "http://127.0.0.1:11434/api/tags"


@patch(
    "scripts.experiments.run_ec_react_main.urllib.request.urlopen",
    return_value=_FakeResponse(),
)
def test_runtime_digest_mismatch_aborts_instead_of_silently_drifting(mocked):
    model = {
        "model_id": "local",
        "require_runtime_digest": True,
        "frozen_runtime_digest": "b" * 64,
    }

    with pytest.raises(RuntimeError, match="digest mismatch"):
        _verify_frozen_runtime_digest(
            model,
            "qwen2.5:7b",
            "http://127.0.0.1:11434/v1",
        )


def test_preflight_rejects_a_required_but_malformed_model_digest():
    blockers = []
    status = _model_status(
        [{
            "model_id": "local",
            "api_key_env": "LOCAL_KEY",
            "model_env": "LOCAL_MODEL",
            "default_model": "qwen2.5:7b",
            "base_url": "http://127.0.0.1:11434/v1",
            "require_runtime_digest": True,
            "frozen_runtime_digest": "not-a-sha256",
        }],
        [{"family": "llm"}],
        {"LOCAL_KEY": "not-secret-test-value"},
        blockers,
    )

    assert any("valid frozen runtime digest" in item for item in blockers)
    assert status[0]["frozen_runtime_digest"] is None


def test_preflight_allows_keyless_local_model_but_locks_remote_snapshot():
    blockers = []
    status = _model_status(
        [
            {
                "model_id": "local",
                "api_key_env": "LOCAL_KEY",
                "api_key_required": False,
                "default_model": "qwen2.5:7b",
            },
            {
                "model_id": "strong",
                "api_key_env": "REMOTE_KEY",
                "api_key_required": True,
                "default_model": "gpt-5.4-2026-03-05",
                "require_exact_version": True,
            },
        ],
        [{"family": "llm"}],
        {"REMOTE_KEY": "not-secret-test-value"},
        blockers,
    )

    assert blockers == []
    assert status[0]["api_key_required"] is False
    assert status[0]["api_key_present"] is False
    assert status[1]["require_exact_version"] is True


def test_preflight_rejects_environment_override_of_exact_snapshot():
    blockers = []
    _model_status(
        [{
            "model_id": "strong",
            "api_key_env": "REMOTE_KEY",
            "model_env": "REMOTE_MODEL",
            "default_model": "gpt-5.4-2026-03-05",
            "require_exact_version": True,
        }],
        [{"family": "llm"}],
        {
            "REMOTE_KEY": "not-secret-test-value",
            "REMOTE_MODEL": "moving-alias",
        },
        blockers,
    )

    assert any("exact version was overridden" in item for item in blockers)


def test_plan_only_model_audit_records_but_does_not_require_key():
    blockers = []
    status = _model_status(
        [{
            "model_id": "strong",
            "api_key_env": "REMOTE_KEY",
            "api_key_required": True,
            "default_model": "gpt-5.4-2026-03-05",
            "require_exact_version": True,
        }],
        [{"family": "llm"}],
        {},
        blockers,
        require_credentials=False,
    )

    assert blockers == []
    assert status[0]["api_key_present"] is False
    assert status[0]["api_key_required"] is True
    assert status[0]["credential_enforced"] is False
