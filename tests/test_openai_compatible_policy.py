from types import SimpleNamespace

from src.agent.ec_react import OpenAICompatibleReActPolicy


class _CapturingCompletions:
    def __init__(self) -> None:
        self.kwargs = None

    def create(self, **kwargs):
        self.kwargs = kwargs
        message = SimpleNamespace(
            content='{"kind":"finish","thought":"done",'
            '"decision":"abstain","hypothesis":"none",'
            '"evidence_observation_ids":[]}'
        )
        return SimpleNamespace(
            choices=[SimpleNamespace(message=message)]
        )


def test_snapshot_policy_omits_temperature_and_sets_reasoning_effort():
    completions = _CapturingCompletions()
    client = SimpleNamespace(
        chat=SimpleNamespace(completions=completions)
    )
    policy = OpenAICompatibleReActPolicy(
        client,
        "gpt-5.4-2026-03-05",
        temperature=None,
        reasoning_effort="medium",
    )

    result = policy.propose({"task_mode": "decision"})

    assert result["kind"] == "finish"
    assert completions.kwargs["model"] == "gpt-5.4-2026-03-05"
    assert completions.kwargs["reasoning_effort"] == "medium"
    assert "temperature" not in completions.kwargs


def test_compatible_policy_keeps_explicit_zero_temperature():
    completions = _CapturingCompletions()
    client = SimpleNamespace(
        chat=SimpleNamespace(completions=completions)
    )
    policy = OpenAICompatibleReActPolicy(
        client,
        "compatible-model",
        temperature=0,
    )

    policy.propose({"task_mode": "decision"})

    assert completions.kwargs["temperature"] == 0
    assert "reasoning_effort" not in completions.kwargs
