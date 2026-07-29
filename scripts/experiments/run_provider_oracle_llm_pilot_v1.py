#!/usr/bin/env python3
"""Run a resumable local-LLM pilot from a frozen provider-oracle config."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import asdict
from hashlib import sha256
import json
from pathlib import Path
import sys
from time import perf_counter
from typing import Any
import urllib.request


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.experiments.run_provider_oracle_protocol_v3 import (  # noqa: E402
    summarize,
)
from src.agent.ec_react import (  # noqa: E402
    ECReactRunner,
    OllamaNativeReActPolicy,
)
from src.agent.ec_react_langgraph import (  # noqa: E402
    ECReactLangGraphRunner,
)
from src.agent.frozen_provider_oracle_environment import (  # noqa: E402
    FrozenProviderOracleEnvironment,
)
from src.experiments.provider_oracle_scoring import (  # noqa: E402
    score_provider_oracle_state,
)


DEFAULT_CONFIG = ROOT / "configs" / "provider_oracle_llm_pilot_v1.json"
DEFAULT_OUTPUT_DIR = ROOT / "output" / "provider_oracle_llm_pilot_v1"
IMPLEMENTATION_PATHS = (
    Path("scripts/experiments/run_provider_oracle_llm_pilot_v1.py"),
    Path("src/agent/ec_react.py"),
    Path("src/agent/ec_react_langgraph.py"),
    Path("src/agent/path_proposal.py"),
    Path("src/agent/published_telemetry_environment.py"),
    Path("src/agent/frozen_provider_oracle_environment.py"),
    Path("src/experiments/provider_oracle_scoring.py"),
    Path("src/verification/cp_cert.py"),
)


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _hash(value: Any) -> str:
    return sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _completed(path: Path) -> set[str]:
    if not path.is_file():
        return set()
    output = set()
    for line_number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(),
        start=1,
    ):
        if not line.strip():
            continue
        item = json.loads(line)
        schedule_id = item.get("schedule_id")
        if not isinstance(schedule_id, str):
            raise ValueError(
                f"missing schedule_id at {path}:{line_number}"
            )
        output.add(schedule_id)
    return output


@contextmanager
def _exclusive_output_lock(output_dir: Path):
    """Prevent concurrent resumptions from executing the same schedule."""
    output_dir.mkdir(parents=True, exist_ok=True)
    lock_path = output_dir / ".runner.lock"
    stream = lock_path.open("a+b")
    stream.seek(0, 2)
    if stream.tell() == 0:
        stream.write(b"\0")
        stream.flush()
    stream.seek(0)
    try:
        if sys.platform == "win32":
            import msvcrt

            msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(
                stream.fileno(),
                fcntl.LOCK_EX | fcntl.LOCK_NB,
            )
    except OSError as exc:
        stream.close()
        raise RuntimeError(
            f"another pilot runner holds {lock_path}"
        ) from exc
    try:
        yield
    finally:
        stream.seek(0)
        if sys.platform == "win32":
            import msvcrt

            msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
        stream.close()


def _deduplicate_scheduled_rows(
    rows: list[dict[str, Any]],
    scheduled_ids: set[str],
) -> tuple[list[dict[str, Any]], int]:
    unique: dict[str, dict[str, Any]] = {}
    duplicates = 0
    for item in rows:
        schedule_id = item.get("schedule_id")
        if schedule_id not in scheduled_ids:
            continue
        if schedule_id in unique:
            duplicates += 1
            continue
        unique[schedule_id] = item
    return list(unique.values()), duplicates


def _merge_compatible_manifest(
    existing: dict[str, Any],
    current: dict[str, Any],
) -> dict[str, Any]:
    compatibility_fields = (
        "experiment_id",
        "protocol_version",
        "config_sha256",
        "implementation_bundle_sha256",
        "public_packet_sha256",
        "gold_packet_sha256",
    )
    mismatches = [
        field for field in compatibility_fields
        if existing.get(field) != current.get(field)
    ]
    if mismatches:
        raise RuntimeError(
            "output directory contains an incompatible manifest: "
            + ", ".join(mismatches)
        )
    merged = dict(existing)
    schedules = {
        item["schedule_id"]: item
        for item in existing.get("schedule", [])
    }
    for item in current.get("schedule", []):
        schedules.setdefault(item["schedule_id"], item)
    merged["schedule"] = sorted(
        schedules.values(), key=lambda item: item["schedule_id"]
    )
    merged["scheduled_runs"] = len(merged["schedule"])
    existing_filters = existing.get("filters") or {}
    invocations = list(
        existing_filters.get("resume_invocations") or []
    )
    if not invocations:
        invocations.append(existing_filters)
    invocations.append(current.get("filters") or {})
    merged["filters"] = {"resume_invocations": invocations}
    return merged


def _ollama_digest(base_url: str, model: str) -> str | None:
    with urllib.request.urlopen(
        base_url.rstrip("/") + "/api/tags",
        timeout=10,
    ) as response:
        payload = json.loads(response.read().decode("utf-8"))
    for item in payload.get("models", []):
        if item.get("name") == model or item.get("model") == model:
            return item.get("digest")
    return None


def run(
    config_path: Path,
    output_dir: Path,
    *,
    method_filter: set[str] | None = None,
    case_filter: set[str] | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    with _exclusive_output_lock(output_dir):
        return _run_locked(
            config_path,
            output_dir,
            method_filter=method_filter,
            case_filter=case_filter,
            limit=limit,
        )


def _run_locked(
    config_path: Path,
    output_dir: Path,
    *,
    method_filter: set[str] | None = None,
    case_filter: set[str] | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    config_bytes = config_path.read_bytes()
    config = json.loads(config_bytes.decode("utf-8"))
    public_path = ROOT / config["data"]["public_packet"]
    gold_path = ROOT / config["data"]["evaluator_gold"]
    split_path = ROOT / config["data"]["split_manifest"]
    public = _load(public_path)
    gold = _load(gold_path)
    splits = _load(split_path)
    if public["protocol_version"] != config["protocol_version"]:
        raise ValueError("public protocol version differs from pilot config")
    if gold["protocol_version"] != config["protocol_version"]:
        raise ValueError("gold protocol version differs from pilot config")
    assignments = {
        item["case_id"]: item for item in splits["assignments"]
    }
    model = config["model"]
    model_digest = _ollama_digest(model["base_url"], model["model"])
    if not model_digest:
        raise RuntimeError(
            f"Ollama model is unavailable: {model['model']}"
        )
    config_sha256 = sha256(config_bytes).hexdigest()
    implementation = [
        {
            "path": path.as_posix(),
            "sha256": sha256((ROOT / path).read_bytes()).hexdigest(),
        }
        for path in IMPLEMENTATION_PATHS
    ]
    implementation_bundle_sha256 = _hash(implementation)

    methods = [
        item for item in config["methods"]
        if method_filter is None
        or item["method_id"] in method_filter
    ]
    cases = [
        item for item in sorted(
            gold["cases"], key=lambda value: value["case_id"]
        )
        if case_filter is None or item["case_id"] in case_filter
    ]
    schedule = []
    execution = config["execution"]
    repeat_ids = (
        list(range(int(execution["repeat_count"])))
        if "repeat_count" in execution
        else [int(execution["repeat"])]
    )
    for metadata in cases:
        for method in methods:
            for repeat_id in repeat_ids:
                orchestration_backend = method.get(
                    "orchestration_backend",
                    execution.get("orchestration_backend", "linear"),
                )
                if orchestration_backend not in {"linear", "langgraph"}:
                    raise ValueError(
                        "orchestration_backend must be linear or langgraph"
                    )
                identity = {
                    "experiment_id": config["experiment_id"],
                    "case_id": metadata["case_id"],
                    "method_id": method["method_id"],
                    "orchestration_backend": orchestration_backend,
                    "model": model["model"],
                    "model_digest": model_digest,
                    "budget": execution["budget"],
                    "repeat": repeat_id,
                    "seed": int(execution["seed"]) + repeat_id,
                    "config_sha256": config_sha256,
                    "implementation_bundle_sha256": (
                        implementation_bundle_sha256
                    ),
                }
                schedule.append({
                    **identity,
                    "schedule_id": "llm-schedule-" + _hash(identity)[:24],
                })
    if limit is not None:
        schedule = schedule[:limit]

    output_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "manifest_version": "1.1.0",
        "experiment_id": config["experiment_id"],
        "protocol_version": config["protocol_version"],
        "research_effectiveness_result": False,
        "config_path": str(config_path.relative_to(ROOT)),
        "config_sha256": config_sha256,
        "implementation": implementation,
        "implementation_bundle_sha256": implementation_bundle_sha256,
        "public_packet_path": str(public_path.relative_to(ROOT)),
        "public_packet_sha256": sha256(public_path.read_bytes()).hexdigest(),
        "gold_packet_path": str(gold_path.relative_to(ROOT)),
        "gold_packet_sha256": sha256(gold_path.read_bytes()).hexdigest(),
        "agent_loaded_gold": False,
        "model": {
            "backend": model["backend"],
            "name": model["model"],
            "digest": model_digest,
            "think": model["think"],
            "temperature": model["temperature"],
            "num_predict": model["num_predict"],
            "num_ctx": model["num_ctx"],
        },
        "filters": {
            "methods": sorted(method_filter) if method_filter else None,
            "cases": sorted(case_filter) if case_filter else None,
            "limit": limit,
        },
        "scheduled_runs": len(schedule),
        "schedule": schedule,
        "secrets_in_manifest": False,
    }
    manifest_path = output_dir / "run_manifest.json"
    if manifest_path.is_file():
        existing_manifest = json.loads(
            manifest_path.read_text(encoding="utf-8")
        )
        manifest = _merge_compatible_manifest(
            existing_manifest, manifest
        )
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    gold_by_id = {item["case_id"]: item for item in gold["cases"]}
    method_by_id = {
        item["method_id"]: item for item in config["methods"]
    }
    run_path = output_dir / "runs.jsonl"
    completed = _completed(run_path)
    executed = 0
    skipped = 0
    with run_path.open("a", encoding="utf-8") as stream:
        for scheduled in schedule:
            if scheduled["schedule_id"] in completed:
                skipped += 1
                continue
            metadata = gold_by_id[scheduled["case_id"]]
            method = method_by_id[scheduled["method_id"]]
            policy = OllamaNativeReActPolicy(
                model["model"],
                base_url=model["base_url"],
                timeout_seconds=float(model["timeout_seconds"]),
                keep_alive=model["keep_alive"],
                num_predict=int(model["num_predict"]),
                num_ctx=int(model["num_ctx"]),
                seed=int(scheduled["seed"]),
            )
            environment = FrozenProviderOracleEnvironment(
                public,
                metadata,
                budget=int(execution["budget"]),
            )
            orchestration_backend = scheduled[
                "orchestration_backend"
            ]
            runner_type = (
                ECReactLangGraphRunner
                if orchestration_backend == "langgraph"
                else ECReactRunner
            )
            runner = runner_type(
                policy,
                max_steps=int(execution["max_steps"]),
                task_mode="path_discovery",
                finish_guard_mode=method["finish_guard_mode"],
                pareto_guard=method["pareto_guard"],
                external_rule_prior=method["external_rule_prior"],
                four_value_memory=method["four_value_memory"],
                budget_stop=method["budget_stop"],
                provider_scope_gate=method.get(
                    "provider_scope_gate",
                    True,
                ),
                max_path_candidates=int(
                    execution["max_path_candidates"]
                ),
            )
            started = perf_counter()
            result = runner.run(
                environment, environment.public_context
            )
            latency = perf_counter() - started
            score = score_provider_oracle_state(
                result, environment.evaluation_metadata()
            )
            record = {
                **scheduled,
                "split": assignments[metadata["case_id"]]["split"],
                "independence_group": metadata["independence_group"],
                "platform": metadata["platform"],
                "label_origin": metadata["label_origin"],
                "method_components": {
                    **{
                        key: method[key]
                        for key in (
                            "pareto_guard",
                            "external_rule_prior",
                            "four_value_memory",
                            "budget_stop",
                            "provider_scope_gate",
                            "finish_guard_mode",
                        )
                        if key in method
                    },
                    "orchestration_backend": orchestration_backend,
                },
                "latency_seconds": latency,
                "result": asdict(result),
                "score": score,
                "secrets_in_record": False,
            }
            stream.write(json.dumps(record, ensure_ascii=False) + "\n")
            stream.flush()
            executed += 1
            print(json.dumps({
                "executed": executed,
                "skipped": skipped,
                "scheduled": len(schedule),
                "case_id": metadata["case_id"],
                "method_id": method["method_id"],
                "orchestration_backend": orchestration_backend,
                "predicted_state": score["predicted_state"],
                "gold_state": score["gold_state"],
                "semantically_correct": score[
                    "semantically_correct_state"
                ],
                "latency_seconds": round(latency, 3),
            }, ensure_ascii=False))

    rows = [
        json.loads(line)
        for line in run_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    scheduled_ids = {item["schedule_id"] for item in schedule}
    selected_rows, duplicate_records_ignored = (
        _deduplicate_scheduled_rows(rows, scheduled_ids)
    )
    report = {
        "experiment_id": config["experiment_id"],
        "protocol_version": config["protocol_version"],
        "research_effectiveness_result": False,
        "warning": config["warning"],
        "scheduled_runs": len(schedule),
        "completed_runs": len(selected_rows),
        "duplicate_records_ignored": duplicate_records_ignored,
        "executed_this_call": executed,
        "resumed_skips": skipped,
        "model": manifest["model"],
        "independence_groups": len({
            item["independence_group"] for item in selected_rows
        }),
        "summary": summarize(selected_rows),
        "rows": selected_rows,
    }
    (output_dir / "results.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--method", action="append")
    parser.add_argument("--case-id", action="append")
    parser.add_argument("--limit", type=int)
    args = parser.parse_args()
    report = run(
        args.config.resolve(),
        args.output_dir.resolve(),
        method_filter=set(args.method) if args.method else None,
        case_filter=set(args.case_id) if args.case_id else None,
        limit=args.limit,
    )
    print(json.dumps({
        "experiment_id": report["experiment_id"],
        "scheduled_runs": report["scheduled_runs"],
        "completed_runs": report["completed_runs"],
        "executed_this_call": report["executed_this_call"],
        "independence_groups": report["independence_groups"],
        "research_effectiveness_result": False,
        "output": str(args.output_dir.resolve() / "results.json"),
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
