"""Run the preflight-gated, resumable EC-ReAct main experiment."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
from typing import Any
import urllib.request

import yaml


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.agent.ec_react import (  # noqa: E402
    OllamaNativeReActPolicy,
    OpenAICompatibleReActPolicy,
)
from src.experiments.ec_react_execution import (  # noqa: E402
    build_run_schedule,
    policy_for_non_llm_method,
    run_frozen_instance,
)
from src.experiments.ec_react_preflight import run_preflight  # noqa: E402


DEFAULT_CONFIG = ROOT / "configs" / "ec_react_main_v1.yaml"
DEFAULT_OUTPUT_DIR = ROOT / "output" / "ec_react_main_v1"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--split", action="append")
    parser.add_argument("--method", action="append")
    parser.add_argument("--model", action="append")
    parser.add_argument("--limit", type=int)
    parser.add_argument(
        "--plan-only",
        action="store_true",
        help="Freeze and report the selected schedule without model calls.",
    )
    args = parser.parse_args()
    if args.limit is not None and args.limit <= 0:
        parser.error("--limit must be positive")

    config_path = args.config.resolve()
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    preflight = run_preflight(
        ROOT,
        config_path,
        selected_method_ids=set(args.method) if args.method else None,
        selected_model_ids=set(args.model) if args.model else None,
    )
    (output_dir / "preflight.json").write_text(
        json.dumps(preflight, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    if not preflight["ready"]:
        print(json.dumps(
            {
                "ready": False,
                "blockers": preflight["blockers"],
                "preflight": str(output_dir / "preflight.json"),
            },
            ensure_ascii=False,
        ))
        return 2

    config_bytes = config_path.read_bytes()
    config_sha = sha256(config_bytes).hexdigest()
    config = yaml.safe_load(config_bytes.decode("utf-8"))
    release_path = Path(preflight["data"]["gold_release"])
    split_path = Path(preflight["data"]["split_manifest"])
    release = json.loads(release_path.read_text(encoding="utf-8"))
    split_manifest = json.loads(split_path.read_text(encoding="utf-8"))
    negative_release_path_value = preflight["data"].get(
        "negative_gold_release"
    )
    negative_release_path = (
        Path(negative_release_path_value)
        if negative_release_path_value
        else None
    )
    negative_release = (
        json.loads(negative_release_path.read_text(encoding="utf-8"))
        if negative_release_path is not None
        else None
    )
    schedule = build_run_schedule(
        config,
        release,
        split_manifest,
        negative_release=negative_release,
        splits=set(args.split) if args.split else None,
        method_ids=set(args.method) if args.method else None,
        model_ids=set(args.model) if args.model else None,
    )
    if args.limit is not None:
        schedule = schedule[:args.limit]
    manifest = {
        "manifest_version": "0.3",
        "experiment_id": config["experiment_id"],
        "config_path": str(config_path),
        "config_sha256": config_sha,
        "path_ontology": preflight["path_ontology"],
        "gold_release_path": str(release_path),
        "gold_release_sha256": _file_hash(release_path),
        "split_manifest_path": str(split_path),
        "split_manifest_sha256": _file_hash(split_path),
        "negative_gold_release_path": (
            str(negative_release_path)
            if negative_release_path is not None
            else None
        ),
        "negative_gold_release_sha256": (
            _file_hash(negative_release_path)
            if negative_release_path is not None
            else None
        ),
        "filters": {
            "splits": args.split,
            "methods": args.method,
            "models": args.model,
            "limit": args.limit,
        },
        "schedule_arms": config.get("schedule_arms"),
        "models": [
            {
                "model_id": item.get("model_id"),
                "client_kind": item.get("client_kind"),
                "default_model": item.get("default_model"),
                "model_env": item.get("model_env"),
                "base_url": item.get("base_url"),
                "base_url_env": item.get("base_url_env"),
                "api_key_required": item.get("api_key_required", True),
                "require_exact_version": item.get(
                    "require_exact_version", False
                ),
                "reasoning_effort": item.get("reasoning_effort"),
                "temperature": item.get("temperature"),
                "think": item.get("think"),
                "num_predict": item.get("num_predict"),
                "num_ctx": item.get("num_ctx"),
                "keep_alive": item.get("keep_alive"),
                "frozen_runtime_digest": item.get(
                    "frozen_runtime_digest"
                ),
            }
            for item in config.get("models", [])
        ],
        "scheduled_runs": len(schedule),
        "schedule": schedule,
        "secrets_in_manifest": False,
    }
    manifest_path = output_dir / "run_manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    if args.plan_only:
        print(json.dumps(
            {
                "ready": True,
                "plan_only": True,
                "scheduled_runs": len(schedule),
                "manifest": str(manifest_path),
            },
            ensure_ascii=False,
        ))
        return 0

    result_path = output_dir / "runs.jsonl"
    completed = _completed_schedule_ids(result_path)
    cases = {item["case_id"]: item for item in release["cases"]}
    if negative_release is not None:
        for item in negative_release.get("cases", []):
            if item["case_id"] in cases:
                raise ValueError(
                    f"duplicate case_id across releases: {item['case_id']}"
                )
            cases[item["case_id"]] = item
    methods = {
        item["method_id"]: item for item in config["methods"]
    }
    models = {
        item["model_id"]: item for item in config.get("models", [])
    }
    shared = config["shared_execution"]
    clients: dict[str, tuple[Any, str, str | None]] = {}
    executed = 0
    skipped = 0
    with result_path.open("a", encoding="utf-8") as stream:
        for row in schedule:
            if row["schedule_id"] in completed:
                skipped += 1
                continue
            method = methods[row["method_id"]]
            if method["family"] == "llm":
                model_config = models[row["model_id"]]
                if row["model_id"] not in clients:
                    clients[row["model_id"]] = _model_client(
                        model_config
                    )
                client, model_name, model_digest = clients[row["model_id"]]
                if model_config.get("client_kind") == "ollama_native":
                    ollama_root = (model_config["base_url"]).rstrip("/")
                    if ollama_root.endswith("/v1"):
                        ollama_root = ollama_root[:-3]
                    policy = OllamaNativeReActPolicy(
                        model_name,
                        base_url=ollama_root,
                        keep_alive=str(
                            model_config.get("keep_alive", "30m")
                        ),
                        num_predict=int(
                            model_config.get("num_predict", 512)
                        ),
                        num_ctx=int(model_config.get("num_ctx", 4096)),
                        seed=row["seed"],
                    )
                else:
                    policy = OpenAICompatibleReActPolicy(
                        client,
                        model_name,
                        temperature=model_config.get("temperature", 0),
                        reasoning_effort=model_config.get(
                            "reasoning_effort"
                        ),
                    )
            else:
                model_name = None
                model_digest = None
                policy = policy_for_non_llm_method(
                    row["method_id"],
                    seed=row["seed"],
                    max_path_candidates=shared[
                        "max_path_candidates"
                    ],
                )
            record = run_frozen_instance(
                cases[row["case_id"]],
                row["instance_id"],
                method=method,
                shared_execution=shared,
                policy=policy,
                budget=row["budget"],
                repeat=row["repeat"],
                seed=row["seed"],
                model_id=row["model_id"],
                model_name=model_name,
                model_digest=model_digest,
                config_sha256=config_sha,
            )
            record["schedule_id"] = row["schedule_id"]
            record["split"] = row["split"]
            stream.write(
                json.dumps(record, ensure_ascii=False) + "\n"
            )
            stream.flush()
            executed += 1
            if executed % 10 == 0:
                print(json.dumps(
                    {
                        "executed": executed,
                        "skipped": skipped,
                        "remaining": len(schedule) - executed - skipped,
                    },
                    ensure_ascii=False,
                ))
    print(json.dumps(
        {
            "ready": True,
            "scheduled_runs": len(schedule),
            "executed": executed,
            "resumed_skips": skipped,
            "results": str(result_path),
            "manifest": str(manifest_path),
        },
        ensure_ascii=False,
    ))
    return 0


def _model_client(
    model: dict[str, Any],
) -> tuple[Any, str, str | None]:
    from openai import OpenAI

    key_name = model.get("api_key_env")
    key_required = model.get("api_key_required", True) is True
    api_key = os.getenv(str(key_name)) if key_name else None
    if key_required and not api_key:
        raise RuntimeError(f"missing required environment variable {key_name}")
    if not api_key:
        api_key = "local-no-auth"
    model_name = (
        os.getenv(model.get("model_env", ""))
        or model.get("default_model")
    )
    if not model_name:
        raise RuntimeError(
            f"model {model['model_id']} has no frozen model name"
        )
    base_url = (
        os.getenv(model.get("base_url_env", ""))
        if model.get("base_url_env")
        else model.get("base_url")
    )
    model_digest = _verify_frozen_runtime_digest(
        model,
        model_name,
        base_url,
    )
    if model.get("require_exact_version") is True:
        expected_model = model.get("default_model")
        if model_name != expected_model:
            raise RuntimeError(
                f"model {model['model_id']} exact version mismatch: "
                f"expected {expected_model}, got {model_name}"
            )
    if model.get("client_kind") == "ollama_native":
        return None, model_name, model_digest
    client = OpenAI(
        api_key=api_key,
        **({"base_url": base_url} if base_url else {}),
    )
    return client, model_name, model_digest


def _verify_frozen_runtime_digest(
    model: dict[str, Any],
    model_name: str,
    base_url: str | None,
) -> str | None:
    expected = model.get("frozen_runtime_digest")
    if not expected:
        if model.get("require_runtime_digest") is True:
            raise RuntimeError(
                f"model {model['model_id']} requires a frozen runtime digest"
            )
        return None
    if not base_url:
        raise RuntimeError(
            f"model {model['model_id']} cannot verify digest without base URL"
        )
    ollama_root = base_url.rstrip("/")
    if ollama_root.endswith("/v1"):
        ollama_root = ollama_root[:-3]
    with urllib.request.urlopen(
        ollama_root + "/api/tags",
        timeout=10,
    ) as response:
        payload = json.loads(response.read().decode("utf-8"))
    actual = next(
        (
            item.get("digest")
            for item in payload.get("models", [])
            if item.get("name") == model_name
            or item.get("model") == model_name
        ),
        None,
    )
    if actual != expected:
        raise RuntimeError(
            f"model {model['model_id']} digest mismatch: "
            f"expected {expected}, got {actual}"
        )
    return actual


def _completed_schedule_ids(path: Path) -> set[str]:
    if not path.is_file():
        return set()
    completed = set()
    for line_number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(),
        start=1,
    ):
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"invalid JSONL at {path}:{line_number}"
            ) from exc
        schedule_id = item.get("schedule_id")
        if not isinstance(schedule_id, str):
            raise ValueError(
                f"missing schedule_id at {path}:{line_number}"
            )
        completed.add(schedule_id)
    return completed


def _file_hash(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


if __name__ == "__main__":
    sys.exit(main())
