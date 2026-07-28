#!/usr/bin/env python3
"""Build dataset_v1 with deterministic group-level splits."""
from __future__ import annotations

import copy
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).parent.parent
INPUT_CORPUS = ROOT / "output" / "semantic_corpus" / "cloud_db_semantic_corpus.json"
OUT_DIR = ROOT / "output" / "dataset_v1"
OUT_CORPUS = OUT_DIR / "dataset_v1_corpus.json"
OUT_MANIFEST = OUT_DIR / "dataset_v1_manifest.json"
OUT_README = OUT_DIR / "dataset_v1_readme.md"
VARIANT_SUFFIXES = (":missing", ":refuted", ":temporal_conflict")
SPLIT_ORDER = ("dev", "validation", "test", "hard_test")


def main() -> None:
    samples = json.loads(INPUT_CORPUS.read_text(encoding="utf-8"))
    groups = _group_samples(samples)
    group_splits = _assign_group_splits(groups)
    enriched = []
    for sample in samples:
        item = copy.deepcopy(sample)
        group_id = _group_id(sample)
        split = group_splits[group_id]
        item["base_id"] = group_id
        item["group_id"] = group_id
        item["source_dataset"] = item.get("raw_dataset") or _source_from_sample_id(item.get("sample_id", ""))
        item["variant_type"] = item.get("variant_type") or _variant_from_sample_id(item.get("sample_id", ""))
        item["split"] = split
        item["evaluation_role"] = _evaluation_role(split)
        enriched.append(item)

    manifest = _build_manifest(enriched, groups, group_splits)
    _assert_no_group_leakage(enriched)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    OUT_CORPUS.write_text(json.dumps(enriched, ensure_ascii=False, indent=2), encoding="utf-8")
    OUT_MANIFEST.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    OUT_README.write_text(_readme(manifest), encoding="utf-8")

    print(f"wrote {OUT_CORPUS}")
    print(f"wrote {OUT_MANIFEST}")
    print(f"wrote {OUT_README}")
    print(json.dumps({"samples_total": manifest["samples_total"], "split_counts": manifest["split_counts"]}, ensure_ascii=False, indent=2))


def _group_samples(samples: list[dict]) -> dict[str, list[dict]]:
    groups: dict[str, list[dict]] = defaultdict(list)
    for sample in samples:
        groups[_group_id(sample)].append(sample)
    return dict(groups)


def _group_id(sample: dict) -> str:
    sample_id = sample.get("sample_id", "")
    for suffix in VARIANT_SUFFIXES:
        if sample_id.endswith(suffix):
            return sample_id[: -len(suffix)]
    return sample_id


def _variant_from_sample_id(sample_id: str) -> str:
    for suffix in VARIANT_SUFFIXES:
        if sample_id.endswith(suffix):
            return suffix[1:]
    return "base"


def _source_from_sample_id(sample_id: str) -> str:
    if ":" not in sample_id:
        return "unknown"
    parts = sample_id.split(":")
    if len(parts) >= 2:
        return ":".join(parts[:-1])
    return "unknown"


def _assign_group_splits(groups: dict[str, list[dict]]) -> dict[str, str]:
    variant_groups = [gid for gid, items in groups.items() if any((item.get("variant_type") or _variant_from_sample_id(item.get("sample_id", ""))) != "base" for item in items)]
    hard_count = max(1, round(len(variant_groups) * 0.15)) if variant_groups else 0
    hard_groups = set(sorted(variant_groups, key=_stable_rank)[:hard_count])

    remaining = [gid for gid in sorted(groups, key=_stable_rank) if gid not in hard_groups]
    validation_count = round(len(remaining) * 0.20)
    test_count = round(len(remaining) * 0.20)
    validation_groups = set(remaining[:validation_count])
    test_groups = set(remaining[validation_count : validation_count + test_count])

    out = {}
    for gid in groups:
        if gid in hard_groups:
            out[gid] = "hard_test"
        elif gid in validation_groups:
            out[gid] = "validation"
        elif gid in test_groups:
            out[gid] = "test"
        else:
            out[gid] = "dev"
    return out


def _stable_rank(value: str) -> int:
    return int(hashlib.sha256(value.encode("utf-8")).hexdigest()[:16], 16)


def _evaluation_role(split: str) -> str:
    return {
        "dev": "development_only",
        "validation": "parameter_selection",
        "test": "main_test",
        "hard_test": "robustness_test",
    }[split]


def _build_manifest(samples: list[dict], groups: dict[str, list[dict]], group_splits: dict[str, str]) -> dict:
    split_counts = Counter(sample["split"] for sample in samples)
    group_counts = Counter(group_splits.values())
    source_by_split = {split: Counter() for split in SPLIT_ORDER}
    variant_by_split = {split: Counter() for split in SPLIT_ORDER}
    label_by_split = {split: Counter() for split in SPLIT_ORDER}
    path_label_by_split = {split: Counter() for split in SPLIT_ORDER}
    retrieval_by_split = Counter()

    for sample in samples:
        split = sample["split"]
        source_by_split[split][sample.get("source_dataset", "unknown")] += 1
        variant_by_split[split][sample.get("variant_type", "base")] += 1
        label_by_split[split][sample.get("sample_label", sample.get("expected_state", "Unknown"))] += 1
        if any(label.get("state") == "Valid" for label in sample.get("path_labels", [])):
            retrieval_by_split[split] += 1
        for label in sample.get("path_labels", []):
            path_label_by_split[split][label.get("state", "Unknown")] += 1

    manifest = {
        "dataset_version": "dataset_v1",
        "input_corpus": INPUT_CORPUS.relative_to(ROOT).as_posix(),
        "output_corpus": OUT_CORPUS.relative_to(ROOT).as_posix(),
        "samples_total": len(samples),
        "groups_total": len(groups),
        "path_labels_total": sum(len(sample.get("path_labels", [])) for sample in samples),
        "split_counts": _ordered_counter(split_counts),
        "group_counts_by_split": _ordered_counter(group_counts),
        "retrieval_samples_by_split": _ordered_counter(retrieval_by_split),
        "source_counts_by_split": {split: dict(sorted(source_by_split[split].items())) for split in SPLIT_ORDER},
        "variant_counts_by_split": {split: dict(sorted(variant_by_split[split].items())) for split in SPLIT_ORDER},
        "sample_label_counts_by_split": {split: dict(sorted(label_by_split[split].items())) for split in SPLIT_ORDER},
        "path_label_counts_by_split": {split: dict(sorted(path_label_by_split[split].items())) for split in SPLIT_ORDER},
        "split_policy": {
            "unit": "group_id",
            "group_id_rule": "sample_id without :missing/:refuted/:temporal_conflict suffix",
            "hard_test_rule": "15% of variant-bearing groups by deterministic SHA-256 rank",
            "validation_rule": "20% of remaining groups by deterministic SHA-256 rank",
            "test_rule": "next 20% of remaining groups by deterministic SHA-256 rank",
            "dev_rule": "all remaining groups",
        },
        "leakage_check": {
            "groups_crossing_splits": 0,
            "status": "passed",
        },
        "notes": [
            "dataset_v1 is a split view of the current semantic corpus, not a new external benchmark.",
            "path-label consistency is a semantic implementation check, not real-cloud generalization accuracy.",
            "SDDP slices remain case-study evidence slices unless explicitly added to a future external_test split.",
            "Main claims should use test and hard_test, not all-corpus development results.",
        ],
    }
    return manifest


def _ordered_counter(counter: Counter) -> dict[str, int]:
    return {split: int(counter.get(split, 0)) for split in SPLIT_ORDER}


def _assert_no_group_leakage(samples: list[dict]) -> None:
    seen: dict[str, set[str]] = defaultdict(set)
    for sample in samples:
        seen[sample["group_id"]].add(sample["split"])
    leaked = {gid: sorted(splits) for gid, splits in seen.items() if len(splits) > 1}
    if leaked:
        raise SystemExit(f"group split leakage detected: {leaked}")


def _readme(manifest: dict) -> str:
    split_rows = "\n".join(
        f"| {split} | {manifest['split_counts'].get(split, 0)} | {manifest['group_counts_by_split'].get(split, 0)} | {manifest['retrieval_samples_by_split'].get(split, 0)} |"
        for split in SPLIT_ORDER
    )
    return f"""# dataset_v1 说明

`dataset_v1` 是当前 C1/C2 语义语料的可信评估切分版本，用于解决同源样本混用和 all-corpus 自测问题。

## 数据来源

输入语料：`{manifest['input_corpus']}`

该输入语料由 `scripts/build_semantic_corpus.py` 从以下来源生成：

- `data/pathbench_60.json`
- `data/pathbench_cloudgoat.json`
- `data/verification_set/samples_v2.json`

当前 SDDP 文件仍作为 case slice，不进入 `dataset_v1` 主实验。

## 当前规模

| 项目 | 数量 |
|---|---:|
| samples_total | {manifest['samples_total']} |
| groups_total | {manifest['groups_total']} |
| path_labels_total | {manifest['path_labels_total']} |

## split 分布

| split | samples | groups | retrieval samples |
|---|---:|---:|---:|
{split_rows}

## 为什么使用 group split

同一个 base 样本会派生 `missing/refuted/temporal_conflict` 等变体。如果把 base 放到开发集、变体放到测试集，就会出现同源结构泄漏。`dataset_v1` 按 `group_id` 切分，保证同一个 base 及其所有变体只出现在同一个 split。

## 指标边界

- `semantic_consistency_check` 只能说明语义标签和验证器实现是否一致。
- `test` 和 `hard_test` 可作为当前主实验结果来源。
- `dev` 和 `validation` 只用于开发检查和参数选择。
- SDDP 切片目前是案例材料，不是真实攻击 ground truth。
"""


if __name__ == "__main__":
    main()
