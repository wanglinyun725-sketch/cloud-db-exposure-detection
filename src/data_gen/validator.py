"""
CloudDB-PathBench SHACL 约束校验器
────────────────────────────────────
14 条结构性校验规则，确保生成样本的质量。

使用: python -m src.data_gen.validator data/pathbench_60.json
"""
import json
import sys
from pathlib import Path
from collections import Counter

from src.graph.evidence_semantics import validate_semantic_attrs

VALID_NODE_TYPES = {"Network", "Identity", "DBInstance", "DBObject", "SensitiveTag", "AuditEvent", "RiskFinding", "Control"}
VALID_EDGE_TYPES = {"can_connect", "can_assume", "has_permission", "contains", "classified_as", "accessed", "triggered", "has_risk", "owns", "protected_by"}
VALID_EXPECTED_TYPES = {"Observed_Risk", "Potential_Exposure", "Insufficient_Evidence", "Low_Risk", "Refuted", "Invalid_Path"}
REQUIRED_EDGE_TYPES_IN_PATH = {"can_connect", "has_permission"}


def validate_sample(sample: dict, idx: int) -> list:
    """对单个样本执行 14 条 SHACL 约束检查，返回违规列表"""
    violations = []
    sid = sample.get("sample_id", f"sample_{idx}")
    nodes = {n["id"]: n for n in sample.get("nodes", [])}
    edges = sample.get("edges", [])

    # ─── R1: sample_id 非空 ───
    if not sample.get("sample_id"):
        violations.append(f"[R1] sample_id 缺失")

    # ─── R2: scenario 非空 ───
    sc = sample.get("scenario", "")
    if not sc:
        violations.append(f"[R2] scenario 缺失")

    # ─── R3: 节点类型必须合法 ───
    for n in sample.get("nodes", []):
        if n["type"] not in VALID_NODE_TYPES:
            violations.append(f"[R3] 节点 {n['id']} 类型 '{n['type']}' 不合法")

    # ─── R4: 边类型必须合法 ───
    for e in edges:
        if e["type"] not in VALID_EDGE_TYPES:
            violations.append(f"[R4] 边 {e['source']}→{e['target']} 类型 '{e['type']}' 不合法")

    # ─── R5: 边的 source/target 必须引用已定义的节点 ───
    node_ids = set(nodes.keys())
    for e in edges:
        if e["source"] not in node_ids:
            violations.append(f"[R5] 边 source '{e['source']}' 未在 nodes 中定义")
        if e["target"] not in node_ids:
            violations.append(f"[R5] 边 target '{e['target']}' 未在 nodes 中定义")

    # ─── R6: 边的 strength ∈ [0, 1] ───
    for e in edges:
        s = e.get("attrs", {}).get("strength")
        if s is not None and (s < 0 or s > 1):
            violations.append(f"[R6] 边 {e['source']}→{e['target']} strength={s} 不在 [0,1]")

    # ─── R7: SensitiveTag 的 level ∈ {1,2,3,4} ───
    for n in sample.get("nodes", []):
        if n["type"] == "SensitiveTag":
            level = n.get("attrs", {}).get("level", 0)
            if level not in {1, 2, 3, 4}:
                violations.append(f"[R7] SensitiveTag {n['id']} level={level} 不在 {{1,2,3,4}}")

    # ─── R8: SensitiveTag 的 confidence ∈ [0, 1] ───
    for n in sample.get("nodes", []):
        if n["type"] == "SensitiveTag":
            conf = n.get("attrs", {}).get("confidence", 0)
            if conf < 0 or conf > 1:
                violations.append(f"[R8] SensitiveTag {n['id']} confidence={conf} 不在 [0,1]")

    # ─── R9: 必须存在至少一个入口节点 ───
    has_entry = any(
        (n["type"] == "Network" and n.get("attrs", {}).get("public_exposed"))
        or (n["type"] == "Identity" and n.get("attrs", {}).get("is_external"))
        for n in sample.get("nodes", [])
    )
    if not has_entry:
        violations.append(f"[R9] 无入口节点（需 public_exposed Network 或 is_external Identity）")

    # ─── R10: 必须存在至少一个高敏目标节点 ───
    has_target = any(
        n["type"] == "SensitiveTag" and n.get("attrs", {}).get("level", 0) >= 3
        for n in sample.get("nodes", [])
    )
    if not has_target:
        violations.append(f"[R10] 无高敏目标节点（需 SensitiveTag level >= 3）")

    # ─── R11: 必须有路径标注或状态标注 ───
    gold = sample.get("gold_paths", [])
    if not gold and not sample.get("expected_state"):
        violations.append(f"[R11] gold_paths 为空且 expected_state 缺失")

    # ─── R12: gold_path 中的节点必须存在于 nodes 中 ───
    for gp in gold:
        for node_id in gp:
            if node_id not in node_ids:
                violations.append(f"[R12] gold_path 中的节点 '{node_id}' 未在 nodes 中定义")

    # ─── R13: expected_type 必须合法 ───
    et = sample.get("expected_type", "")
    if et not in VALID_EXPECTED_TYPES:
        violations.append(f"[R13] expected_type='{et}' 不合法")

    # ─── R14: 每条边必须有 evidence_ref ───
    for e in edges:
        if not e.get("attrs", {}).get("evidence_ref"):
            violations.append(f"[R14] 边 {e['source']}→{e['target']} 缺少 evidence_ref")

    # ─── R15: 可选证据语义字段必须合法 ───
    for e in edges:
        for msg in validate_semantic_attrs(e["type"], e.get("attrs", {})):
            violations.append(f"[R15] 边 {e['source']}→{e['target']} {msg}")

    return violations


def validate_dataset(filepath: str) -> dict:
    """校验整个数据集"""
    with open(filepath, "r", encoding="utf-8") as f:
        samples = json.load(f)
    if isinstance(samples, dict):
        samples = [samples]

    total = len(samples)
    passed = 0
    failed = 0
    all_violations = []
    rule_counts = Counter()

    for i, s in enumerate(samples):
        vs = validate_sample(s, i)
        if vs:
            failed += 1
            all_violations.append((s.get("sample_id", f"#{i}"), vs))
            for v in vs:
                rule = v.split("]")[0] + "]"
                rule_counts[rule] += 1
        else:
            passed += 1

    return {
        "total": total,
        "passed": passed,
        "failed": failed,
        "pass_rate": round(passed / max(total, 1), 4),
        "violations_by_rule": dict(rule_counts),
        "sample_violations": all_violations,
    }


if __name__ == "__main__":
    filepath = sys.argv[1] if len(sys.argv) > 1 else "data/pathbench_60.json"
    filepath = str(Path(__file__).parent.parent.parent / filepath)

    result = validate_dataset(filepath)

    print(f"\n{'═' * 50}")
    print(f"  SHACL 约束校验报告")
    print(f"{'═' * 50}")
    print(f"  总样本数:   {result['total']}")
    print(f"  通过:       {result['passed']}")
    print(f"  不通过:     {result['failed']}")
    print(f"  通过率:     {result['pass_rate']:.0%}")

    if result["violations_by_rule"]:
        print(f"\n  违规统计:")
        for rule, count in sorted(result["violations_by_rule"].items()):
            print(f"    {rule}: {count} 次")

    if result["sample_violations"]:
        print(f"\n  失败样本详情 (前 5 个):")
        for sid, vs in result["sample_violations"][:5]:
            print(f"    {sid}:")
            for v in vs:
                print(f"      - {v}")

    print()
