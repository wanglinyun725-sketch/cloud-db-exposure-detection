#!/usr/bin/env python3
"""
生成 web_results_v2.json - 在 4 个种子各取 1 个代表案例上运行 EIC-Agent
有 DEEPSEEK_API_KEY 时调用真实 LLM，否则降级为确定性归因/处置
"""
import sys
import json
import time
import io
from pathlib import Path
from contextlib import redirect_stdout

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from src.graph.graph_builder import build_graph, get_entry_nodes, get_target_nodes, load_samples
from src.graph.gate_score import load_config
from src.agent.agent_graph import run_linear

def main():
    # 加载数据
    samples = load_samples(str(ROOT / "data" / "verification_set" / "samples_v2.json"))
    config = load_config()

    # 从 4 个种子各取 1 个代表案例（codebuild / data_secrets / rce_web_app / rds_snapshot）
    REPRESENTATIVE = ["case_001", "case_007", "case_013", "case_019"]
    sample_map = {s["sample_id"]: s for s in samples}
    selected = [sample_map[sid] for sid in REPRESENTATIVE if sid in sample_map]
    print(f"将在 {len(selected)} 个代表案例上运行分析: {REPRESENTATIVE}")

    all_results = {}
    for i, sample in enumerate(selected):
        sid = sample["sample_id"]
        print(f"\n[{i+1}/{len(selected)}] {sid}: {sample['scenario_name']}")

        # 构建图
        G = build_graph(sample)
        node_count = G.number_of_nodes()
        edge_count = G.number_of_edges()
        entries = get_entry_nodes(G)
        targets = get_target_nodes(G)

        # 节点类型统计
        node_types = {}
        for _, d in G.nodes(data=True):
            t = d.get("node_type", "unknown")
            node_types[t] = node_types.get(t, 0) + 1

        # 运行 Agent循环 (确定性模式，无LLM)
        # 抑制 run_linear 的详细打印输出
        buf = io.StringIO()
        start = time.time()
        with redirect_stdout(buf):
            results = run_linear(sample, config)
        elapsed = round(time.time() - start, 2)

        # 序列化结果
        serialized = []
        for r in results:
            serialized.append({
                "path": r.get("path", []),
                "evidence_vector": r.get("evidence_vector", {}),
                "gate_result": r.get("gate_result", {}),
                "attribution": r.get("attribution", ""),
                "remediation": r.get("remediation", ""),
            })

        all_results[sid] = {
            "scenario": sample["scenario"],
            "scenario_name": sample["scenario_name"],
            "industry": sample.get("industry", ""),
            "expected": sample.get("expected_type", ""),
            "elapsed": elapsed,
            "node_count": node_count,
            "edge_count": edge_count,
            "node_types": node_types,
            "entries": entries,
            "targets": targets,
            "results": serialized,
        }

        # 打印摘要
        passed = [r for r in serialized if r.get("gate_result", {}).get("gate", 0) == 1]
        print(f"  节点:{node_count} 边:{edge_count} | 候选路径:{len(serialized)} | Gate通过:{len(passed)} | 耗时:{elapsed}s")
        if passed:
            best = max(passed, key=lambda r: r["gate_result"]["score"])
            print(f"  最佳: {best['gate_result']['path_type']} Score={best['gate_result']['score']}")
            print(f"  路径: {' -> '.join(best['path'])}")

    # 保存
    output_file = ROOT / "output" / "web_results_v2.json"
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(all_results, f, ensure_ascii=False, indent=2)

    print(f"\n✅ 结果已保存: {output_file}")
    print(f"   共 {len(all_results)} 个案例")

    # 汇总
    total_paths = sum(len(v["results"]) for v in all_results.values())
    total_passed = sum(len([r for r in v["results"] if r.get("gate_result", {}).get("gate", 0) == 1]) for v in all_results.values())
    correct = 0
    for sid, v in all_results.items():
        passed = [r for r in v["results"] if r.get("gate_result", {}).get("gate", 0) == 1]
        if passed:
            best = max(passed, key=lambda r: r["gate_result"]["score"])
            if best["gate_result"]["path_type"] == v["expected"]:
                correct += 1
    print(f"\n📊 汇总: {correct}/{len(all_results)} 类型匹配 | {total_paths} 候选路径 | {total_passed} Gate通过")

if __name__ == "__main__":
    main()
