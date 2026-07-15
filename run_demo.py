#!/usr/bin/env python3
"""
EIC-Agent 端到端演示程序
─────────────────────────
面向云数据库高敏数据暴露路径侦测的证据约束智能体

运行: python run_demo.py
"""
import sys
import json
import time
from pathlib import Path

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))

from src.graph.graph_builder import build_graph, get_entry_nodes, get_target_nodes, load_samples, print_graph_summary
from src.graph.constrained_search import constrained_dfs
from src.graph.gate_score import compute_evidence_vector, gate_score, evaluate_path, load_config
from src.agent.agent_graph import run_linear, run_graph, build_agent_graph, HAS_LANGGRAPH


# ════════════════════════════════════════════════
# 输出格式化
# ════════════════════════════════════════════════
def banner(title: str, char: str = "═", width: int = 60):
    print(f"\n{char * width}")
    print(f"  {title}")
    print(f"{char * width}")


def sub_banner(title: str):
    print(f"\n{'─' * 50}")
    print(f"  {title}")
    print(f"{'─' * 50}")


def color_type(path_type: str) -> str:
    """给路径类型加颜色标记"""
    icons = {
        "Observed_Risk": "🔴",
        "Potential_Exposure": "🟡",
        "Low_Risk": "🟢",
        "Insufficient_Evidence": "⚪",
    }
    return f"{icons.get(path_type, '❓')} {path_type}"


def print_evidence_bar(ev: dict):
    """可视化证据向量"""
    dims = {"entry": "入口暴露", "reach": "网络可达", "perm": "权限授予",
            "target": "目标价值", "sense": "敏感确认"}
    for k, label in dims.items():
        v = ev.get(k, 0)
        filled = int(v * 20)
        bar = "█" * filled + "░" * (20 - filled)
        print(f"    {label}: {bar} {v:.3f}")


# ════════════════════════════════════════════════
# 单样本分析
# ════════════════════════════════════════════════
def analyze_sample(sample: dict, config: dict, use_langgraph: bool = False):
    """对单个样本运行完整 EIC-Agent Agent循环分析"""
    results = run_graph(sample, config)

    # 额外输出: 与 gold_path 对比
    gold_paths = sample.get("gold_paths", [])
    expected_type = sample.get("expected_type", "?")

    if gold_paths and results:
        best_match = 0
        for r in results:
            if r.get("gate_result", {}).get("gate", 0) == 0:
                continue
            for gp in gold_paths:
                # 计算节点重叠率
                overlap = len(set(r["path"]) & set(gp)) / max(len(gp), 1)
                best_match = max(best_match, overlap)
        if best_match > 0:
            print(f"\n  📍 Gold路径覆盖率: {best_match:.0%}")

    return results


# ════════════════════════════════════════════════
# 主程序
# ════════════════════════════════════════════════
def main():
    banner("EIC-Agent 端到端演示", "═")
    print("  面向云数据库高敏数据暴露路径侦测的证据约束智能体方法")
    print(f"  {'─' * 50}")

    # 加载配置
    config = load_config()
    print(f"\n  ✅ 配置加载完成")
    print(f"     Gate阈值: entry={config['gate_thresholds']['entry']}, "
          f"reach={config['gate_thresholds']['reach']}, "
          f"perm={config['gate_thresholds']['perm']}")
    print(f"     Score权重: {config['score_weights']}")
    print(f"     风险等级: high≥{config['risk_levels']['high']}, "
          f"medium≥{config['risk_levels']['medium']}")

    # 加载样本
    samples_path = ROOT / "data" / "verification_set" / "samples_v2.json"
    samples = load_samples(str(samples_path))
    print(f"\n  ✅ 验证样本加载: {len(samples)} 个场景")
    for s in samples:
        print(f"     [{s['scenario']}] {s['sample_id']} — {s['scenario_name']}")

    # 检查 LLM
    from src.agent.agent_graph import get_llm_client
    client = get_llm_client()
    llm_mode = "Qwen API (DashScope)" if client else "确定性逻辑 (无 LLM)"
    print(f"\n  ✅ 运行模式: {llm_mode}")

    # 检查 LangGraph
    if HAS_LANGGRAPH:
        print(f"  ✅ LangGraph: 可用 (状态机模式)")
    else:
        print(f"  ⚠️  LangGraph: 不可用 (线性执行模式)")

    # ─── 逐样本分析 ───
    all_sample_results = {}
    total_start = time.time()

    for i, sample in enumerate(samples):
        sub_banner(f"样本 {i+1}/{len(samples)}: [{sample['scenario']}] {sample['sample_id']}")
        print(f"  场景: {sample['scenario_name']}")
        print(f"  预期判定: {sample.get('expected_type', '?')}")

        start = time.time()
        results = analyze_sample(sample, config)
        elapsed = time.time() - start

        all_sample_results[sample["sample_id"]] = {
            "results": results,
            "expected": sample.get("expected_type", "?"),
            "scenario": sample["scenario"],
            "scenario_name": sample["scenario_name"],
            "elapsed": elapsed,
        }

        # 打印每条路径结果
        if not results:
            print(f"\n  ⚠️  未找到候选暴露路径")
        else:
            print(f"\n  ┌─ 共找到 {len(results)} 条候选路径 ─┐")
            for j, r in enumerate(results):
                gr = r.get("gate_result", {})
                path_type = gr.get("path_type", "N/A")
                score = gr.get("score", 0)
                gate = gr.get("gate", 0)
                ev = gr.get("evidence_vector", {})

                print(f"\n  │ 路径 {j+1}: {' → '.join(r['path'])}")
                print(f"  │   判定: {color_type(path_type)} (Score={score:.4f}, Gate={'通过' if gate else '拦截'})")
                print_evidence_bar(ev)

                if gr.get("blocked_by"):
                    print(f"  │   拦截原因: {', '.join(gr['blocked_by'])}")
                if r.get("attribution"):
                    attr = r["attribution"][:200]
                    print(f"  │   归因: {attr}")
                if r.get("remediation") and gate == 1:
                    print(f"  │   处置建议: {r['remediation'][:200]}")

            print(f"  └{'─' * 40}┘")

        print(f"\n  ⏱  耗时: {elapsed:.2f}s")

    total_elapsed = time.time() - total_start

    # ─── 汇总报告 ───
    banner("汇总报告", "═")
    print(f"\n  {'场景':<6} {'样本':<30} {'预期':<25} {'实际':<25} {'Score':>8} {'匹配'}")
    print(f"  {'─' * 105}")

    type_correct = 0
    type_total = 0
    total_paths_found = 0
    total_risk_paths = 0
    total_gate_blocked = 0

    for sample_id, data in all_sample_results.items():
        results = data["results"]
        expected = data["expected"]
        total_paths_found += len(results)

        if results:
            # 取 Gate 通过且 score 最高的路径
            passed = [r for r in results if r.get("gate_result", {}).get("gate", 0) == 1]
            total_risk_paths += len(passed)
            total_gate_blocked += len(results) - len(passed)

            if passed:
                best = max(passed, key=lambda r: r["gate_result"]["score"])
                actual_type = best["gate_result"]["path_type"]
                best_score = best["gate_result"]["score"]
            else:
                actual_type = "Insufficient_Evidence"
                best_score = 0.0

            match = "✅" if actual_type == expected else "⚠️"
            if actual_type == expected:
                type_correct += 1
            type_total += 1

            print(f"  {data['scenario']:<6} {sample_id:<30} {expected:<25} {actual_type:<25} {best_score:>8.4f} {match}")
        else:
            print(f"  {data['scenario']:<6} {sample_id:<30} {expected:<25} {'No_Path':<25} {'N/A':>8} ⚠️")
            type_total += 1

    accuracy = type_correct / max(type_total, 1)

    print(f"\n  ┌─ 统计 ─────────────────────────────────────────┐")
    print(f"  │  总样本数:            {len(samples):<33}│")
    print(f"  │  发现候选路径总数:    {total_paths_found:<33}│")
    print(f"  │  Gate通过(风险路径):  {total_risk_paths:<33}│")
    print(f"  │  Gate拦截(证据不足):  {total_gate_blocked:<33}│")
    print(f"  │  类型匹配准确率:      {type_correct}/{type_total} = {accuracy:.0%}{'':<24}│")
    print(f"  │  总耗时:              {total_elapsed:.2f}s{'':<28}│")
    print(f"  └{'─' * 52}┘")

    # ─── 关键发现 ───
    banner("关键发现", "═")
    print("""
  1. Gate·Score 机制验证:
     - 硬约束一票否决: entry/reach/perm 任一不达标 → 路径被拦截
     - 加权几何均值: 多维度证据融合为连续 Score

  2. Agent 循环流程:
     ①假设生成(DFS枚举候选路径) → ②证据采集(工具调用查询)
     → ③信念更新(Gate·Score计算) → ④动作决策(剪枝/补证/确认/终止)

  3. 表达-判定分离:
     - LLM 负责调度、解释、建议（环节 2/6/7）
     - Gate·Score 确定性判定（环节 5）不依赖 LLM
     - 保证判定结果可复现、可审计
""")

    # ─── 保存详细结果 ───
    output_dir = ROOT / "output"
    output_dir.mkdir(exist_ok=True)
    output_file = output_dir / "demo_results.json"

    output_data = {}
    for sample_id, data in all_sample_results.items():
        serializable_results = []
        for r in data["results"]:
            serializable_results.append({
                "path": r.get("path", []),
                "evidence_vector": r.get("evidence_vector", {}),
                "gate_result": r.get("gate_result", {}),
                "attribution": r.get("attribution", ""),
                "remediation": r.get("remediation", ""),
            })
        output_data[sample_id] = {
            "expected": data["expected"],
            "scenario": data["scenario"],
            "scenario_name": data["scenario_name"],
            "elapsed": data["elapsed"],
            "results": serializable_results,
        }

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(output_data, f, ensure_ascii=False, indent=2)
    print(f"  📁 详细结果已保存: {output_file}")
    print()


if __name__ == "__main__":
    main()
