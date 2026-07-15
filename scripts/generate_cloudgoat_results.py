#!/usr/bin/env python3
"""
generate_cloudgoat_results.py — 在 CloudGoat 种子数据集上跑 EIC-Agent，产出 web 看板数据

读取 data/pathbench_cloudgoat.json（真实靶场种子合成的样本），逐个跑 run_linear，
序列化为 showcase 看板所需的 web_results 格式，输出到独立文件（不覆盖 web_results_v2）。

输出:
  output/web_results_cloudgoat.json   —— 看板结果（含 results/gate/归因等）
  data/verification_set/samples_cloudgoat.json —— 看板所需的图结构副本
"""
import sys
import json
import time
import io
from pathlib import Path
from contextlib import redirect_stdout

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from src.graph.graph_builder import build_graph, get_entry_nodes, get_target_nodes
from src.graph.gate_score import load_config
from src.agent.agent_graph import run_linear

DATASET = ROOT / "data" / "pathbench_cloudgoat.json"
RESULTS_OUT = ROOT / "output" / "web_results_cloudgoat.json"
SAMPLES_OUT = ROOT / "data" / "verification_set" / "samples_cloudgoat.json"

SIGNAL_BY_SEED = {
    "rds_snapshot": {"type": "public_db_exposure", "entity": "cg-rds-db_instance"},
    "rce_web_app": {"type": "web_rce_to_db", "entity": "web_app"},
    "vpc_peering_overexposed": {"type": "public_db_exposure", "entity": "customer_db"},
    "data_secrets": {"type": "user_data_leak", "entity": "sensitive_lambda"},
    "secrets_in_the_cloud": {"type": "user_data_leak", "entity": "secrets_manager_user"},
}


def main():
    samples = json.loads(DATASET.read_text(encoding="utf-8"))
    config = load_config()
    print(f"在 {len(samples)} 个 CloudGoat 种子样本上运行 EIC-Agent")

    all_results = {}
    samples_out = []
    for i, sample in enumerate(samples):
        sid = sample["sample_id"]
        seed = sample.get("scenario_name", "").replace("[CloudGoat] ", "")

        G = build_graph(sample)
        node_count = G.number_of_nodes()
        edge_count = G.number_of_edges()
        entries = get_entry_nodes(G)
        targets = get_target_nodes(G)
        node_types = {}
        for _, d in G.nodes(data=True):
            t = d.get("node_type", "unknown")
            node_types[t] = node_types.get(t, 0) + 1

        buf = io.StringIO()
        start = time.time()
        with redirect_stdout(buf):
            results = run_linear(sample, config)
        elapsed = round(time.time() - start, 2)

        serialized = [{
            "path": r.get("path", []),
            "evidence_vector": r.get("evidence_vector", {}),
            "gate_result": r.get("gate_result", {}),
            "attribution": r.get("attribution", ""),
            "remediation": r.get("remediation", ""),
        } for r in results]

        # 无候选路径时的显式诊断（避免静默空白）
        no_path_reason = ""
        if not serialized:
            import networkx as nx
            connected = False
            for e in entries:
                for t in targets:
                    try:
                        if nx.has_path(G, e, t):
                            connected = True
                            break
                    except Exception:
                        pass
                if connected:
                    break
            if not connected:
                no_path_reason = "图不连通：入口与敏感目标之间无物理路径（种子数据链路缺失）"
            else:
                no_path_reason = "约束搜索在深度/类型约束下未找到合法路径"

        all_results[sid] = {
            "scenario": sample.get("scenario", ""),
            "scenario_name": sample.get("scenario_name", ""),
            "industry": sample.get("industry", ""),
            "expected": sample.get("expected_type", ""),
            "elapsed": elapsed,
            "node_count": node_count,
            "edge_count": edge_count,
            "node_types": node_types,
            "entries": entries,
            "targets": targets,
            "results": serialized,
            "no_path_reason": no_path_reason,
        }

        # 看板 samples 副本：补 initial_signal（看板右栏用）
        s_copy = dict(sample)
        s_copy.setdefault("initial_signal", SIGNAL_BY_SEED.get(seed, {"type": seed, "entity": ""}))
        samples_out.append(s_copy)

        passed = [r for r in serialized if r.get("gate_result", {}).get("gate", 0) == 1]
        blocked = [r for r in serialized if r.get("gate_result", {}).get("gate", 0) == 0]
        print(f"  [{i+1}/{len(samples)}] {sid} [{seed}] 期望={sample.get('expected_type')} | 路径{len(serialized)} 通过{len(passed)}/拦截{len(blocked)}")

    RESULTS_OUT.parent.mkdir(parents=True, exist_ok=True)
    SAMPLES_OUT.parent.mkdir(parents=True, exist_ok=True)
    RESULTS_OUT.write_text(json.dumps(all_results, ensure_ascii=False, indent=2), encoding="utf-8")
    SAMPLES_OUT.write_text(json.dumps(samples_out, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"\n✅ 看板结果已保存: {RESULTS_OUT}")
    print(f"✅ 看板图结构已保存: {SAMPLES_OUT}")
    print(f"   共 {len(all_results)} 个案例")


if __name__ == "__main__":
    main()
