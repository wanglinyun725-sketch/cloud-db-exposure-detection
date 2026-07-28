#!/usr/bin/env python3
"""Experiments on the C1 semantic corpus for C2 refute-aware search."""
import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

from src.eval.metrics import summarize_path_ranking
from src.graph.constrained_search import constrained_dfs, VALID_EDGE_TRANSITIONS
from src.graph.gate_score import compute_evidence_vector, gate_score, load_config, verify_path
from src.graph.graph_builder import build_graph, get_entry_nodes, get_target_nodes
from src.graph.path_utils import EvidencePath, edge_aware_path_key, path_from_label, path_query_cost
from src.graph.refute_aware_search import refute_aware_beam_search

DATA = os.path.join(ROOT, "output", "semantic_corpus", "cloud_db_semantic_corpus.json")
OUT = os.path.join(ROOT, "output", "semantic_corpus", "semantic_experiments_results.json")
CFG = load_config()
MIN_D = CFG["search"]["min_depth"]
MAX_D = CFG["search"]["max_depth"]


def load_samples():
    with open(DATA, encoding="utf-8") as f:
        return json.load(f)


def plain_dfs(G, entries, targets, max_depth=MAX_D):
    out = []
    tset = set(targets)
    expanded = 0
    for start in entries:
        stack = [(start, EvidencePath([start]), None, {start})]
        while stack:
            cur, path, last_edge, visited = stack.pop()
            if cur in tset and MIN_D <= len(path) - 1 <= max_depth:
                out.append(path)
            if len(path) - 1 >= max_depth:
                continue
            edges = list(G.edges(cur, keys=True, data=True))
            expanded += len(edges)
            for _, nb, edge_key, ed in edges:
                if nb in visited:
                    continue
                stack.append((
                    nb,
                    path.extended(nb, edge_key, ed.get("edge_type", "")),
                    ed.get("edge_type", ""),
                    visited | {nb},
                ))
    return {"paths": _dedup(out), "expanded_edges": expanded, "generated_paths": len(out), "completed_paths": len(out)}


def type_dfs(G, entries, targets, max_depth=MAX_D):
    out = []
    tset = set(targets)
    expanded = 0
    for start in entries:
        stack = [(start, EvidencePath([start]), None, {start})]
        while stack:
            cur, path, last_edge, visited = stack.pop()
            if cur in tset and MIN_D <= len(path) - 1 <= max_depth:
                out.append(path)
            if len(path) - 1 >= max_depth:
                continue
            edges = list(G.edges(cur, keys=True, data=True))
            expanded += len(edges)
            for _, nb, edge_key, ed in edges:
                if nb in visited:
                    continue
                et = ed.get("edge_type", "")
                if last_edge is not None and et not in VALID_EDGE_TRANSITIONS.get(last_edge, set()):
                    continue
                stack.append((nb, path.extended(nb, edge_key, et), et, visited | {nb}))
    return {"paths": _dedup(out), "expanded_edges": expanded, "generated_paths": len(out), "completed_paths": len(out)}


def full_constrained(G, entries, targets):
    t0 = time.perf_counter()
    paths = constrained_dfs(G, entries, targets, min_depth=MIN_D, max_depth=MAX_D)
    return {"paths": paths, "expanded_edges": None, "generated_paths": len(paths), "completed_paths": len(paths), "time_s": time.perf_counter() - t0}


def rank_by_gatescore(G, paths):
    return sorted(paths, key=lambda p: _gatescore_key(G, p), reverse=True)


def _gatescore_key(G, path):
    result = gate_score(compute_evidence_vector(G, path), CFG)
    return (result["gate"], result["score"], -len(path))


def evaluate_method(samples, name, runner, ranker=None):
    rows = []
    sample_rows = []
    state_counts = {}
    sample_false_positive = 0
    non_valid_samples = 0
    retrieval_n = 0
    sample_eval_n = 0
    expanded_total = 0
    generated_total = 0
    completed_total = 0
    top_query_cost_total = 0
    runtime = 0.0
    for sample in samples:
        G = build_graph(sample)
        entries, targets = get_entry_nodes(G), get_target_nodes(G)
        if not entries or not targets:
            continue
        t0 = time.perf_counter()
        result = runner(G, entries, targets)
        runtime += time.perf_counter() - t0
        paths = result["paths"]
        ranked = ranker(G, paths) if ranker else paths
        valid_gold = _labeled_paths(sample, "Valid")
        if valid_gold:
            metrics = summarize_path_ranking(ranked, valid_gold)
            rows.append(metrics)
            sample_rows.append({"sample_id": sample["sample_id"], **metrics})
            retrieval_n += 1
        sample_eval_n += 1
        if result.get("expanded_edges") is not None:
            expanded_total += result["expanded_edges"]
        generated_total += result.get("generated_paths", 0)
        completed_total += result.get("completed_paths", len(paths))
        if ranked:
            top_state = verify_path(G, ranked[0], CFG)["state"]
            state_counts[top_state] = state_counts.get(top_state, 0) + 1
            top_query_cost_total += _path_query_cost(G, ranked[0])
            if sample.get("sample_label") != "Valid":
                non_valid_samples += 1
                if top_state == "Valid":
                    sample_false_positive += 1
    return _pack(
        name,
        rows,
        sample_rows,
        retrieval_n,
        sample_eval_n,
        expanded_total,
        generated_total,
        completed_total,
        top_query_cost_total,
        state_counts,
        sample_false_positive,
        non_valid_samples,
        runtime,
    )


def evaluate_path_labels(samples):
    counts = {"total": 0, "correct": 0, "by_expected": {}, "confusion": {}}
    for sample in samples:
        labels = sample.get("path_labels", [])
        if not labels:
            continue
        G = build_graph(sample)
        for label in labels:
            expected = label.get("state")
            got = verify_path(G, path_from_label(label), CFG)["state"]
            counts["total"] += 1
            counts["correct"] += int(got == expected)
            counts["by_expected"][expected] = counts["by_expected"].get(expected, 0) + 1
            key = f"{expected}->{got}"
            counts["confusion"][key] = counts["confusion"].get(key, 0) + 1
    counts["accuracy"] = round(counts["correct"] / max(counts["total"], 1), 4)
    return counts


def _labeled_paths(sample, state):
    return [
        path_from_label(label)
        for label in sample.get("path_labels", [])
        if label.get("state") == state and label.get("path")
    ]


def _pack(name, rows, sample_rows, retrieval_n, sample_eval_n, expanded, generated, completed, top_cost, states, fp, non_valid_samples, runtime):
    out = {"method": name, "n_retrieval_samples": retrieval_n, "n_sample_eval": sample_eval_n}
    if rows:
        for key in rows[0].keys():
            out[key] = round(sum(row[key] for row in rows) / len(rows), 4)
    out.update({
        "avg_expanded_edges": round(expanded / max(sample_eval_n, 1), 3),
        "avg_generated_paths": round(generated / max(sample_eval_n, 1), 3),
        "avg_completed_paths": round(completed / max(sample_eval_n, 1), 3),
        "avg_top_query_cost": round(top_cost / max(sample_eval_n, 1), 3),
        "top_state_counts": states,
        "non_valid_samples": non_valid_samples,
        "sample_false_positive_rate": round(fp / max(non_valid_samples, 1), 4),
        "time_s": round(runtime, 4),
        # 统计检验必须使用同一样本上的成对指标，不能从聚合均值伪造样本。
        "sample_metrics": sample_rows,
    })
    return out


def _path_query_cost(G, path):
    return path_query_cost(G, path)


def _dedup(paths):
    seen = set()
    out = []
    for path in paths:
        key = edge_aware_path_key(path)
        if key not in seen:
            seen.add(key)
            out.append(path)
    return out


def main():
    samples = load_samples()
    methods = {
        "plain_dfs_gatescore": (lambda G, e, t: plain_dfs(G, e, t), rank_by_gatescore),
        "type_dfs_gatescore": (lambda G, e, t: type_dfs(G, e, t), rank_by_gatescore),
        "full_constrained_gatescore": (lambda G, e, t: full_constrained(G, e, t), rank_by_gatescore),
        # 与生产实现的默认参数保持一致；参数敏感性另由消融实验报告。
        "refute_aware_beam": (lambda G, e, t: refute_aware_beam_search(G, e, t, MIN_D, MAX_D, beam_width=4, top_k=20), None),
    }
    results = {
        "dataset": os.path.relpath(DATA, ROOT).replace("\\", "/"),
        "n_samples": len(samples),
        "path_label_verification": evaluate_path_labels(samples),
        "methods": {},
    }
    print(f"semantic corpus samples={len(samples)}")
    print("path-label verifier", results["path_label_verification"])
    for name, (runner, ranker) in methods.items():
        res = evaluate_method(samples, name, runner, ranker)
        results["methods"][name] = res
        console_res = {key: value for key, value in res.items() if key != "sample_metrics"}
        print(name, json.dumps(console_res, ensure_ascii=False))
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
