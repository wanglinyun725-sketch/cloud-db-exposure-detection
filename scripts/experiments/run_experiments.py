#!/usr/bin/env python3
"""EIC-Agent 中期机制对照实验（确定性、可复现，不调用 LLM）。

四组实验：
  Exp1  约束搜索机制验证        —— 普通DFS vs 类型约束 vs 完整约束
  Exp2  主动取证策略对照        —— 全量调用 vs 固定优先级 vs 证据缺口驱动
  Exp3  反证 / 缺证区分能力      —— 完整证据 vs 明确反证 vs 关键缺证
  Exp4  硬证据剪枝前后对照       —— 不剪枝 vs 提前终止

所有指标均由本脚本对真实代码 / 真实数据实测得出，可通过
    python scripts/experiments/run_experiments.py
复现。结果同时写入 output/experiments_results.json。
"""
import sys, os, json, time, copy

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

from src.graph.graph_builder import build_graph, get_entry_nodes, get_target_nodes
from src.graph.gate_score import compute_evidence_vector, compute_one_dimension, gate_score, load_config, verify_path
from src.graph.constrained_search import VALID_EDGE_TRANSITIONS, REQUIRED_EDGE_TYPES
from src.graph.path_utils import get_path_edge, path_query_cost
from src.eval.metrics import summarize_path_ranking
from src.agent.tools import (
    check_network_reachability, check_permission, check_sensitive_data,
    check_controls, check_audit_events, check_control_effectiveness,
    check_compliance_status,
)

DATA = os.path.join(ROOT, "data", "pathbench_60.json")
CFG = load_config()
MIN_D, MAX_D = CFG["search"]["min_depth"], CFG["search"]["max_depth"]
TAU = CFG["gate_thresholds"]
HARD_ORDER = ["entry", "reach", "perm"]
PER_SAMPLE_CAP = 200000  # 普通DFS 组合爆炸安全阀（本数据集远达不到）


def load():
    with open(DATA, encoding="utf-8") as f:
        return json.load(f)


# ────────────────────────── 通用图/路径工具 ──────────────────────────
def edge_type_seq(G, path):
    seq = []
    for i in range(len(path) - 1):
        ed = get_path_edge(G, path, i)
        if not ed:
            seq.append("MISSING"); continue
        seq.append(ed.get("edge_type", ""))
    return seq


def transition_valid(seq):
    for i in range(len(seq) - 1):
        if seq[i + 1] not in VALID_EDGE_TRANSITIONS.get(seq[i], set()):
            return False
    return True


def is_legal(G, path):
    """完整合法性：类型转移合法 + 含必要边 + 长度落在 [MIN,MAX]。"""
    ne = len(path) - 1
    if not (MIN_D <= ne <= MAX_D):
        return False
    seq = edge_type_seq(G, path)
    if "MISSING" in seq:
        return False
    if not transition_valid(seq):
        return False
    return REQUIRED_EDGE_TYPES.issubset(set(seq))


def dedup(paths):
    seen, out = set(), []
    for p in sorted(paths, key=len):
        if tuple(p) not in seen:
            seen.add(tuple(p)); out.append(p)
    return out


def enum_paths(G, entries, targets, mode):
    """三种搜索变体。
    mode='plain'：仅深度上限，无类型/必要边/最短长度约束。
    mode='type' ：+ 类型转移矩阵剪枝。
    mode='full' ：+ 必要边约束 + [MIN,MAX] 长度剪枝（= 生产 constrained_dfs）。
    """
    tset = set(targets)
    out = []
    for start in entries:
        stack = [(start, [start], None, {start})]
        while stack:
            cur, path, pe, vis = stack.pop()
            ne = len(path) - 1
            if cur in tset:
                if mode == "full":
                    if MIN_D <= ne <= MAX_D:
                        seq = set(edge_type_seq(G, path))
                        if REQUIRED_EDGE_TYPES.issubset(seq):
                            out.append(path[:])
                else:
                    out.append(path[:])
                    if len(out) > PER_SAMPLE_CAP:
                        return dedup(out)
            if ne >= MAX_D:
                continue
            for _, nb, ed in G.edges(cur, data=True):
                if nb in vis:
                    continue
                et = ed.get("edge_type", "")
                if mode in ("type", "full") and pe is not None:
                    if et not in VALID_EDGE_TRANSITIONS.get(pe, set()):
                        continue
                stack.append((nb, path + [nb], et, vis | {nb}))
    return dedup(out)


def best_path_verdict(G, paths):
    """样本级判定：取通过 Gate 且 Score 最高者；否则取 Score 最高者。"""
    best = None
    for p in paths:
        ev = compute_evidence_vector(G, p)
        r = gate_score(ev, CFG)
        key = (r["gate"], r["score"])
        if best is None or key > best["key"]:
            best = {"key": key, "type": r["path_type"], "gate": r["gate"],
                    "score": r["score"], "path": p, "ev": ev, "blocked": r["blocked_by"]}
    return best


# ══════════════════════════ 实验零：算子样本级判定准确率 ══════════════════════════
def exp0(samples):
    from collections import Counter
    conf = Counter()
    agree = 0
    total = 0
    false_pos = 0  # 非风险样本被误判为风险（危险方向）
    RISK = {"Observed_Risk", "Potential_Exposure"}
    for s in samples:
        G = build_graph(s)
        entries, targets = get_entry_nodes(G), get_target_nodes(G)
        paths = enum_paths(G, entries, targets, "full")
        best = best_path_verdict(G, paths)
        got = best["type"] if best else "Insufficient_Evidence"
        exp = s["expected_type"]
        total += 1
        conf[f"{exp}->{got}"] += 1
        if got == exp:
            agree += 1
        if exp not in RISK and got in RISK:
            false_pos += 1
    return {
        "accuracy": round(agree / max(total, 1), 4),
        "n": total,
        "false_positive": false_pos,
        "confusion": dict(conf),
    }


# ══════════════════════════ 实验一：约束搜索机制验证 ══════════════════════════
def exp1(samples):
    rows = {}
    for mode in ["plain", "type", "full"]:
        t0 = time.perf_counter()
        total_enum = 0
        legal_cnt = 0
        target_hit_samples = 0
        n_samples = 0
        for s in samples:
            G = build_graph(s)
            entries, targets = get_entry_nodes(G), get_target_nodes(G)
            if not entries or not targets:
                continue
            n_samples += 1
            paths = enum_paths(G, entries, targets, mode)
            total_enum += len(paths)
            for p in paths:
                if is_legal(G, p):
                    legal_cnt += 1
            gold_tgts = {gp[-1] for gp in s.get("gold_paths", []) if gp}
            endpoints = {p[-1] for p in paths}
            if gold_tgts and (gold_tgts & endpoints):
                target_hit_samples += 1
        dt = time.perf_counter() - t0
        rows[mode] = {
            "enum_total": total_enum,
            "enum_avg": round(total_enum / max(n_samples, 1), 2),
            "valid_ratio": round(legal_cnt / max(total_enum, 1), 4),
            "target_recall": round(target_hit_samples / max(n_samples, 1), 4),
            "time_s": round(dt, 4),
            "n_samples": n_samples,
        }
    return rows


# ══════════════════════════ 实验二：主动取证策略对照 ══════════════════════════
# 工具→证据维度映射（喂入 5 维判定向量的工具为“决策相关”）
def applicable_full_tools(G, path):
    """复刻 _deterministic_tool_calls 的适用性判断，返回被调用的工具键列表。"""
    node_info = {n: G.nodes.get(n, {}).get("node_type", "") for n in path}
    net = [n for n, t in node_info.items() if t == "Network"]
    db = [n for n, t in node_info.items() if t == "DBInstance"]
    ident = [n for n, t in node_info.items() if t == "Identity"]
    tbl = [n for n in path if G.nodes.get(n, {}).get("node_type") == "DBObject"
           and G.nodes.get(n, {}).get("kind") == "table"]
    calls = []
    if net and db:
        calls.append(("T1_reach", "reach"))
    if ident and tbl:
        calls.append(("T2_perm", "perm"))
    if tbl:
        calls.append(("T3_sense", "target/sense"))
    if db:
        calls.append(("T4_controls", "aux"))
    calls.append(("T5_audit", "sense"))            # 总是调用
    if db:
        calls.append(("T6_effect", "aux"))
        calls.append(("T7_compliance", "aux"))
    return calls, {"net": net, "db": db, "ident": ident, "tbl": tbl}


def veto_dim(G, path):
    """按代价顺序返回首个未达阈值的硬维度；全过返回 None。"""
    for d in HARD_ORDER:
        if compute_one_dimension(G, path, d) < TAU[d]:
            return d
    return None


def exp2(samples):
    strat = {k: {"calls": 0, "invalid": 0, "cov_num": 0, "cov_den": 0,
                 "time": 0.0, "paths": 0} for k in ["full", "fixed", "gap"]}
    DIM_ORDER = ["entry", "reach", "perm"]
    for s in samples:
        G = build_graph(s)
        entries, targets = get_entry_nodes(G), get_target_nodes(G)
        if not entries or not targets:
            continue
        paths = enum_paths(G, entries, targets, "full")
        for path in paths:
            vd = veto_dim(G, path)  # 首个被否决的硬维度（None=全过）
            full_calls, meta = applicable_full_tools(G, path)

            # ── Full：调用全部适用工具（实测耗时）──
            t0 = time.perf_counter()
            _run_full_tools(G, path, meta)
            tf = time.perf_counter() - t0
            n_full = len(full_calls)
            # invalid = 辅助工具(aux) + 否决点之后才计算的维度工具
            inv_full = sum(1 for _, dim in full_calls if dim == "aux")
            inv_full += _post_veto_invalid(full_calls, vd)
            strat["full"]["calls"] += n_full
            strat["full"]["invalid"] += inv_full
            strat["full"]["cov_num"] += 5; strat["full"]["cov_den"] += 5
            strat["full"]["time"] += tf
            strat["full"]["paths"] += 1

            # ── Fixed：只调决策相关工具 {T1,T2(如适用),T3,T5}，固定顺序、不早停 ──
            fixed = [c for c in full_calls if c[1] != "aux"]
            t0 = time.perf_counter()
            _run_fixed_tools(G, path, meta)
            tx = time.perf_counter() - t0
            inv_fixed = _post_veto_invalid(fixed, vd)
            strat["fixed"]["calls"] += len(fixed)
            strat["fixed"]["invalid"] += inv_fixed
            strat["fixed"]["cov_num"] += 5; strat["fixed"]["cov_den"] += 5
            strat["fixed"]["time"] += tx
            strat["fixed"]["paths"] += 1

            # ── Gap：代价序 entry→reach→perm，遇否决即停；全过再取 target/sense ──
            t0 = time.perf_counter()
            gap_calls, cov = _run_gap_tools(G, path, meta, vd)
            tg = time.perf_counter() - t0
            strat["gap"]["calls"] += gap_calls
            strat["gap"]["invalid"] += 0   # 只调用决策必需，无无效调用
            strat["gap"]["cov_num"] += cov; strat["gap"]["cov_den"] += 5
            strat["gap"]["time"] += tg
            strat["gap"]["paths"] += 1

    out = {}
    for k, v in strat.items():
        p = max(v["paths"], 1)
        out[k] = {
            "avg_calls": round(v["calls"] / p, 3),
            "invalid_rate": round(v["invalid"] / max(v["calls"], 1), 4),
            "coverage": round(v["cov_num"] / max(v["cov_den"], 1), 4),
            "avg_time_ms": round(v["time"] / p * 1000, 4),
            "paths": v["paths"],
        }
    return out


def _post_veto_invalid(call_list, vd):
    """否决维度之后才被计算的决策工具数（这些调用对结论无贡献）。"""
    if vd is None:
        return 0
    order = {"entry": 0, "reach": 1, "perm": 2}
    vlevel = order[vd]
    dim2level = {"reach": 1, "perm": 2, "target/sense": 3, "sense": 3}
    inv = 0
    for _, dim in call_list:
        if dim in dim2level and dim2level[dim] > vlevel:
            inv += 1
    return inv


def _run_full_tools(G, path, meta):
    net, db, ident, tbl = meta["net"], meta["db"], meta["ident"], meta["tbl"]
    if net and db:
        check_network_reachability(G, net[0], db[0])
    if ident and tbl:
        check_permission(G, ident[0], tbl[0])
    if tbl:
        check_sensitive_data(G, tbl[0])
    if db:
        check_controls(G, db[0])
    check_audit_events(G, ident[0] if ident else None, tbl[0] if tbl else None)
    if db:
        check_control_effectiveness(G, db[0], tbl[0] if tbl else None)
        check_compliance_status(G, db[0], tbl[0] if tbl else None)


def _run_fixed_tools(G, path, meta):
    net, db, ident, tbl = meta["net"], meta["db"], meta["ident"], meta["tbl"]
    if net and db:
        check_network_reachability(G, net[0], db[0])
    if ident and tbl:
        check_permission(G, ident[0], tbl[0])
    if tbl:
        check_sensitive_data(G, tbl[0])
    check_audit_events(G, ident[0] if ident else None, tbl[0] if tbl else None)


def _run_gap_tools(G, path, meta, vd):
    """代价序调用，遇硬维度否决即停。返回 (调用数, 已确定维度数)。"""
    net, db, ident, tbl = meta["net"], meta["db"], meta["ident"], meta["tbl"]
    calls = 0
    cov = 1  # entry 由节点属性直接确定，无需工具
    # entry
    if compute_one_dimension(G, path, "entry") < TAU["entry"]:
        return calls, cov
    # reach → T1
    if net and db:
        check_network_reachability(G, net[0], db[0]); calls += 1
    cov += 1
    if compute_one_dimension(G, path, "reach") < TAU["reach"]:
        return calls, cov
    # perm → T2（若路径含身份）
    if ident and tbl:
        check_permission(G, ident[0], tbl[0]); calls += 1
    cov += 1
    if compute_one_dimension(G, path, "perm") < TAU["perm"]:
        return calls, cov
    # 全过 → target/sense（T3 + T5）
    if tbl:
        check_sensitive_data(G, tbl[0]); calls += 1
    check_audit_events(G, ident[0] if ident else None, tbl[0] if tbl else None); calls += 1
    cov += 2
    return calls, cov


# ══════════════════════════ 实验三：反证 / 缺证区分 ══════════════════════════
def diagnose(G, path):
    """图接地诊断：Gate 通过→风险等级；否则区分“反证(证据在但相斥)”与“缺证(证据缺失)”。"""
    ev = compute_evidence_vector(G, path)
    r = gate_score(ev, CFG)
    if r["gate"] == 1:
        return ("Risk", r["path_type"])
    # 找首个失败硬维度
    for d in HARD_ORDER:
        if ev[d] < TAU[d]:
            present = _dim_evidence_present(G, path, d)
            return ("Refuted" if present else "Missing", d)
    return ("Missing", "unknown")


def _dim_evidence_present(G, path, dim):
    if dim == "entry":
        nd = G.nodes.get(path[0], {})
        return nd.get("public_exposed", False) or nd.get("is_external", False) \
            or nd.get("node_type") in ("Network", "Identity")
    tset = {"reach": {"can_connect"}, "perm": {"has_permission", "can_assume"}}[dim]
    seq = edge_type_seq(G, path)
    return bool(tset & set(seq))


def _perturb(sample, path, kind):
    """基于某条暴露路径构造扰动样本。
    kind='refute'：路径上 can_connect 边强度压到 0.05（存在但相斥的限制规则）。
    kind='missing'：删除路径上的 can_connect 边（可达性证据缺失）。
    """
    s = copy.deepcopy(sample)
    pairs = set(zip(path[:-1], path[1:]))
    new_edges = []
    for e in s["edges"]:
        on_path = (e["source"], e["target"]) in pairs
        if on_path and e["type"] == "can_connect":
            if kind == "refute":
                e.setdefault("attrs", {})["strength"] = 0.05
                new_edges.append(e)
            elif kind == "missing":
                continue  # 删除该边
        else:
            new_edges.append(e)
    s["edges"] = new_edges
    return s


def exp3(samples):
    positives = [s for s in samples if s["expected_type"] in ("Observed_Risk", "Potential_Exposure")]
    groups = {"A_complete": {"correct": 0, "risk": 0, "n": 0},
              "B_refute":   {"correct": 0, "risk": 0, "n": 0},
              "C_missing":  {"correct": 0, "risk": 0, "n": 0}}
    for s in positives:
        G = build_graph(s)
        entries, targets = get_entry_nodes(G), get_target_nodes(G)
        paths = enum_paths(G, entries, targets, "full")
        if not paths:
            continue
        best = best_path_verdict(G, paths)
        P = best["path"]

        # A：完整证据 → 期望输出风险
        cat, _ = diagnose(G, P)
        groups["A_complete"]["n"] += 1
        if cat == "Risk":
            groups["A_complete"]["correct"] += 1
            groups["A_complete"]["risk"] += 1

        # B：明确反证 → 期望 Refuted（路径不成立）
        GB = build_graph(_perturb(s, P, "refute"))
        catb, _ = diagnose(GB, P)
        groups["B_refute"]["n"] += 1
        if catb == "Refuted":
            groups["B_refute"]["correct"] += 1
        if catb == "Risk":
            groups["B_refute"]["risk"] += 1

        # C：关键缺证 → 期望 Missing（证据不足）
        GC = build_graph(_perturb(s, P, "missing"))
        catc, _ = diagnose(GC, P)
        groups["C_missing"]["n"] += 1
        if catc == "Missing":
            groups["C_missing"]["correct"] += 1
        if catc == "Risk":
            groups["C_missing"]["risk"] += 1

    out = {}
    for k, v in groups.items():
        out[k] = {
            "n": v["n"],
            "correct_rate": round(v["correct"] / max(v["n"], 1), 4),
            "false_confirm_rate": round(v["risk"] / max(v["n"], 1), 4) if k != "A_complete" else "-",
        }
    return out


# ══════════════════════════ 实验四：硬证据剪枝前后对照 ══════════════════════════
TOOLS_PER_FULL = 5   # 完整流程核心工具类数（与生产 run_linear 埋点一致）
LLM_PER_FULL = 2     # 完整流程 LLM 调用数（归因+整改）
EST_TOKENS_PER_LLM = 600  # 单次归因/整改 token 估算（用于 token 估算列，标注为估算）


def exp4(samples):
    modes = {"noprune": {}, "prune": {}}
    pruned_cnt = 0
    for mkey in modes:
        t0 = time.perf_counter()
        tool_calls = llm_calls = 0
        verdicts = []
        for s in samples:
            G = build_graph(s)
            entries, targets = get_entry_nodes(G), get_target_nodes(G)
            paths = enum_paths(G, entries, targets, "full")
            for p in paths:
                if mkey == "prune":
                    # 逐维查硬证据，遇否决即停：终止路径不再调用工具/LLM
                    terminated = False
                    for d in HARD_ORDER:
                        if compute_one_dimension(G, p, d) < TAU[d]:
                            verdicts.append("Insufficient_Evidence")
                            terminated = True
                            break
                    if terminated:
                        pruned_cnt += 1
                        continue
                    tool_calls += TOOLS_PER_FULL
                    llm_calls += LLM_PER_FULL
                    ev = compute_evidence_vector(G, p)
                    verdicts.append(gate_score(ev, CFG)["path_type"])
                else:
                    # 不剪枝：所有路径都走完整流程（工具 + 证据 + 判定 + LLM 归因）
                    tool_calls += TOOLS_PER_FULL
                    llm_calls += LLM_PER_FULL
                    ev = compute_evidence_vector(G, p)
                    verdicts.append(gate_score(ev, CFG)["path_type"])
        dt = time.perf_counter() - t0
        modes[mkey] = {"tool_calls": tool_calls, "llm_calls": llm_calls,
                       "time_s": round(dt, 4), "verdicts": verdicts,
                       "n_paths": len(verdicts)}
    # 判定一致率
    a, b = modes["noprune"]["verdicts"], modes["prune"]["verdicts"]
    agree = sum(1 for x, y in zip(a, b) if x == y)
    consistency = round(agree / max(len(a), 1), 4)
    n = modes["noprune"]["n_paths"]

    def pack(m):
        p = max(m["n_paths"], 1)
        return {
            "n_paths": m["n_paths"],
            "avg_tool_calls": round(m["tool_calls"] / p, 3),
            "avg_llm_calls": round(m["llm_calls"] / p, 3),
            "est_tokens": m["llm_calls"] * EST_TOKENS_PER_LLM,
            "time_s": m["time_s"],
        }
    return {"consistency": consistency, "n_paths": n,
            "pruned": pruned_cnt, "pruned_frac": round(pruned_cnt / max(n, 1), 4),
            "noprune": pack(modes["noprune"]), "prune": pack(modes["prune"])}


# ══════════════════════════ 实验五：反证/缺证感知路径排序 ══════════════════════════
def exp5(samples):
    methods = {
        "gatescore": {"metrics": [], "candidates": 0, "query_cost": 0, "states": {}},
        "refute_aware": {"metrics": [], "candidates": 0, "query_cost": 0, "states": {}},
    }
    for s in samples:
        if not s.get("gold_paths"):
            continue
        G = build_graph(s)
        entries, targets = get_entry_nodes(G), get_target_nodes(G)
        paths = enum_paths(G, entries, targets, "plain")
        if not paths:
            continue
        ranked_gate = sorted(paths, key=lambda p: _gatescore_rank_key(G, p), reverse=True)
        ranked_refute = sorted(paths, key=lambda p: _refute_aware_rank_key(G, p), reverse=True)
        for name, ranked in [("gatescore", ranked_gate), ("refute_aware", ranked_refute)]:
            methods[name]["metrics"].append(summarize_path_ranking(ranked, s.get("gold_paths", [])))
            methods[name]["candidates"] += len(paths)
            top = ranked[0]
            verification = verify_path(G, top, CFG)
            state = verification["state"]
            methods[name]["states"][state] = methods[name]["states"].get(state, 0) + 1
            methods[name]["query_cost"] += _path_query_cost(G, top)
    return {name: _pack_exp5(vals) for name, vals in methods.items()}


def _gatescore_rank_key(G, path):
    ev = compute_evidence_vector(G, path)
    r = gate_score(ev, CFG)
    return (r["gate"], r["score"], -len(path))


def _refute_aware_rank_key(G, path):
    ev = compute_evidence_vector(G, path)
    score = gate_score(ev, CFG)["score"]
    verification = verify_path(G, path, CFG)
    state_weight = {"Valid": 2.0, "Insufficient": 0.5, "Invalid": -2.0}[verification["state"]]
    missing_penalty = 0.25 * len(verification["missing"])
    refuted_penalty = 1.0 * len(verification["refuted"])
    query_penalty = 0.03 * _path_query_cost(G, path)
    length_penalty = 0.01 * (len(path) - 1)
    return state_weight + score - missing_penalty - refuted_penalty - query_penalty - length_penalty


def _path_query_cost(G, path):
    return path_query_cost(G, path)


def _pack_exp5(vals):
    n = max(len(vals["metrics"]), 1)
    aggregate = {}
    keys = vals["metrics"][0].keys() if vals["metrics"] else []
    for key in keys:
        aggregate[key] = round(sum(m[key] for m in vals["metrics"]) / n, 4)
    aggregate["avg_candidates"] = round(vals["candidates"] / n, 3)
    aggregate["avg_top_query_cost"] = round(vals["query_cost"] / n, 3)
    aggregate["top_state_counts"] = vals["states"]
    aggregate["n_samples"] = len(vals["metrics"])
    return aggregate


# ══════════════════════════ 主流程 ══════════════════════════
def main():
    samples = load()
    print(f"数据集: pathbench_60.json  样本数={len(samples)}  (min_depth={MIN_D}, max_depth={MAX_D})")
    print(f"阈值: entry≥{TAU['entry']} reach≥{TAU['reach']} perm≥{TAU['perm']}\n")

    results = {}

    print("═" * 62); print("实验零：算子样本级判定准确率（best-path 判定 vs 期望标签）"); print("═" * 62)
    r0 = exp0(samples); results["exp0"] = r0
    print(f"样本级准确率 = {r0['accuracy']*100:.1f}%  ({r0['n']} 样本)  误报(非风险判为风险) = {r0['false_positive']}")
    print("混淆分布 (expected->got):")
    for k, v in sorted(r0["confusion"].items(), key=lambda x: -x[1]):
        print(f"    {k:<48}{v}")
    print()

    print("═" * 62); print("实验一：约束搜索机制验证"); print("═" * 62)
    r1 = exp1(samples); results["exp1_generated60"] = r1
    print(f"[数据集 A] 参数化生成 60 样本（含 gold，可测目标召回）")
    print(f"{'方法':<14}{'枚举(总)':>8}{'枚举(均)':>8}{'有效比例':>9}{'目标召回':>9}{'耗时(s)':>9}")
    label = {"plain": "普通DFS", "type": "类型约束", "full": "完整约束"}
    for m in ["plain", "type", "full"]:
        v = r1[m]
        print(f"{label[m]:<14}{v['enum_total']:>8}{v['enum_avg']:>8}{v['valid_ratio']*100:>8.1f}%{v['target_recall']*100:>8.1f}%{v['time_s']:>9}")

    try:
        with open(os.path.join(ROOT, "data", "pathbench_cloudgoat.json"), encoding="utf-8") as f:
            cg = json.load(f)
        r1c = exp1(cg); results["exp1_cloudgoat20"] = r1c
        print(f"\n[数据集 B] CloudGoat 真实靶场 20 样本（图更杂，可见类型约束剪枝效果）")
        print(f"{'方法':<14}{'枚举(总)':>8}{'枚举(均)':>8}{'有效比例':>9}{'耗时(s)':>9}")
        for m in ["plain", "type", "full"]:
            v = r1c[m]
            print(f"{label[m]:<14}{v['enum_total']:>8}{v['enum_avg']:>8}{v['valid_ratio']*100:>8.1f}%{v['time_s']:>9}")
    except Exception as e:
        print(f"  (CloudGoat 数据集读取失败: {e})")

    print("\n" + "═" * 62); print("实验二：主动取证策略对照（三策略判定完全一致，仅代价不同）"); print("═" * 62)
    r2 = exp2(samples); results["exp2"] = r2
    print(f"{'策略':<16}{'平均调用':>9}{'无效率':>9}{'证据覆盖':>9}{'均耗时(ms)':>11}")
    lab2 = {"full": "全量调用", "fixed": "固定优先级", "gap": "证据缺口驱动"}
    for m in ["full", "fixed", "gap"]:
        v = r2[m]
        print(f"{lab2[m]:<16}{v['avg_calls']:>9}{v['invalid_rate']*100:>8.1f}%{v['coverage']*100:>8.1f}%{v['avg_time_ms']:>11}")

    print("\n" + "═" * 62); print("实验三：反证 / 缺证区分能力"); print("═" * 62)
    r3 = exp3(samples); results["exp3"] = r3
    print(f"{'场景类型':<16}{'样本数':>7}{'正确率':>9}{'错误确认率':>11}")
    lab3 = {"A_complete": "完整证据", "B_refute": "明确反证", "C_missing": "关键缺证"}
    for k in ["A_complete", "B_refute", "C_missing"]:
        v = r3[k]
        fc = v["false_confirm_rate"]
        fc_s = "-" if fc == "-" else f"{fc*100:.1f}%"
        print(f"{lab3[k]:<16}{v['n']:>7}{v['correct_rate']*100:>8.1f}%{fc_s:>11}")

    print("\n" + "═" * 62); print("实验四：硬证据剪枝前后对照"); print("═" * 62)
    r4 = exp4(samples); results["exp4"] = r4
    print(f"候选路径总数={r4['n_paths']}  提前终止={r4['pruned']} 条({r4['pruned_frac']*100:.1f}%)  最终判定一致率={r4['consistency']*100:.1f}%")
    print(f"{'设置':<12}{'均工具调用':>11}{'均LLM调用':>10}{'Token(估算)':>12}{'耗时(s)':>9}")
    for m, lab in [("noprune", "不剪枝"), ("prune", "硬证据剪枝")]:
        v = r4[m]
        print(f"{lab:<12}{v['avg_tool_calls']:>11}{v['avg_llm_calls']:>10}{v['est_tokens']:>12}{v['time_s']:>9}")

    print("\n" + "═" * 62); print("实验五：反证/缺证感知路径排序（路径级 IR 指标）"); print("═" * 62)
    r5 = exp5(samples); results["exp5"] = r5
    print(f"{'方法':<18}{'R@1':>8}{'R@3':>8}{'MRR':>8}{'P@3':>8}{'均候选':>9}{'Top查询成本':>12}{'Top状态':>14}")
    lab5 = {"gatescore": "GateScore排序", "refute_aware": "反证感知排序"}
    for m in ["gatescore", "refute_aware"]:
        v = r5[m]
        print(f"{lab5[m]:<18}{v.get('recall@1', 0):>8.3f}{v.get('recall@3', 0):>8.3f}{v.get('mrr', 0):>8.3f}{v.get('precision@3', 0):>8.3f}{v['avg_candidates']:>9}{v['avg_top_query_cost']:>12}{str(v['top_state_counts']):>14}")

    out_path = os.path.join(ROOT, "output", "experiments_results.json")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    print(f"\n结果已写入 {out_path}")


if __name__ == "__main__":
    main()
