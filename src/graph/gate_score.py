"""EIC Gate·Score 判定引擎（含 Observed-EIC 审计衰减扩展）"""
import math
import yaml
from typing import Optional
from pathlib import Path
from datetime import datetime, timezone
from src.graph.path_utils import get_path_edge

CONFIG_PATH = Path(__file__).parent.parent.parent / "configs" / "thresholds.yaml"


def load_config(path: str = None) -> dict:
    p = path or CONFIG_PATH
    with open(p, encoding="utf-8") as f:
        return yaml.safe_load(f)


def compute_evidence_vector(G, path: list) -> dict:
    """从图上计算路径的五维证据向量
    
    Args:
        G: CDB-RG 图
        path: 节点 ID 列表
        
    Returns:
        dict: {entry, reach, perm, target, sense} 五维证据值
    """
    eps = {"entry": 0.0, "reach": 1.0, "perm": 1.0, "target": 0.0, "sense": 0.0}
    
    if not path or len(path) < 2:
        return eps
    
    # --- entry: 入口暴露 ---
    start = path[0]
    start_data = G.nodes.get(start, {})
    if start_data.get("public_exposed", False):
        eps["entry"] = 1.0
    elif start_data.get("is_external", False):
        eps["entry"] = 0.9
    elif start_data.get("node_type") in ("Network", "Identity"):
        eps["entry"] = 0.5
    
    # --- reach: 网络可达（乘积聚合） ---
    reach_product = 1.0
    has_reach_edge = False
    for i in range(len(path) - 1):
        edge_data = get_path_edge(G, path, i)
        if edge_data and edge_data.get("edge_type") == "can_connect":
            reach_product *= edge_data.get("strength", 0.5)
            has_reach_edge = True
    eps["reach"] = reach_product if has_reach_edge else 0.1
    
    # --- perm: 权限授予（最小值） ---
    perm_min = 1.0
    has_perm = False
    for i in range(len(path) - 1):
        edge_data = get_path_edge(G, path, i)
        if edge_data and edge_data.get("edge_type") == "has_permission":
            perm_min = min(perm_min, edge_data.get("strength", 0.5))
            has_perm = True
    # 也检查 can_assume 链
    for i in range(len(path) - 1):
        edge_data = get_path_edge(G, path, i)
        if edge_data and edge_data.get("edge_type") == "can_assume":
            perm_min = min(perm_min, edge_data.get("strength", 0.5))
            has_perm = True
    eps["perm"] = perm_min if has_perm else 0.1
    
    # --- target: 目标价值（终点敏感性） ---
    end = path[-1]
    end_data = G.nodes.get(end, {})
    if end_data.get("node_type") == "SensitiveTag":
        level = end_data.get("level", 0)
        confidence = end_data.get("confidence", 1.0)
        eps["target"] = (level * confidence) / 4.0
    elif end_data.get("node_type") == "DBObject":
        # 查找连接的 SensitiveTag
        for _, target, edge_data in G.edges(end, data=True):
            if edge_data.get("edge_type") == "classified_as":
                tag_data = G.nodes.get(target, {})
                level = tag_data.get("level", 0)
                confidence = tag_data.get("confidence", 1.0)
                val = (level * confidence) / 4.0
                eps["target"] = max(eps["target"], val)
    
    # --- sense: 敏感数据确认（max） ---
    for node in path:
        node_data = G.nodes.get(node, {})
        if node_data.get("node_type") == "SensitiveTag":
            level = node_data.get("level", 0)
            confidence = node_data.get("confidence", 1.0)
            val = (level * confidence) / 4.0
            eps["sense"] = max(eps["sense"], val)
    
    # --- Observed-EIC 审计证据时间衰减扩展 ---
    # 当路径中存在审计事件，计算 audit_boost 提升 sense
    audit_config = None
    try:
        full_config = load_config()
        audit_config = full_config.get("audit", {})
    except Exception:
        pass
    
    if audit_config:
        gamma = audit_config.get("gamma", 0.95)
        delta_t_hours = audit_config.get("delta_t_hours", 24)
        tau_audit = audit_config.get("tau_audit", 0.6)
        now = datetime.now(timezone.utc)
        
        max_audit_boost = 0.0
        for node in path:
            node_data = G.nodes.get(node, {})
            if node_data.get("node_type") == "AuditEvent":
                anomaly_score = node_data.get("anomaly_score", 0.0)
                timestamp_str = node_data.get("t", "")
                
                # 计算时间衰减
                decay = 1.0
                if timestamp_str:
                    try:
                        event_time = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
                        if event_time.tzinfo is None:
                            event_time = event_time.replace(tzinfo=timezone.utc)
                        hours_elapsed = (now - event_time).total_seconds() / 3600
                        decay = gamma ** (hours_elapsed / delta_t_hours)
                    except (ValueError, TypeError):
                        decay = 0.5  # 无法解析时间时用默认衰减
                
                audit_boost = anomaly_score * decay
                max_audit_boost = max(max_audit_boost, audit_boost)
        
        # 当 audit_boost > tau_audit 时，提升 sense 维度
        if max_audit_boost > tau_audit:
            # sense 提升为 max(sense, audit_boost)
            eps["sense"] = max(eps["sense"], min(max_audit_boost, 1.0))
    
    return eps


def gate_score(evidence_vector: dict, config: dict = None) -> dict:
    """EIC Gate·Score 判定
    
    Args:
        evidence_vector: {entry, reach, perm, target, sense}
        config: 阈值配置
        
    Returns:
        dict: {gate, score, path_type, blocked_by, details}
    """
    if config is None:
        config = load_config()
    
    tau = config["gate_thresholds"]
    weights = config["score_weights"]
    levels = config["risk_levels"]
    
    eps = evidence_vector
    blocked_by = []
    
    # Gate: 硬约束一票否决
    if eps["entry"] < tau["entry"]:
        blocked_by.append(f"entry({eps['entry']:.2f}<{tau['entry']})")
    if eps["reach"] < tau["reach"]:
        blocked_by.append(f"reach({eps['reach']:.2f}<{tau['reach']})")
    if eps["perm"] < tau["perm"]:
        blocked_by.append(f"perm({eps['perm']:.2f}<{tau['perm']})")
    
    gate = 1 if not blocked_by else 0
    
    # Score: 加权几何均值
    score = 1.0
    for dim in ["entry", "reach", "perm", "target", "sense"]:
        val = max(eps[dim], 1e-6)  # 避免 log(0)
        score *= val ** weights.get(dim, 0.2)
    
    final_score = gate * score
    
    # 路径分类
    if gate == 0:
        path_type = "Insufficient_Evidence"
    elif final_score >= levels["high"]:
        path_type = "Observed_Risk"
    elif final_score >= levels["medium"]:
        path_type = "Potential_Exposure"
    else:
        path_type = "Low_Risk"
    
    return {
        "gate": gate,
        "score": round(final_score, 4),
        "path_type": path_type,
        "blocked_by": blocked_by,
        "evidence_vector": {k: round(v, 4) for k, v in eps.items()},
    }


def evaluate_path(G, path: list, config: dict = None) -> dict:
    """端到端路径评估：计算证据向量 → Gate·Score 判定"""
    ev = compute_evidence_vector(G, path)
    result = gate_score(ev, config)
    result["path"] = path
    result["path_length"] = len(path) - 1
    return result


HARD_DIMS = ["entry", "reach", "perm"]
ALL_DIMS = ["entry", "reach", "perm", "target", "sense", "temporal"]
DIM_EDGE_TYPES = {
    "reach": {"can_connect"},
    "perm": {"has_permission", "can_assume"},
    "target": {"classified_as", "contains"},
    "sense": {"classified_as", "accessed"},
}


def evidence_status(G, path: list, dim: str, config: dict = None) -> str:
    """Return T/F/U for one evidence dimension using semantic evidence status.

    T means visible evidence supports the dimension, F means visible evidence
    explicitly contradicts it, and U means the required evidence is absent or
    unknown in the partial graph. Numeric strength is a risk/severity signal,
    not by itself a refutation.
    """
    if dim == "entry":
        start_data = G.nodes.get(path[0], {}) if path else {}
        if start_data.get("public_exposed", False) or start_data.get("is_external", False):
            return "T"
        return "T" if start_data.get("node_type") in ("Network", "Identity") else "U"

    if dim == "perm" and not _permission_applicable(G, path):
        return "T"

    if dim == "temporal":
        return _temporal_status(G, path)

    if dim in ("target", "sense"):
        return _target_status(G, path)

    statuses = []
    edge_types = DIM_EDGE_TYPES.get(dim, set())
    for i in range(len(path) - 1):
        edge_data = get_path_edge(G, path, i)
        if edge_data and edge_data.get("edge_type") in edge_types:
            statuses.append(edge_data.get("status", "Supported"))
    if "Contradicted" in statuses:
        return "F"
    if "Unknown" in statuses:
        return "U"
    if "Supported" in statuses:
        return "T"
    return "U"


def _permission_applicable(G, path: list) -> bool:
    if any(G.nodes.get(node, {}).get("node_type") == "Identity" for node in path):
        return True
    for i in range(len(path) - 1):
        edge_data = get_path_edge(G, path, i)
        if edge_data and edge_data.get("edge_type") in {"has_permission", "can_assume"}:
            return True
    return False


def _target_status(G, path: list) -> str:
    statuses = []
    for node in path:
        if G.nodes.get(node, {}).get("node_type") == "SensitiveTag":
            return "T"
    for i in range(len(path) - 1):
        edge_data = get_path_edge(G, path, i)
        if edge_data and edge_data.get("edge_type") == "classified_as":
            statuses.append(edge_data.get("status", "Supported"))
    end = path[-1] if path else None
    if end:
        for _, target, edge_data in G.edges(end, data=True):
            if edge_data.get("edge_type") == "classified_as":
                statuses.append(edge_data.get("status", "Supported"))
    if "Contradicted" in statuses:
        return "F"
    if "Supported" in statuses:
        return "T"
    if "Unknown" in statuses:
        return "U"
    return "U"


def _temporal_status(G, path: list) -> str:
    saw_edge = False
    for i in range(len(path) - 1):
        edge_data = get_path_edge(G, path, i)
        if not edge_data:
            continue
        saw_edge = True
        if edge_data.get("temporal_conflict"):
            return "F"
        timestamp = edge_data.get("time") or edge_data.get("observed_at") or edge_data.get("t")
        if not timestamp or _parse_time(timestamp) is None:
            return "U"
    return "T" if saw_edge else "U"


def _parse_time(value):
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def verify_path(G, path: list, config: dict = None) -> dict:
    """Classify a path as Valid, Invalid, or Insufficient using T/F/U evidence."""
    statuses = {dim: evidence_status(G, path, dim, config) for dim in ALL_DIMS}
    if any(status == "F" for status in statuses.values()):
        state = "Invalid"
    elif any(status == "U" for status in statuses.values()):
        state = "Insufficient"
    else:
        state = "Valid"
    return {
        "state": state,
        "statuses": statuses,
        "missing": [dim for dim, status in statuses.items() if status == "U"],
        "refuted": [dim for dim, status in statuses.items() if status == "F"],
    }


def _dim_threshold(dim: str, config: dict) -> float:
    if dim in config.get("gate_thresholds", {}):
        return config["gate_thresholds"][dim]
    return 1e-6


def _dim_evidence_present(G, path: list, dim: str) -> bool:
    if not path:
        return False
    if dim == "entry":
        node_data = G.nodes.get(path[0], {})
        return node_data.get("node_type") in ("Network", "Identity")
    if dim in ("target", "sense"):
        if any(G.nodes.get(node, {}).get("node_type") == "SensitiveTag" for node in path):
            return True
    edge_types = DIM_EDGE_TYPES.get(dim, set())
    for i in range(len(path) - 1):
        edge_data = get_path_edge(G, path, i)
        if edge_data and edge_data.get("edge_type") in edge_types:
            if edge_data.get("status") == "Unknown":
                continue
            return True
    return False


# ════════════════════════════════════════════════
# 逐维证据计算（支持"逐维查 + 当场判 + 不达标即停"）
# ════════════════════════════════════════════════
def compute_one_dimension(G, path: list, dim: str) -> float:
    """只计算某一个维度的证据值（与 compute_evidence_vector 逻辑一致）。

    用于 agent 的逐维探索：查一维、判一维，硬维度不达标即可提前终止，
    无需一次性把五维全算出来。

    Args:
        G: CDB-RG 图
        path: 节点 ID 列表
        dim: 维度名，取 entry / reach / perm / target / sense 之一
    Returns:
        float: 该维度的证据值
    """
    if not path or len(path) < 2:
        defaults = {"entry": 0.0, "reach": 1.0, "perm": 1.0, "target": 0.0, "sense": 0.0}
        return defaults.get(dim, 0.0)

    if dim == "entry":
        start_data = G.nodes.get(path[0], {})
        if start_data.get("public_exposed", False):
            return 1.0
        if start_data.get("is_external", False):
            return 0.9
        if start_data.get("node_type") in ("Network", "Identity"):
            return 0.5
        return 0.0

    if dim == "reach":
        reach_product = 1.0
        has_reach_edge = False
        for i in range(len(path) - 1):
            edge_data = get_path_edge(G, path, i)
            if edge_data and edge_data.get("edge_type") == "can_connect":
                reach_product *= edge_data.get("strength", 0.5)
                has_reach_edge = True
        return reach_product if has_reach_edge else 0.1

    if dim == "perm":
        perm_min = 1.0
        has_perm = False
        for i in range(len(path) - 1):
            edge_data = get_path_edge(G, path, i)
            if edge_data and edge_data.get("edge_type") in ("has_permission", "can_assume"):
                perm_min = min(perm_min, edge_data.get("strength", 0.5))
                has_perm = True
        return perm_min if has_perm else 0.1

    if dim == "target":
        end_data = G.nodes.get(path[-1], {})
        if end_data.get("node_type") == "SensitiveTag":
            return (end_data.get("level", 0) * end_data.get("confidence", 1.0)) / 4.0
        val = 0.0
        if end_data.get("node_type") == "DBObject":
            for _, target, edge_data in G.edges(path[-1], data=True):
                if edge_data.get("edge_type") == "classified_as":
                    tag_data = G.nodes.get(target, {})
                    v = (tag_data.get("level", 0) * tag_data.get("confidence", 1.0)) / 4.0
                    val = max(val, v)
        return val

    if dim == "sense":
        val = 0.0
        for node in path:
            node_data = G.nodes.get(node, {})
            if node_data.get("node_type") == "SensitiveTag":
                v = (node_data.get("level", 0) * node_data.get("confidence", 1.0)) / 4.0
                val = max(val, v)
        return val

    return 0.0


def _get_edge(G, src, dst) -> Optional[dict]:
    """获取边数据"""
    data = G.get_edge_data(src, dst)
    if data:
        for key, val in data.items():
            return val
    return None
