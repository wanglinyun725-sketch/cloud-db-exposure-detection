"""约束路径搜索：基于类型转移矩阵的 DFS"""
import networkx as nx
from typing import Optional
from src.graph.path_utils import EvidencePath, edge_aware_path_key

# 类型转移矩阵：哪些边类型可以连续出现
# 正则: can_connect+ owns? can_assume* has_permission contains* classified_as?
VALID_EDGE_TRANSITIONS = {
    "can_connect": {"can_connect", "can_assume", "has_permission", "owns", "contains", "classified_as"},
    "can_assume": {"can_assume", "has_permission"},
    "has_permission": {"contains", "classified_as", "accessed"},
    "contains": {"contains", "classified_as"},
    "classified_as": set(),  # 终结
    "accessed": {"triggered", "has_risk"},
    "triggered": set(),
    "has_risk": set(),
    "owns": {"can_connect", "can_assume", "has_permission", "owns", "contains", "classified_as"},
    "protected_by": set(),
}

# 路径必须包含的边类型
REQUIRED_EDGE_TYPES = {"can_connect", "has_permission"}


def constrained_dfs(
    G: nx.MultiDiGraph,
    entry_nodes: list,
    target_nodes: list,
    min_depth: int = 4,
    max_depth: int = 8,
) -> list:
    """约束 DFS 搜索候选暴露路径
    
    Args:
        G: CDB-RG 图
        entry_nodes: 入口节点列表
        target_nodes: 目标节点列表
        min_depth: 最小路径长度（边数）
        max_depth: 最大路径长度（边数）
        
    Returns:
        list of list: 候选路径列表，每条路径是节点 ID 列表
    """
    target_set = set(target_nodes)
    all_paths = []
    
    for start in entry_nodes:
        # DFS stack: (current_node, path, last_edge_type, visited_set)
        stack = [(start, EvidencePath([start]), None, {start})]
        
        while stack:
            current, path, prev_edge_type, visited = stack.pop()
            num_edges = len(path) - 1
            
            # 检查是否到达目标
            if current in target_set and min_depth <= num_edges <= max_depth:
                if _is_valid_path(path.edge_types):
                    all_paths.append(path)
            
            # 深度限制
            if num_edges >= max_depth:
                continue
            
            # 扩展邻居
            for _, neighbor, edge_key, edge_data in G.edges(current, keys=True, data=True):
                if neighbor in visited:
                    continue
                
                edge_type = edge_data.get("edge_type", "")
                
                # 类型转移矩阵剪枝
                if prev_edge_type is not None:
                    valid_next = VALID_EDGE_TRANSITIONS.get(prev_edge_type, set())
                    if edge_type not in valid_next:
                        continue
                
                stack.append((
                    neighbor,
                    path.extended(neighbor, edge_key, edge_type),
                    edge_type,
                    visited | {neighbor}
                ))
    
    return _dedup_paths(all_paths)


def _get_edge_type_sequence(G: nx.MultiDiGraph, path: list) -> list:
    """获取路径的边类型序列"""
    if getattr(path, "edge_types", None):
        return list(path.edge_types)
    types = []
    for i in range(len(path) - 1):
        src, dst = path[i], path[i + 1]
        edge_data = G.get_edge_data(src, dst)
        if edge_data:
            # MultiDiGraph 返回 dict of dict
            for key, data in edge_data.items():
                types.append(data.get("edge_type", ""))
                break
    return types


def _is_valid_path(edge_types: list) -> bool:
    """检查路径是否包含必需的边类型"""
    type_set = set(edge_types)
    return REQUIRED_EDGE_TYPES.issubset(type_set)


def _dedup_paths(paths: list) -> list:
    """去重：去除重复路径和子路径"""
    seen = set()
    result = []
    # 按长度排序，优先保留短路径
    paths.sort(key=len)
    for p in paths:
        key = edge_aware_path_key(p)
        if key not in seen:
            seen.add(key)
            result.append(p)
    return result
