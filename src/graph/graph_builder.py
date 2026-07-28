"""CDB-RG 图构建器：从 JSON 样本构建 NetworkX 有向图"""
import json
import networkx as nx
from typing import Optional

from src.graph.evidence_semantics import normalize_edge_attrs
from src.graph.path_utils import assign_edge_ids


def build_graph(sample: dict) -> nx.MultiDiGraph:
    """从样本 JSON 构建 CDB-RG 图
    
    Args:
        sample: 包含 nodes 和 edges 的样本字典
        
    Returns:
        nx.MultiDiGraph: 带类型属性的有向图
    """
    G = nx.MultiDiGraph()
    G.graph["sample_id"] = sample["sample_id"]
    G.graph["scenario"] = sample.get("scenario", "")
    G.graph["industry"] = sample.get("industry", "")
    
    # 添加节点
    for node in sample["nodes"]:
        node_id = node["id"]
        node_type = node["type"]
        attrs = node.get("attrs", {})
        G.add_node(node_id, node_type=node_type, **attrs)
    
    # 添加边。显式 key 保证搜索、验证和 gold 匹配引用同一条并行边。
    assign_edge_ids(sample)
    for edge in sample["edges"]:
        source = edge["source"]
        target = edge["target"]
        edge_type = edge["type"]
        attrs = normalize_edge_attrs(edge_type, edge.get("attrs", {}))
        edge_id = str(edge["edge_id"])
        G.add_edge(
            source,
            target,
            key=edge_id,
            edge_id=edge_id,
            edge_type=edge_type,
            **attrs,
        )
    
    return G


def get_entry_nodes(G: nx.MultiDiGraph) -> list:
    """获取入口节点：外部可达的 Network 或 Identity"""
    entries = []
    for node, data in G.nodes(data=True):
        ntype = data.get("node_type", "")
        if ntype == "Network" and data.get("public_exposed", False):
            entries.append(node)
        elif ntype == "Identity" and data.get("is_external", False):
            entries.append(node)
    return entries


def get_target_nodes(G: nx.MultiDiGraph, sensitivity_threshold: float = 3.0) -> list:
    """获取高价值目标节点：SensitiveTag 或含高敏字段的 DBObject"""
    targets = []
    for node, data in G.nodes(data=True):
        ntype = data.get("node_type", "")
        if ntype == "SensitiveTag":
            level = data.get("level", 0)
            confidence = data.get("confidence", 1.0)
            if level * confidence >= sensitivity_threshold:
                targets.append(node)
        elif ntype == "DBObject" and data.get("kind") == "field":
            # 检查是否连接到高敏 tag
            for _, target, edge_data in G.edges(node, data=True):
                if edge_data.get("edge_type") == "classified_as":
                    target_data = G.nodes[target]
                    level = target_data.get("level", 0)
                    confidence = target_data.get("confidence", 1.0)
                    if level * confidence >= sensitivity_threshold:
                        targets.append(node)
                        break
    return targets


def load_samples(filepath: str) -> list:
    """加载样本文件"""
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)


def print_graph_summary(G: nx.MultiDiGraph):
    """打印图摘要"""
    type_counts = {}
    for _, data in G.nodes(data=True):
        t = data.get("node_type", "unknown")
        type_counts[t] = type_counts.get(t, 0) + 1
    
    edge_type_counts = {}
    for _, _, data in G.edges(data=True):
        t = data.get("edge_type", "unknown")
        edge_type_counts[t] = edge_type_counts.get(t, 0) + 1
    
    print(f"\n{'='*50}")
    print(f"样本: {G.graph.get('sample_id', '?')} | 场景: {G.graph.get('scenario', '?')}")
    print(f"{'='*50}")
    print(f"节点数: {G.number_of_nodes()} | 边数: {G.number_of_edges()}")
    print(f"节点类型分布: {type_counts}")
    print(f"边类型分布: {edge_type_counts}")
    print(f"入口节点: {get_entry_nodes(G)}")
    print(f"目标节点: {get_target_nodes(G)}")
