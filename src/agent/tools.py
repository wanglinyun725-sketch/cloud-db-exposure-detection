"""EIC-Agent 证据获取工具集（7 个工具 T1-T7）"""
import networkx as nx
from typing import Optional


def check_network_reachability(G: nx.MultiDiGraph, source: str, target: str) -> dict:
    """工具 T1: 检查网络可达性
    
    检查从 source 到 target 是否存在 can_connect 边链。
    """
    # 查找 source→...→target 的 can_connect 链
    reachability = 1.0
    hops = []
    current = source
    
    # BFS 找最短 can_connect 路径
    visited = {current}
    queue = [(current, [current], 1.0)]
    found = False
    
    while queue:
        node, path, strength = queue.pop(0)
        if node == target:
            hops = path
            reachability = strength
            found = True
            break
        for _, neighbor, edge_data in G.edges(node, data=True):
            if edge_data.get("edge_type") == "can_connect" and neighbor not in visited:
                visited.add(neighbor)
                new_strength = strength * edge_data.get("strength", 0.5)
                queue.append((neighbor, path + [neighbor], new_strength))
    
    return {
        "tool": "NetworkReachability",
        "source": source,
        "target": target,
        "reachable": found,
        "reachability": round(reachability, 4),
        "hops": hops,
        "evidence_ref": f"net_{source}_to_{target}"
    }


def check_permission(G: nx.MultiDiGraph, identity: str, resource: str) -> dict:
    """工具 T2: 检查权限授予
    
    检查 identity 对 resource 的访问权限（含 can_assume 链）。
    """
    # 查找 has_permission 或 can_assume → has_permission
    permissions = []
    max_strength = 0.0
    
    for _, target, edge_data in G.edges(identity, data=True):
        etype = edge_data.get("edge_type", "")
        if etype == "has_permission" and target == resource:
            permissions.append({
                "privilege": edge_data.get("privilege", "unknown"),
                "strength": edge_data.get("strength", 0.5),
                "evidence_ref": edge_data.get("evidence_ref", "")
            })
            max_strength = max(max_strength, edge_data.get("strength", 0.5))
        elif etype == "can_assume":
            # 检查被 assume 的角色是否有权限
            role = target
            for _, role_target, role_edge in G.edges(role, data=True):
                if role_edge.get("edge_type") == "has_permission" and role_target == resource:
                    combined = min(
                        edge_data.get("strength", 0.5),
                        role_edge.get("strength", 0.5)
                    )
                    permissions.append({
                        "privilege": role_edge.get("privilege", "unknown"),
                        "strength": combined,
                        "via_role": role,
                        "evidence_ref": role_edge.get("evidence_ref", "")
                    })
                    max_strength = max(max_strength, combined)
    
    return {
        "tool": "PermissionCheck",
        "identity": identity,
        "resource": resource,
        "has_permission": len(permissions) > 0,
        "max_strength": round(max_strength, 4),
        "permissions": permissions
    }


def check_sensitive_data(G: nx.MultiDiGraph, db_object: str) -> dict:
    """工具 T3: 检查敏感数据
    
    检查 DBObject 是否包含高敏字段。
    """
    sensitive_fields = []
    max_level = 0
    max_confidence = 0.0
    
    # 查找 classified_as 边
    for node in G.nodes():
        node_data = G.nodes.get(node, {})
        if node_data.get("node_type") == "DBObject" and node_data.get("kind") == "field":
            # 检查是否是 db_object 的后代
            if _is_descendant(G, db_object, node):
                for _, target, edge_data in G.edges(node, data=True):
                    if edge_data.get("edge_type") == "classified_as":
                        tag_data = G.nodes.get(target, {})
                        level = tag_data.get("level", 0)
                        confidence = tag_data.get("confidence", 1.0)
                        sensitive_fields.append({
                            "field": node,
                            "tag": target,
                            "category": tag_data.get("category", ""),
                            "level": level,
                            "confidence": confidence,
                            "score": round(level * confidence, 2),
                            "evidence_ref": edge_data.get("evidence_ref", "")
                        })
                        max_level = max(max_level, level)
                        max_confidence = max(max_confidence, confidence)
    
    return {
        "tool": "SensitiveDataCheck",
        "db_object": db_object,
        "has_sensitive": len(sensitive_fields) > 0,
        "max_level": max_level,
        "max_confidence": round(max_confidence, 4),
        "sensitive_fields": sensitive_fields,
        "count": len(sensitive_fields)
    }


def check_controls(G: nx.MultiDiGraph, instance: str) -> dict:
    """工具 T4: 检查安全控制项
    
    检查 DBInstance 的安全控制状态（TDE、Audit、Backup 等）。
    """
    controls = []
    
    for _, target, edge_data in G.edges(instance, data=True):
        if edge_data.get("edge_type") == "protected_by":
            ctrl_data = G.nodes.get(target, {})
            controls.append({
                "control_id": target,
                "kind": ctrl_data.get("kind", "unknown"),
                "enabled": ctrl_data.get("enabled", False),
                "scope": ctrl_data.get("scope", ""),
                "evidence_ref": edge_data.get("evidence_ref", "")
            })
    
    # 计算防护覆盖率
    kinds_enabled = {c["kind"] for c in controls if c["enabled"]}
    kinds_total = {c["kind"] for c in controls}
    
    return {
        "tool": "ControlCheck",
        "instance": instance,
        "controls": controls,
        "protection_coverage": round(len(kinds_enabled) / max(len(kinds_total), 1), 2),
        "tde_enabled": any(c["kind"] == "TDE" and c["enabled"] for c in controls),
        "audit_enabled": any(c["kind"] == "Audit" and c["enabled"] for c in controls),
        "unprotected_kinds": list(kinds_total - kinds_enabled)
    }


def check_audit_events(G: nx.MultiDiGraph, identity: str = None, resource: str = None) -> dict:
    """工具 T5: 检查审计事件
    
    查询与 identity/resource 相关的异常审计事件。
    """
    events = []
    
    for node, data in G.nodes(data=True):
        if data.get("node_type") == "AuditEvent":
            # 检查关联性
            relevant = False
            if identity:
                for src, _, edge_data in G.in_edges(node, data=True):
                    pass
                for _, target, edge_data in G.edges(node, data=True):
                    pass
                # 检查 accessed 边
                for src, target, edge_data in G.edges(data=True):
                    if edge_data.get("edge_type") == "accessed":
                        if edge_data.get("via") == node:
                            relevant = True
            if not relevant and resource:
                for src, target, edge_data in G.edges(data=True):
                    if edge_data.get("edge_type") == "accessed" and target == resource:
                        if edge_data.get("via") == node:
                            relevant = True
            
            if relevant or (not identity and not resource):
                events.append({
                    "event_id": node,
                    "action": data.get("action", ""),
                    "success": data.get("success", False),
                    "src_ip": data.get("src_ip", ""),
                    "anomaly_score": data.get("anomaly_score", 0.0),
                    "timestamp": data.get("t", ""),
                })
    
    max_anomaly = max((e["anomaly_score"] for e in events), default=0.0)
    
    return {
        "tool": "AuditEventCheck",
        "identity": identity,
        "resource": resource,
        "events_found": len(events),
        "events": events,
        "max_anomaly_score": round(max_anomaly, 4),
        "has_suspicious": max_anomaly >= 0.7
    }


def _is_descendant(G: nx.MultiDiGraph, ancestor: str, descendant: str) -> bool:
    """检查 descendant 是否是 ancestor 的后代（通过 contains 边）"""
    if ancestor == descendant:
        return True
    visited = set()
    stack = [ancestor]
    while stack:
        current = stack.pop()
        if current == descendant:
            return True
        if current in visited:
            continue
        visited.add(current)
        for _, target, edge_data in G.edges(current, data=True):
            if edge_data.get("edge_type") == "contains":
                stack.append(target)
    return False


def check_control_effectiveness(G: nx.MultiDiGraph, instance: str, target_object: str = None) -> dict:
    """工具 T6: 检查控制项有效性
    
    检查实例上启用的控制项是否真正覆盖目标资产。
    例如 TDE 启用了但没有加密到目标表字段，应判为无效。
    返回控制项有效性得分 ∈ [0, 1]。
    """
    effectiveness_details = []
    weighted_score = 0.0
    total_weight = 0.0
    
    # 各控制项类型的权重（用于有效性加权计算）
    KIND_WEIGHTS = {
        "TDE": 0.30,        # 透明加密最重要
        "Audit": 0.25,      # 审计日志
        "Backup": 0.15,     # 备份
        "AccessControl": 0.20,  # 访问控制
        "DataMasking": 0.10,    # 数据脱敏
    }
    
    for _, target, edge_data in G.edges(instance, data=True):
        if edge_data.get("edge_type") != "protected_by":
            continue
        ctrl_data = G.nodes.get(target, {})
        kind = ctrl_data.get("kind", "unknown")
        enabled = ctrl_data.get("enabled", False)
        scope = ctrl_data.get("scope", "")
        
        # 覆盖性判断：scope 是否包含目标表
        covers_target = True
        if target_object and scope:
            covers_target = (scope == instance) or (target_object in scope) or (scope == "all")
        
        weight = KIND_WEIGHTS.get(kind, 0.05)
        actual_score = 1.0 if (enabled and covers_target) else 0.0
        weighted_score += weight * actual_score
        total_weight += weight
        
        effectiveness_details.append({
            "control_id": target,
            "kind": kind,
            "enabled": enabled,
            "covers_target": covers_target,
            "effective": enabled and covers_target,
            "weight": weight,
            "evidence_ref": edge_data.get("evidence_ref", "")
        })
    
    # 归一化有效性得分
    effectiveness = (weighted_score / total_weight) if total_weight > 0 else 0.0
    
    return {
        "tool": "ControlEffectiveness",
        "instance": instance,
        "target_object": target_object,
        "effectiveness_score": round(effectiveness, 4),
        "effective_controls": [d for d in effectiveness_details if d["effective"]],
        "ineffective_controls": [d for d in effectiveness_details if not d["effective"]],
        "details": effectiveness_details,
        "is_well_protected": effectiveness >= 0.7,
    }


def check_compliance_status(G: nx.MultiDiGraph, instance: str, target_object: str = None) -> dict:
    """工具 T7: 检查合规状态
    
    按照等保2.0 + GDPR + PCI-DSS 的多项合规要求检查：
    - 高敏字段(L3/L4)必须启用 TDE
    - 高敏字段必须启用审计
    - 外部账号访问必须启用 MFA
    - 公网暴露的实例必须有访问控制
    返回合规分数 ∈ [0, 1] 以及违规项列表。
    """
    violations = []
    checks_passed = 0
    checks_total = 0
    
    inst_data = G.nodes.get(instance, {})
    
    # 获取实例上的控制项
    enabled_kinds = set()
    for _, ctrl, edge_data in G.edges(instance, data=True):
        if edge_data.get("edge_type") == "protected_by":
            cdata = G.nodes.get(ctrl, {})
            if cdata.get("enabled"):
                enabled_kinds.add(cdata.get("kind", ""))
    
    # 检查高敏字段
    max_sensitivity = 0
    has_sensitive = False
    for node in G.nodes():
        nd = G.nodes[node]
        if nd.get("node_type") != "DBObject" or nd.get("kind") != "field":
            continue
        # 是否在实例下
        if target_object and not _is_descendant(G, target_object, node):
            continue
        if not target_object and not _is_descendant(G, instance, node):
            continue
        for _, tag, ed in G.edges(node, data=True):
            if ed.get("edge_type") == "classified_as":
                td = G.nodes.get(tag, {})
                lvl = td.get("level", 0)
                max_sensitivity = max(max_sensitivity, lvl)
                if lvl >= 3:
                    has_sensitive = True
    
    # 规则1: 高敏字段必须启用 TDE
    if has_sensitive:
        checks_total += 1
        if "TDE" in enabled_kinds:
            checks_passed += 1
        else:
            violations.append({
                "rule": "TDE_REQUIRED_FOR_SENSITIVE",
                "severity": "high",
                "description": f"实例包含 L{max_sensitivity} 敏感字段，但未启用 TDE 透明加密",
                "standard": "等保2.0 8.1.4 / GDPR Art.32"
            })
    
    # 规则2: 高敏字段必须启用审计
    if has_sensitive:
        checks_total += 1
        if "Audit" in enabled_kinds or inst_data.get("audit_on"):
            checks_passed += 1
        else:
            violations.append({
                "rule": "AUDIT_REQUIRED_FOR_SENSITIVE",
                "severity": "high",
                "description": f"实例包含 L{max_sensitivity} 敏感字段，但未启用审计日志",
                "standard": "等保2.0 8.1.5 / PCI-DSS 10.2"
            })
    
    # 规则3: 外部账号必须启用 MFA
    for node, nd in G.nodes(data=True):
        if nd.get("node_type") == "Identity" and nd.get("is_external"):
            checks_total += 1
            if nd.get("mfa"):
                checks_passed += 1
            else:
                violations.append({
                    "rule": "MFA_REQUIRED_FOR_EXTERNAL",
                    "severity": "high",
                    "description": f"外部账号 {node} 未启用 MFA",
                    "standard": "等保2.0 8.1.3 / NIST 800-63"
                })
    
    # 规则4: 公网暴露的实例必须启用访问控制
    is_public = False
    for node, nd in G.nodes(data=True):
        if nd.get("node_type") == "Network" and nd.get("public_exposed"):
            for _, target, ed in G.edges(node, data=True):
                if ed.get("edge_type") == "can_connect" and target == instance:
                    is_public = True
                    break
    if is_public:
        checks_total += 1
        if "AccessControl" in enabled_kinds:
            checks_passed += 1
        else:
            violations.append({
                "rule": "ACCESS_CONTROL_REQUIRED_FOR_PUBLIC",
                "severity": "critical",
                "description": f"实例 {instance} 公网暴露，但未配置访问控制",
                "standard": "等保2.0 8.1.2"
            })
    
    compliance_score = (checks_passed / checks_total) if checks_total > 0 else 1.0
    
    return {
        "tool": "ComplianceStatus",
        "instance": instance,
        "target_object": target_object,
        "compliance_score": round(compliance_score, 4),
        "checks_passed": checks_passed,
        "checks_total": checks_total,
        "violations": violations,
        "is_compliant": compliance_score >= 0.8 and not any(v["severity"] == "critical" for v in violations),
        "standards_checked": ["等保2.0", "GDPR", "PCI-DSS"],
    }
