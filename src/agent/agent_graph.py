"""EIC-Agent LangGraph 状态机：Agent循环完整 Agent"""
import json
import os
import sys
from typing import TypedDict, Annotated, Optional
from pathlib import Path
from dotenv import load_dotenv

# 项目根目录
ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(ROOT))
load_dotenv(ROOT / ".env")

from src.graph.graph_builder import build_graph, get_entry_nodes, get_target_nodes, load_samples, print_graph_summary
from src.graph.constrained_search import constrained_dfs
from src.graph.gate_score import compute_evidence_vector, compute_one_dimension, gate_score, evaluate_path, load_config
from src.agent.tools import (
    check_network_reachability,
    check_permission,
    check_sensitive_data,
    check_controls,
    check_audit_events,
    check_control_effectiveness,
    check_compliance_status,
)

# ─── LangGraph ───
try:
    from langgraph.graph import StateGraph, END
    from langchain_core.messages import HumanMessage, SystemMessage
    HAS_LANGGRAPH = True
except ImportError:
    HAS_LANGGRAPH = False

# ─── LLM ───
try:
    from openai import OpenAI
    HAS_OPENAI = True
except ImportError:
    HAS_OPENAI = False


# ════════════════════════════════════════════════
# 状态定义
# ════════════════════════════════════════════════
class AgentState(TypedDict):
    sample: dict                    # 输入样本
    graph: object                   # NetworkX 图
    config: dict                    # 阈值配置
    candidate_paths: list           # 环节1: 候选路径
    current_path_idx: int           # 当前分析第几条
    current_path: list              # 当前路径
    tool_results: dict              # 环节3: 工具调用结果
    evidence_vector: dict           # 环节4: 证据向量
    gate_result: dict               # 环节5: Gate·Score 结果
    attribution: str                # 环节6: 归因解释
    remediation: str                # 环节7: 处置建议
    all_results: list               # 所有路径结果
    llm_available: bool             # LLM 是否可用


# ════════════════════════════════════════════════
# LLM 初始化
# ════════════════════════════════════════════════
def get_llm_client():
    """获取 LLM 客户端（DeepSeek）"""
    if os.environ.get("EIC_DISABLE_LLM", "").strip().lower() in {"1", "true", "yes"}:
        return None
    api_key = os.environ.get("DEEPSEEK_API_KEY", "sk-6eff39f5e9c54e5c8146b01c2fbfa478")
    if not HAS_OPENAI:
        return None
    try:
        client = OpenAI(
            api_key=api_key,
            base_url="https://api.deepseek.com",
        )
        return client
    except Exception:
        return None


def call_llm(client, system_prompt: str, user_prompt: str) -> str:
    """调用 DeepSeek LLM"""
    if client is None:
        return ""
    try:
        resp = client.chat.completions.create(
            model="deepseek-chat",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.1,
            max_tokens=2048,
        )
        return resp.choices[0].message.content
    except Exception as e:
        return f"[LLM Error: {e}]"


# ════════════════════════════════════════════════
# 环节 1: 约束 DFS 找候选路径
# ════════════════════════════════════════════════
def stage1_find_paths(state: AgentState) -> dict:
    """环节1: 图搜索算法找候选路径"""
    G = state["graph"]
    config = state["config"]
    entries = get_entry_nodes(G)
    targets = get_target_nodes(G)
    
    paths = constrained_dfs(
        G, entries, targets,
        min_depth=config.get("search", {}).get("min_depth", 4),
        max_depth=config.get("search", {}).get("max_depth", 8),
    )
    
    print(f"\n  [环节1] 约束DFS找到 {len(paths)} 条候选路径")
    for i, p in enumerate(paths):
        print(f"    路径{i+1}: {' → '.join(p)} ({len(p)-1}跳)")
    
    return {"candidate_paths": paths, "current_path_idx": 0, "all_results": []}


# ════════════════════════════════════════════════
# 环节 2: LLM 决定验证顺序
# ════════════════════════════════════════════════
def stage2_plan_verification(state: AgentState) -> dict:
    """环节2: LLM 决定验证顺序，并实际重排路径"""
    paths = state["candidate_paths"]
    client = get_llm_client()
    
    if client and paths and len(paths) > 1:
        prompt = f"""你是一个云数据库安全分析智能体。以下是 {len(paths)} 条候选暴露路径：
"""
        for i, p in enumerate(paths):
            prompt += f"  路径{i}: {' → '.join(p)} ({len(p)-1}跳)\n"
        prompt += """\n请按风险优先级对这些路径排序，输出格式为 JSON 数组，如 [2, 0, 1] 表示先验证路径2，再路径0，再路径1。
只输出 JSON 数组，不要其他内容。"""
        
        result = call_llm(client, "你是云数据库安全分析专家。", prompt)
        try:
            order = json.loads(result.strip().strip("`").replace("json", "").strip())
            if isinstance(order, list) and len(order) == len(paths):
                # 实际重排 candidate_paths
                reordered = [paths[i] for i in order if 0 <= i < len(paths)]
                if len(reordered) == len(paths):
                    print(f"  [环节2] LLM排序: {order} → 已重排")
                    return {"candidate_paths": reordered, "current_path_idx": 0}
        except (json.JSONDecodeError, ValueError, IndexError):
            pass
    
    print(f"  [环节2] 使用默认顺序（按路径长度排序）")
    return {"current_path_idx": 0}


# ═══════════════════════════════════════════════
# Function Calling 工具定义
# ════════════════════════════════════════════════
TOOL_DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "check_network_reachability",
            "description": "检查从 source 到 target 的网络可达性（can_connect 边链）",
            "parameters": {
                "type": "object",
                "properties": {
                    "source": {"type": "string", "description": "起始网络节点ID"},
                    "target": {"type": "string", "description": "目标数据库实例ID"}
                },
                "required": ["source", "target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "check_permission",
            "description": "检查 identity 对 resource 的访问权限（含 can_assume 角色继承）",
            "parameters": {
                "type": "object",
                "properties": {
                    "identity": {"type": "string", "description": "身份节点ID"},
                    "resource": {"type": "string", "description": "目标资源节点ID"}
                },
                "required": ["identity", "resource"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "check_sensitive_data",
            "description": "检查 DBObject 是否包含高敏字段（classified_as 标签）",
            "parameters": {
                "type": "object",
                "properties": {
                    "db_object": {"type": "string", "description": "数据库对象节点ID"}
                },
                "required": ["db_object"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "check_controls",
            "description": "检查数据库实例的安全控制项状态（TDE/Audit/Backup）",
            "parameters": {
                "type": "object",
                "properties": {
                    "instance": {"type": "string", "description": "数据库实例节点ID"}
                },
                "required": ["instance"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "check_audit_events",
            "description": "查询与 identity/resource 相关的异常审计事件",
            "parameters": {
                "type": "object",
                "properties": {
                    "identity": {"type": "string", "description": "身份节点ID（可选）"},
                    "resource": {"type": "string", "description": "资源节点ID（可选）"}
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "check_control_effectiveness",
            "description": "检查控制项是否真正生效（是否覆盖目标资产）",
            "parameters": {
                "type": "object",
                "properties": {
                    "instance": {"type": "string", "description": "数据库实例节点ID"},
                    "target_object": {"type": "string", "description": "目标资产节点ID（可选）"}
                },
                "required": ["instance"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "check_compliance_status",
            "description": "检查合规状态（等保2.0/GDPR/PCI-DSS），返回违规项",
            "parameters": {
                "type": "object",
                "properties": {
                    "instance": {"type": "string", "description": "数据库实例节点ID"},
                    "target_object": {"type": "string", "description": "目标资产节点ID（可选）"}
                },
                "required": ["instance"]
            }
        }
    }
]

# 工具映射表
TOOL_MAP = {
    "check_network_reachability": check_network_reachability,
    "check_permission": check_permission,
    "check_sensitive_data": check_sensitive_data,
    "check_controls": check_controls,
    "check_audit_events": check_audit_events,
    "check_control_effectiveness": check_control_effectiveness,
    "check_compliance_status": check_compliance_status,
}


# ════════════════════════════════════════════════
# 环节 3: LLM Function Calling 调用工具获取证据
# ════════════════════════════════════════════════
def stage3_call_tools(state: AgentState) -> dict:
    """环节3: LLM 通过 Function Calling 决定调用哪些工具，收集证据"""
    G = state["graph"]
    paths = state["candidate_paths"]
    idx = state["current_path_idx"]
    
    if idx >= len(paths):
        return {"tool_results": {}}
    
    path = paths[idx]
    print(f"\n  [环节3] 对路径{idx+1}调用工具: {' → '.join(path)}")
    
    # 提取路径中的关键节点
    node_info = {}
    for n in path:
        nd = G.nodes.get(n, {})
        nt = nd.get("node_type", "")
        node_info[n] = nt
    
    results = {}
    client = get_llm_client()
    
    if client:
        # 通过 Function Calling 让 LLM 决定调用哪些工具
        path_desc = ' → '.join([f"{n}({node_info[n]})" for n in path])
        prompt = f"""你是云数据库安全分析智能体。请分析以下暴露路径，调用合适的工具收集证据。

路径: {path_desc}

请调用合适的工具检查这条路径的风险，包括网络可达性、权限、敏感数据、安全控制项和审计事件。"""
        
        try:
            resp = client.chat.completions.create(
                model="deepseek-chat",
                messages=[
                    {"role": "system", "content": "你是云安全分析Agent，请调用工具收集证据。"},
                    {"role": "user", "content": prompt},
                ],
                tools=TOOL_DEFINITIONS,
                tool_choice="auto",
                temperature=0.1,
            )
            
            msg = resp.choices[0].message
            
            if msg.tool_calls:
                print(f"    LLM决定调用 {len(msg.tool_calls)} 个工具:")
                for tc in msg.tool_calls:
                    fn_name = tc.function.name
                    fn_args = json.loads(tc.function.arguments)
                    print(f"      → {fn_name}({fn_args})")
                    
                    if fn_name in TOOL_MAP:
                        # 执行工具，第一个参数始终是 G
                        tool_result = TOOL_MAP[fn_name](G, **fn_args)
                        tool_key = fn_name.replace("check_", "")
                        results[tool_key] = tool_result
                        print(f"        ✓ 结果: {_brief(tool_result)}")
                
                return {"tool_results": results, "current_path": path}
        except Exception as e:
            print(f"    Function Calling 异常: {e}，回退确定性模式")
    
    # 降级: 确定性直调所有工具
    results = _deterministic_tool_calls(G, path, node_info)
    return {"tool_results": results, "current_path": path}


def _deterministic_tool_calls(G, path, node_info):
    """确定性工具调用（降级方案）"""
    results = {}
    network_nodes = [n for n, t in node_info.items() if t == "Network"]
    db_nodes = [n for n, t in node_info.items() if t == "DBInstance"]
    identity_nodes = [n for n, t in node_info.items() if t == "Identity"]
    table_nodes = [n for n in path if G.nodes.get(n, {}).get("node_type") == "DBObject" and G.nodes.get(n, {}).get("kind") == "table"]
    
    if network_nodes and db_nodes:
        results["network_reachability"] = check_network_reachability(G, network_nodes[0], db_nodes[0])
        print(f"    T1 NetworkReachability: reachable={results['network_reachability']['reachable']}")
    if identity_nodes and table_nodes:
        results["permission"] = check_permission(G, identity_nodes[0], table_nodes[0])
        print(f"    T2 PermissionCheck: has_perm={results['permission']['has_permission']}")
    if table_nodes:
        results["sensitive_data"] = check_sensitive_data(G, table_nodes[0])
        print(f"    T3 SensitiveDataCheck: has_sensitive={results['sensitive_data']['has_sensitive']}")
    if db_nodes:
        results["controls"] = check_controls(G, db_nodes[0])
        print(f"    T4 ControlCheck: coverage={results['controls']['protection_coverage']}")
    identity = identity_nodes[0] if identity_nodes else None
    resource = table_nodes[0] if table_nodes else None
    results["audit_events"] = check_audit_events(G, identity, resource)
    print(f"    T5 AuditEventCheck: events={results['audit_events']['events_found']}")
    if db_nodes:
        results["control_effectiveness"] = check_control_effectiveness(G, db_nodes[0], table_nodes[0] if table_nodes else None)
        print(f"    T6 ControlEffectiveness: score={results['control_effectiveness']['effectiveness_score']}")
        results["compliance"] = check_compliance_status(G, db_nodes[0], table_nodes[0] if table_nodes else None)
        print(f"    T7 ComplianceStatus: score={results['compliance']['compliance_score']}")
    return results


def _brief(result: dict) -> str:
    """工具结果摘要"""
    tool = result.get("tool", "")
    if tool == "NetworkReachability":
        return f"reachable={result.get('reachable')}, strength={result.get('reachability')}"
    elif tool == "PermissionCheck":
        return f"has_perm={result.get('has_permission')}, strength={result.get('max_strength')}"
    elif tool == "SensitiveDataCheck":
        return f"has_sensitive={result.get('has_sensitive')}, max_level={result.get('max_level')}"
    elif tool == "ControlCheck":
        return f"tde={result.get('tde_enabled')}, audit={result.get('audit_enabled')}"
    elif tool == "AuditEventCheck":
        return f"events={result.get('events_found')}, suspicious={result.get('has_suspicious')}"
    elif tool == "ControlEffectiveness":
        return f"effectiveness={result.get('effectiveness_score')}"
    elif tool == "ComplianceStatus":
        return f"compliance={result.get('compliance_score')}, violations={len(result.get('violations', []))}"
    return str(result)[:80]


# ════════════════════════════════════════════════
# 环节 4: LLM 解读工具返回 → 证据向量
# ════════════════════════════════════════════════
def stage4_parse_evidence(state: AgentState) -> dict:
    """环节4: 将工具结果转化为五维证据向量
    
    设计原则：“表达—判定分离”
    - 确定性算法计算证据向量（权威数据）
    - LLM 只做辅助解释，不覆盖数值
    """
    G = state["graph"]
    path = state["current_path"]
    tool_results = state["tool_results"]
    client = get_llm_client()
    
    if not path:
        return {"evidence_vector": {}}
    
    # ━━━ 确定性计算（权威数据）━━━
    ev = compute_evidence_vector(G, path)
    
    # ━━━ LLM 只做解释性验证，不覆盖数值 ━━━
    if client and tool_results:
        prompt = f"""你是证据分析员。请验证以下确定性计算的五维证据向量是否与工具调用结果一致。

路径: {' → '.join(path)}
确定性计算结果: {json.dumps(ev, ensure_ascii=False)}
工具调用结果:
- 网络可达: {json.dumps(tool_results.get('network', {}), ensure_ascii=False)}
- 权限: {json.dumps(tool_results.get('permission', {}), ensure_ascii=False)}
- 敏感数据: {json.dumps(tool_results.get('sensitive', {}), ensure_ascii=False)}
- 控制项: {json.dumps(tool_results.get('controls', {}), ensure_ascii=False)}
- 审计事件: {json.dumps(tool_results.get('audit', {}), ensure_ascii=False)}

请用一句话总结证据情况，不要修改数值。"""
        
        explanation = call_llm(client, "你是证据分析员，对工具返回的数据做简洁总结。", prompt)
        if explanation and not explanation.startswith("[LLM Error"):
            print(f"  [环节4] LLM证据解读: {explanation[:120]}...")
    
    print(f"  [环节4] 证据向量: entry={ev['entry']:.2f}, reach={ev['reach']:.2f}, perm={ev['perm']:.2f}, target={ev['target']:.2f}, sense={ev['sense']:.2f}")
    return {"evidence_vector": ev}


# ════════════════════════════════════════════════
# 环节 5: Gate·Score 确定性判定
# ════════════════════════════════════════════════
def stage5_gate_judgment(state: AgentState) -> dict:
    """环节5: Gate·Score 确定性判定（不经过 LLM）"""
    ev = state["evidence_vector"]
    config = state["config"]
    
    if not ev:
        return {"gate_result": {}}
    
    result = gate_score(ev, config)
    
    status = "✅ Gate通过" if result["gate"] == 1 else f"❌ Gate拦截 ({', '.join(result['blocked_by'])})"
    print(f"  [环节5] Gate·Score: {status}")
    print(f"    Score={result['score']:.4f} → {result['path_type']}")
    
    return {"gate_result": result}


# ════════════════════════════════════════════════
# 环节 6: LLM 生成归因解释
# ════════════════════════════════════════════════
def stage6_generate_attribution(state: AgentState) -> dict:
    """环节6: LLM 生成归因解释"""
    path = state["current_path"]
    gate_result = state["gate_result"]
    tool_results = state["tool_results"]
    G = state["graph"]
    client = get_llm_client()
    
    if not path or not gate_result:
        return {"attribution": ""}
    
    if client:
        prompt = f"""请根据以下暴露路径和证据向量，生成专业的风险归因分析。

路径: {' → '.join(path)}
证据向量: {gate_result['evidence_vector']}
判定结果: {gate_result['path_type']} (Score={gate_result['score']})
"""
        if gate_result.get("blocked_by"):
            prompt += f"被拦截原因: {', '.join(gate_result['blocked_by'])}\n"
        
        prompt += f"""
要求：
- 直接以风险判定结论开头，如"该路径被判定为{gate_result['path_type']}"
- 使用正式技术语言，禁止口语化表达
- 不要寒暄、不要说"作为专家"、不要说"好的"
- 结构：判定结论 → 证据链分析 → 关键风险点
- 限200字以内"""
        
        attr = call_llm(client, "你是云数据库安全风险分析系统。直接输出风险归因分析结论，禁止寒暄和口语化表达。", prompt)
        if attr and not attr.startswith("[LLM Error"):
            print(f"  [环节6] LLM归因: {attr[:100]}...")
            return {"attribution": attr}
    
    # 降级: 确定性归因
    attr = _deterministic_attribution(G, path, gate_result, tool_results)
    print(f"  [环节6] 确定性归因: {attr[:100]}...")
    return {"attribution": attr}


# ════════════════════════════════════════════════
# 环节 7: LLM 生成处置建议
# ════════════════════════════════════════════════
def stage7_generate_remediation(state: AgentState) -> dict:
    """环节7: LLM 生成处置建议"""
    path = state["current_path"]
    gate_result = state["gate_result"]
    G = state["graph"]
    client = get_llm_client()
    
    if not path or not gate_result:
        return {"remediation": ""}
    
    if gate_result["gate"] == 0:
        rem = f"路径证据不足，无需处置。被拦截原因: {', '.join(gate_result.get('blocked_by', []))}"
        print(f"  [环节7] {rem}")
        return {"remediation": rem}
    
    if client:
        prompt = f"""请根据以下暴露路径和风险判定，生成专业的处置建议。

路径: {' → '.join(path)}
风险等级: {gate_result['path_type']}
Score: {gate_result['score']}

要求：
- 直接以处置方案开头，如"建议立即执行以下处置"
- 使用正式技术语言，禁止口语化表达
- 不要寒暄、不要说"作为专家"、不要说"好的"
- 结构：紧急处置 → 权限收敛 → 网络隔离 → 长期改进
- 每条建议包含具体的资源 ID 和操作
- 限150字以内"""
        
        rem = call_llm(client, "你是云数据库安全处置系统。直接输出处置建议，禁止寒暄和口语化表达。", prompt)
        if rem and not rem.startswith("[LLM Error"):
            print(f"  [环节7] LLM处置建议:\n{rem}")
            return {"remediation": rem}
    
    # 降级: 确定性建议
    rem = _deterministic_remediation(G, path, gate_result)
    print(f"  [环节7] 确定性处置建议:\n{rem}")
    return {"remediation": rem}


# ════════════════════════════════════════════════
# 辅助: 确定性归因和建议
# ════════════════════════════════════════════════
def _deterministic_attribution(G, path, gate_result, tool_results):
    """确定性归因"""
    parts = []
    ev = gate_result["evidence_vector"]
    
    if ev["entry"] >= 0.8:
        parts.append(f"入口暴露(public_exposed, ε={ev['entry']:.2f})")
    if ev["reach"] >= 0.5:
        parts.append(f"网络可达(ε={ev['reach']:.2f})")
    elif ev["reach"] < 0.5:
        parts.append(f"网络可达性不足(ε={ev['reach']:.2f})")
    if ev["perm"] >= 0.5:
        parts.append(f"权限授予(ε={ev['perm']:.2f})")
    elif ev["perm"] < 0.5:
        parts.append(f"权限不足(ε={ev['perm']:.2f})")
    if ev["sense"] >= 0.8:
        parts.append(f"高敏数据确认(ε={ev['sense']:.2f})")
    
    return f"判定: {gate_result['path_type']} (Score={gate_result['score']})。证据: {'; '.join(parts)}。"


def _deterministic_remediation(G, path, gate_result):
    """确定性处置建议"""
    suggestions = []
    
    for node in path:
        data = G.nodes.get(node, {})
        ntype = data.get("node_type", "")
        
        if ntype == "Network" and data.get("public_exposed"):
            suggestions.append(f"1. 收紧安全组 {node} 的入站规则，移除 0.0.0.0/0")
        elif ntype == "DBInstance" and not data.get("encrypted"):
            suggestions.append(f"2. 为实例 {node} 开启 TDE 透明数据加密")
        elif ntype == "DBInstance" and not data.get("audit_on"):
            suggestions.append(f"3. 为实例 {node} 开启 SQL 审计日志")
        elif ntype == "Identity" and not data.get("mfa"):
            suggestions.append(f"4. 为账号 {node} 启用 MFA 多因素认证")
    
    for node in path:
        for _, target, edge_data in G.edges(node, data=True):
            if edge_data.get("edge_type") == "classified_as":
                tag = G.nodes.get(target, {})
                if tag.get("level", 0) >= 4:
                    suggestions.append(f"5. 对字段 {node} 开启列级访问控制和动态脱敏")
    
    return "\n".join(suggestions) if suggestions else "无需处置。"


# ════════════════════════════════════════════════
# 循环控制
# ════════════════════════════════════════════════
def should_continue(state: AgentState) -> str:
    """判断是否还有路径需要分析"""
    idx = state["current_path_idx"]
    paths = state["candidate_paths"]
    
    # advance_to_next 已经先把索引加一；只要新索引仍落在候选范围内，
    # 就必须继续处理。旧条件会稳定漏掉最后一条候选路径。
    if idx < len(paths):
        return "next_path"
    return "finish"


def advance_to_next(state: AgentState) -> dict:
    """推进到下一条路径"""
    results = list(state.get("all_results", []))
    # 空候选集也会经过一次状态机骨架；不要把空路径记录成真实结果。
    if state.get("current_path") and state.get("gate_result"):
        results.append({
            "path": state["current_path"],
            "evidence_vector": state["evidence_vector"],
            "gate_result": state["gate_result"],
            "attribution": state["attribution"],
            "remediation": state["remediation"],
        })
    return {
        "all_results": results,
        "current_path_idx": state["current_path_idx"] + 1,
    }


# ════════════════════════════════════════════════
# 构建 LangGraph 状态机
# ════════════════════════════════════════════════
def build_agent_graph():
    """构建 EIC-Agent LangGraph 状态机"""
    if not HAS_LANGGRAPH:
        print("❌ LangGraph 未安装，使用线性执行模式")
        return None
    
    workflow = StateGraph(AgentState)
    
    # 添加节点
    workflow.add_node("find_paths", stage1_find_paths)
    workflow.add_node("plan_verification", stage2_plan_verification)
    workflow.add_node("call_tools", stage3_call_tools)
    workflow.add_node("parse_evidence", stage4_parse_evidence)
    workflow.add_node("gate_judgment", stage5_gate_judgment)
    workflow.add_node("generate_attribution", stage6_generate_attribution)
    workflow.add_node("generate_remediation", stage7_generate_remediation)
    workflow.add_node("advance", advance_to_next)
    
    # 设置入口
    workflow.set_entry_point("find_paths")
    
    # 连接节点
    workflow.add_edge("find_paths", "plan_verification")
    workflow.add_edge("plan_verification", "call_tools")
    workflow.add_edge("call_tools", "parse_evidence")
    workflow.add_edge("parse_evidence", "gate_judgment")
    workflow.add_edge("gate_judgment", "generate_attribution")
    workflow.add_edge("generate_attribution", "generate_remediation")
    workflow.add_edge("generate_remediation", "advance")
    
    # 条件边: 继续下一条路径 or 结束
    workflow.add_conditional_edges(
        "advance",
        should_continue,
        {
            "next_path": "call_tools",
            "finish": END,
        }
    )
    
    return workflow.compile()


# ════════════════════════════════════════════════
# 提前终止预检：逐维查硬证据 + 当场判 + 不达标即停
# ════════════════════════════════════════════════
def gate_precheck(G, path: list, config: dict) -> dict:
    """在昂贵的工具调用与 LLM 归因之前，逐维核验硬证据。

    按"代价低→高 / 最可能否决优先"的顺序检查硬维度 entry → reach → perm，
    每算完一维立刻与阈值比较；任一硬维度不达标即当场终止、剪枝该路径，
    不再计算后续维度、不调用 LLM。三维全过才放行走完整流程。

    Returns:
        dict: {
          terminated: bool,        # 是否提前终止（被剪枝）
          blocked_by: str,         # 触发终止的维度描述（终止时）
          dims_checked: int,       # 实际计算了几个硬维度
          hard_evidence: dict,     # 已算出的硬维度证据值
        }
    """
    tau = config["gate_thresholds"]
    hard_order = ["entry", "reach", "perm"]  # 代价低、最可能一票否决者优先
    hard_evidence = {}
    for i, dim in enumerate(hard_order, start=1):
        val = compute_one_dimension(G, path, dim)
        hard_evidence[dim] = round(val, 4)
        if val < tau[dim]:
            return {
                "terminated": True,
                "blocked_by": f"{dim}({val:.2f}<{tau[dim]})",
                "dims_checked": i,
                "hard_evidence": hard_evidence,
            }
    return {
        "terminated": False,
        "blocked_by": "",
        "dims_checked": len(hard_order),
        "hard_evidence": hard_evidence,
    }


# ════════════════════════════════════════════════
# 线性执行（LangGraph 不可用时）
# ════════════════════════════════════════════════
def run_linear(sample: dict, config: dict = None) -> list:
    """线性执行 Agent循环"""
    if config is None:
        config = load_config()
    
    G = build_graph(sample)
    print_graph_summary(G)
    
    state = {
        "sample": sample,
        "graph": G,
        "config": config,
        "candidate_paths": [],
        "current_path_idx": 0,
        "current_path": [],
        "tool_results": {},
        "evidence_vector": {},
        "gate_result": {},
        "attribution": "",
        "remediation": "",
        "all_results": [],
        "llm_available": get_llm_client() is not None,
    }
    
    # 环节1
    updates = stage1_find_paths(state)
    state.update(updates)
    
    # 环节2
    updates = stage2_plan_verification(state)
    state.update(updates)
    
    # 对每条候选路径执行环节 3-7（先做提前终止预检）
    n_pruned = 0
    n_full = 0
    tool_calls_actual = 0     # 走完整流程实际发生的工具调用次数
    tool_calls_saved = 0      # 因提前终止省下的工具调用次数（每条完整流程约 5 类核心工具）
    llm_calls_saved = 0       # 因提前终止省下的 LLM 调用次数（归因+整改 = 2）
    hard_dims_computed = 0    # 实际计算的硬维度总数（逐维探索的代价度量）
    TOOLS_PER_FULL = 5        # 完整流程调用的核心工具类数（估算基准）
    LLM_PER_FULL = 2          # 完整流程的 LLM 调用数（归因+整改）
    for idx in range(len(state["candidate_paths"])):
        state["current_path_idx"] = idx
        path = state["candidate_paths"][idx]
        print(f"\n{'─'*50}")
        print(f"分析路径 {idx+1}/{len(state['candidate_paths'])}: {' → '.join(path)}")
        print(f"{'─'*50}")

        # ━━━ 提前终止预检：逐维查硬证据 + 当场判 + 不达标即停 ━━━
        pre = gate_precheck(G, path, config)
        hard_dims_computed += pre["dims_checked"]
        if pre["terminated"]:
            n_pruned += 1
            tool_calls_saved += TOOLS_PER_FULL
            llm_calls_saved += LLM_PER_FULL
            print(f"  [提前终止] 硬证据 {pre['blocked_by']} 不达标 "
                  f"(仅查 {pre['dims_checked']}/3 维即剪枝，省 ~{TOOLS_PER_FULL} 次工具 + {LLM_PER_FULL} 次 LLM)")
            state["all_results"].append({
                "path": path,
                "evidence_vector": pre["hard_evidence"],
                "gate_result": {
                    "gate": 0,
                    "score": 0.0,
                    "path_type": "Insufficient_Evidence",
                    "blocked_by": [pre["blocked_by"]],
                    "evidence_vector": pre["hard_evidence"],
                    "early_terminated": True,
                    "dims_checked": pre["dims_checked"],
                },
                "attribution": f"路径在硬证据维度 {pre['blocked_by']} 未达阈值，"
                               f"经确定性 Gate 一票否决提前终止，判定为证据不足（Insufficient_Evidence）。",
                "remediation": "",
            })
            continue

        # ━━━ 预检通过 → 走完整流程（工具调用 + 证据 + 判定 + LLM 归因）━━━
        n_full += 1
        state["current_path"] = path
        for stage_fn in [stage3_call_tools, stage4_parse_evidence, 
                         stage5_gate_judgment, stage6_generate_attribution, 
                         stage7_generate_remediation]:
            updates = stage_fn(state)
            state.update(updates)

        tool_calls_actual += len(state.get("tool_results", {}))
        
        state["all_results"].append({
            "path": state["current_path"],
            "evidence_vector": state["evidence_vector"],
            "gate_result": state["gate_result"],
            "attribution": state["attribution"],
            "remediation": state["remediation"],
        })

    total = len(state["candidate_paths"])
    print(f"\n{'═'*50}")
    print(f"[提前终止统计] 候选路径 {total} 条 | 提前剪枝 {n_pruned} 条 | 走完整流程 {n_full} 条")
    print(f"  工具调用: 实际 {tool_calls_actual} 次 | 剪枝省下 ~{tool_calls_saved} 次")
    print(f"  LLM 调用: 剪枝省下 ~{llm_calls_saved} 次")
    print(f"  硬维度计算: {hard_dims_computed} 次 (满查为 {total*3} 次)")
    print(f"{'═'*50}")

    # 效率埋点写入结果供上层采集（B6 vs B7 Pareto 前沿用）
    state["_efficiency_stats"] = {
        "total_paths": total,
        "pruned_paths": n_pruned,
        "full_paths": n_full,
        "tool_calls_actual": tool_calls_actual,
        "tool_calls_saved_est": tool_calls_saved,
        "llm_calls_saved_est": llm_calls_saved,
        "hard_dims_computed": hard_dims_computed,
        "hard_dims_if_full": total * 3,
    }

    return state["all_results"]


# ════════════════════════════════════════════════
# LangGraph 编译执行（优先模式）
# ════════════════════════════════════════════════
def run_graph(sample: dict, config: dict = None) -> list:
    """通过 LangGraph 编译状态机执行 Agent循环，失败时降级到 run_linear"""
    if config is None:
        config = load_config()
    
    graph = build_agent_graph()
    if graph is None:
        print("  ⚠️  LangGraph 不可用，降级到线性执行")
        return run_linear(sample, config)
    
    G = build_graph(sample)
    print_graph_summary(G)
    
    initial_state = {
        "sample": sample,
        "graph": G,
        "config": config,
        "candidate_paths": [],
        "current_path_idx": 0,
        "current_path": [],
        "tool_results": {},
        "evidence_vector": {},
        "gate_result": {},
        "attribution": "",
        "remediation": "",
        "all_results": [],
        "llm_available": get_llm_client() is not None,
    }
    
    try:
        final_state = graph.invoke(initial_state)
        results = final_state.get("all_results", [])
        # 补上最后一条路径的结果（advance 在最后一轮可能未被执行）
        if final_state.get("current_path") and final_state.get("gate_result"):
            last = {
                "path": final_state["current_path"],
                "evidence_vector": final_state.get("evidence_vector", {}),
                "gate_result": final_state.get("gate_result", {}),
                "attribution": final_state.get("attribution", ""),
                "remediation": final_state.get("remediation", ""),
            }
            if not results or results[-1].get("path") != last["path"]:
                results.append(last)
        return results
    except Exception as e:
        print(f"  ⚠️  LangGraph 执行异常: {e}，降级到线性执行")
        return run_linear(sample, config)
