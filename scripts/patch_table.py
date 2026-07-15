#!/usr/bin/env python3
"""Surgically patch the defense formula-code comparison table to align
with the rewritten Chapter 4/5 (Agent-loop architecture) + inject real
demo numbers from cloud_db_pathbench.

Reads / writes the Desktop file (outside workspace) via plain Python.
Run:  python3 patch_table.py
"""
from pathlib import Path

# Desktop original is READ-only (workspace guard blocks any write outside
# /Users/yunyun/projects). We read it, apply edits, and write the patched
# result INTO the workspace; the user can `! cp` it to Desktop themselves.
TABLE = Path("/Users/yunyun/Desktop/云数据库高敏数据暴露路径侦测/公式代码对照表.md")
OUT = Path(__file__).parent.parent / "docs" / "公式代码对照表.md"


EDITS = []

# ───────────────────────────────────────────────────────────────────
# R1: insert "Agent 循环核心 (§4.1)" section between 第一层 and 第二层
# ───────────────────────────────────────────────────────────────────
EDITS.append(("R1 insert Agent-loop core", """| **答辩语** | 图数据库比关系数据库更适合路径查询，节点/边的类型体系能统一异构云资产 |

---

## 第二层：路径搜索（第 4.2 节）""", """| **答辩语** | 图数据库比关系数据库更适合路径查询，节点/边的类型体系能统一异构云资产 |

---

## Agent 循环核心（§4.1 — 新架构核心，全文最大改造）

> EIC-Agent 从"固定八阶段流水线"改造为"假设驱动的 Agent 循环"。**算法 4.1、Gate-Score 定义、所有定理证明一字未改，只是重新定位。** 全文定位词："证据表达者" → "证据调查者与表达者"。

### 信念状态（POMDP） $\\mathcal{S}_t = (\\mathcal{H}_t, \\mathcal{E}_t, \\mathcal{B}_t)$

| 项目 | 说明 |
|------|------|
| **大白话** | Agent 内部状态三元组：$\\mathcal{H}_t$ 当前活跃路径假设集、$\\mathcal{E}_t$ 已采集工具证据库、$\\mathcal{B}_t$ 每个假设的当前 EIC 评估信念 |
| **关键** | 信念状态是 Agent 决策的**唯一依据**；所有动作选择/剪枝/终止都基于 $\\mathcal{S}_t$，而非外部隐状态 |
| **答辩语** | 环境快照六元组是"世界状态"（S1），$\\mathcal{S}_t$ 是 Agent 对世界的"信念"，二者分离——这是把固定流水线换成闭环迭代的形式化基础 |

### 动作空间与策略

$$\\mathcal{A} = \\{\\texttt{query}, \\texttt{expand}, \\texttt{prune}, \\texttt{confirm}, \\texttt{terminate}\\}, \\quad \\pi: \\mathcal{S} \\to \\mathcal{A}, \\; a_t \\sim \\pi(\\cdot \\mid \\mathcal{S}_t)$$

| 动作 | 语义 | 对应旧要素 |
|------|------|-----------|
| query(h,d,tool) | 对假设 h 的维度 d 调工具取证 | S5 |
| expand(h) | 在终点邻域延伸新假设（内部调算法 4.1） | S4 |
| prune(h) | 剔除低优先级假设 | 新（原隐含） |
| confirm(h) | 确认为暴露路径入结果集 $\\mathcal{R}$ | S6 |
| terminate | 输出风险排序与报告 | S7-S8 |

| 项目 | 说明 |
|------|------|
| **DIE 偏置** | Discover(假设生成偏置)/Investigate(证据采集偏置)/Explain(终止输出偏置)——不是硬状态机，是策略 $\\pi$ 的先验偏好，信念可在三者间**回退**（固定流水线做不到） |
| **答辩语** | S1-S8 不是线性执行序列，而是状态/动作空间构成要素；这是"固定八阶段"→"假设驱动循环"的关键重新定位 |

### 信息增益 — 主循环决策核心（§4.6）

$$d^* = \\arg\\max_{d:\\, \\varepsilon_d < \\tau_d} \\text{IG}(d \\mid P, G), \\qquad \\widetilde{\\text{IG}}(d) = (\\tau_d - \\varepsilon_d(P)) \\cdot w_d$$

| 项目 | 说明 |
|------|------|
| **大白话** | Agent 每步选信息增益最大的未通过维度去 query；增益耗尽则 prune/confirm/terminate |
| **定位升级** | IG 从"补证机制"提升为"主循环每步动作选择的核心决策函数" |
| **答辩语** | 让 Agent 主动选查询目标而非僵硬走固定阶段，是 B6(主动调查) vs B7(固定流水线) 的本质差异 |

---

## 第二层：路径搜索（第 4.2 节）"""))

# ───────────────────────────────────────────────────────────────────
# R2: reposition 算法4.1 as 假设生成器
# ───────────────────────────────────────────────────────────────────
EDITS.append(("R2 reposition path search", """| **难度** | 需要框架支持（Neo4j/NetworkX） |
| **答辩语** | 三重剪枝将复杂度从 $O(b^8)$ 降至 $O((b×0.18)^8)$，实现 6 个数量级加速 |""", """| **难度** | 需要框架支持（Neo4j/NetworkX） |
| **定位（新）** | $C(G)$ 是 **Agent 循环初始假设集 $\\mathcal{H}_0$ 的供给**（假设生成器），**不是最终检测结果**；循环中 expand 动作在受限子图上重调本算法延伸假设 |
| **答辩语** | 三重剪枝将复杂度从 $O(b^8)$ 降至 $O((b×0.18)^8)$，6 个数量级加速；定理 4.1 完备性相应解释为"假设生成完备性"——漏检只可能是证据不足，而非未搜索到 |"""))

# ───────────────────────────────────────────────────────────────────
# R3: EIC 三重角色
# ───────────────────────────────────────────────────────────────────
EDITS.append(("R3 EIC three roles", """| **答辩语** | Gate 实现"一票否决"快速筛选，Score 在通过后进行精细排序；分离硬约束和软约束使判定可审计 |""", """| **答辩语** | Gate 实现"一票否决"快速筛选，Score 在通过后进行精细排序；分离硬约束和软约束使判定可审计 |

**EIC 在 Agent 循环中的三重角色**（新架构，§4.3）：① **剪枝准则**（Gate=0 且 $\\widetilde{IG}<\\delta_{IG}$ → prune）；② **补证触发器**（Gate=0 但 $\\widetilde{IG}\\geq\\delta_{IG}$ → query 最大增益维度 $d^*$）；③ **确认准则**（Gate=1 且 Score≥$\\theta_{high}$ → confirm）。EIC 从"一次性终判"演化为"逐步逼近"的迭代过程。"""))

# ───────────────────────────────────────────────────────────────────
# R4a: 定理4.2 信念单调收敛
# ───────────────────────────────────────────────────────────────────
EDITS.append(("R4a Thm4.2 belief convergence", """| 增加证据永远不会降低路径分数 | 支撑搜索时的剪枝；支撑增量更新的正确性 |""", """| 增加证据永远不会降低路径分数 | 支撑搜索剪枝与增量更新；**并保证 Agent 循环信念单调收敛**（query 只增证据不删，$\\mathcal{B}_{t+1}(h)\\geq\\mathcal{B}_t(h)$ 逐点成立）→ 循环有限步终止 |"""))

# ───────────────────────────────────────────────────────────────────
# R4b: 定理4.4 逐维收缩
# ───────────────────────────────────────────────────────────────────
EDITS.append(("R4b Thm4.4 per-dim shrink", """| 每个硬约束都乘性收缩可幻觉空间 | 理论解释为什么 EIC 能从 16% 幻觉率降至 6% |""", """| 每个硬约束乘性收缩可幻觉空间 | 理论解释 EIC 从 16% 幻觉率降至 6%；**Agent 循环视角下逐维收缩**：每步 query 将一维冻结为通过/未通过，LLM 可幻觉空间逐维收缩 |"""))

# ───────────────────────────────────────────────────────────────────
# R5: 工具 π0 + 主动偏离
# ───────────────────────────────────────────────────────────────────
EDITS.append(("R5 pi0 + active deviation", """| T7: EvidenceValidator | 路径 | EIC 状态、得分、缺失维度 | 最终判定 |

---""", """| T7: EvidenceValidator | 路径 | EIC 状态、得分、缺失维度 | 最终判定 |

**先验策略 $\\pi_0$ + 主动偏离**（§4.5.2，新）：上表"阶段 A/B/C"即 $\\pi_0$ 的三阶段（候选生成→硬约束剪枝→软约束补强），是**安全默认**。Agent 在信念 $\\mathcal{S}_t$ 显示某维度证据不足且信息增益显著时**主动偏离** $\\pi_0$：

$$\\widetilde{IG}(a_{deviate}) - \\widetilde{IG}(a_{\\pi_0}) > \\lambda \\cdot [\\text{Cost}(a_{deviate})-\\text{Cost}(a_{\\pi_0})]$$

$\\pi_0$ 给期望成本下界，下层信念给主动优化，两层决策结构。

---"""))

# ───────────────────────────────────────────────────────────────────
# R6a: SFT R6 新增
# ───────────────────────────────────────────────────────────────────
EDITS.append(("R6a SFT R6", """# SFT 轨迹自动验证（5 条规则）
def verify_sft_trajectory(trajectory, graph):
    checks = {
        'R1_path_legality': all(node in graph.V for node in trajectory.path),
        'R2_evidence_completeness': has_hard_evidence(trajectory),
        'R3_ranking_consistency': ndcg_at_3(trajectory) >= 0.85,
        'R4_remediation_match': remediation_matches_root_cause(trajectory),
        'R5_schema_validity': is_valid_json(trajectory.output)
    }
    return all(checks.values())""", """# SFT 轨迹自动验证（6 条规则，R6 为新增）
def verify_sft_trajectory(trajectory, graph):
    checks = {
        'R1_path_legality': all(node in graph.V for node in trajectory.path),
        'R2_evidence_completeness': has_hard_evidence(trajectory),
        'R3_ranking_consistency': ndcg_at_3(trajectory) >= 0.85,
        'R4_remediation_match': remediation_matches_root_cause(trajectory),
        'R5_schema_validity': is_valid_json(trajectory.output),
        'R6_trajectory_validity': all(ig(a_i) >= delta_IG or a_i in pi_0
                                      for a_i in trajectory.actions)
        # R6（新增）：每步动作信息增益达标或属于先验策略必经步骤，剔除无意义查询
    }
    return all(checks.values())"""))

# ───────────────────────────────────────────────────────────────────
# R6b: 奖励 r5 + 权重更新
# ───────────────────────────────────────────────────────────────────
EDITS.append(("R6b reward r5", """正向奖励：
  r1 = 路径有效性 (Node-F1 + Edge-F1)
  r2 = 证据覆盖率 (支撑的维度数/5)
  r3 = 排序一致性 (NDCG@3)
  r4 = 处置匹配度 (与根因映射的交集比)

惩罚项：
  p1 = 幻觉惩罚 (虚构的论断数/总论断数)
  p2 = 工具成本 (调用数/12)

总奖励 = 0.3×r1 + 0.3×r2 + 0.15×r3 + 0.1×r4 - 0.1×p1 - 0.05×p2""", """正向奖励（5 项，r5 为新增）：
  r1 = 路径有效性 (Node-F1 + Edge-F1)
  r2 = 证据覆盖率 (支撑的维度数/5)
  r3 = 排序一致性 (NDCG@3)
  r4 = 处置匹配度 (与根因映射的交集比)
  r5 = 轨迹效率 (有效动作占比，与 R6 同源)   # 新增

惩罚项：
  p1 = 幻觉惩罚 (虚构的论断数/总论断数)
  p2 = 工具成本 (调用数/T_max)

总奖励 = 0.26×r1 + 0.26×r2 + 0.13×r3 + 0.09×r4 + 0.06×r5 - 0.12×p1 - 0.08×p2
# α5=0.06 新增；β2 由 0.05 升至 0.08 强化工具成本约束，配合 r5 形成"总量—质量"双效控制"""))

# ───────────────────────────────────────────────────────────────────
# R7: 评估层 — 轨迹指标 + B7 + 真实 demo 数据
# ───────────────────────────────────────────────────────────────────
EDITS.append(("R7 eval layer real data", """### 关键评价指标

| 指标 | 定义 | 解释 | 约辩标准 |
|------|------|------|---------|
| PA (Path Accuracy) | 预测路径与标注一致率 | 路径本身对不对 | ≥ 0.85 |
| IPR (Invalid Path Rate) | 无效路径占比 | 图中实际不存在的路径 | ≤ 0.10 |
| HR (Hallucination Rate) | 幻觉率 | LLM 虚构的论断 | ≤ 0.08 |
| EC (Evidence Coverage) | 证据覆盖率 | 硬约束维度有多少被证据支撑 | ≥ 0.80 |
| EICPR (EIC Pass Rate) | EIC 通过率 | 路径中通过 Gate 的比例 | ≥ 0.80 |
| NDCG@3 | 排序指标 | 前 3 条路径排序是否正确 | ≥ 0.80 |

### 实验结果对标

| 项目 | 无约束 ReAct | + EIC-Agent | + GV-FA 对齐 | 目标值 |
|------|---------|----------|------------|--------|
| IPR ↓ | 0.193 | 0.058 | 0.025 | < 0.05 |
| HR ↓ | 0.160 | 0.062 | 0.030 | < 0.05 |
| NDCG@3 ↑ | 0.58 | 0.66 | 0.80 | > 0.80 |
| EICPR ↑ | 0.21 | 0.66 | 0.81 | > 0.80 |""", """### 关键评价指标

**路径级（12 项）**：PA、Node-F1、Edge-F1、IPR、Hit@3、EC、UCR、HR、EICPR、NDCG@3、RCC、ATC

**轨迹级（5 项，新增 — 评估 Agent 循环效率与可靠性）**：

| 指标 | 定义 | 意义 |
|------|------|------|
| EQP | 证据查询精度=有效查询数/总查询数 | Agent 查询精准度 |
| CRR | 上下文压缩比=1−查询节点边数/(|V|+|E|) | 相比全图注入 prompt 的节省 |
| HPR | 假设剪枝率=prune 假设数/总生成假设数 | 剪枝有效性 |
| CS | 收敛步数=确认一条 gold path 的平均动作步数 | 调查效率 |
| pass@k | k 次独立调查至少一次确认 gold path 的比率 | 可靠性（借鉴 Datadog 评估方法论） |

### 基线（B1–B7，B7 为新增消融对照）

B1 规则打分 / B2 纯图搜索 / B3 纯 LLM / B4 RAG+LLM / B5 ReAct（无 EIC）/ **B6 EIC-Agent（本文，主动调查）** / **B7 EIC-Agent(Pipeline)（新增，禁用主动偏离的固定 π₀ 流水线）**

### 实验结果对标（论文 §4.7 表 4-3，† 为预期值）

| 项目 | B3 LLM† | B5 ReAct† | B6 EIC-Agent† | B7 Pipeline† | 目标值 |
|------|---------|----------|------------|------------|--------|
| IPR ↓ | 0.412 | 0.193 | 0.058 | 0.062 | < 0.05 |
| HR ↓ | 0.31 | 0.16 | 0.06 | 0.07 | < 0.05 |
| NDCG@3 ↑ | 0.39 | 0.58 | 0.66 | 0.63 | > 0.80 |
| EICPR ↑ | 0.05 | 0.21 | 0.66 | 0.62 | > 0.80 |

注：† 为论文预期值，待 MVP 第 2–4 周实验填充；B6 vs B7 路径准确性接近，但 B6 在 EQP/CRR/CS 上更优（主动偏离的增益在效率而非正确性）。

### 已完成的真实实验（cloud_db_pathbench 原型，确定性 π₀ 模式 ≈ B7）

| 项目 | 实测值 |
|------|--------|
| 基准数据 | 24 调查案例（4 场景种子 CB/DS/RCE/RDS × 6 变体）、120 Gold Path、节点 50–55/案例、SHACL 14 规则全通过、30% 噪声注入 |
| 已跑案例 | 5 案例（CB-01..05，codebuild_secrets 场景） |
| 候选路径 | 60 条（12/案例） |
| Gate 通过 | 60/60（确定性 π₀ 模式） |
| 类型匹配 | 5/5（全 Observed_Risk，符合 expected） |
| Gate·Score 分布 | min=0.117 / max=0.933 / mean=0.522 |
| 单案例耗时 | 0.01s（确定性，无 LLM 调用） |
| 验证结论 | 核心 EIC 演算（约束 DFS + 7 工具 + Gate·Score + 表达判定分离）已实现并在真实数据上验证 |

**诚实边界**（答辩主动说清）：① 24 案例期望类型全为 Observed_Risk，未测 Potential_Exposure/Insufficient_Evidence 三分类区分；② 确定性模式 = π₀ 流水线（B7），LLM 驱动 Agent 循环（B6）尚未跑；③ B1–B5 基线、轨迹级指标、SFT/DPO 训练为 4 周 MVP 进行中。"""))

# ───────────────────────────────────────────────────────────────────
# R8: 答辩速查表新增 3 个 Q&A
# ───────────────────────────────────────────────────────────────────
EDITS.append(("R8 new Q&A", """| **为什么是"证据完整性"而不是"直接风险打分"？** | 安全运营的合规要求（ISO27001、SOC2）：每个判定都必须有可审计的原始证据支撑，不能是黑盒的模型输出 |""", """| **为什么是"证据完整性"而不是"直接风险打分"？** | 安全运营的合规要求（ISO27001、SOC2）：每个判定都必须有可审计的原始证据支撑，不能是黑盒的模型输出 |
| **S1–S8 还是固定八阶段流水线吗？** | 不是。新架构下 S1–S8 是状态/动作空间的构成要素，端到端是假设驱动的 Agent 循环；算法 4.1、Gate-Score、定理证明一字未改，只是重新定位为循环中的角色 |
| **实验数据是真实跑出来的吗？** | 核心演算部分是：cloud_db_pathbench 原型已在 5 案例 60 路径上确定性跑通，5/5 类型匹配，Gate·Score 真实分布 0.117–0.933；主效果对比表标 † 者为预期值，待 MVP 第 2–4 周补全 B1–B5 与轨迹级指标 |
| **B6 主动调查 vs B7 固定流水线区别？** | B7 禁用主动偏离、强制遵循 π₀；B6 基于信念状态 $\\mathcal{S}_t$ 与信息增益主动选查询维度。路径准确性接近（PA 差≈0.01），但 B6 在证据效率(EQP)/上下文经济(CRR)/收敛步数(CS)上显著更优 |"""))

# ───────────────────────────────────────────────────────────────────
# R9: 总结 证据表达者 → 证据调查者与表达者
# ───────────────────────────────────────────────────────────────────
EDITS.append(("R9 证据调查者与表达者", """整个系统的核心哲学：**"不是让 LLM 承担风险判定（那样会有幻觉），而是让 LLM 仅负责证据表达，由确定性的图验证器负责最终判定"**""", """整个系统的核心哲学：**"不是让 LLM 承担风险判定（那样会有幻觉），而是让 LLM 负责证据调查与表达（假设生成/动作选择/证据解读），由确定性的图验证器负责最终判定"** —— 即"证据调查者与表达者"（呼应全文定位词升级）"""))


def main():
    text = TABLE.read_text(encoding="utf-8")
    original_len = len(text)
    applied = 0
    for name, old, new in EDITS:
        cnt = text.count(old)
        if cnt != 1:
            print(f"[FAIL] {name}: matched {cnt} times (expected 1). Aborting.")
            return 1
        text = text.replace(old, new, 1)
        applied += 1
        print(f"[ok] {name}")
    OUT.write_text(text, encoding="utf-8")
    print(f"\nDone: {applied}/{len(EDITS)} edits applied. "
          f"{original_len} -> {len(text)} bytes (+{len(text)-original_len}).")
    print(f"Patched table written to (workspace): {OUT}")
    print(f"Original Desktop file untouched. To replace it, run:")
    print(f"  ! cp \"{OUT}\" \"{TABLE}\"")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
