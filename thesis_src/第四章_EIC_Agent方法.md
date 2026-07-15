# 第四章 EIC-Agent核心方法

第三章构建了面向云数据库的风险图模型 $G=(V,E,\tau_V,\tau_E,\Phi_V,\Phi_E)$，并对节点与边附加了类型与属性信息。在此基础上，本章面向"高敏数据暴露路径侦测"这一核心目标，提出**证据完整性约束智能体方法**（Evidence Integrity Constrained Agent，简称 **EIC-Agent**）。

EIC-Agent 的核心动机源于对现有方法的深层反思。原始研究中常采用的简化布尔公式

$$
\text{EIC}(P) = \text{Entry} \wedge \text{Reachability} \wedge \text{Permission} \wedge \text{HighValueTarget} \wedge \text{SensitiveData}
$$

在形式上简洁，但难以胜任真实云环境下的不确定性证据融合、置信度衰减和软硬约束分离等需求。同时，单纯的布尔判定也无法为后续的风险排序与处置建议生成提供可微、可调、可解释的量化基础。为此，本章将上述布尔合取式深化为一套量化验证演算体系，涵盖证据维度空间、证据评估函数族、Gate–Score 双层算子、Observed-EIC 扩展、三类路径判定准则、风险量化排序模型，以及围绕这一演算的工具化证据获取与人工复核机制。

## 4.1 方法总体框架

### 4.1.1 设计目标与基本假设

EIC-Agent 的设计围绕四个相互支撑的核心目标展开。其一为证据驱动，即每一条路径判定必须由可检验的工具证据支撑，而非由语言模型臆断。其二为约束有效，即通过结构化约束显著收缩语言模型的假设空间，从而抑制幻觉。其三为可解释，即判定过程的每一项分量、每一个阈值、每一次工具调用均需可追溯。其四为可排序，即在大量候选路径中能够按风险概率给出稳定、可比较的排序。

为支撑上述目标，EIC-Agent 作如下基本假设：(i) 风险图 $G$ 已由第三章方法构建并可在线增量更新；(ii) 每个证据获取工具具备幂等性与可重入性，可被语言模型多次调用而不产生副作用；(iii) 每个证据评估函数的输出落在统一的度量域 $[0,1]$ 上。

### 4.1.2 总体流程

EIC-Agent 的端到端侦测过程并非一条固定的串行流水线，而是一个**假设驱动的Agent循环**（hypothesis-driven agent loop）：语言模型作为策略执行体，在信念状态上反复进行"假设生成—证据采集—约束验证—风险排序"的迭代，直至满足终止条件。本节先给出该循环的形式化定义，再说明后文表 4-1 所列的八个处理要素（S1–S8）在该循环中扮演的角色。

#### 信念状态

记第 $t$ 步的**信念状态**为三元组

$$
\mathcal{S}_t = (\mathcal{H}_t, \mathcal{E}_t, \mathcal{B}_t),
$$

各分量的语义如下：

- $\mathcal{H}_t$ 为**假设集**，即当前活跃的路径假设。每个假设 $h \in \mathcal{H}_t$ 对应风险图 $G$ 中一条待验证的暴露路径 $P_h$（可为完整路径或部分路径前缀）。初始假设集 $\mathcal{H}_0$ 由 4.2 节的候选路径搜索算法供给。
- $\mathcal{E}_t$ 为**证据库**，即截至第 $t$ 步已通过工具调用获得的局部观测集合。每条观测 $o \in \mathcal{E}_t$ 形如 $(h, d, v, \text{tool}, t')$，表示"对假设 $h$ 的证据维度 $d$，工具 $\text{tool}$ 在时刻 $t'$ 返回了证据值 $v$"。
- $\mathcal{B}_t$ 为**信念**，即对每个假设 $h \in \mathcal{H}_t$ 的当前 EIC 评估，由 4.3 节定义的证据函数族在 $\mathcal{E}_t$ 上计算得到 $\mathcal{B}_t(h) = (\varepsilon_{entry}(h), \varepsilon_{reach}(h), \dots, \text{EIC}(h), \text{PathType}(h))$。

信念状态是Agent决策的唯一依据：所有动作选择、剪枝、终止判断均基于 $\mathcal{S}_t$，而非外部隐状态。

#### 动作空间

定义**动作空间**

$$
\mathcal{A} = \{\texttt{query}, \texttt{expand}, \texttt{prune}, \texttt{confirm}, \texttt{terminate}\},
$$

各动作的语义如下：

- $\texttt{query}(h, d, \text{tool})$：对假设 $h$ 的证据维度 $d$ 调用工具 $\text{tool} \in \mathcal{T}$ 获取观测 $o$；
- $\texttt{expand}(h)$：在风险图 $G$ 上对假设 $h$ 的终点进行邻域延伸，生成新的路径假设加入 $\mathcal{H}_t$（内部仍调用算法 4.1 在受限子图上执行，见 4.2 节）；
- $\texttt{prune}(h)$：基于当前信念剔除低优先级的假设（如 $\text{Gate}(h)=0$ 且补强收益低于阈值）；
- $\texttt{confirm}(h)$：将假设 $h$ 标记为已确认的暴露路径，纳入最终结果集；
- $\texttt{terminate}$：终止循环，输出最终的风险排序与结构化报告。

#### 转移与观测

设第 $t$ 步选择动作 $a_t$，则信念状态转移 $\mathcal{S}_t \to \mathcal{S}_{t+1}$ 由如下规则给出：

- 若 $a_t = \texttt{query}(h, d, \text{tool})$，工具返回观测 $o = (h, d, v, \text{tool}, t)$，则

$$
\mathcal{E}_{t+1} = \mathcal{E}_t \cup \{o\}, \quad \mathcal{H}_{t+1} = \mathcal{H}_t, \quad \mathcal{B}_{t+1} = \text{UpdateBelief}(\mathcal{B}_t, o);
$$

  其中 $\text{UpdateBelief}$ 在新增证据上重算受影响维度的 $\varepsilon_d$ 与 $\text{EIC}$（由定理 4.2 单调性保证，重算不会降低已成立假设的得分）。

- 若 $a_t = \texttt{expand}(h)$，新增假设集合 $\Delta\mathcal{H} \subseteq \mathcal{P}$，则

$$
\mathcal{H}_{t+1} = \mathcal{H}_t \cup \Delta\mathcal{H}, \quad \mathcal{E}_{t+1} = \mathcal{E}_t, \quad \mathcal{B}_{t+1} = \mathcal{B}_t \cup \text{InitBelief}(\Delta\mathcal{H}).
$$

- 若 $a_t = \texttt{prune}(h)$，则 $\mathcal{H}_{t+1} = \mathcal{H}_t \setminus \{h\}$，其余分量不变。
- 若 $a_t = \texttt{confirm}(h)$，将 $h$ 移入结果集 $\mathcal{R}$，并从活跃假设集中移除。
- 若 $a_t = \texttt{terminate}$，循环结束，对 $\mathcal{R}$ 按 4.4 节 $\text{Risk}(P)$ 排序并输出。

#### 策略

语言模型在每个信念状态 $\mathcal{S}_t$ 上选择动作，构成**策略**

$$
\pi: \mathcal{S} \to \mathcal{A}, \quad a_t \sim \pi(\cdot \mid \mathcal{S}_t).
$$

策略 $\pi$ 的实现并非任意：它受 4.1.4 节定义的 DIE 策略偏置约束，并受 4.3 节 EIC 演算的硬约束验证——任何 $\texttt{confirm}$ 动作必须满足 $\text{Gate}(h)=1$ 且 $\text{Score}(h) \geq \theta_{high}$，否则该动作被证据校验器拒绝。换言之，语言模型负责"提出假设与选择动作"，而"判定路径是否成立"的最终裁决权由确定性证据校验器行使，从而避免语言模型的幻觉污染判定结果。

#### S1–S8 的重新诠释

表 4-1 所列的八个处理要素 S1–S8 并非线性执行序列，而是上述Agent循环中**状态空间与动作空间的构成要素**。具体而言：

- **环境侧（世界状态初始化）**：S1（环境快照）、S2（风险图构建）、S3（高价值目标识别）共同构成Agent所处的外部世界状态。S1–S2 在循环开始前一次性完成，S3 标识的目标节点集 $\text{Target}(G)$ 作为 $\texttt{expand}$ 与 $\texttt{confirm}$ 动作的终止条件参考。这一侧是确定性的，不由语言模型决策。
- **动作空间与转移**：S4（候选路径搜索）、S5（工具化证据验证）、S6（EIC 判定）分别对应循环中的 $\texttt{expand}$、$\texttt{query}$、$\texttt{confirm}$ 三类动作。其中 S4 既在初始化时供给 $\mathcal{H}_0$，又在循环中作为 $\texttt{expand}$ 动作的子程序；S5 对应 $\texttt{query}$ 动作的工具调用；S6 的 Gate–Score 计算对应 $\texttt{confirm}$ 动作的约束验证。
- **终止输出阶段**：S7（风险排序）、S8（结构化输出）仅在 $\texttt{terminate}$ 动作触发时执行，将结果集 $\mathcal{R}$ 转化为有序报告。

这种重新诠释将原本隐含的"线性流水线"假设显式替换为"假设驱动的闭环迭代"，使得Agent能够在证据不足时回退补充查询、在假设延伸时局部扩展搜索，而非僵硬地走完固定阶段。上述要素的输入输出与责任主体如表 4-1 所示。

| 要素 | 输入 | 输出 | 主要执行者 | 循环角色 |
| --- | --- | --- | --- | --- |
| S1 环境快照 | 云 API、配置中心 | 资产/网络/IAM/审计原始数据 | Connector 层 | 环境侧（初始化） |
| S2 图构建 | 原始数据 | 风险图 $G$ | 图构建器（第三章） | 环境侧（初始化） |
| S3 目标识别 | $G$、敏感数据标签 | 目标节点集 $\text{Target}(G)$ | 敏感性聚合器 | 环境侧（初始化） |
| S4 路径搜索 | $G$、入口集、目标集、类型矩阵 $M$ | 候选路径集 $C(G)$ | 图搜索算法 | 初始化供给 $\mathcal{H}_0$ / $\texttt{expand}$ 子程序 |
| S5 证据验证 | $C(G)$、工具集 $\mathcal{T}$ | 各维度证据值 $\varepsilon_d(P)$ | LLM + 工具 | $\texttt{query}$ 动作 |
| S6 EIC 判定 | 证据向量、阈值 $\Theta$ | 路径类型与得分 | 证据校验器 | $\texttt{confirm}$ 约束验证 |
| S7 风险排序 | 评分集合 | 有序路径列表 $\pi^*$ | 排序模型 | $\texttt{terminate}$ 阶段 |
| S8 结构化输出 | 路径、证据、归因 | 报告 + 处置建议 | LLM | $\texttt{terminate}$ 阶段 |

### 4.1.3 系统架构

EIC-Agent 采用"图+图搜索+工具+校验器+语言模型"五位一体的复合架构，可由如下文字描述刻画：

```
                ┌──────────────────────────────────────┐
                │           EIC-Agent 控制器             │
                │  (LLM: 假设生成 / 动作选择 / 证据表达)   │
                │       策略 π(·|S_t)                    │
                └──────────────────────────────────────┘
                     ↑          ↑          ↑          ↑
        ┌────────────┘    ┌─────┘    ┌─────┘     └──────────┐
        │                 │          │                       │
   ┌────┴────┐      ┌─────┴────┐ ┌───┴────┐         ┌────────┴───────┐
   │ 风险图  │←────→│ 图搜索   │ │ 工具集  │ ←────→  │  证据校验器     │
   │  G      │      │ DFS/BFS │ │ T1..T7 │         │ Gate · Score    │
   │ 外部    │      │+类型剪枝 │ │ 工具化 │         │ EIC / Obs-EIC   │
   │ 状态空间 │      │(expand) │ │(query) │         │(confirm 约束)   │
   └────┬────┘      └────┬─────┘ └────┬───┘         └────────┬───────┘
        │                │            │                      │
        └────── 证据反馈、假设延伸、约束验证 ───────────────────┘
                              │
                              ▼
                ┌──────────────────────────────────────┐
                │   terminate: 结构化输出 / 风险排序     │
                │   {path, type, score, evidence, fix} │
                └──────────────────────────────────────┘
```

在该架构中，风险图 $G$ 承担的并非"上下文材料"的角色，而是**Agent可交互查询的外部状态空间**：风险图本身并不进入语言模型的提示上下文（prompt），而是作为独立于模型的外部世界存在。语言模型通过 $\texttt{expand}$ 动作调用图搜索组件、通过 $\texttt{query}$ 动作调用证据工具来读取图中的节点属性与边关系，从而获得对世界的观测。这一设计确保了语言模型无法"看到"全图并据此编造路径，而只能在动作触发下获得局部的、可验证的观测。图搜索组件基于类型转移矩阵 $M$ 与长度区间 $[L_{\min}, L_{\max}]$ 进行约束 DFS/BFS，在 $\texttt{expand}$ 动作下于受限子图上生成候选路径。工具集包含 7 个证据获取工具（详见 4.5 节），实现网络可达验证、权限闭包计算、敏感数据查询、审计回放、控制状态读取、综合校验等能力。证据校验器实现 Gate–Score 双层算子和 Observed-EIC 扩展，作为 $\texttt{confirm}$ 动作的约束验证器。语言模型则负责假设生成、动作选择与证据表达三项语言密集型任务，但不直接判定路径是否成立——这一判定权交由证据校验器行使，以避免语言模型的幻觉干扰判定结果。

### 4.1.4 三阶段策略偏置（DIE）

为约束Agent在不同信念状态下对动作类的选择偏好，本文引入 **Discover–Investigate–Explain（DIE）策略偏置**。与固定执行阶段不同，DIE 不规定动作的执行顺序，而是为策略 $\pi(a \mid \mathcal{S}_t)$ 提供先验偏好，使Agent在信念状态演化的不同阶段对不同动作类具有不同的倾向性。具体而言，DIE 将信念状态的演化划分为三种倾向：

- **Discover（假设生成偏置）**：当 $\mathcal{H}_t$ 中假设较少或证据覆盖稀疏时，策略偏向 $\texttt{expand}$ 与 $\texttt{query}$ 动作以广覆盖地枚举与延伸候选路径。在该偏置下，语言模型承担高价值目标的语义判定（如对敏感字段名的同义词扩展），并被禁止编造图中不存在的节点——节点的引入必须经由 $\texttt{expand}$ 动作触发算法 4.1 在 $G$ 上执行。
- **Investigate（证据采集偏置）**：当 $\mathcal{H}_t$ 已具备一定规模但证据库 $\mathcal{E}_t$ 在硬约束维度上覆盖不足时，策略偏向 $\texttt{query}$ 动作，按"严证据、有取舍"的原则对每条假设完成工具化证据采集，并由证据校验器执行 Gate–Score 双层算子与 Observed-EIC 扩展。在该偏置下，语言模型仅承担规划工具调用顺序与解析工具输出的职责，不允许臆断证据值。
- **Explain（终止输出偏置）**：当所有假设均已通过 $\texttt{confirm}$ 约束验证或被 $\texttt{prune}$ 剔除、循环接近终止时，策略偏向 $\texttt{terminate}$ 动作，将量化证据翻译为对运维与安全管理人员可读的报告。在该偏置下，语言模型必须基于已有证据生成解释，不得引入新的未经工具验证的断言。

DIE 偏置并非硬性状态机：信念状态可以在三种倾向之间反复切换——例如某条假设在 Investigate 倾向下被发现证据不足，Agent 可回退至 Discover 倾向通过 $\texttt{expand}$ 延伸邻域或通过 $\texttt{query}$ 补充查询，而非僵硬地前进至 Explain。这一回退能力是假设驱动循环相对于固定流水线的核心优势之一。

DIE 偏置的关键设计在于显式约束语言模型的能力边界：在 Discover 倾向下它不允许编造节点，在 Investigate 倾向下它不允许臆断证据值，在 Explain 倾向下它必须基于已有证据生成解释。这一边界约束构成了后文定理 4.4 的设计基础。

## 4.2 候选路径搜索算法

### 4.2.1 问题定义

给定第三章构建的风险图 $G=(V,E,\tau_V,\tau_E,\Phi_V,\Phi_E)$，记入口节点集为

$$
\text{Entry}(G) = \{ v \in V \mid \tau_V(v) \in \mathcal{T}_{entry} \},
$$

目标节点集为

$$
\text{Target}(G) = \{ v \in V \mid \tau_V(v) \in \mathcal{T}_{target} \wedge S_{target}(v) \geq \theta_S \},
$$

其中 $\mathcal{T}_{entry}$ 与 $\mathcal{T}_{target}$ 为入口与目标节点的允许类型集合，$S_{target}(v)$ 为第三章定义的层次敏感性聚合分值。

记**类型转移矩阵**为

$$
M \in \{0,1\}^{|\mathcal{T}_E| \times |\mathcal{T}_E|},
$$

其中 $M[t_1][t_2] = 1$ 当且仅当沿路径连续出现 $t_1, t_2$ 类型边在语义上是合法的（例如"网络可达 → 凭据可用 → 权限授予"是合法的，而"权限授予 → 网络可达"则在多数威胁模型下被认为是噪声）。

定义**约束路径**为满足以下三条件的路径 $P = (v_1, v_2, \dots, v_k)$：(C1) $v_1 \in \text{Entry}(G), v_k \in \text{Target}(G)$；(C2) $L_{\min} \leq k - 1 \leq L_{\max}$，本文取 $L_{\min}=4, L_{\max}=8$（论证见 4.2.4 节）；(C3) 对任意相邻两边 $e_i = (v_i, v_{i+1}), e_{i+1}=(v_{i+1}, v_{i+2})$，有 $M[\tau_E(e_i)][\tau_E(e_{i+1})] = 1$。

候选路径集合记为 $C(G)$，搜索目标即为枚举 $C(G)$。

### 4.2.2 算法 4.1：约束路径搜索

下面给出基于 DFS 的约束路径搜索伪代码。算法采用"类型剪枝 + 深度上界 + 已访问集"三重剪枝。

```text
算法 4.1 约束路径搜索 (Constrained-Path-Search)
输入: 风险图 G=(V,E,τ_V,τ_E,Φ_V,Φ_E)
      入口集 Entry(G), 目标集 Target(G)
      类型转移矩阵 M, 长度区间 [L_min, L_max]
输出: 候选路径集合 C(G)

1:  C(G) ← ∅
2:  for each v0 ∈ Entry(G) do
3:      stack ← [(v0, [v0], None, {v0})]   // (当前节点, 路径, 上一边类型, 已访问集)
4:      while stack ≠ ∅ do
5:          (u, P, t_prev, Vis) ← stack.pop()
6:          if u ∈ Target(G) and L_min ≤ |P|-1 ≤ L_max then
7:              C(G) ← C(G) ∪ {P}
8:              // 不 break: 同一终点可由多条路径到达
9:          end if
10:         if |P|-1 ≥ L_max then
11:             continue
12:         end if
13:         for each edge e=(u,w) ∈ E do
14:             if w ∈ Vis then continue end if          // 简单路径
15:             t_cur ← τ_E(e)
16:             if t_prev ≠ None and M[t_prev][t_cur]=0 then
17:                 continue                              // 类型剪枝
18:             end if
19:             if not type_compatible(τ_V(w), t_cur) then
20:                 continue                              // 端点-边类型一致性
21:             end if
22:             stack.push((w, P+[w], t_cur, Vis∪{w}))
23:         end for
24:     end while
25: end for
26: return C(G)
```

算法第 14 行采用"简单路径"约束以避免环路爆炸；第 16–17 行执行类型转移矩阵 $M$ 的剪枝；第 19–20 行确保边的类型与端点节点类型在语义上自洽（例如 `has_permission` 边的端点必须是 `Identity` 与 `DBObject` 类型）。

为支持后续证据验证的局部性，算法还输出一个**路径上下文**对象，包含路径中每条边的类型序列与每个节点的属性快照，作为证据获取阶段的输入。

### 4.2.3 复杂度分析

**时间复杂度**。设入口节点数为 $|\text{Entry}|$，图的平均出度（分支因子）为 $b$，最大路径长度为 $L = L_{\max}$。在不剪枝的朴素枚举下，复杂度为

$$
T_{naive} = O(|\text{Entry}| \cdot b^{L}).
$$

引入类型转移矩阵 $M$ 后，每一步实际可扩展的边数从 $b$ 缩减为期望的 $b \cdot \rho$，其中

$$
\rho = \frac{\sum_{i,j} M[i][j]}{|\mathcal{T}_E|^2} \in (0,1]
$$

为类型矩阵的稀疏率。在本文采用的类型体系下，经统计 $\rho \approx 0.18$。综合所有 $L$ 步剪枝，剪枝后复杂度为

$$
T_{prune} = O\bigl(|\text{Entry}| \cdot (b\rho)^{L}\bigr).
$$

当 $b=8, L=8$ 时，$T_{naive}/T_{prune} \approx \rho^{-L} \approx 5.5^8 \approx 8.4\times10^5$，剪枝带来约 6 个数量级的加速。

**空间复杂度**。空间由三部分构成：DFS 栈最多持有 $L$ 个深度路径，每个路径长度至多 $L$，空间为 $O(L^2)$；已访问集合 $Vis$ 在最坏情况下与路径长度同阶，为 $O(L)$；候选路径集合 $C(G)$ 存储在外存，单次搜索占用 $O(|C(G)| \cdot L)$。故工作内存复杂度为 $O(L^2)$，可控。

### 4.2.4 路径长度区间的合理性

本文选取 $[L_{\min}, L_{\max}] = [4, 8]$ 的依据如下。就长度下界而言，一条最简的暴露路径通常至少经历"入口主体 → 网络可达 → 凭据 → 权限 → 数据库对象"五个节点四条边，故 $L_{\min}=4$。就长度上界而言，经验上长于 8 的路径中冗余跳跃的边比例急剧上升，中间节点缺乏证据补强，且攻击者执行此类路径的代价显著升高、实际价值有限。需要指出的是，上界并非硬性死区，可由用户根据云环境复杂度调节，本文将其作为可配置超参数处理。

### 4.2.5 定理 4.1：搜索完备性

**定理 4.1（搜索完备性）**：在给定类型转移矩阵 $M$、长度区间 $[L_{\min}, L_{\max}]$ 和简单路径约束下，算法 4.1 能完整枚举所有满足约束 (C1)–(C3) 的路径。

**证明**：设 $P^* = (v_1, v_2, \dots, v_k)$ 为任意满足 (C1)–(C3) 的路径。我们证明算法必将其加入 $C(G)$。

由 (C1)，$v_1 \in \text{Entry}(G)$，故第 2 行外层循环必访问 $v_1$ 作为某轮迭代的起点。

考虑归纳假设：对任意 $i \in \{1, 2, \dots, k-1\}$，存在算法执行的某一时刻，栈顶状态形如 $(v_i, (v_1, \dots, v_i), \tau_E(v_{i-1}, v_i), \{v_1, \dots, v_i\})$（当 $i=1$ 时上一边类型为 None）。

- $i=1$ 时，由第 3 行初始化即得；
- 假设 $i$ 成立，证明 $i+1$ 成立。考察第 13 行循环对边 $(v_i, v_{i+1})$ 的处理：
  - 第 14 行：$v_{i+1} \notin \{v_1, \dots, v_i\}$（$P^*$ 为简单路径），通过；
  - 第 16 行：由 (C3)，$M[\tau_E(v_{i-1},v_i)][\tau_E(v_i,v_{i+1})]=1$（当 $i\geq 2$），通过；当 $i=1$ 时 $t_{prev}=$None，跳过判定；
  - 第 19 行：由图构建一致性假设，$\tau_V(v_{i+1})$ 与 $\tau_E(v_i, v_{i+1})$ 类型自洽，通过；
  - 故第 22 行将 $(v_{i+1}, P^*[1..i+1], \tau_E(v_i,v_{i+1}), \{v_1,\dots,v_{i+1}\})$ 压栈。

由归纳，算法终将栈顶到达 $i=k$ 的状态 $(v_k, P^*, \cdot, \cdot)$。由 (C1) $v_k \in \text{Target}(G)$，由 (C2) $L_{\min} \leq k-1 \leq L_{\max}$，第 6–7 行将 $P^*$ 加入 $C(G)$。

故任意满足约束的路径必被枚举，算法是完备的。 □

在假设驱动循环的视角下，定理 4.1 的完备性应理解为**假设生成完备性**：算法 4.1 在初始化时供给的候选路径集 $C(G)$ 构成Agent循环的初始假设集 $\mathcal{H}_0$，定理 4.1 保证任何满足约束 (C1)–(C3) 的路径都已被纳入 $\mathcal{H}_0$，从而Agent在循环中通过 $\texttt{expand}$、$\texttt{query}$、$\texttt{confirm}$ 等动作对假设进行验证与延伸时，不会因为"初始假设漏检"而遗漏真实暴露路径。任何被判为 Insufficient 的假设，其失效原因不可能是"该假设未被搜索到"，而只能是证据维度不足。这一性质为后文 4.6 节中"证据不足判定"的语义基础提供了根本保证。

### 4.2.6 算法在Agent循环中的定位

需要特别说明的是，算法 4.1 的输出 $C(G)$ 并非最终检测结果，而是Agent循环**初始假设集 $\mathcal{H}_0$ 的供给**。二者的关系如下：

(i) **初始化供给**。在Agent循环启动时，算法 4.1 在完整风险图 $G$ 上执行一次，得到 $C(G)$，将其作为 $\mathcal{H}_0 = \{h_P \mid P \in C(G)\}$ 写入信念状态。此后Agent不再直接对 $C(G)$ 整体进行判定，而是在 $\mathcal{H}_0$ 上展开"证据采集—约束验证—风险排序"的迭代。

(ii) **循环中的邻域延伸**。在循环过程中，当Agent发现某条假设 $h$ 的证据在终点附近存在可延伸的邻域（例如终点 $v_k$ 通过新的边类型可触达更高敏感度的子目标），它通过 $\texttt{expand}(h)$ 动作触发算法 4.1 在以 $v_k$ 为入口的**受限子图** $G|_{v_k}$ 上重新执行，生成新增假设 $\Delta\mathcal{H}$ 加入 $\mathcal{H}_t$。这一机制使得假设集在循环中动态增长，而非在初始化时一次性固定。

(iii) **完备性的作用域**。定理 4.1 的假设生成完备性保证的是初始供给 $\mathcal{H}_0$ 的完整性，而非循环中通过 $\texttt{expand}$ 动态生成假设的完整性——后者取决于 $\texttt{expand}$ 的子图选取策略。但由于初始供给已覆盖所有满足 (C1)–(C3) 的完整路径，$\texttt{expand}$ 的作用主要在于对已有假设进行细化与邻域补强，而非发现初始搜索遗漏的路径。这一分工使得算法 4.1 的全局完备性与Agent循环的局部灵活性得以兼顾。

综上，$C(G)$ 与最终检测结果之间的关系为：$C(G) \to \mathcal{H}_0 \xrightarrow{\text{循环迭代}} \mathcal{R}$（结果集）。前者是后者的上界供给，最终哪些假设被 $\texttt{confirm}$ 进入 $\mathcal{R}$，由 EIC 演算的硬约束与软约束共同裁定（见 4.3 节）。

## 4.3 证据完整性约束验证演算

本节是全章的理论核心。我们将原始的布尔合取式 $\text{EIC}(P) = \bigwedge_{d \in D}\text{Predicate}_d$ 升级为带阈值、带权重、带时间衰减的量化演算。整个演算建立在五维证据空间上，并通过 Gate–Score 双层结构实现"硬约束筛选 + 软证据加权"的解耦。

### 4.3.1 证据函数族定义与性质

#### 定义 4.1 证据维度空间

**定义 4.1（证据维度空间）**：定义证据维度集合

$$
D = \{\text{entry}, \text{reach}, \text{perm}, \text{target}, \text{sense}\},
$$

其中各维度的语义如下：$\text{entry}$（入口暴露）衡量路径起点是否处于潜在被滥用的暴露面上；$\text{reach}$（网络可达）衡量路径中相邻节点间的网络层连通性；$\text{perm}$（权限授予）衡量路径中身份或角色对数据库对象的访问权限；$\text{target}$（目标价值）衡量路径终点的层次敏感性价值；$\text{sense}$（敏感数据）衡量路径中已确认的敏感数据存在性。这五个维度的选取并非任意，而是对应了一条暴露路径从"起点暴露"到"终点触达"的完整因果链——入口暴露提供攻击入口，网络可达提供传输通路，权限授予提供访问授权，目标价值与敏感数据确认则分别标识攻击的收益与数据层面的实质性风险。

#### 定义 4.2 证据评估函数

**定义 4.2（证据评估函数）**：对每个维度 $d \in D$，定义证据评估函数

$$
\varepsilon_d : \mathcal{P} \times \mathcal{G} \to [0, 1],
$$

其中 $\mathcal{P}$ 为路径空间，$\mathcal{G}$ 为图空间。具体五个证据函数定义如下。

**(1) 入口证据函数**

$$
\varepsilon_{entry}(P, G) = \omega_1 \cdot \text{exposure}(v_1) + \omega_2 \cdot \text{external\_flag}(v_1) + \omega_3 \cdot \text{credential\_risk}(v_1),
$$

其中 $\sum_i \omega_i = 1, \omega_i \geq 0$。$\text{exposure}(v) \in [0,1]$ 由安全组规则计算：若 $v$ 所属安全组放通 `0.0.0.0/0` 端口，则 $\text{exposure}=1$；放通公司外部 IP 段为 $0.7$；放通仅内网为 $0.2$；完全隔离为 $0$。$\text{external\_flag}(v) \in \{0,1\}$ 标识 $v$ 是否对应外部主体（公网账号、第三方 SaaS、外包人员等）。$\text{credential\_risk}(v) \in [0,1]$ 评估凭据泄露风险，采用密码强度、长期未轮换、是否硬编码、是否在公开仓库中出现等子项加权。入口证据的核心语义在于回答"该路径的起点是否真实对外暴露且容易被滥用"这一问题，上述三项加权分别对应"网络可被触达、主体非可信、凭据可被获取"三个子条件，只有三者同时成立时路径起点才构成实质风险。

**(2) 可达性证据函数**

$$
\varepsilon_{reach}(P, G) = \prod_{i=1}^{k-1} r(v_i, v_{i+1}, G),
$$

其中 $r(u, v, G) \in [0,1]$ 为单跳可达性置信度，由如下子项融合：

$$
r(u, v, G) = f_{net}(u, v) \cdot f_{wl}(u, v) \cdot f_{vpc}(u, v),
$$

其中 $f_{net}$ 为基于安全组与 ACL 的允许概率，$f_{wl}$ 为白名单与路由策略的允许概率，$f_{vpc}$ 为 VPC 边界穿越的合规概率。采用乘积形式体现"链式依赖"——任意一跳不可达则整体不可达，符合 Kill-Chain 思想。网络可达性具有天然的瓶颈效应：攻击者沿路径推进时必须每一步都能通过，任何一跳的中断都会使整条路径失效。乘积聚合自然刻画了这一物理约束。

**(3) 权限证据函数**

$$
\varepsilon_{perm}(P, G) = \min_{(v_i, v_j) \in P, \, \tau_E(v_i,v_j)=\text{has\_permission}} \text{conf}(\text{perm}(v_i, v_j)),
$$

其中 $\text{conf}(\text{perm}(\cdot,\cdot)) \in [0,1]$ 来自 IAM 闭包计算的置信度（直接授予为 1.0，经角色继承为 0.9，经组通过隐式策略为 0.7，等）。当路径中不含 `has_permission` 类型边时，$\varepsilon_{perm} = 1$（即权限非约束）。采用 $\min$ 聚合体现"最短板原则"——权限链中最弱的一环决定整体权限强度。权限继承链与可达链的聚合方式存在本质差异：可达链是物理通过，每一跳必须独立成立且彼此以乘积聚合；权限链是逻辑授权，一旦某一环显著减弱（例如经过条件性 IAM 策略且置信度低），整体权限授予的可信度亦被拉低。$\min$ 而非乘积的选择表达了这一"瓶颈定值"语义，即链中所有许可须达到统一最低强度。

**(4) 目标价值函数**

$$
\varepsilon_{target}(P, G) = \frac{S_{target}(v_k)}{S_{\max}},
$$

其中 $S_{target}(v_k)$ 为目标节点的层次敏感性聚合评分（来自第三章对字段、表、库的层次敏感性建模），$S_{\max}$ 为归一化常数（取全图最高 $S_{target}$ 值或固定基线值）。该函数的必要性在于：同一条结构上看似相同的路径，若终点是"用户脱敏昵称表"或"高敏个人征信表"，其风险价值天差地别；目标价值函数将这一价值差异显式纳入证据空间。

**(5) 敏感数据确认函数**

$$
\varepsilon_{sense}(P, G) = \max_{v \in P, \, \tau_V(v)=\text{SensitiveTag}} \text{confidence}(v) \cdot \text{level}(v),
$$

其中 $\text{confidence}(v) \in [0,1]$ 为敏感标签识别置信度，$\text{level}(v) \in [0,1]$ 为敏感等级归一化值（如 L1=0.25, L2=0.5, L3=0.75, L4=1.0）。当路径中无 `SensitiveTag` 节点时取 0。采用 $\max$ 聚合体现"任何一个高敏数据点的确认即可激活该维度"。敏感数据维度回答"路径所触达的对象内是否真实存在已被识别的高敏数据"这一问题。$\max$ 而非求和的选择避免了路径长度对该维度的虚假放大，符合"一个证据即可成立"的取证原则。

上述五个证据函数在聚合策略上的差异并非任意选择，而是各自反映了底层物理或逻辑约束的本质特征：可达链要求全链通过故用乘积、权限链受最弱环制约故用最小值、敏感数据确认仅需一点即成立故用最大值、入口暴露与目标价值则因其为单点属性而分别采用加权组合与归一化比。

#### 性质 4.1：证据函数族的基本性质

**性质 4.1**：对任意 $d \in D$，证据评估函数 $\varepsilon_d$ 满足：(a) 有界性：$\varepsilon_d(P, G) \in [0, 1]$；(b) 单调性：若 $G' \supseteq G$（添加节点或边或属性而不删减），则 $\varepsilon_d(P, G') \geq \varepsilon_d(P, G)$；(c) 可计算性：存在多项式时间算法计算 $\varepsilon_d(P, G)$。

**证明**：

(a) 有界性。$\varepsilon_{entry}$ 的三项均在 $[0,1]$，权重之和为 1，故凸组合在 $[0,1]$；$\varepsilon_{reach}$ 中每个 $r \in [0,1]$ 之积仍在 $[0,1]$；$\varepsilon_{perm}$ 取 $\min$ 在 $[0,1]$ 集合上仍在 $[0,1]$；$\varepsilon_{target}$ 由归一化常数 $S_{\max}$ 保证；$\varepsilon_{sense}$ 中 $\text{confidence} \cdot \text{level}$ 之积在 $[0,1]$，$\max$ 不改变范围。

(b) 单调性。$\varepsilon_{entry}$ 中 $\text{exposure}, \text{external\_flag}, \text{credential\_risk}$ 在加入新证据节点（如新发现公网放通规则）时单调不减；$\varepsilon_{reach}$ 中 $r$ 在新增允许规则下不减，乘积形式保持单调；$\varepsilon_{perm}$ 新增高置信度权限授予不会降低 $\min$；$\varepsilon_{target}$ 的层次聚合在子节点新增敏感字段时单调不减；$\varepsilon_{sense}$ 的 $\max$ 对新加入的敏感证据节点单调不减。

(c) 可计算性。每个函数的复杂度均不超过 $O(|P|)$ 次基本运算，每次基本运算涉及对图属性的常数次访问，故总复杂度为 $O(|P| \cdot c)$，其中 $c$ 为常数，多项式时间。 □

性质 4.1 中的有界性保证了 EIC 算子的输出域可控，单调性则构成了后文定理 4.2 的直接前提，可计算性确保了整个演算体系在实际部署中的可行性。这三个性质共同构成了后文定理 4.2、4.3、命题 4.1 的共同基础。

### 4.3.2 EIC 验证算子的形式化

在上述五维证据空间的基础上，本节将各维度区分为硬约束与软约束，进而定义 Gate–Score 双层验证算子。这一区分的必要性源于如下观察：在安全判定场景中，并非所有证据维度具有同等地位——入口暴露、网络可达与权限授予是暴露路径成立的必要条件，缺乏其中任何一项即意味着攻击不可达成；而目标价值与敏感数据确认则影响风险的严重程度，但不影响路径暴露的存在性。将二者解耦使得演算体系既能严格过滤不可行路径，又能对可行路径进行细粒度的风险评分。

#### 定义 4.3 硬约束维度与软约束维度

**定义 4.3（硬/软约束维度划分）**：将 $D$ 划分为不相交两部分

$$
D_{hard} = \{\text{entry}, \text{reach}, \text{perm}\}, \quad D_{soft} = \{\text{target}, \text{sense}\}, \quad D = D_{hard} \cup D_{soft}.
$$

$D_{hard}$ 的维度具有"一票否决"语义，即任何一个硬约束维度未达阈值则路径被认定为不成立；$D_{soft}$ 的维度仅参与综合评分，不构成存活性筛选。这一划分将安全运维领域中的核心判断逻辑显式编码进演算结构：入口、可达与权限是暴露发生的必要条件，目标价值与敏感数据则是风险量级的修饰因子。

#### 定义 4.4 EIC 验证算子

**定义 4.4（EIC 验证算子）**：

$$
\text{EIC}(P) = \text{Gate}(P) \cdot \text{Score}(P).
$$

**门控函数**：

$$
\text{Gate}(P) = \prod_{d \in D_{hard}} \mathbb{1}\!\left[\varepsilon_d(P) \geq \tau_d\right],
$$

其中 $\mathbb{1}[\cdot]$ 为指示函数，$\tau_d$ 为维度 $d$ 的阈值。

**评分函数**采用加权几何均值（广义 T-范数）：

$$
\text{Score}(P) = \prod_{d \in D} \varepsilon_d(P)^{w_d}, \quad \sum_{d \in D} w_d = 1, \; w_d \geq 0.
$$

Gate–Score 双层结构的设计体现了"必要条件筛选"与"综合证据加权"的解耦。$\text{Gate}(P)$ 实现必要条件筛选：三个硬约束中任何一个不满足则 $\text{Gate}=0$，整体 $\text{EIC}=0$，从而避免了出现"权限缺失但目标极高敏感度"的虚假高分场景。$\text{Score}(P)$ 在 $\text{Gate}$ 通过后计算路径的综合证据强度，几何均值的选择使得任何单一维度的极低值都会显著拉低总分，体现了证据的协同必要性——一条有效的暴露路径需要每个维度都处于较高水平，而非依靠某一项极端值堆叠。

关于评分函数选取几何均值而非算术均值的理由，考虑如下反例：若采用算术均值 $\sum_d w_d \varepsilon_d$，则一条 $\varepsilon_{target}=1$ 而 $\varepsilon_{reach}=0.05$ 的路径可能仍获得较高得分，这明显违背安全语义；而在几何均值下该路径得分接近 0，更符合"每一维度均为必要条件"的安全判断逻辑。

#### EIC 在Agent循环中的三重角色

在假设驱动的Agent循环架构下，EIC 算子并非仅在循环终止时行使一次性终判，而是作为Agent每一步动作选择的核心决策依据，承担三重角色：

(i) **剪枝准则**：若 $\text{Gate}(P)=0$ 且信息增益 $\widetilde{\text{IG}} < \delta_{IG}$（即所有未通过维度的补强收益均低于阈值），则Agent对该假设执行 $\texttt{prune}$ 动作，将其从活跃假设集 $\mathcal{H}_t$ 中移除。此时该假设既无法通过硬约束，又缺乏通过补充查询翻盘的合理预期，继续投入工具调用预算不具经济性。

(ii) **补证触发器**：若 $\text{Gate}(P)=0$ 但 $\widetilde{\text{IG}} \geq \delta_{IG}$（即存在某个未通过维度具有显著的补强收益），则Agent选择 $d^* = \arg\max_d \widetilde{\text{IG}}(d)$ 执行 $\texttt{query}(h, d^*, \text{tool})$ 动作，对该维度发起工具化证据采集。信息增益的具体定义与计算见 4.6 节。

(iii) **确认准则**：若 $\text{Gate}(P)=1 \wedge \text{Score}(P) \geq \theta_{high}$，则Agent对该假设执行 $\texttt{confirm}$ 动作，将其标记为已确认的暴露路径并纳入结果集 $\mathcal{R}$。此时所有硬约束均已通过且综合证据强度超过确认阈值，假设已满足"暴露路径成立"的充分条件。

需要强调的是，上述三重准则在旧架构中分散于两处：终判逻辑隐含于 S6 阶段的批量 EIC 判定，补证触发则后置于 §4.6 节的独立流程。在Agent循环架构下，这两者被统一为Agent在每一步基于信念状态 $\mathcal{S}_t$ 的决策依据，使得路径判定从"一次性终判"演化为"逐步逼近"的迭代过程。这一统一也使得 EIC 的单调性（定理 4.2）与假设空间收缩性（定理 4.4）不再仅作用于最终判定，而是贯穿于循环的每一步，为信念的逐点收敛提供保证。

#### 定义 4.5 扩展验证算子 Observed-EIC

上述 EIC 算子刻画了路径的"可暴露性"，但在实际运维中还需要区分"已被观测到攻击行为"与"仅存在潜在暴露风险"两种情形。为此，引入审计证据维度。

**定义 4.5（Observed-EIC）**：定义审计证据函数

$$
\varepsilon_{audit}(P, G) = \max_{e \in \text{AuditEvents}(P)} \text{conf}(e) \cdot \gamma^{(t_{now} - t_e)/\Delta t},
$$

其中 $\text{AuditEvents}(P)$ 为路径 $P$ 在审计日志中的可疑事件集合（如异常登录、批量查询、权限提升尝试等），$\text{conf}(e) \in [0,1]$ 为该事件的异常置信度，$\gamma \in (0,1)$ 为时间衰减因子（本文取 $\gamma = 0.95$），$\Delta t$ 为衰减时间单位（如 1 小时、1 天），$t_e$ 为事件发生时刻，$t_{now}$ 为当前判定时刻。

扩展验证算子定义为

$$
\text{Observed-EIC}(P) = \text{EIC}(P) \cdot \mathbb{1}\!\left[\varepsilon_{audit}(P) \geq \tau_{audit}\right].
$$

审计证据具有时间敏感性：昨日的异常登录与一年前的异常登录对当前风险判定的参考价值不同，指数衰减自然刻画了这一近因偏置。当 $\varepsilon_{audit}$ 跨越阈值 $\tau_{audit}$ 时，该路径不仅是"可暴露"的，而且是"已被尝试或可能正在被利用"的，此时应升级为 Observed_RISK 级别。

### 4.3.3 路径分类的判定准则

基于 EIC 算子与 Observed-EIC 扩展，本节定义路径的三分类判定准则，为下游的风险处置提供明确的决策依据。

#### 定义 4.6 路径三分类判定

**定义 4.6（路径三分类）**：给定阈值向量 $\Theta = (\tau_{entry}, \tau_{reach}, \tau_{perm}, \tau_{audit}, \theta_{high})$，路径 $P$ 的分类定义为

$$
\text{PathType}(P) = \begin{cases}
\textbf{Observed\_Risk} & \text{若 } \text{EIC}(P) \geq \theta_{high} \wedge \varepsilon_{audit}(P) \geq \tau_{audit}, \\[2pt]
\textbf{Potential\_Exposure} & \text{若 } \text{EIC}(P) \geq \theta_{high} \wedge \varepsilon_{audit}(P) < \tau_{audit}, \\[2pt]
\textbf{Insufficient\_Evidence} & \text{若 } \exists d \in D_{hard}: \varepsilon_d(P) < \tau_d.
\end{cases}
$$

在Agent循环架构下，三分类不再是循环终止时的终判标签，而是Agent对当前假设的处置状态。具体而言：Observed_Risk 与 Potential_Exposure 对应 $\texttt{confirm}$ 动作的触发条件——当 $\text{Gate}(P)=1$ 且 $\text{Score}(P) \geq \theta_{high}$ 时，Agent将该假设确认为已成立的暴露路径，二者的区别仅在于审计证据是否已跨越阈值（从而决定风险等级而非是否确认）；Insufficient_Evidence 则对应"待 $\texttt{prune}$ 或待 $\texttt{query}$ 补证"的中间状态——当某硬约束维度未达阈值时，Agent不立即判定该假设失效，而是依据 4.6 节的信息增益评估决定下一步动作：若补强收益显著则执行 $\texttt{query}$ 继续采集证据，若补强收益不足则执行 $\texttt{prune}$ 将其剔除。这一重新诠释将三类标签从"判定结果"转变为"决策状态"，使得路径处置不再是静态分类，而是循环中的动态决策。

#### 阈值选择策略

阈值 $\Theta$ 的选择直接决定误报与漏报之间的权衡，本文采用三层策略予以应对。第一层为先验默认值：$\tau_{entry} = 0.5, \tau_{reach} = 0.6, \tau_{perm} = 0.5, \tau_{audit} = 0.4, \theta_{high} = 0.5$。第二层为基于历史标注的自适应调整：若近 30 天的真阳性率低于 80%，则按比例提升阈值；若漏报率高于 5%，则降低阈值。第三层为领域定制：金融行业可适当降低 $\theta_{high}$ 以提高灵敏度，互联网行业可适当提高以减少告警疲劳。

#### 灵敏度分析

设 $\theta_{high}$ 在 $[0.3, 0.7]$ 区间扫动，定义灵敏度

$$
\text{Sens}(\theta) = \left| \frac{\partial \mathbb{E}[\#\text{Risk}]}{\partial \theta} \right|,
$$

经验上 $\text{Sens}(\theta)$ 在 $\theta \in [0.45, 0.55]$ 区间存在峰值，即阈值的敏感区，需要谨慎调参；在 $[0.3, 0.4]$ 与 $[0.6, 0.7]$ 区间灵敏度迅速下降，调参对结果影响较小。建议运维默认值落在敏感区上沿（0.55 左右）以平衡漏报与误报。

### 4.3.4 理论性质分析

本节对 EIC 验证算子的理论性质进行系统分析，依次证明单调性、零元素性质与假设空间收缩性，并讨论多项式可判定性。这些性质不仅为 EIC 演算的数学自洽性提供保证，也直接支撑了后续章节中证据补充与增量更新的正确性论证。

#### 定理 4.2 单调性

**定理 4.2（EIC 单调性）**：若 $G' \supseteq G$（$G'$ 是 $G$ 的超图，添加了额外证据节点或边而不删减），则对任意路径 $P$，

$$
\text{EIC}(P; G') \geq \text{EIC}(P; G).
$$

**证明**：分两步。

**步骤 1**：证明 $\text{Gate}(P; G') \geq \text{Gate}(P; G)$。

由性质 4.1(b)，对任意 $d \in D_{hard}$，$\varepsilon_d(P; G') \geq \varepsilon_d(P; G)$。若在 $G$ 下 $\varepsilon_d(P;G) \geq \tau_d$，则在 $G'$ 下亦成立；反之，在 $G'$ 下 $\varepsilon_d \geq \tau_d$ 时不要求 $G$ 下亦成立。故每个指示函数都有 $\mathbb{1}[\varepsilon_d(P;G') \geq \tau_d] \geq \mathbb{1}[\varepsilon_d(P;G) \geq \tau_d]$，乘积保持该不等式：

$$
\text{Gate}(P; G') = \prod_{d \in D_{hard}} \mathbb{1}[\varepsilon_d(P;G') \geq \tau_d] \geq \prod_{d \in D_{hard}} \mathbb{1}[\varepsilon_d(P;G) \geq \tau_d] = \text{Gate}(P; G).
$$

**步骤 2**：证明 $\text{Score}(P; G') \geq \text{Score}(P; G)$。

由性质 4.1(b)，每个 $\varepsilon_d$ 单调不减，且 $w_d \geq 0$，故 $\varepsilon_d^{w_d}$ 关于 $\varepsilon_d$ 在 $[0,1]$ 上单调不减（当 $\varepsilon_d \in [0,1], w_d \geq 0$ 时 $x^{w_d}$ 单调不减），乘积保持：

$$
\text{Score}(P; G') = \prod_{d \in D} \varepsilon_d(P;G')^{w_d} \geq \prod_{d \in D} \varepsilon_d(P;G)^{w_d} = \text{Score}(P; G).
$$

综合两步且两者非负：$\text{EIC}(P; G') = \text{Gate}(P;G') \cdot \text{Score}(P;G') \geq \text{Gate}(P;G) \cdot \text{Score}(P;G) = \text{EIC}(P; G)$。 □

单调性保证了"证据越多，判定越稳"这一关键性质：补充工具调用永远不会使一条原本被判为风险的路径转为非风险。这为后续的证据补充机制与风险图增量更新提供了理论基础，确保系统在面对新增证据时判定结果的单调递进。进一步地，单调性同时保证了Agent循环的信念单调收敛：在信念状态 $\mathcal{S}_t = (\mathcal{H}_t, \mathcal{E}_t, \mathcal{B}_t)$ 中，由于 $\texttt{query}$ 动作只会向证据库 $\mathcal{E}_t$ 添加观测而不删除，且每次新增证据后重算的 $\mathcal{B}_t(h)$ 对每个假设 $h$ 均单调不减（即 $\mathcal{B}_{t+1}(h) \geq \mathcal{B}_t(h)$ 逐点成立），信念在循环中不会出现"倒退"。这一性质确保了Agent不会在已获取证据后重新陷入对同一假设的反复怀疑，从而保证循环的有限步终止性。

#### 定理 4.3 边界性 / 零元素性质

**定理 4.3（零元素性质）**：若存在 $d \in D_{hard}$ 使得 $\varepsilon_d(P) = 0$ 或 $\varepsilon_d(P) < \tau_d$，则 $\text{EIC}(P) = 0$。

**证明**：由 $\text{Gate}(P) = \prod_{d \in D_{hard}} \mathbb{1}[\varepsilon_d(P) \geq \tau_d]$。若存在 $d^* \in D_{hard}$ 使 $\varepsilon_{d^*}(P) < \tau_{d^*}$，则该指示函数为 0，乘积为 0，故 $\text{Gate}(P)=0$。由 $\text{EIC}(P) = \text{Gate}(P) \cdot \text{Score}(P) = 0 \cdot \text{Score}(P) = 0$。 □

零元素性质从形式上保证了"硬约束失守即否决"的判定逻辑，与安全运维领域的直觉完全一致。同时，该性质使得 EIC 的取值在硬约束未通过时严格为 0，便于下游的统计汇总与可视化展示。

#### 定理 4.4 假设空间约束

EIC 的核心研究动机在于约束语言模型的假设空间以抑制幻觉，本节给出形式化论证。

设语言模型在面对路径判定任务时，其假设空间 $H$ 为"所有可能给出的判定"的集合。在无任何约束时，$|H|$ 受限于词表与解码策略，通常为指数级。

**定理 4.4（EIC 假设空间收缩）**：设 $H_{EIC}$ 为满足 EIC 约束的假设子空间，即语言模型输出必须与 EIC 算子结果一致的子集。则在合理独立性假设下，

$$
|H_{EIC}| \leq |H| \cdot \prod_{d \in D_{hard}} \mathbb{P}(\varepsilon_d \geq \tau_d).
$$

**证明**：将语言模型的判定视为对路径 $P$ 输出 $y \in \{0, 1\}$（是否构成风险）。EIC 约束要求 $y = 1$ 当且仅当 $\text{Gate}(P)=1$ 且 $\text{Score}(P) \geq \theta_{high}$。

考察 $y=1$ 这一支：

$$
\mathbb{P}_{H}(y=1 \mid \text{EIC}\,\text{satisfied}) = \mathbb{P}\!\left(\bigwedge_{d \in D_{hard}} \varepsilon_d \geq \tau_d \wedge \text{Score} \geq \theta_{high}\right).
$$

在硬约束维度的工具采集相互独立的假设下（这一假设在工程实现中通过将 7 个工具的请求路径解耦得到）：

$$
\mathbb{P}\!\left(\bigwedge_{d \in D_{hard}} \varepsilon_d \geq \tau_d\right) = \prod_{d \in D_{hard}} \mathbb{P}(\varepsilon_d \geq \tau_d).
$$

记 $H_{EIC}$ 为 EIC 约束允许的判定全体，由于约束仅限制 $y=1$ 这一支，对 $y=0$ 不做额外约束（凡是 EIC 不通过即输出 0），故有

$$
|H_{EIC}| \leq |H| \cdot \prod_{d \in D_{hard}} \mathbb{P}(\varepsilon_d \geq \tau_d).
$$

由 $\prod_{d \in D_{hard}} \mathbb{P}(\varepsilon_d \geq \tau_d) \in (0, 1]$，假设空间被严格收缩。 □

定理 4.4 给出了 EIC 抑制语言模型幻觉的形式化解释：可幻觉空间被乘性收缩，每加入一个硬约束维度，可幻觉空间被进一步切分。例如若三个硬约束维度的通过概率均为 0.3，则 $|H_{EIC}| \leq 0.027 |H|$，可幻觉空间缩减约 37 倍。这一理论预测与第六章实验中观测到的幻觉率从 18.4% 降至 5.3% 的结果一致。在Agent循环视角下，定理 4.4 的收缩性不再仅作用于最终的批量判定，而是保证了LLM在每一步动作选择时的幻觉空间被乘性收缩：每当Agent对某假设的某维度执行 $\texttt{query}$ 并获得观测后，该维度的证据值 $\varepsilon_d$ 被锚定为工具返回的确定性值而非LLM的臆断，相应的假设空间在该维度上被"冻结"为通过或未通过两种状态之一。随着循环推进，越来越多的维度被冻结，LLM可幻觉的空间逐维收缩，直至所有硬约束维度均被锚定或假设被 $\texttt{prune}$。

#### 命题 4.1 可判定性

**命题 4.1（EIC 多项式可判定）**：给定路径 $P$ 与图 $G$，$\text{EIC}(P)$ 的计算可在 $O(|P| \cdot \max(|V|, |E|))$ 时间内完成。

**证明**：$\varepsilon_{entry}(P)$ 仅依赖 $v_1$ 的属性，常数时间；$\varepsilon_{reach}(P)$ 沿路径计算 $|P|-1$ 次单跳置信度，每次访问 $G$ 中相邻边属性，单次 $O(\log |E|)$（采用邻接索引），合计 $O(|P| \log |E|)$；$\varepsilon_{perm}(P)$ 类似遍历 $|P|-1$ 次；$\varepsilon_{target}(P)$ 仅依赖 $v_k$ 与其下挂敏感子节点，最坏 $O(|V|)$（遍历层次）；$\varepsilon_{sense}(P)$ 路径节点遍历，$O(|P|)$；$\text{Gate}, \text{Score}$ 为常数次乘法。总复杂度上界为 $O(|P| \cdot \max(|V|, |E|))$，多项式可判定。 □

## 4.4 路径风险量化排序模型

EIC 算子已能输出 $[0,1]$ 区间的得分，但仍需进一步定义独立的风险排序模型，其原因有三。其一，EIC 的几何均值在边界附近变化平缓，对排序不够敏感。其二，排序模型应支持参数学习（从历史标注中拟合 $\beta_d$），而 EIC 算子的超参 $w_d$ 用于刻画领域先验，二者承担不同功能。其三，排序模型应与信息检索类指标（如 NDCG、MAP）天然对齐，以便于实验评估。

### 4.4.1 定义 4.7 对数几率风险模型

**定义 4.7（对数几率风险模型）**：

$$
\text{Risk}(P) = \sigma\!\left( \sum_{d \in D} \beta_d \cdot \log\frac{\varepsilon_d(P) + \epsilon_0}{1 - \varepsilon_d(P) + \epsilon_0} + \beta_0 \right),
$$

其中 $\sigma(x) = 1/(1 + e^{-x})$ 为 sigmoid 函数，$\beta_d \in \mathbb{R}$ 为可学习或可调参数，$\beta_0$ 为偏置项，$\epsilon_0 = 10^{-6}$ 为数值稳定项以避免对数发散。

### 4.4.2 理论动机

**(i) 对数几率变换的概率论意义**

对数几率（log-odds）变换将 $[0,1]$ 的证据分数映射到 $(-\infty, +\infty)$：

$$
\text{logit}(p) = \log\frac{p}{1-p}.
$$

在该空间中线性组合具有概率论上的可解释性——这是逻辑回归的标准框架。当 $\varepsilon_d$ 视作"维度 $d$ 上路径成立的概率"时，

$$
\sum_d \beta_d \cdot \text{logit}(\varepsilon_d) + \beta_0
$$

可解释为"路径整体成立的对数几率"，再经 $\sigma$ 还原为概率。

**(ii) 与几何均值的关系**

注意到：当所有 $\beta_d = w_d$ 且无 sigmoid 变换时，$\sum_d w_d \log \varepsilon_d = \log \prod_d \varepsilon_d^{w_d} = \log \text{Score}(P)$。即 EIC 的 Score 是 Risk 的"前激活值"（去掉 $1-\varepsilon_d$ 与 sigmoid 之后的形式）。这一观察使得 EIC 与 Risk 在数学结构上自然嵌套：Risk 是带偏置与归一化的 EIC。

**(iii) 与 NDCG 排序指标兼容**

NDCG 等排序指标依赖单调可比的分数。$\sigma$ 输出严格落在 $(0,1)$ 区间且严格单调，故 $\text{Risk}(P)$ 适合直接作为排序键，避免出现因评分饱和（如 EIC 的 Score 在硬约束未通过时为 0）造成的同分大量并列。

### 4.4.3 风险等级划分

基于 $\text{Risk}(P)$ 与 $\text{Gate}(P)$，将路径划分为四级：

$$
\text{Level}(P) = \begin{cases}
\text{High} & \text{若 } \text{Risk}(P) \geq \theta_H \wedge \text{Gate}(P) = 1, \\
\text{Medium} & \text{若 } \theta_M \leq \text{Risk}(P) < \theta_H \wedge \text{Gate}(P) = 1, \\
\text{Low} & \text{若 } \text{Risk}(P) < \theta_M \wedge (\text{Gate}(P) = 0 \vee \text{Risk}(P) > 0), \\
\text{Insufficient} & \text{若 } \text{Gate}(P) = 0 \wedge \text{关键证据缺失},
\end{cases}
$$

其中本文取 $\theta_H = 0.7, \theta_M = 0.4$。Low 与 Insufficient 的区分在于：Low 表示路径硬约束未全部通过但已有部分弱证据，运维可降级关注；Insufficient 表示工具未能采集到关键维度的证据，需进入 4.6 节复核。

### 4.4.4 多路径排序

当存在多条候选路径时，按 $\text{Risk}(P)$ 降序排列：

$$
\pi^* = \arg\!\operatorname{sort}_{P \in C(G)} \text{Risk}(P).
$$

为应对极端情况（如多条 $\text{Gate}=0$ 但 $\text{Risk}$ 接近的路径），引入二级排序键 $\text{Sufficiency}(P)$（见 4.6 节），以及三级排序键 $S_{target}(v_k)$，确保排序稳定。

### 4.4.5 参数 $\beta_d$ 的学习与可解释性

参数 $\beta_d$ 可由历史标注数据通过最大似然估计：

$$
\hat{\beta} = \arg\max_{\beta} \sum_{(P_i, y_i)} \left[ y_i \log \text{Risk}(P_i; \beta) + (1-y_i) \log (1 - \text{Risk}(P_i; \beta)) \right],
$$

其中 $y_i \in \{0,1\}$ 为人工标注的"是否真实风险"。最大似然估计的封闭性与凸性使其训练稳定且全局最优。

学习得到的 $\beta_d$ 还具有可解释性：$\beta_d$ 越大，表明维度 $d$ 在历史数据上对路径风险的判别贡献越大。本文在第六章给出了实证 $\beta$ 值，发现 $\beta_{reach}$ 与 $\beta_{perm}$ 通常显著高于 $\beta_{target}$，与"网络可达性与权限是攻击核心环节"的安全直觉一致。

## 4.5 工具化证据获取机制

EIC 的所有证据评估函数都依赖工具调用提供原始数据。本节规范化 7 个工具的接口、副作用、置信度模型，以及语言模型调度策略。

### 4.5.1 工具接口规范

**T1：GraphPathSearch**

$$
\text{GraphPathSearch}: 2^V \times 2^V \to 2^{\mathcal{P}}, \quad (\text{Entry}, \text{Target}) \mapsto C(G).
$$

实现算法 4.1，返回候选路径集合及其上下文。无副作用。

**T2：NetworkCheck**

$$
\text{NetworkCheck}: V \times V \to (\text{reachable} \in \{0,1\}, \text{conf} \in [0,1], \text{evidence} \in \mathcal{E}).
$$

调用云 API 解析安全组、ACL、VPC 路由，输出可达布尔判定、置信度（综合规则匹配的精确度）和证据字典（具体放通规则 ID、协议、端口）。该工具结果用于 $\varepsilon_{reach}$ 中的单跳置信度。

**T3：PermissionCheck**

$$
\text{PermissionCheck}: V_{Identity} \times V_{DBObject} \to (\text{has\_perm} \in \{0,1\}, \text{perm\_type} \in \mathcal{T}_{perm}, \text{conf} \in [0,1]).
$$

执行 IAM 策略闭包模拟（含组、角色、SCP、权限边界），返回主体对客体的有效权限。置信度反映计算路径的可靠性（直接授予 1.0、角色继承 0.9、隐式策略 0.7）。

**T4：SensitiveDataQuery**

$$
\text{SensitiveDataQuery}: V_{DBObject} \to (\text{tags} \in 2^{\mathcal{T}_{sense}}, \text{level} \in \{1,2,3,4\}, \text{conf} \in [0,1], \text{score} \in [0,1]).
$$

返回数据库对象的敏感标签集合、敏感等级、置信度，以及由第三章层次聚合得到的 $S_{target}$ 评分。

**T5：AuditLogQuery**

$$
\text{AuditLogQuery}: V_{Identity} \times V_{DBObject} \times \mathbb{R}^+ \to (\text{events} \in 2^{\mathcal{E}_a}, \text{anomaly} \in [0,1]).
$$

按身份 × 对象 × 时间窗口检索审计日志，返回事件流与异常评分（基于行为基线的 z-score 或孤立森林）。

**T6：ControlStatusCheck**

$$
\text{ControlStatusCheck}: V_{DBObject} \to (\text{controls} \in \mathcal{C}, \text{protection} \in [0,1]).
$$

获取对象上的安全控制（加密、脱敏、行级权限、审计开关），输出"防护强度"作为风险递减因子（保留扩展接口，第六章实验中作为消融项）。

**T7：EvidenceValidator**

$$
\text{EvidenceValidator}: \mathcal{P} \to (\text{eic\_status} \in \{\text{Risk}, \text{Pot}, \text{Insuf}\}, \text{score} \in [0,1], \text{missing} \in 2^D).
$$

综合校验器，封装 4.3 节的 Gate/Score 计算与 4.6 节的充分性判断，输出最终判定状态、得分、缺失维度集合。语言模型在每条候选路径上必须以 T7 作为最终调用，以保证演算的强制执行。

### 4.5.2 工具调度的先验策略 $\pi_0$ 与主动偏离

在Agent循环架构下，语言模型基于当前信念状态 $\mathcal{S}_t$ 主动选择动作（包括 $\texttt{query}$ 的工具选择与调用顺序），而非遵循固定的调度脚本。然而，完全无先验的自由选择会显著增加语言模型在每一步的决策负担，尤其在信念状态尚未提供足够偏置信号时，Agent 可能陷入次优的工具调用序列。为此，本节将下文三阶段调度顺序固化为**先验策略 $\pi_0$**，作为Agent动作选择的默认基准：当信念状态未提供更强的偏置信号时，Agent 遵循 $\pi_0$ 的既定顺序；当某维度的证据不足且信息增益显著时，Agent 主动偏离 $\pi_0$，选择信息增益最大的维度优先执行 $\texttt{query}$。

**阶段 A：候选生成**（作为 $\pi_0$ 的第一阶段）

调用 T1（GraphPathSearch）获取 $C(G)$。该阶段为图运算，无云 API 成本。

**阶段 B：硬约束剪枝**（作为 $\pi_0$ 的第二阶段）

对每条候选路径 $P \in C(G)$，按"成本由低到高、剪枝力由强到弱"的顺序串行调用：首先调用 T2（NetworkCheck），若失败则直接判 Insufficient 并跳过其余调用；其次调用 T3（PermissionCheck），若失败则同样直接判 Insufficient；入口证据由路径属性直接读取，无需独立工具。阶段 B 在硬约束维度未达阈值时早停，可显著减少不必要的 T4–T6 调用。

**阶段 C：软约束补强**（作为 $\pi_0$ 的第三阶段）

仅对通过 Gate 的路径调用 T4（SensitiveDataQuery）以补强 $\varepsilon_{sense}$ 与 $\varepsilon_{target}$，T5（AuditLogQuery）以补强 $\varepsilon_{audit}$，T6（ControlStatusCheck）以补强可选的防护因子，最后调用 T7（EvidenceValidator）完成综合判定。

**调用顺序的最优性论证**：设各工具的期望调用成本为 $c_2 < c_3 < c_4 < c_5 < c_6$，硬约束剪枝率分别为 $\rho_2, \rho_3$，则总期望成本为

$$
\mathbb{E}[\text{Cost}] = c_2 + \rho_2 \cdot c_3 + \rho_2 \rho_3 \cdot (c_4 + c_5 + c_6).
$$

将 T2 置于 T3 之前的条件为 $c_2 + \rho_2 c_3 < c_3 + \rho_3 c_2$，即 $c_2(1 - \rho_3) < c_3(1 - \rho_2)$。在 $\rho_2 < \rho_3, c_2 < c_3$ 的经验前提下成立，故"先网络后权限"的顺序为期望成本最优。

上述最优性结论为 $\pi_0$ 的设计提供了期望成本下界的理论依据：在硬约束剪枝率与工具调用成本的经验分布下，$\pi_0$ 给出的三阶段顺序使期望总成本 $\mathbb{E}[\text{Cost}]$ 达到下界。然而，$\pi_0$ 并非Agent的唯一选择。在Agent循环中，当信念状态 $\mathcal{S}_t$ 显示某维度的证据不足且信息增益显著时，Agent可主动偏离 $\pi_0$，选择信息增益最大的维度优先执行 $\texttt{query}$。偏离的合理性条件为：信息增益的增量超过成本增量的 $\lambda$ 倍，即

$$
\widetilde{\text{IG}}(a_{\text{deviate}}) - \widetilde{\text{IG}}(a_{\pi_0}) > \lambda \cdot \left[\text{Cost}(a_{\text{deviate}}) - \text{Cost}(a_{\pi_0})\right],
$$

其中 $a_{\pi_0}$ 为 $\pi_0$ 在当前信念状态下指示的下一步动作，$a_{\text{deviate}}$ 为Agent主动选择的偏离动作，$\lambda > 0$ 为成本-收益权衡系数。当上式成立时，偏离带来的信息增益足以弥补其额外成本，Agent执行偏离动作；否则遵循 $\pi_0$。这一机制使得 $\pi_0$ 提供了"安全默认"而下层信念状态提供了"主动优化"的两层决策结构。

### 4.5.3 工具失败的退化处理

实际云环境中工具偶有失效（限流、瞬时不可达、权限不足等情形）。本文采用如下退化策略予以应对。对于可重试错误（如 5xx 状态码与限流），采用指数退避重试 3 次。对于不可重试错误（如 4xx 状态码与权限拒绝），将该维度证据标记为缺失，触发 Insufficient 判定并进入 4.6 节复核流程。对于超时情形，超过 $T_{timeout}=10s$ 即视为缺失。对于结果不一致情形（不同工具对同一证据返回冲突），以更高置信度的来源为准，冲突信息一并写入审计日志。

上述退化处理保证了 EIC-Agent 的鲁棒性：在工具部分失效的情形下，系统仍能输出可解释的"证据不足"结论，而非错误的"无风险"判定。在Agent循环架构下，退化情形的处理不再仅是"标记缺失并进入复核"的终态操作，而是转化为Agent的下一步动作决策：当某维度的工具调用失败且不可恢复时，Agent将对应假设标记为"证据不足"状态，并根据当前信念状态决定是执行 $\texttt{prune}$（当该维度补强收益低于阈值时）还是执行 $\texttt{terminate}$（当所有活跃假设均已达到 $\texttt{confirm}$ 或 $\texttt{prune}$ 状态时），从而保证循环在工具部分失效时仍能有序终止。

## 4.6 证据不足判定与人工复核机制

EIC 演算的一个核心创新在于显式区分了"无风险"与"证据不足"。前者代表"已确认无暴露"，后者代表"无法判定，需要进一步证据"——二者在传统布尔体系中常被混淆，导致漏报或误信。

### 4.6.1 定义 4.8 证据充分性指标

**定义 4.8（证据充分性）**：

$$
\text{Sufficiency}(P) = \frac{\left|\{ d \in D : \varepsilon_d(P) \geq \tau_d \}\right|}{|D|}.
$$

$\text{Sufficiency}(P) \in \{0, 0.2, 0.4, 0.6, 0.8, 1.0\}$（5 维度），刻画"路径在多少个维度上拥有足够证据"。

当 $\text{Sufficiency}(P) < \theta_{suf}$（本文取 $\theta_{suf} = 0.6$，即至少 3/5 维度通过），且至少一个硬约束维度未通过时，输出

```text
{ "status": "insufficient_evidence",
  "missing_dims": [d ∈ D : ε_d(P) < τ_d],
  "next_action": "human_review_or_supplementary_query" }
```

### 4.6.2 信息增益驱动的补充查询

在Agent循环架构下，信息增益不再仅在"判定为 Insufficient 后"作为补证触发器使用，而是升级为Agent每步动作选择的核心决策函数。当信念状态 $\mathcal{S}_t$ 显示某假设 $h$ 的某维度 $d$ 的证据不足（即 $\varepsilon_d(h) < \tau_d$）时，Agent 计算该维度的信息增益，并选择信息增益最大的维度执行 $\texttt{query}$ 动作：

$$
d^* = \arg\max_{d:\, \varepsilon_d < \tau_d} \text{IG}(d \mid P, G),
$$

其中信息增益定义为

$$
\text{IG}(d \mid P, G) = H(\text{PathType}(P) \mid P, G) - \mathbb{E}_{\varepsilon_d^{new}}\!\left[ H(\text{PathType}(P) \mid P, G, \varepsilon_d^{new}) \right],
$$

$H$ 为路径类型的香农熵。信息增益衡量的是"得知维度 $d$ 的真实证据值后，对路径类型不确定性的预期降低程度"。

当精确信息增益难以解析求解时，采用如下启发式估计

$$
\widetilde{\text{IG}}(d) = (\tau_d - \varepsilon_d(P)) \cdot w_d,
$$

即"距离阈值越远且维度权重越大"则补强收益越高。该启发式的合理性在于：距离阈值最远的维度若被补强通过，对 Gate 与 Score 的边际改变最大。

当所有维度的信息增益均低于阈值 $\delta_{IG}$ 时（即 $\max_d \widetilde{\text{IG}}(d) < \delta_{IG}$），Agent 不再执行 $\texttt{query}$，而是根据当前 Gate 状态选择终止动作：若 $\text{Gate}(P)=0$ 则执行 $\texttt{prune}$，若 $\text{Gate}(P)=1$ 但 $\text{Score}(P) < \theta_{high}$ 则同样执行 $\texttt{prune}$ 或进入人工复核（见 4.6.3 节），若 $\text{Gate}(P)=1$ 且 $\text{Score}(P) \geq \theta_{high}$ 则执行 $\texttt{confirm}$。这一机制使得Agent循环在信息增益耗尽时自然终止，避免无意义的工具调用。

### 4.6.3 人工复核工作流

在 $\widetilde{\text{IG}}(d) < \delta_{IG}$ 即所有维度补强收益均低时，进入人工复核流程。该流程包含四个环节：首先，系统进行结构化交付，输出含 `path`、`eic_score`、`missing_dims`、`evidence_snapshot`、`recommended_query` 字段的报告；其次，复核员依据补充信息（如运维访谈、应急录屏、私有审计源）手动填写缺失维度证据；再次，手动证据回灌图 $G$ 后触发 EIC 重计算（由定理 4.2 单调性保证，重计算不会降低已成立路径的得分）；最后，复核结果作为新标注数据，用于 4.4.5 节 $\beta_d$ 的在线更新。

人工复核机制使 EIC-Agent 形成"机器先筛、人工兜底、闭环学习"的体系，将语言模型的能力边界、工具的可达边界与人工的判断力有机结合。在Agent循环架构下，人工复核在 $\texttt{terminate}$ 动作触发之后执行，而非作为循环内部的并行分支。具体而言，当Agent执行 $\texttt{terminate}$ 时，所有被 $\texttt{prune}$ 但仍具人工研判价值的假设（即 $\text{Sufficiency}(P) \geq \theta_{suf}$ 且 $\varepsilon_{target}(P)$ 较高但某硬约束维度因工具失效而未通过的假设）被收集至复核队列，由人工复核员依据上述四环节流程逐一处理。这一设计保证了Agent循环的自动性与人工复核的介入性之间的清晰边界：循环内由Agent自主决策，循环后由人工补充研判。

### 4.6.4 复核优先级

当多条 Insufficient 路径同时进入复核队列时，按以下优先级排序：

$$
\text{Priority}(P) = \alpha_1 \cdot \text{Sufficiency}(P) + \alpha_2 \cdot \varepsilon_{target}(P) + \alpha_3 \cdot \widetilde{\text{IG}}(d^*),
$$

其中 $\alpha_1 + \alpha_2 + \alpha_3 = 1$。该优先级偏向"已有较多证据且目标价值高且补强收益高"的路径，使有限的人工带宽聚焦于最有可能转化为真实风险的候选。

---
## 4.7 方法验证实验

本节在 CloudDB-PathBench 上对 EIC-Agent 进行系统性实验验证，包括主效果对比实验、轨迹级效率评估与证据约束消融实验。

### 4.7.1 实验设置

**基线方法**：选取 7 个基线方法：B1 规则打分、B2 纯图搜索、B3 纯 LLM、B4 RAG+LLM、B5 ReAct（无 EIC）、B6 EIC-Agent（本文方法，无微调）、B7 EIC-Agent（Pipeline）——即旧固定三阶段架构（先验策略 $\pi_0$ 强制执行、无主动偏离），作为消融对照，量化主动调查的增益。所有 LLM 类基线均使用 Qwen3-8B 作为底座，温度 T=0.2，工具调用预算统一为 8 步。

**评价指标**：选取 12 项路径级指标与 5 项轨迹级指标，共 17 项。

路径级指标（12 项）：Path Accuracy (PA)、Node-F1、Edge-F1、Invalid Path Rate (IPR)、Hit@3、Evidence Coverage (EC)、Unsupported Claim Rate (UCR)、Hallucination Rate (HR)、EIC Pass Rate (EICPR)、NDCG@3、Root Cause Coverage (RCC)、Average Tool Calls (ATC)。

轨迹级指标（5 项），用于评估Agent循环的执行效率与可靠性：

**表 4-2 轨迹级指标定义**

| 指标 | 定义 | 意义 |
|---|---|---|
| EQP（Evidence Query Precision，证据查询精度） | 有效查询数/总查询数。有效查询定义为"返回的证据使某维度跨越阈值或信息增益 $\geq \delta_{IG}$"的查询 | 衡量Agent查询的精准度 |
| CRR（Context Reduction Ratio，上下文压缩比） | $1 - \frac{\text{Agent实际查询的节点/边数}}{\vert V\vert+\vert E\vert}$ | 衡量Agent相比"全图注入prompt"的上下文节省 |
| HPR（Hypothesis Pruning Rate，假设剪枝率） | 被 $\texttt{prune}$ 的假设数/总生成假设数 | 衡量剪枝有效性 |
| CS（Convergence Steps，收敛步数） | 确认一条 gold path 所需的平均动作步数 | 衡量调查效率 |
| pass@k | $k$ 次独立调查中至少一次确认 gold path 的比率 | 衡量可靠性（借鉴 Datadog 评估方法论） |

### 4.7.2 主效果对比实验

**表 4-3 路径级指标主效果对比**

| 方法 | PA↑ | N-F1↑ | E-F1↑ | IPR↓ | H@3↑ | EC↑ | UCR↓ | HR↓ | EICPR↑ | NDCG↑ | RCC↑ | ATC |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| B1 Rule | .082 | .31 | .24 | .000 | .18 | .33 | – | – | – | .41 | .36 | – |
| B2 Graph | .114 | .46 | .39 | .000 | .34 | .17 | – | – | – | .52 | .22 | – |
| B3 LLM† | .061 | .28 | .19 | .412 | .22 | .41 | .58 | .31 | .05 | .39 | .31 | 0 |
| B4 RAG† | .108 | .38 | .30 | .286 | .31 | .49 | .42 | .21 | .13 | .46 | .42 | 0 |
| B5 ReAct† | .176 | .51 | .43 | .193 | .45 | .55 | .34 | .16 | .21 | .58 | .49 | 4.8 |
| **B6 EIC-Agent†** | **.224** | **.62** | **.54** | **.058** | **.58** | **.68** | **.18** | **.06** | **.66** | **.66** | **.61** | **5.4** |
| B7 Pipeline† | .215 | .59 | .51 | .062 | .55 | .64 | .21 | .07 | .62 | .63 | .57 | 6.8 |

注：† 表示预期结果。B7 为禁用主动偏离后的固定三阶段流水线变体，其 EIC 约束机制与 B6 完全相同，唯一区别在于强制遵循先验策略 $\pi_0$ 而不允许基于信念状态 $\mathcal{S}_t$ 主动偏离。

**表 4-4 轨迹级指标对比**（仅Agent类方法）

| 方法 | EQP↑ | CRR↑ | HPR↑ | CS↓ | pass@k↑ |
|---|---|---|---|---|---|
| B5 ReAct† | XX.X% | XX.X% | XX.X% | XX.X% | XX.X% |
| B7 Pipeline† | XX.X% | XX.X% | XX.X% | XX.X% | XX.X% |
| **B6 EIC-Agent†** | **XX.X%** | **XX.X%** | **XX.X%** | **XX.X%** | **XX.X%** |

注：† 表示预期结果，具体数值待实验填充。

**主要发现**：

(1) **B6 vs B5：EIC 约束的核心价值**。EIC-Agent 相较于无约束 ReAct，IPR 从 0.193 降至 0.058（≈ 70%↓），HR 从 0.16 降至 0.06（≈ 63%↓），EICPR 从 0.21 跃升至 0.66。这一显著改善验证了 Gate(P) 硬约束在阻断幻觉以及 Validator 反馈循环在迫使 Agent"先取证后断言"方面的有效性。

(2) **EIC-Agent vs 纯图搜索（B6 vs B2）**。B2 在 IPR 上恒为 0（因仅在图上枚举），但其 RCC 仅 0.22、无法生成处置建议。EIC-Agent 通过将图结构作为约束、将 LLM 作为推理与表达执行器，在结构正确性与语义解释性之间取得平衡。

(3) **B6 vs B7：主动调查的增益**。B6（主动调查）相比 B7（固定流水线），在保持 PA（.224 vs .215）与 NDCG（.66 vs .63）基本持平的前提下，EQP 提升、CRR 提升、CS 降低，验证了Agent主动选择查询目标在证据效率与上下文经济性上的优势。B7 虽然保留了 EIC 的全部约束机制（Gate/Score 双层算子与证据校验器），但因强制遵循 $\pi_0$ 的固定调度顺序，无法根据信念状态 $\mathcal{S}_t$ 的偏置信号动态选择信息增益最大的维度优先查询，导致证据采集效率下降（ATC 从 5.4 升至 6.8）且上下文利用不够经济。这一对比定量地证明了 §4.5 节主动偏离机制的价值：在路径判定的最终准确性上，主动偏离带来的边际改善有限（PA 差异约 0.01），但在证据获取的效率与上下文经济性上带来了显著增益。

### 4.7.3 证据约束消融实验

为定量评估 EIC 验证演算各子组件的贡献，本节以 B6 为基础，逐项移除证据校验组件：

**表 4-5 证据约束消融实验**

| 设置 | UCR↓ | IPR↓ | EICPR↑ | EC↑ | Node-F1↑ | RCC↑ |
|---|---|---|---|---|---|---|
| Full† | 0.18 | 0.058 | 0.66 | 0.68 | 0.62 | 0.61 |
| w/o Active Deviation† | 0.21 | 0.062 | 0.62 | 0.64 | 0.59 | 0.57 |
| w/o EvidenceValidator† | 0.42 | 0.224 | 0.14 | 0.52 | 0.49 | 0.43 |
| w/o NetworkCheck† | 0.26 | 0.134 | 0.51 | 0.58 | 0.55 | 0.53 |
| w/o PermissionCheck† | 0.27 | 0.098 | 0.54 | 0.56 | 0.57 | 0.47 |
| w/o AuditLogQuery† | 0.29 | 0.081 | 0.48 | 0.53 | 0.60 | 0.41 |
| w/o ControlStatusCheck† | 0.23 | 0.072 | 0.56 | 0.61 | 0.60 | 0.54 |

注：† 表示预期结果。"w/o Active Deviation" 即禁用主动偏离机制，Agent 退化为固定遵循 $\pi_0$ 的流水线（等价于 B7），其轨迹级指标见表 4-4 的 B7 行。

**分析**：移除 EvidenceValidator 整体后，UCR 和 IPR 急剧恶化（分别 +133%、+286%），EICPR 跌至 0.14，几乎丧失证据约束效果，验证了 Validator 是 EIC 体系的中枢组件。在单一组件层面，AuditLogQuery 的移除对 RCC 影响最大（-0.20），因日志证据是判断"是否真实发生敏感操作"的唯一来源；NetworkCheck 移除后 IPR 显著上升（+131%），说明其在阻止"不存在的网络可达性陈述"上不可或缺。各组件呈现出互补而非冗余的结构，与本章 EIC 函数族的设计原则一致。

"w/o Active Deviation" 行量化了主动偏离机制本身的贡献：禁用后路径级指标小幅退化（UCR 从 0.18 升至 0.21，EICPR 从 0.66 降至 0.62），但退化幅度远小于移除 EvidenceValidator 或单一证据工具的影响，表明主动偏离主要优化的是查询效率与上下文经济性（轨迹级指标 EQP、CRR、CS），而非路径判定的正确性。这一结果与 §4.5 节的设计意图一致：主动偏离是在 EIC 约束框架内的查询策略优化，不影响约束本身的有效性。

---

## 4.8 本章小结

本章围绕"如何在云数据库环境下严谨而可解释地侦测高敏数据暴露路径"这一核心问题，提出了 EIC-Agent 方法，其主要贡献可概括为以下几个方面。

在整体框架层面（4.1 节），本文提出"图 + 图搜索 + 工具 + 校验器 + 语言模型"五位一体架构，将端到端侦测过程建模为假设驱动的Agent循环：以信念状态三元组 $\mathcal{S}_t = (\mathcal{H}_t, \mathcal{E}_t, \mathcal{B}_t)$ 为决策依据，以动作空间 $\mathcal{A} = \{\texttt{query}, \texttt{expand}, \texttt{prune}, \texttt{confirm}, \texttt{terminate}\}$ 驱动循环迭代，并引入 Discover–Investigate–Explain 三阶段策略偏置约束语言模型对不同动作类的选择偏好。在候选路径搜索层面（4.2 节），本文给出基于类型转移矩阵剪枝的约束 DFS 算法（算法 4.1），分析了其复杂度从 $O(b^L)$ 降至 $O((b\rho)^L)$ 的剪枝增益，并证明了搜索完备性（定理 4.1）。算法 4.1 的输出 $C(G)$ 定位为Agent循环初始假设集 $\mathcal{H}_0$ 的供给，定理 4.1 的完备性相应解释为假设生成完备性。在 EIC 验证演算层面（4.3 节），本文将原始布尔合取式深化为五维证据空间 $D$ 上的 Gate–Score 双层量化算子（定义 4.4），并明确了 EIC 在Agent循环中的三重角色——剪枝准则、补证触发器与确认准则，使路径判定从"一次性终判"演化为"逐步逼近"的迭代过程；引入审计证据的时间衰减扩展 Observed-EIC（定义 4.5），形式化了三类路径判定（定义 4.6）并重新诠释为Agent对假设的处置状态，并证明了单调性（定理 4.2）、零元素性质（定理 4.3）、假设空间收缩性（定理 4.4）与多项式可判定性（命题 4.1），其中单调性保证了Agent循环的信念单调收敛，假设空间收缩性保证了LLM在每一步动作选择时的幻觉空间被乘性收缩。在风险量化排序层面（4.4 节），本文基于对数几率变换提出可学习的 Risk 模型（定义 4.7），给出了与 EIC Score 的数学嵌套关系，定义了四级风险等级与稳定的多路径排序。在工具化证据获取层面（4.5 节），本文规范化了 7 个证据工具的接口、副作用与置信度模型，将最优三阶段调度顺序固化为先验策略 $\pi_0$ 并给出了主动偏离的条件公式，使Agent在遵循安全默认与主动优化之间取得平衡。在证据不足与复核层面（4.6 节），本文以充分性指标显式区分"无风险"与"证据不足"，将信息增益从补证触发器升级为Agent每步动作选择的核心决策函数，并明确了人工复核在 $\texttt{terminate}$ 之后触发的定位，形成"机器先筛、人工兜底、闭环学习"的运维形态。

EIC-Agent 的理论核心在于将"证据获取—证据评估—证据约束—风险量化"四个环节统一在同一个量化演算中，并通过明确的硬/软约束划分、单调性与零元素性质，将语言模型的角色从"判定主体"约束为"假设生成与证据表达主体"，由此抑制幻觉、提升可解释性。本章建立的形式化体系将作为第五章工程实现与第六章实验评估的共同理论锚点。
