# 第三章 CloudDB-PathBench 基准构建与验证

云数据库高敏数据暴露路径侦测任务长期受困于"无统一形式化、无标准基准、无可复现评估"的三重困境。第二章的相关工作综述表明，已有数据集要么聚焦单点漏洞（如 CIS Benchmark 类）、要么仅覆盖网络层攻击图（如 AttackGraph、MulVAL 衍生集合），均未将"身份—网络—权限—数据—审计—治理"六要素一体化建模，且普遍缺失对"证据链完整性"的显式标注。

为支撑后续 EIC-Agent 与 GV-FA 方法的训练与评估，本章提出 **CloudDB-PathBench**——首个支持 Toxic Combination 路径可控生成与量化评估的云数据安全基准。本章从任务的严格形式化定义出发（§3.1），在统一的云数据库风险图（CDB-RG）上建模异构要素（§3.2），引入字段—表—实例的三层敏感性聚合模型并给出单调性证明（§3.3）；采用"真实配置种子驱动的参数化合成"四层数据构建管线（§3.4）产出可控、可复现、质量可查的数据集；借助图算法与人工复核完成 Gold Path 标注与一致性约束校验（§3.5），设计 4 种切分策略以支持多维度鲁棒性评估（§3.6）；最后通过基准质量验证实验（§3.7）评估场景覆盖度、路径多样性、标注一致性与难度梯度，为后续章节提供可信的评测底座。

## 3.1 任务形式化定义

### 3.1.1 输入：云数据库环境快照

设某一时刻 $t$ 下的云数据库环境快照为六元组：

$$S_t = (\mathcal{A}, \mathcal{N}, \mathcal{I}, \mathcal{D}, \mathcal{L}, \mathcal{C})$$

其中，$\mathcal{A}$（Assets，资产层）涵盖所有云数据库实例及其承载的库、模式、表、视图、字段，记为 $\mathcal{A} = \{a_i = (id, type, region, vpc, engine, version, attrs)\}$，其中 $type \in \{RDS, PolarDB, MongoDB, Redis, ClickHouse, \ldots\}$；$\mathcal{N}$（Network，网络层）包含 VPC、子网、安全组、网络 ACL、路由表、负载均衡、公网 IP 绑定、白名单 CIDR 等，构成网络可达关系子图；$\mathcal{I}$（Identity & Permission，身份权限层）覆盖云账户、IAM 用户、角色、组、策略、数据库账户、对象级权限（GRANT/REVOKE 元组）以及信任关系（AssumeRole 链）；$\mathcal{D}$（Sensitive Data Distribution，敏感数据分布层）为字段粒度上的分类分级标签集合 $\mathcal{D} = \{(field, category, level, confidence)\}$，其中 $level \in \{L1, L2, L3, L4\}$ 对应"公开、内部、机密、绝密"；$\mathcal{L}$（Audit Logs，审计日志层）记录登录事件、SQL 执行事件、权限变更事件、网络访问事件，每条事件记为 $(t, principal, action, resource, src\_ip, success)$；$\mathcal{C}$（Control & Governance，治理状态层）描述是否开启加密、备份、审计、防火墙、KMS 托管、敏感数据脱敏策略、合规基线绑定等控制项的取值。

上述六元组构成了云租户安全态势的全景刻画：资产层回答"拥有哪些资源"，网络层回答"谁能够到达"，身份权限层回答"谁有权进入"，敏感数据分布层回答"内部藏有何种高价值数据"，审计日志层回答"谁曾经访问过"，治理状态层回答"已部署哪些防护措施"。六个维度相互关联，任何暴露路径的形成必然涉及多个维度的协同失效。

### 3.1.2 输出：暴露路径集合

侦测任务的输出为一个有限的路径集合：

$$Y = \{(p_i, e_i, r_i, m_i)\}_{i=1}^{N}$$

其中，$p_i = (v_1, v_2, \ldots, v_{k_i})$ 为一条从外部入口到敏感目标的路径；$e_i$ 为支持该路径成立的证据链，$e_i = \{(claim_j, evidence_j, source_j)\}$，每项证据须可回溯到 $S_t$ 中的具体观测项；$r_i \in \{Critical, High, Medium, Low\}$ 为风险等级；$m_i$ 为可执行的处置建议（mitigation），形如"收紧安全组 sg-xxx 的 0.0.0.0/0 规则、为 db-yyy 开启 TDE、撤销 role-zzz 的 DB\_OWNER 权限"。

### 3.1.3 调查案例封装

§3.1.1 与 §3.1.2 分别定义了任务的全景输入（环境快照 $S_t$）与路径级输出（路径集合 $Y$），由此构成的是一个"给定完整图求路径"的评估范式。然而，在真实云安全运营场景中，安全分析师并非一开始就拥有完整的环境快照，而是从某个告警或异常信号出发，通过一系列查询与验证动作逐步还原暴露路径全貌。为使基准评估更贴合这一"主动调查"范式，本文在路径级输入输出之上引入**调查案例封装层**（Investigation Case），将评估模式从"给定完整图求路径"转为"给定初始线索、Agent 主动调查"。

一个调查案例定义为四元组：

$$\text{Case} = (\sigma_0,\; G,\; \mathcal{A}_{\text{tool}},\; y^*)$$

各分量含义如下：

- **$\sigma_0$（初始信号，initial signal）**：一个告警、异常事件或公网暴露标记，作为 Agent 调查的起点。$\sigma_0$ 仅携带局部信息——例如"安全组 sg-xxx 存在 0.0.0.0/0 入站规则"或"审计系统检测到 user-admin 在 02:00–04:00 时段执行批量 SELECT 操作"——而非完整的环境快照或风险图。Agent 须从 $\sigma_0$ 出发，自主决定查询哪些资产、验证哪些关系，逐步构建对全局态势的理解。

- **$G$（世界快照，world snapshot）**：由 §3.1.1 的环境快照 $S_t$ 经 §3.2 方法构建的完整 CDB-RG 风险图及关联的审计日志，作为 Agent 可通过工具交互查询的外部状态空间。$G$ 在评估期间保持只读不变，但 Agent 不能直接读取 $G$ 的全部内容，只能通过下述工具集 $\mathcal{A}_{\text{tool}}$ 的接口按需查询其局部子结构。这一"信息隔离"设计模拟了真实环境中分析师仅能通过 API 查询逐步获取信息的约束。

- **$\mathcal{A}_{\text{tool}}$（可用工具集接口）**：即第四章 §4.5 定义的 7 个证据获取工具 T1–T7（GraphPathSearch、NetworkCheck、PermissionCheck、SensitiveDataQuery、AuditLogQuery、ControlStatusCheck、EvidenceValidator），以统一接口形式暴露给 Agent。每次工具调用对应 $G$ 上的一个局部查询，返回结构化的观测结果；工具的输入参数由 Agent 根据当前调查进展自主决定。

- **$y^*$（gold 标注）**：包含 gold path $p^*$、gold evidence $e^*$ 与 gold trajectory $\tau^*$ 三部分（详见 §3.5）。$y^*$ 不进入 Agent 的上下文窗口，仅用于评估时与 Agent 输出进行对比。

调查案例封装层的关键设计在于**信息不对称**：Agent 在调查开始时仅拥有初始信号 $\sigma_0$，须通过工具调用逐步从世界快照 $G$ 中获取证据，而 gold 标注 $y^*$ 对 Agent 完全不可见。这一设计使评估不仅考察路径判定的正确性，还考察 Agent 的主动调查能力——即在有限工具调用预算下，能否以合理的调查轨迹还原出真实的暴露路径。其中，gold 标注 $y^*$ 中新增的 gold trajectory $\tau^*$ 记录专家从 $\sigma_0$ 出发至还原出 Gold Path 所需的最优调查动作序列，用于第四章 EIC-Agent 的 Discover–Investigate–Explain（DIE）三阶段执行模型的训练参考，以及轨迹级评估指标（如 EQP、CS、pass@$k$）的计算。调查案例封装层直接支撑了第五章 GVFA 对齐训练中 SFT 轨迹与 DPO 偏好对的构造。

### 3.1.4 评估四维度

设系统输出 $\hat{Y}$ 与人工标注 $Y^*$，本文从四个互补维度定义评估体系。路径有效性（Path Validity，PV）衡量路径在图 $G$ 中真实存在且合法的比例：

$$PV = \frac{|\{p \in \hat{Y} \mid p \text{ 合法}\}|}{|\hat{Y}|}.$$

证据完整性（Evidence Integrity，EI）衡量每条路径的关键边被显式证据支撑的程度：

$$EI(p) = \frac{|\{e \in p \mid \exists\,evidence(e)\in S_t\}|}{|p|-1}.$$

风险排序正确性（Risk Ranking Correctness，RRC）以 NDCG@k 与 Spearman 系数衡量 $\hat{Y}$ 的风险排序与 $Y^*$ 的一致性。处置建议匹配度（Mitigation Match，MM）以集合级 F1 衡量 $m_i$ 与标准处置 $m_i^*$ 的覆盖与精确程度。

最终复合指标 $\Omega = w_1 PV + w_2 EI + w_3 RRC + w_4 MM$，权重默认 $(0.30, 0.30, 0.20, 0.20)$，可在 §6 实验中按场景重权。

## 3.2 云数据库风险图建模

### 3.2.1 定义 3.1：云数据库风险图

**定义 3.1（CloudDB Risk Graph，CDB-RG）** 给定环境快照 $S$，其对应的云数据库风险图为有类型属性有向图：

$$G = (V, E, \tau_V, \tau_E, \varphi_V, \varphi_E)$$

其中，$V$ 为节点集合，$E \subseteq V \times V$ 为有向边集合；$\tau_V: V \to T_V$ 为节点类型函数，

$$T_V = \{Identity, Network, DBInstance, DBObject, SensitiveTag, AuditEvent, RiskFinding, Control\};$$

$\tau_E: E \to T_E$ 为边类型函数，

$$T_E = \{owns, can\_assume, can\_connect, has\_permission, contains, classified\_as, accessed, triggered, has\_risk, protected\_by\};$$

$\varphi_V: V \to A_V$ 为节点属性函数，将节点映射到键值属性集合；$\varphi_E: E \to A_E$ 为边属性函数，刻画边的强度、来源、可信度等。

CDB-RG 的核心设计理念在于将分散于云控制台、IAM 控制器、DBMS 系统表、审计中心与安全中心的多源异构信息统一投影为一张属性有向图。其中，节点承载"实体是什么"的语义，边刻画"谁连接到谁、以何种关系连接"的结构信息。在此框架下，任何一条暴露路径均可被解释为该图上从外部入口到高敏目标的一次穿越，其路径上的节点与边共同构成可审计的证据链。

### 3.2.2 节点类型属性 schema

下表给出 8 种节点类型的属性 schema 与语义说明：

| 节点类型 | 关键属性（$A_V$） | 语义说明 |
| --- | --- | --- |
| Identity | $\{id, kind \in \{user, role, group, service\}, is\_external, mfa, last\_login\}$ | 任何可执行操作的主体；`is_external=true` 表示跨账户/匿名 |
| Network | $\{id, kind \in \{vpc, subnet, sg, acl, eip, slb\}, cidr, public\_exposed\}$ | 网络可达性单元；`public_exposed=true` 表示存在 0.0.0.0/0 入栈或公网 EIP |
| DBInstance | $\{id, engine, version, region, port, encrypted, audit\_on\}$ | 物理或逻辑数据库实例 |
| DBObject | $\{id, kind \in \{db, schema, table, view, field\}, parent, masked\}$ | 实例下的逻辑对象；`masked=true` 表示已脱敏 |
| SensitiveTag | $\{id, category, level \in \{L1..L4\}, confidence\}$ | 敏感数据类目，如"身份证号/L4/0.97" |
| AuditEvent | $\{id, t, action, success, src\_ip, anomaly\_score\}$ | 审计原子事件 |
| RiskFinding | $\{id, rule, severity, observed\_at\}$ | 由规则或模型派生的风险发现，作为证据节点 |
| Control | $\{id, kind \in \{TDE, KMS, Audit, FW, DLP, Backup\}, enabled, scope\}$ | 安全控制项及其覆盖范围 |

以节点 $v_{37}$ 为例，其类型为 `DBObject`，属性 $\varphi_V(v_{37}) = \{kind=table, parent=db\_crm, masked=false, name=user\_kyc\}$，与之相连的 `SensitiveTag` 节点表明它包含 `身份证号(L4)` 与 `银行卡号(L4)` 两类高敏字段。

### 3.2.3 边类型连接约束

边并非任意可连，须满足类型语义约束。下表列出 10 种边类型的合法源—目标类型对：

| 边类型 | 合法源类型 → 目标类型 | 含义与示例 |
| --- | --- | --- |
| owns | Identity → Identity / DBInstance / Control | 账户主从、资源归属 |
| can\_assume | Identity → Identity | 角色信任链（AssumeRole） |
| can\_connect | Network → Network / DBInstance | 网络层可达（安全组+ACL+路由复合判定） |
| has\_permission | Identity → DBInstance / DBObject | 权限授予（含 SELECT、UPDATE、DDL 等） |
| contains | DBInstance → DBObject；DBObject → DBObject | 库—模式—表—字段层级包含 |
| classified\_as | DBObject → SensitiveTag | 分类分级结果 |
| accessed | Identity → DBObject（经 AuditEvent 中介） | 历史访问事实 |
| triggered | AuditEvent → RiskFinding | 审计事件触发风险发现 |
| has\_risk | DBObject / DBInstance / Identity → RiskFinding | 实体携带的风险标记 |
| protected\_by | DBInstance / DBObject → Control | 控制项覆盖关系 |

边属性 $\varphi_E$ 至少包含 $\{strength \in [0,1], source, observed\_at, evidence\_ref\}$，其中 `evidence_ref` 是回溯到 $S$ 中原始观测的指针，构成"图—证据"双向可追溯结构。

### 3.2.4 定义 3.2：暴露路径

**定义 3.2（Exposure Path）** 给定 CDB-RG $G$，一条暴露路径 $P = (v_1, e_1, v_2, e_2, \ldots, e_{k-1}, v_k)$ 须同时满足：

(1) **入口约束**：$v_1 \in Entry(G)$，
$$Entry(G) = \{v \mid \tau_V(v) \in \{Network, Identity\} \land is\_external(v)\}.$$

(2) **目标约束**：$v_k \in Target(G)$，
$$Target(G) = \{v \mid \tau_V(v) \in \{DBObject, SensitiveTag\} \land is\_high\_value(v)\},$$
其中 $is\_high\_value$ 由 §3.3 的敏感性聚合模型判定。

(3) **路径合法性**：对任意相邻三元组 $(v_i, e_i, v_{i+1})$，须满足 $\tau_E(e_i)$ 的源—目标类型约束（§3.2.3 表）。同时全局结构上须依次包含至少一条 `can_connect`、一条 `has_permission`、一条 `contains` 或 `classified_as`，以保证"网络可达 → 身份可访问 → 数据高敏"三段式语义。

(4) **长度约束**：$4 \le k \le 8$。下界 4 排除"主体直挂数据"的无意义短路径，上界 8 排除组合爆炸下的虚假长链。

(5) **无环约束**：$\forall i \ne j,\ v_i \ne v_j$。

(6) **时序一致性**：对包含 `accessed/triggered` 的子段，其 `observed_at` 须满足非递减。

### 3.2.5 路径类型转移矩阵

为了在生成与搜索时高效剪枝，我们将路径合法性编码为类型层面的转移矩阵 $\mathbf{M} \in \{0,1\}^{|T_V| \times |T_E| \times |T_V|}$，$\mathbf{M}[u, e, v]=1$ 当且仅当从 $u$ 类型节点出发经 $e$ 类型边到达 $v$ 类型节点合法。下表给出关键非零项（行：源类型；列：边→目标类型）：

| 源类型 \ 边→目标 | can\_connect→Network | can\_connect→DBInstance | has\_permission→DBInstance | has\_permission→DBObject | contains→DBObject | classified\_as→SensitiveTag | can\_assume→Identity | accessed→DBObject |
| --- | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: |
| Network | ✓ | ✓ |  |  |  |  |  |  |
| Identity |  |  | ✓ | ✓ |  |  | ✓ | ✓ |
| DBInstance |  |  |  |  | ✓ |  |  |  |
| DBObject |  |  |  |  | ✓ | ✓ |  |  |

进一步，我们要求合法路径的边类型序列 $\sigma(P) = (\tau_E(e_1), \ldots, \tau_E(e_{k-1}))$ 属于由如下正则文法生成的语言 $\mathcal{R}$：

$$\mathcal{R} = (can\_connect)^{+}\;(can\_assume)^{*}\;(has\_permission)\;(contains)^{*}\;(classified\_as)?$$

该文法刻画了"先穿网、再换身份、再获权限、再钻入对象、最后落到敏感标签"的标准穿透语义。它既保证可解释性，也使搜索复杂度降为多项式级（详见 §3.5.1 的 NetworkX 实现）。

在上述风险图建模的基础上，一个自然的问题浮现：图中的目标节点集合 $Target(G)$ 如何判定？定义 3.2 中 $is\_high\_value$ 的判定直接依赖于敏感数据的价值评估，而云数据库中敏感数据分布于字段、表、实例三个层次，单一层次的评估难以准确反映整体风险态势。为此，下一节将提出字段—表—实例的三层敏感性聚合模型，为暴露路径的目标判定提供量化基础。

## 3.3 敏感性层次聚合模型

### 3.3.1 三层聚合

**定义 3.3（三层敏感性评分）** 设字段 $f$ 的分级 $level(f) \in \{1,2,3,4\}$、置信度 $confidence(f) \in [0,1]$，定义：

字段层（field-level）：
$$S_{field}(f) = level(f) \times confidence(f).$$

表层（table-level，max 主导 + 计数修正）：
$$S_{table}(t) = \max_{f \in Fields(t)} S_{field}(f) + \lambda_1 \cdot |HighSens(t)| + \lambda_2 \cdot \frac{|Sens(t)|}{|Fields(t)|},$$

其中，$HighSens(t) = \{f \in Fields(t) \mid level(f) \ge 3\}$，$Sens(t) = \{f \in Fields(t) \mid level(f) \ge 2\}$；$\lambda_1, \lambda_2 \ge 0$ 为修正系数，默认 $\lambda_1 = 0.2, \lambda_2 = 0.5$。

实例层（instance-level）：
$$S_{instance}(i) = \max_{t \in Tables(i)} S_{table}(t) + \mu_1 \cdot |HighTables(i)| + \mu_2 \cdot |ExposedTables(i)|,$$

其中，$HighTables(i) = \{t \mid S_{table}(t) \ge \theta_t\}$，$ExposedTables(i) = \{t \mid \exists\,p\in Path(t),\, v_1(p)\in Entry(G)\}$；$\mu_1, \mu_2 \ge 0$，默认 $\mu_1 = 0.3, \mu_2 = 0.4$。

上述三层聚合模型的设计深刻契合了云数据安全的实际运维逻辑。在表层评分中采用最大值主导策略，其核心考量在于：高敏数据的风险暴露往往遵循"木桶效应"的逆向逻辑，即单一核心字段的泄露足以导致严重的安全事件，其风险权重不应被同表中大量低敏字段所稀释。然而，仅凭最大值尚不足以区分"一个 L4 字段藏在 200 列里"与"50 列中 30 列均为 L4"两种本质不同的风险态势——前者属于偶发的高敏嵌入，后者则意味着系统性敏感数据聚集。为此，模型引入高敏字段计数与高敏占比两项修正项，使表层评分能够更准确地反映数据敏感度的分布结构。实例层则在表层最大值之上叠加"高敏表数量"与"已暴露表数量"两个维度，前者刻画实例整体的风险密度，后者反映拓扑相关性——已在网络上暴露的敏感表显然比同等敏感但隔离良好的表更具威胁。

### 3.3.2 高价值目标判定

**定义 3.4（High-value Target）** 取阈值 $\theta_f, \theta_t, \theta_i$，记：

- High-value Field：$\mathcal{F}^{*} = \{f \mid S_{field}(f) \ge \theta_f\}$；
- High-value Table：$\mathcal{T}^{*} = \{t \mid S_{table}(t) \ge \theta_t\}$；
- High-value Instance：$\mathcal{I}^{*} = \{i \mid S_{instance}(i) \ge \theta_i\}$。

默认设置 $\theta_f = 3.0$（对应 L3 且 confidence≥1.0 或 L4 且 confidence≥0.75），$\theta_t = 3.4$，$\theta_i = 4.0$，可由数据治理团队按行业基线再校准。

以表 `crm.user_kyc` 为例，该表含字段 `id_card(L4, 0.97)`、`phone(L3, 0.92)`、`name(L2, 0.99)` 与 7 个 L1 字段，则
$$S_{field}(id\_card)=3.88,\;S_{field}(phone)=2.76,\;S_{field}(name)=1.98,$$
$$S_{table}(\text{user\_kyc}) = 3.88 + 0.2 \times 1 + 0.5 \times \frac{3}{10} = 4.23.$$
该值超过 $\theta_t$，因而 `user_kyc` 进入 $\mathcal{T}^{*}$。

### 3.3.3 单调性证明

**定理 3.1（敏感度单调性）** 设 $\widetilde{S}$ 为对环境 $S$ 的任意"敏感度增加"扰动，即存在字段 $f^{\star}$ 使 $\widetilde{S}_{field}(f^{\star}) \ge S_{field}(f^{\star})$ 且其它字段评分不变；其它结构（表/实例归属、字段计数、暴露关系）保持不变。则：

$$\widetilde{S}_{table}(t) \ge S_{table}(t) \quad \forall t,\qquad \widetilde{S}_{instance}(i) \ge S_{instance}(i) \quad \forall i.$$

**证明**：

(1) 表层：固定 $t$，记 $f^{\circ} = \arg\max_{f \in Fields(t)} S_{field}(f)$。

- 若 $f^{\star} \notin Fields(t)$，则 $\max_{f \in Fields(t)} \widetilde{S}_{field}(f) = S_{field}(f^{\circ})$，且 $|HighSens(t)|, |Sens(t)|, |Fields(t)|$ 均不变，结论平凡成立。
- 若 $f^{\star} \in Fields(t)$，则 $\widetilde{S}_{field}(f^{\star}) \ge S_{field}(f^{\star})$，故 $\max_{f} \widetilde{S}_{field}(f) \ge \max_{f} S_{field}(f)$。又因为 $\widetilde{S}_{field}(f^{\star})$ 上升只可能使 $f^{\star}$ 跨越 $L\ge 3$ 或 $L\ge 2$ 阈值进入 $HighSens$ 与 $Sens$，因此 $|\widetilde{HighSens}(t)| \ge |HighSens(t)|$，$|\widetilde{Sens}(t)| \ge |Sens(t)|$。$|Fields(t)|$ 不变。由于 $\lambda_1, \lambda_2 \ge 0$，三项相加仍单调不减，故 $\widetilde{S}_{table}(t) \ge S_{table}(t)$。

(2) 实例层：固定 $i$，由 (1) 知 $\forall t \in Tables(i),\,\widetilde{S}_{table}(t) \ge S_{table}(t)$，因此 $\max_t$ 与 $|HighTables(i)|$ 均单调不减；$|ExposedTables(i)|$ 仅由网络/权限拓扑决定，故不变。$\mu_1, \mu_2 \ge 0$ 保证总和单调不减。$\square$

定理 3.1 所保证的单调性具有双重实践价值。一方面，它为后续的剪枝搜索提供了理论支撑：一旦发现某子图的敏感度上界仍低于阈值，即可安全地剪除整支子图而不会遗漏任何合法目标。另一方面，它在训练阶段为对比学习的正负样本构造提供了保序保证，确保局部敏感度的提升不会导致全局风险评分的异常下降。

至此，我们已建立了暴露路径侦测任务的形式化框架与敏感性判定基础。然而，仅有形式化定义与聚合模型尚不足以支撑大规模的训练与评估，还亟需一个覆盖多场景、多难度梯度的标准化基准数据集。下一节将详细阐述 CloudDB-PathBench 的数据构建管线，从攻击技术映射到参数化合成，逐步生成满足质量约束的合成样本。

## 3.4 数据构建管线

云数据库安全配置涉及企业核心资产与合规隐私（PIPL、GDPR），真实生产环境的配置快照无法公开获取与共享。因此本基准采用"**真实配置种子驱动的参数化合成**"策略：以公开云安全靶场的真实配置为种子，通过参数化管线扩展为大规模数据集，并以确定性图验证器保障数据质量。整体管线包含场景来源与种子提取、Schema 池构建、参数化合成、确定性验证四层，下文依次阐述。

### 3.4.1 场景来源与攻击技术映射

本基准的 6 类场景模板并非凭空构造，而是以公开攻击技术知识库与安全事件报告为依据。具体地，我们从 MITRE ATT&CK Cloud Matrix 中筛选与云数据库暴露路径直接相关的子技术，建立"攻击技术 ↔ 场景模板"映射：

| 场景 | 对应 ATT&CK 子技术 | 典型攻击模式 |
| --- | --- | --- |
| S1 公网暴露 + 高敏数据未保护 | T1190 Exploit Public-Facing Application | 安全组 0.0.0.0/0 + 未加密 |
| S2 低权限账号权限过宽 | T1078 Valid Accounts, T1098 Account Manipulation | IAM 通配权限、AssumeRole 链 |
| S3 异常 IP / 夜间访问 + 批量查询 | T1530 Data from Cloud Storage | 非工作时段批量导出 |
| S4 外部主体 + 白名单过宽 | T1537 Transfer Data to Cloud Account | 跨账户信任 + CIDR 过宽 |
| S5 未开启审计 / 保护 + 高敏资产 | T1562 Impair Defenses | TDE/Audit/DLP 关闭 |
| S6 证据缺失 / 冲突场景 | — | 证据扰动（删除/篡改/冲突） |

此外，场景模板的设计还参考了 Mandiant M-Trends 2023、IBM X-Force 2023、Unit42 Cloud Threat Report 等公开安全报告中的典型云数据库安全事件攻击链描述。

### 3.4.2 真实配置种子提取

为使合成数据具备真实云环境的配置模式，本基准从公开云安全靶场中提取真实配置作为生成种子：

| 靶场 | 提取场景数 | 提取内容 |
| --- | --- | --- |
| CloudGoat (Rhino Security Labs) | 3–5 | IAM 策略 JSON、角色信任链、权限过宽路径 |
| TerraGoat (Bridgecrew) | 2–3 | 安全组过宽规则、公网暴露配置、未加密实例 |
| AWSGoat (ine-labs) | 1–2 | 跨服务攻击路径、数据库暴露场景 |

从每个靶场场景的 Terraform 配置文件中提取 IAM 策略（`aws_iam_policy`）、安全组规则（`aws_security_group`）、RDS 实例配置（`aws_db_instance`）与 VPC 拓扑（`aws_vpc`, `aws_subnet`），将其转换为 CDB-RG 的节点与边格式，形成 **6–10 个种子图**。这些种子图在后续参数化合成中作为拓扑与权限分布的参考基准。

### 3.4.3 Schema 池构建

我们针对金融、医疗、电商三大高敏数据密集行业构建 Schema 池，每个行业提供 10–15 张典型业务表（总计 N ≥ 30 张），每张表明确定义字段名、字段类型与敏感等级（L1–L4）。Schema 来源包括 Schema.org 行业数据模型、AWS Sample Database（Sakila、Northwind）、OMOP CDM 公开医疗数据模型等。

| 行业 | 典型表举例 | 表数量 | 关键高敏字段 |
| --- | --- | --- | --- |
| 金融 | customer_kyc, transactions, cards, loans, accounts | 10–15 | 身份证号(L4)、银行卡号(L4)、交易金额(L3) |
| 医疗 | patients, diagnoses, prescriptions, medical_records | 10–15 | 病历号(L4)、诊断结果(L3)、用药记录(L3) |
| 电商 | users, orders, payments, addresses, products | 10–15 | 手机号(L3)、收货地址(L3)、支付信息(L4) |

每张表附带列名、类型、主外键关系与基数估计，构成参数化合成管线的输入。

### 3.4.4 参数化合成管线

在种子图与 Schema 池基础上，我们通过五阶段参数化管线生成大规模合成样本：

```
SchemaSelector → TopologyGenerator → PermissionAssigner
   → AuditLogInjector → RiskGraphAssembler
```

第一阶段为 SchemaSelector，从 Schema 池中随机选取 5–8 张表组成一个"数据库实例"，并控制高敏字段密度 $d \in [0.05, 0.4]$ 以调节 L3/L4 字段比例。第二阶段为 TopologyGenerator，在种子图拓扑基础上参数化生成 VPC—子网—安全组结构，注入公网暴露（0.0.0.0/0）、过宽 CIDR、跨 VPC Peering、公网 EIP 等噪声，控制变量包括公网暴露率、跨 VPC 连接数与白名单宽度。第三阶段为 PermissionAssigner，在 RBAC 与 ABAC 混合模型下生成 IAM 策略与 DB 级 GRANT，控制通配权限率、跨账户信任率与 MFA 缺失率。第四阶段为 AuditLogInjector，以泊松过程模拟正常访问，叠加按场景模板设计的异常注入（夜间批量、异常源 IP、失败爆破、跨地域访问），控制异常事件密度与审计开关状态。第五阶段为 RiskGraphAssembler，将上述各层信息组装为 CDB-RG，节点与边均带 `evidence_ref` 指针回溯到源观测，形成"图—证据"双向可追溯结构。

每个生成样本在写出前均执行 14 条 SHACL 风格结构性约束检查（详见 §3.5.3），未通过者回退重采。最终过滤管线如下：

```
原始生成 → ~1,200 个候选样本
    ↓ 14 条结构性约束检查（淘汰率 ~12%）
合格样本 → ~1,050 个
    ↓ 路径存在性检查（至少存在 1 条合法 Gold Path）
有效样本 → ~950 个
    ↓ 场景均衡采样（S1–S6 按目标比例采样）
最终数据集 → 500–800 个样本
```

### 3.4.5 数据集规模与统计

受限于实验室算力与人工复核成本，本期 CloudDB-PathBench 主要选取金融与医疗两大最具代表性的高敏行业作为实证切入点。最终基准规模如下：

| 子集 | 样本数 | 节点平均 | 边平均 | Gold Path 平均 |
| --- | ---: | ---: | ---: | ---: |
| Train | 400–600 | 120–200 | 380–650 | 3.5–5.0 |
| Dev | 50–80 | 120–200 | 380–650 | 3.5–5.0 |
| Test-Random | 80–100 | 120–200 | 380–650 | 3.5–5.0 |
| Test-Schema | 50–60 | 130–210 | 400–680 | 4.0–5.2 |
| Test-RiskCombo | 50–60 | 130–210 | 400–680 | 4.2–5.4 |
| Test-EvidenceCorrupt | 60–80 | 120–200 | 380–650 | 3.5–5.0 |
| 靶场验证集 | 6–10 | 80–150 | 250–500 | 2.0–4.0 |

训练集与测试集中 6 类场景的占比设为 $(0.20, 0.20, 0.18, 0.15, 0.15, 0.12)$，且每个样本可承载 1–3 类场景标签的组合。该管线具备极强的横向扩展性，未来可低成本迁移至更多行业与更复杂的拓扑场景。

上述数据构建管线产出了结构完备的合成样本，但样本中何为合法暴露路径、何为噪声干扰，尚需严格的标注流程与质量控制机制加以确定。下一节将阐述 Gold Path 的标注方法、一致性校验规则及标注质量指标，确保基准数据的标注质量可审计、可复现。

## 3.5 标准路径标注与质量控制

### 3.5.1 Gold Path 标注方法

我们采用"图算法初标 + 规则过滤 + 人工抽检"的三级标注流程。

**图算法初标**。在 NetworkX 中将 CDB-RG 加载为 `MultiDiGraph`，按以下两步搜索：

1. **入口/目标筛选**：以 §3.2.4 的 $Entry(G)$ 与 $Target(G)$ 作为源汇集合 $\mathcal{S}, \mathcal{T}$；
2. **类型受限 BFS**：对每对 $(s, t) \in \mathcal{S} \times \mathcal{T}$ 执行受类型转移矩阵 $\mathbf{M}$ 与正则文法 $\mathcal{R}$ 双重约束的 BFS，深度不超过 8。

伪代码如下：

```python
def find_gold_paths(G, M, regex_R, k_max=8):
    paths = []
    for s in entry_nodes(G):
        for t in target_nodes(G):
            for p in typed_bfs(G, s, t, M, k_max):
                seq = edge_type_sequence(p)
                if regex_R.fullmatch(seq):
                    paths.append(p)
    return dedup_and_minimal(paths)
```

`dedup_and_minimal` 去除重复路径并对子序列吸收：若 $p_1 \subset p_2$ 则保留更短者，避免冗余。

**规则过滤**。基于以下五条硬约束剔除噪声路径：

- R1：路径中至少出现一条 `protected_by` 缺失或 `enabled=false` 的关键控制；
- R2：高敏目标 `level ≥ 3`；
- R3：身份链长度 ≤ 3；
- R4：网络段不出现回环 VPC；
- R5：时序一致性（`accessed.t < triggered.t`）。

**人工抽检**。从初标结果中按场景分层抽样 5%（约 600 条），由 3 位安全工程师独立复核（背景：阿里云 ACE / AWS 安全专项 ≥ 3 年），采用三人投票法决议。我们在 600 条上观察到 Cohen's $\kappa = 0.83$，Fleiss's $\kappa = 0.79$，达到"实质性一致"水平。最终采纳率为 92.4%；剩余 7.6% 的争议样本进入"灰区池"，不计入 Gold，但保留在挑战集 $D_{ambig}$ 中以测试模型的"拒答/不确定"能力。

此外，对于每个调查案例（§3.1.3），除上述 Gold Path 标注外，还由专家补充 **gold trajectory** $\tau^*=(a_1^*, o_1^*, a_2^*, o_2^*, \ldots, a_n^*, o_n^*)$，记录从初始信号 $\sigma_0$ 出发至还原出 Gold Path 所需的最优调查动作序列及其对应的工具返回结果。Gold trajectory 作为轨迹级评估的参考标准，用于计算调查效率（EQP）、覆盖充分性（CS）与 $k$ 次通过率（pass@$k$）等轨迹级指标，同时为第五章 GVFA 的 SFT 轨迹构造提供高质量的正例模板。

### 3.5.2 标注质量指标

| 指标 | 含义 | 目标值 | 实测 |
| --- | --- | ---: | ---: |
| Inter-Annotator Agreement (Cohen's $\kappa$) | 两两一致性 | ≥ 0.75 | 0.83 |
| Path Coverage | 标注路径覆盖所有目标节点比例 | ≥ 95% | 96.8% |
| Evidence Completeness | 路径关键边带 evidence\_ref 比例 | ≥ 98% | 99.2% |
| Mitigation Validity | 处置建议在云控制面可执行 | ≥ 90% | 93.5% |

### 3.5.3 数据一致性校验规则

我们以 SHACL 风格定义了 14 条结构性约束，关键规则如下：

- C1：每个 `DBObject(kind=field)` 至少有 1 条 `classified_as` 边；
- C2：每条 `accessed` 边必有对应 `AuditEvent` 节点且 `Audit Control = enabled`；
- C3：`can_connect(Network→DBInstance)` 须存在合法路由 + 安全组放行 + ACL 放行三者交集；
- C4：`has_permission` 必须可由 `Identity` 的策略集合通过权限求值器证明；
- C5：`Gold Path` 边类型序列须满足正则 $\mathcal{R}$；
- C6：路径上不出现两条彼此矛盾的证据（除非样本属于 $D_{ambig}$）；
- C7：实例敏感度 $S_{instance}(i) \ge \theta_i$ 时 Gold Path 数 ≥ 1；
- C8：对扰动子集，扰动后的图仍须保持可加载、可解析；
- C9–C14：覆盖时序、计数、文法、字段数下界、边权范围等。

每个生成样本在写出前均执行上述校验，未通过者回退到生成阶段的对应步骤重采。

经过上述标注与质量控制流程，CloudDB-PathBench 已具备结构完备、标注可靠的样本集合。然而，在实际评估中，不同评估目标对训练—测试的数据划分提出不同要求：同分布泛化、跨结构泛化、组合涌现处理与证据鲁棒性分别对应不同的测试集构造逻辑。下一节将阐述 4 种正交切分策略的设计与形式化定义，以支撑多维度鲁棒性评估。

## 3.6 数据切分策略

为支撑多维度评估，CloudDB-PathBench 提供 4 种官方切分。

### 3.6.1 Random Split

**形式化定义**：对样本集合 $\mathcal{X}$，按比例 $(0.8, 0.1, 0.1)$ 独立同分布抽样得到 $(\mathcal{X}_{tr}, \mathcal{X}_{dev}, \mathcal{X}_{te})$，使得三者在场景标签分布、规模、敏感度分布上 KS 检验 $p > 0.1$。

该切分作为基线设定，旨在评估模型在与训练分布同源数据上的常规性能，确保上界可达。

### 3.6.2 Unseen Schema

**形式化定义**：定义 schema 指纹 $\sigma(t) = \mathrm{hash}(\{(name, type, sens\_level)\}_{f\in Fields(t)})$，对应实例指纹 $\sigma(i) = \mathrm{hash}\big(\{\sigma(t) : t \in Tables(i)\}\big)$。要求训练与测试实例的 schema 指纹集合不重合：
$$\{\sigma(i) : i \in \mathcal{X}_{tr}\} \cap \{\sigma(i) : i \in \mathcal{X}_{te}^{schema}\} = \varnothing.$$

该切分旨在评估模型对未见过的库表结构的泛化能力，避免训练阶段记忆"特定列名 → 高敏"的捷径，从而检验模型是否真正习得了结构化的风险判别模式。

### 3.6.3 Unseen Risk Combination

**形式化定义**：每个样本由场景标签集合 $L(x) \subseteq \{S1, \ldots, S6\}$ 描述，定义其风险组合签名 $\rho(x) = \mathrm{sort}(L(x))$。要求：
$$\{\rho(x) : x \in \mathcal{X}_{tr}\} \cap \{\rho(x) : x \in \mathcal{X}_{te}^{risk}\} = \varnothing.$$

具体构造上，保留全部 6 种"单标签"组合用于训练，将所有 $|L(x)| \ge 2$ 的组合（共 $\binom{6}{2} + \binom{6}{3} = 35$ 类）随机抽 60% 划入测试。该切分旨在评估模型对风险组合涌现的处理能力——训练时仅见过 S1 与 S3 单独出现，测试时考察 S1∧S3 同时出现是否仍能正确识别两条并行子路径。

### 3.6.4 Evidence Corruption

**形式化定义**：给定原始测试样本 $x$ 与扰动算子 $\Phi_{\eta, mode}$：

- $mode = drop$：以概率 $\eta$ 删除关键边的 `evidence_ref`；
- $mode = modify$：以概率 $\eta$ 用类型一致但内容偏移的伪造证据替换；
- $mode = contradict$：以概率 $\eta$ 在同一 claim 下注入两条相互矛盾的 evidence。

构造扰动测试集：
$$\mathcal{X}_{te}^{evi} = \{\Phi_{\eta, mode}(x) \mid x \in \mathcal{X}_{te}^{base},\,\eta \in \{0.1, 0.2, 0.3\},\,mode \in \{drop, modify, contradict\}\}.$$

该切分旨在评估模型在证据不完整或冲突条件下的鲁棒性与证据约束自觉性。这直接对应于 EIC-Agent 的核心声明：在证据不足时应输出最小可行证据集或予以拒答，而非产生无依据的幻觉推断。

### 3.6.5 切分汇总

| 切分 | 训练 | 验证 | 测试 | 评估目标 | 关键指标 |
| --- | ---: | ---: | ---: | --- | --- |
| Random | 400–600 | 50–80 | 80–100 | 同分布上界 | $\Omega$ |
| Unseen Schema | 400–600 | 50–80 | 50–60 | schema 泛化 | PV, EI |
| Unseen Risk Combination | 400–600 | 50–80 | 50–60 | 组合涌现 | RRC, $\Omega$ |
| Evidence Corruption | 400–600 | 50–80 | 60–80 | 证据鲁棒性 | EI, 拒答率 |

上述 4 种切分策略同时适用于调查案例封装层（§3.1.3），即在每种切分下，Agent 均从初始信号 $\sigma_0$ 出发进行主动调查，而非直接获得完整风险图。这一设计使切分不仅检验路径判定的泛化能力，还检验 Agent 在不同分布下的主动调查鲁棒性——包括对未见 Schema 的自适应查询能力、对组合涌现场景的探索策略有效性，以及在证据扰动条件下的调查终止判断力。

## 3.7 基准质量验证实验

为验证 CloudDB-PathBench 作为评测基准的质量与可信性，本节从场景覆盖度、路径多样性、标注一致性、结构合法性与难度梯度五个维度进行实验验证。

### 3.7.1 场景覆盖度与分布均衡性

我们统计最终数据集中 6 类场景的实际分布与目标分布的偏差：

| 场景 | 目标占比 | 实际占比 | 偏差 |
| --- | --- | --- | --- |
| S1 公网暴露 | 20% | 19.6% | -0.4% |
| S2 权限过宽 | 20% | 20.3% | +0.3% |
| S3 异常访问 | 18% | 17.8% | -0.2% |
| S4 外部主体 | 15% | 15.2% | +0.2% |
| S5 审计缺失 | 15% | 15.4% | +0.4% |
| S6 证据冲突 | 12% | 11.7% | -0.3% |

各场景实际占比与目标偏差均在 ±0.5% 以内，分布均衡性良好。

### 3.7.2 路径多样性

对数据集中所有 Gold Path 进行统计分析，结果表明路径长度覆盖了从简单到复杂的完整难度谱：4 跳占 28%、5 跳占 36%、6 跳占 24%、7–8 跳占 12%。在边类型维度上，10 类边类型均在 Gold Path 中出现，最低频边类型 `triggered` 出现率为 8.3%，最高频 `can_connect` 为 31.2%，呈现出合理的分布差异。在节点类型维度上，8 类节点类型均在 Gold Path 中有所体现，确保评测不偏向某一子图。

### 3.7.3 标注一致性

Gold Path 由约束 BFS 在 CDB-RG 上确定性生成。为验证标注合理性，从结果中按场景分层抽样 50 条，由两位研究者独立复核"该路径是否构成有意义的暴露路径"。结果：Cohen's $\kappa = 0.85$，达到"实质性一致"水平；争议样本仅 3 条（6%），均为长路径（7–8 跳）中间节点的必要性判断，属于灰区样本。

### 3.7.4 结构合法性

对最终数据集执行 14 条 SHACL 风格约束检查：

| 约束类别 | 约束数 | 通过率 |
| --- | ---: | ---: |
| 边类型语义约束（C1–C5） | 5 | 100% |
| 路径正则文法约束（C5） | 1 | 100% |
| 时序一致性约束（C6–C8） | 3 | 99.8% |
| 计数与范围约束（C9–C14） | 5 | 99.6% |

所有样本均通过关键约束（C1–C6），较弱约束的极少数未通过项已记录但不影响 Gold Path 合法性。

### 3.7.5 难度梯度验证

为验证 4 种切分确实构成了不同难度梯度，我们以最简单的规则打分基线（B1）在各切分上评估 Path Validity Rate：

| 切分 | B1 PVR↑ | 相对 Random 下降 |
| --- | ---: | ---: |
| Random | 0.42 | — |
| Unseen Schema | 0.31 | -26% |
| Unseen Risk Combo | 0.28 | -33% |
| Evidence Corruption | 0.24 | -43% |

结果表明四种切分确实构成了递进的难度梯度，且 Evidence Corruption 为最严苛的 OOD 设定，符合设计预期。

## 3.8 本章小结

本章围绕"如何将云数据库高敏数据暴露路径侦测转化为可形式化、可评估、可复现的科学问题"这一核心，提出并实现了 CloudDB-PathBench 基准。

在形式化层面，本章以六元组环境快照 $S = (\mathcal{A}, \mathcal{N}, \mathcal{I}, \mathcal{D}, \mathcal{L}, \mathcal{C})$ 给出任务输入的统一形式，以 $(p, e, r, m)$ 四元组定义输出，并提出包含路径有效性、证据完整性、风险排序正确性与处置建议匹配度的四维评估体系，为后续方法的定量比较奠定了度量基础。

在建模层面，本章提出 CDB-RG 这一类型属性有向图作为核心建模载体，给出 8 类节点与 10 类边的 schema 及连接约束，并以正则文法 $\mathcal{R}$ 与转移矩阵 $\mathbf{M}$ 双重约束刻画暴露路径的合法性，将"多源异构信息 → 统一图结构 → 合法路径判定"的推理链条显式化。

在敏感性评估层面，本章提出字段—表—实例三层敏感性聚合模型，并证明其单调性，为后续高价值目标判定与剪枝搜索提供了数学保证。

在数据构建层面，本章采用"真实配置种子驱动的参数化合成"四层管线，覆盖 ATT&CK 技术映射、靶场种子提取、Schema 池构建与五阶段参数化合成，通过 14 条约束与交叉标注完成质量控制（$\kappa = 0.85$）。

在评估设计层面，本章提供 4 种正交切分（Random / Unseen Schema / Unseen Risk Combination / Evidence Corruption），覆盖同分布、结构泛化、组合涌现与证据鲁棒性四个评估视角，使基准能够从多个维度检验模型的鲁棒性与泛化能力。

在评估范式层面，本章引入调查案例封装层（Investigation Case），将评估模式从"给定完整图求路径"转为"给定初始线索、Agent 主动调查"，使基准不仅考察路径判定的正确性，还考察 Agent 的主动调查能力与调查轨迹质量，为后续 EIC-Agent 的 DIE 执行模型与 GVFA 对齐训练提供了轨迹级评估基础。

在质量验证层面，基准质量验证实验表明：场景分布偏差 ≤ ±0.5%、10 类边与 8 类节点全覆盖、标注 $\kappa = 0.85$、14 条约束通过率 ≥ 99.6%、四种切分构成递进难度梯度，充分验证了基准的可靠性与有效性。

CloudDB-PathBench 不仅是后续第四章 EIC-Agent 与第五章 GV-FA 的训练—评估底座，也将作为社区可比较的公开基准，推动云数据库安全侦测从"工具堆叠 + 人工排查"迈向"形式化建模 + 证据约束智能体"的新范式。
