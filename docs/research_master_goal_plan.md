# CloudDB PathBench 研究升级总目标与执行计划

## 1. 冻结目标

在现有项目基础上完成三个不可妥协的结果：

1. 建设来源真实、可追溯、许可清楚、非脚本/AI 自生成的云攻击路径数据集；
2. 实现以 ReAct 和 Tool Use 为核心的 LLM Agent，使其能在部分可观测环境中
   渐进、高效地发现高敏数据攻击/暴露路径；
3. 形成 2–3 个相互独立、都有代码、数据、基线、消融和统计结果支撑的创新点。

本项目不再以“做出一个能演示的 Agent”为终点，而以“每个结论均能由原始证据、
冻结协议和 held-out 结果复核”为完成标准。

### 1.1 2026-07-27 客观进度快照

- 数据候选：150 个真实上游候选、113 个 independence group、6 个正向来源；
- 运行证据：主候选包 v0.5 含 91 个非空无标签实例，其中 9 个 Splunk 实例、
  70 个 Cross-Cloud 条件盲化实例、11 个 Stratus/Grimoire 真实爆破实例，以及
  1 个 OTRF 发布的 CloudGoat 派生实例；脚本/AI 生成路径标签仍为 0；
- 外部负对照：30 份 DOI 固定的真实可靠性报告（29 个独立事件组）已形成无标签
  筛选包；双人盲审、
  第三人裁决、冻结环境和主调度接口已完成，但人工确认数仍为 0；
- 人工 gold：0。双人盲标、实例级状态、第三人裁决和哈希冻结工具已就绪，但
  未经真人完成前，数据创新仍未验收；
- EC-ReAct：已实现 Top-K `submit_path`、真实工具调用、可见证据 ledger、
  可执行字段断言、Pareto/预算守卫、四值反馈、CP-Cert 终止以及线性/LangGraph
  一致执行；
- 语义合同：已冻结 `cloud_data_path_v1`（16 类节点、27 类边及显式别名），
  人工 gold 与 Agent 均要求 canonical type；细粒度 exact 是主指标，
  literal/coarse 只作为不参与假设检验的敏感性分析；
- 基线与实验：固定顺序、种子随机、全量查询及 LLM 消融共享同一工具、预算和
  输出 schema；主实验支持预检、实例调度、断点续跑、人工 gold 评分、group
  cluster bootstrap、配对置换和 Holm 校正；场景来源与遥测发布来源分别进入
  schedule、score、分层 bootstrap 和来源增益异质性检验；
- 当前主实验仍为 `ready=false`：缺少双人人工实例 gold、冻结 split 与模型
  运行条件，并缺少至少 20 份双人确认负对照。因此目前只有工程协议结果，
  没有任何可声称的方法有效性数字。

## 2. 数据底线

### 2.1 主数据集禁止事项

下列内容不得作为主实验独立样本：

- 由本项目脚本随机生成的拓扑、身份、权限、日志或标签；
- 由 LLM 编写的攻击故事、工具输出或 gold path；
- 从同一基础图改一个状态得到的 missing/refuted/temporal 变体；
- 没有原始 URL、版本、许可证、下载时间和哈希的二手数据；
- 仅由当前验证器反向生成的标签。

这类数据可保留用于单元测试、调试或专门的鲁棒性压力测试，但必须与主数据集
物理隔离，论文中单列说明，不能计入独立样本量。

### 2.2 允许的处理

“不能生成数据”不等于不能写数据处理代码。允许且必须实现可审计 ETL：

- 下载官方原始仓库、日志、Terraform、STIX、walkthrough；
- 解析原始字段，规范化节点和边；
- 去标识化、去重、格式转换；
- 保存原始片段、来源行号、对象 ID 和 SHA-256；
- 由人工依据原始材料标注 edge-aware 路径和证据状态。

任何规范化边都必须能追溯到：

```text
normalized edge
→ raw artifact
→ source URL / repository commit
→ file path / object ID / line or event ID
```

### 2.3 数据层级

| 层级 | 定义 | 主用途 |
|---|---|---|
| A：生产事件/权威一手审计证据 | 可独立复核的生产事件、官方审计记录或等价一手材料 | external test 首选 |
| B：公开实验/靶场真实云遥测 | 可信项目在真实隔离云账号中执行攻击后发布的 API 与日志 | train/validation/test |
| C：官方靶场结构与 walkthrough | Terraform、场景定义、官方攻击步骤，但未实际执行 | 结构路径和工具任务 |
| D：本项目构造/衍生数据 | 原 308 样本及变体 | 仅开发、单元测试、压力测试 |

论文必须按层级分别报告，不能把 B/C 称作真实生产攻击。

## 3. 第一批官方来源白名单

首批仅接入许可证和复现边界相对明确的来源：

| 来源 | 原始内容 | 拟提取证据 | 初步定位 |
|---|---|---|---|
| MITRE ATT&CK STIX | technique、procedure、relationship、citation | 真实案例过程、技术、数据源和引用 | A/CTI |
| Splunk Attack Data | 攻击日志、YAML 元数据、ATT&CK 映射 | CloudTrail/审计事件与攻击步骤 | A/B |
| CloudGoat | Terraform、场景、官方 walkthrough | AWS 网络、IAM、RDS/S3/Secret 路径 | B/C |
| CloudFoxable | Terraform、18 个挑战、攻击路径 | AWS 枚举、权限、数据库和 secret 路径 | B/C |
| Stratus Red Team | 公开技术定义与 35 份 Grimoire 脱敏 CloudTrail 爆破日志 | 310 条真实测试云事件；其中 11 个云数据候选、139 条事件进入 B 级运行池 | B/C |
| OTRF Security Datasets | 固定攻击元数据与 CloudTrail JSONL | CloudGoat `cloud_breach_s3` 的103条独立发布运行观测；保留共同场景 lineage | B（主候选包 v0.5） |
| CloudFox | 多云枚举工具输出 | Agent 可调用的真实工具 schema 与观察 | B |
| Cross-Cloud Observability（DOI: 10.5281/zenodo.19933893） | 35 类攻击脚本及 AWS/Azure/GCP 脱敏日志 | payload/no-payload 配对遥测与跨云泛化 | B |
| Cloud Incident Reports 2016–2024（DOI: 10.5281/zenodo.14010282） | 3,087 份 AWS/Azure/GCP 生产可靠性事件报告 | external negative control，测量攻击路径误报与 abstention | B |

候选但尚未进入白名单的来源必须先完成许可、维护状态、原始性和下载验证。

截至 2026-07-27，白名单已有 9 个固定版本来源、23 个原始工件，共
163,828,757 bytes。Cross-Cloud
Observability 原始压缩包含 8,327 个 JSON 日志文件。首轮小 pilot 保留 2 个
攻击家族、3 个平台的 240 个 episode / 120 对 payload 对照，共 26,404
条原始观测。完整云数据候选池现覆盖 12 个独立攻击家族、36 个平台×攻击组，
包含 1,424 个严格配对 episode / 712 对对照和 65,041 条原始观测；另有 5 个
上游未完整配对的 run key 被显式排除，没有补造缺失数据。episode 是重复运行
单位，不能把 1,424 个 episode 计作独立路径案例。

生产可靠性事件来源包含 3,087 份真实报告；机械关键词仅路由出 996 份云数据
相关候选，其中 4 份命中安全词。它们全部保持未标注状态，只有双人确认“云数据
相关且非攻击”的报告才可成为外部负对照，绝不计入正向攻击路径数量。

## 4. 三项创新的最终结构

### 创新一：RealPathBench-CD——来源可追溯的真实云数据攻击路径基准

#### 问题

现有项目数据主要由有限基础样本和规则变体组成，无法支撑真实泛化结论；公开云
攻击材料又分散在 STIX、Terraform、walkthrough 和日志中，缺少面向高敏数据
路径的统一、edge-aware、工具可交互标注。

#### 方法工作

构建一个多源证据对齐管线：

\[
\mathcal A_{\mathrm{raw}}
\xrightarrow{\text{parse}}
\mathcal E_{\mathrm{typed}}
\xrightarrow{\text{entity alignment}}
G
\xrightarrow{\text{human annotation}}
(P^*,C^*,Q^*).
\]

其中：

- \(P^*\)：精确到并行边 ID 的攻击/暴露路径；
- \(C^*\)：支持或否定该路径的证据证书；
- \(Q^*\)：调查时可调用的工具和其观察范围。

每个样本保存来源、版本、提交哈希、许可证、原始证据引用、云平台、服务、路径
长度、攻击阶段和标注者信息。

#### 独立性

这是数据与评测协议创新，不依赖后续 Agent 是否使用某个模型。

#### 最低验收门槛

- 至少 80 个独立基础案例，目标 120–150 个；
- AWS、Azure、GCP 至少覆盖两个，目标覆盖三个；
- 至少 30 个完全冻结的 source-held-out/external-test 案例；
- 主测试集中脚本/AI 生成案例数为 0；
- 至少 20% 样本双人独立标注并报告一致性；关键测试集争取全量复核；
- edge-aware 路径、证据引用和许可证字段覆盖率 100%。

### 创新二：EC-ReAct——证据约束、成本感知的渐进式工具调用 Agent

#### 问题

Vanilla ReAct 能交替推理和行动，但在攻击路径任务中容易重复调用、错误调用、
过早停止、遗忘反证或直接依据语言常识下结论。现有离线 Agent 又曾一次性读取
完整证据，无法体现主动发现。

#### 方法

构建双层控制的 ReAct 循环：

```text
Thought
→ propose ToolCall
→ deterministic action guard
→ execute tool
→ Observation
→ T/F/U/Conflict belief update
→ frontier update
→ SubmitPath / Verify / Continue / Abstain
```

状态：

\[
b_t=(\mathcal F_t,\mathcal O_t,\mathcal U_t,B_t,H_t),
\]

其中 \(\mathcal F_t\) 为候选路径前沿，\(\mathcal O_t\) 为已观察证据，
\(\mathcal U_t\) 为未知证据，\(B_t\) 为预算，\(H_t\) 为工具轨迹。

LLM 的职责：

- 根据当前证据缺口提出下一项工具；
- 在多个可行候选之间进行语义规划；
- 解释观察并维护任务级计划；
- 在证据充分时提出停止；
- 渐进提交最多 5 条有序候选路径，而不是只输出一个“可疑事件”。

确定性控制器的职责：

- 拦截不存在、参数非法、重复或越权的工具调用；
- 禁止读取未查询的隐藏证据；
- 更新证据状态和候选前沿；
- 最终判定和证书校验；
- 只允许引用实际渲染给 policy 的 observation/call，并独立执行字段断言。

动作候选先经过 Pareto 筛选，不再依赖单一手调权重：

\[
u_t(a)=
\bigl(
g_{\mathrm{ext}}(a),
g_{\mathrm{cov}}(a),
g_{\mathrm{res}}(a),
-\widehat c_t(a)
\bigr).
\]

候选来自摘要、operation/service 搜索、已见事件详情、actor 时间线、status
搜索，以及只从已见 request/response 中提取的 resource 查询。动作 \(a\)
支配 \(b\) 当且仅当所有效用维度均不差且至少一维严格更好。完整方法只把
非支配前沿提交给 LLM；`w/o Pareto` 获得同一生成器的全部预算可行候选并关闭
前沿拒绝。\(g_{\mathrm{ext}}\) 不是手工关键词分，而是固定 SigmaHQ
`r2026-07-01` 云检测规则中匹配 operation 的不同规则数；不加权、不读 gold，
并排除 filter 分支。该动作空间冻结为 `cross_tool_visible_sigma_v0.3`，避免在测试集上事后
改候选规则。自由构造且未被生成器覆盖的 account/region/timestamp 过滤仍受
工具和预算守卫约束，但不计入当前 Pareto 创新范围。

外部规则覆盖不是均匀的：72-episode 冻结审计中，Sigma 仅覆盖 19.05% 的唯一
platform-operation 组合、13.53% 的事件量，且 Azure 覆盖明显高于 AWS/GCP。
因此已加入独立 `w/o external prior` 消融；论文必须分平台报告，并把零规则命中
解释为 Unknown，而不是 benign。

#### 独立性

这是 Agent 决策与 Tool Use 方法创新。即使使用相同数据和验证器，也可独立
对比 Vanilla ReAct、固定顺序、随机、全量查询及纯算法策略。

#### 最低验收门槛

- LLM 在查询前无法看到隐藏证据；
- 工具调用、观察、预算和停止原因全部可回放；
- 在冻结测试集上，至少在一条成本—召回 Pareto 曲线上稳定优于 Vanilla ReAct
  或固定顺序强基线；
- 不以“调用次数更少但正样本全部找不到”作为成功；
- 跨模型、跨来源报告，失败样本必须分析。

### 创新三：CP-Cert——冲突保持的路径验证与最小证据证书

#### 问题

三值逻辑无法表达“同一事实同时存在支持和反证”。普通加权分数也无法证明一条
路径为何成立、为何应拒绝，导致 LLM 很容易忽略矛盾证据。

#### 方法

将证据状态扩展为四值：

\[
\mathbb B_4=\{\bot,T,F,\top\},
\]

分别表示未知、仅支持、仅反证、支持与反证并存。证据融合保留冲突，不通过平均
分数消除反证。

对候选集合 \(\mathcal P\) 生成最小代价否定证书：

\[
C^-=\arg\min_{C\subseteq E_q}\sum_{e\in C}c(e),
\quad
\text{s.t.}\ \forall P\in\mathcal P,\ C\cap Block(P)\neq\varnothing.
\]

这是一个加权 hitting-set 问题；小图使用精确分支定界或 ILP，大图使用带近似
界的贪心算法。正证书则必须覆盖路径全部硬前提，并包含原始证据引用。

证书只证明内部结构、引用可见性、可执行断言和证据覆盖，不自动证明路径与现实
语义一致。人工 `instance_labels` 是外部 gold；内部证书通过但不匹配人工 Valid
路径的预测仍按语义误报统计。

#### 独立性

这是可信判定与解释创新，不依赖 LLM。可以单独评价证书正确性、最小性、冲突
识别和人工可核验性。

#### 最低验收门槛

- 支持、反证、未知、冲突四态均有真实来源案例；
- 小规模实例上与穷举最优解一致；
- 相对“输出整条路径全部证据”显著降低证书冗余；
- 删除证书中任一必要证据后，结论应失去充分性；
- LLM 不得修改确定性验证结果。

## 5. 实验协议

### 5.1 数据划分

- 以事件/场景/仓库 challenge 为 group，任何同源重放不得跨 split；
- development 用于代码调试；
- validation 选择 prompt、阈值、预算和策略；
- test 冻结后只用于主结果；
- external/source-held-out 完全排除某一来源或云平台，用于泛化结论；
- 生产可靠性事件仅进入单独的 `external_negative_control`，不得与正向攻击
  路径混合训练或计数；同一报告只能出现一次；
- 原 308 个构造样本不得进入 v2 主 test。

### 5.2 研究问题

| RQ | 问题 |
|---|---|
| RQ1 | RealPathBench-CD 是否具有足够的来源、平台、服务和路径结构覆盖？ |
| RQ2 | EC-ReAct 是否比 Vanilla ReAct 和非 Agent 基线更快发现有效路径？ |
| RQ3 | 各组件——Pareto guard、证据状态、预算、反证记忆——是否有独立贡献？ |
| RQ4 | CP-Cert 是否能正确处理冲突并生成更小的可审计证书？ |
| RQ5 | 方法能否跨数据来源、云平台和未见工具泛化？ |
| RQ6 | 面对真实但非攻击的云数据服务故障，方法能否避免臆造攻击路径并正确 abstain？ |

### 5.3 基线

路径与非 Agent 基线：

- DFS、类型约束 DFS；
- BFS/Yen k-shortest path；
- 当前 Beam Search；
- 全量工具查询、固定顺序、随机查询；
- 当前 VOI/Cost 策略。

Agent 基线：

- LLM 直接回答，无工具；
- Vanilla ReAct；
- ReAct + 全量工具；
- Plan-and-Execute；
- EC-ReAct。

验证基线：

- Gate·Score；
- T/F/U 三值验证；
- 四值冲突保持验证；
- 全证据解释、贪心证书、精确最小证书。

### 5.4 主指标

正确性：

- edge-aware Valid Path Recall@K；
- Exact Path Match、MRR；
- valid discovery recall；
- correct rejection、false positive、abstention；
- stop decision accuracy；
- external negative control 上的 hallucinated-path rate、unsupported-evidence
  rate 和 correct-abstention rate。

效率：

- 平均工具调用、无效调用、重复调用；
- 查询成本、token、时延；
- 首条有效路径发现成本；
- 固定预算下的召回。

可信性：

- 证据状态准确率、冲突识别率；
- 证书充分性、最小性和冗余率；
- 原始证据引用完整率；
- 工具轨迹可回放率。

### 5.5 统计要求

- 随机 LLM 策略每个案例至少重复 5 次；
- 以独立 group 为统计单元，不把衍生变体当独立样本；
- 报告均值、95% cluster bootstrap CI 和效应量；
- 主要方法使用配对置换检验；
- 多指标使用 Holm 校正；
- 同时报告分来源和合并结果；
- prompt、模型版本、温度、工具 schema 和 commit 全部冻结。

## 6. 里程碑与验收门

### M1：来源审计与原始数据落盘

交付：

- `data/real_sources/source_registry.yaml`；
- 原始下载脚本、commit/hash/许可证；
- 每个来源的解析可行性报告。

验收：至少 4 个来源通过，且至少 2 个包含可用日志或可执行云轨迹。

当前状态：已通过。8 个来源、20 个固定原始工件，全部具有本地 SHA-256；
Zenodo 数据另与上游 MD5 双重核对。

### M2：RealPathBench-CD pilot

交付：

- 首批 10–20 个完全人工核验样本；
- 标注指南、审阅记录和一致性计算；
- 每条路径可回链原始证据。

验收：验证器不能依靠脚本自动标签获得 100%；人工标签与规则判定要独立。

当前工程进度：旧 11 案例包保留为流程 smoke；两来源 pilot v1 在无人开始标注
前因发现已固定的第三运行时来源而被 v2 取代。正式 v2 已冻结为 23 个案例、
35 个真实运行实例、14 个完整 independence group 和 389 条观测，
AWS/Azure/GCP 实例分布为 18/9/8，覆盖 Cross-Cloud、Splunk、Stratus 三个来源。
主候选包 v0.5 的 150 案例覆盖 6 个候选来源、4 个运行时证据发布者和 113 个
independence group，所有标签字段均为空。其中 93 个静态候选保守记为 C 级，
必须经人工准入，必要时在隔离
云账号执行后才能进入
主测试。盲法双人分发、human attestation、源材料哈希冻结、
结构/引用校验、案例级 Cohen's kappa、
edge identity F1、证据状态 macro-F1、路径状态 kappa、第三人裁决和批量冻结
工具链已经通过自动测试。人工任务已隐藏 evaluator-only 的 episode 条件；pilot
准入阈值和失败处理也已预注册并实现为机器 gate。当前仍未产生任何人工 gold，
M2 尚未验收；下一步必须由两位不同的人独立完成首轮任务，不能由 AI 或脚本代填。

### M3：EC-ReAct

交付：

- ReAct 状态机、工具注册表、隐藏证据环境；
- action guard、Pareto 候选和轨迹回放；
- Vanilla ReAct 与非 Agent 基线。

验收：真实 LLM 确实根据 observation 改变后续动作，不能只是预定工具顺序。

当前工程进度：已完成框架无关控制器、LangGraph
`plan → guard/tool/update → route` 后端、真实三云日志工具、动作/预算/引用泄漏
守卫和 OpenAI-compatible policy 接口。已在 12 个攻击家族、36 个
platform×attack 组、72 个真实 episode 上完成双后端协议验证，后端不一致和
策略可见隐藏标签泄漏均为 0。当前确定性 smoke policy 对上游有/无 payload
条件没有区分力，因此该结果只证明工程协议，尚未达到 M3 验收；必须等人工 gold
pilot 冻结后运行真实 LLM 与公平基线实验。

另已完成 `cross_tool_visible_sigma_v0.3` 动作空间工程审计：72 个真实 episode 中
2 个为上游零观测文件，70 个非空 episode 均到达跨工具候选阶段；详情后完整
候选均值 14.87、Pareto 前沿均值 7.07、平均裁剪 46.84%，探针异常 0。该结果
只证明候选空间与消融开关真实生效，明确标记
`research_effectiveness_result=false`，不用于声称路径发现有效。

主实验的机器可读冻结配置和严格 preflight 已落地：相同工具 schema、12 步上限、
三档预算、7 个 LLM 完整/消融方法、3 个非 LLM 基线、2 个模型条件，以及
cluster bootstrap、配对置换和 Holm 校正均已固定。预检会拒绝 pending/非人工
gold、跨 split group、来源哈希不一致和缺失运行环境；当前如实返回
`ready=false`，不会生成伪主结果。

### M4：CP-Cert

交付：

- 四值融合；
- 精确/近似最小证书；
- 冲突案例与单元测试。

验收：最优性、充分性和删除测试通过。

当前工程进度：已实现四值单调融合、保守路径判定、正/否证书、分支定界精确
求解、带上界的加权贪心、独立证书审计和删除测试；精确解已与独立穷举 oracle
对齐。旧调查器已修正“Unknown 当反证”的逻辑错误，并接入 CP-Cert 最小共享
反证证书。当前仅达到算法/协议测试，尚未达到 M4 研究验收：真实来源的四态
案例、人工 gold 与主实验仍未完成。

### M5：冻结实验

交付：

- 数据卡、模型卡、实验配置；
- 主实验、消融、来源异质性、失败案例；
- 一键复现脚本。

验收：任何主表数字均能从冻结 JSON 自动生成。

### M6：论文与答辩

论文贡献固定为：

1. RealPathBench-CD；
2. EC-ReAct；
3. CP-Cert。

如果某一项未达到验收门，就降级为工程模块或未来工作，不硬凑创新点。

## 7. 当前项目的重新定位

| 现有资产 | 新定位 |
|---|---|
| 308 个语义样本 | development/压力测试，不进入 v2 主测试 |
| edge-aware 路径 | v2 标注规范基础 |
| PartialEvidenceEnvironment | EC-ReAct 环境基础 |
| VOI/Cost | 非 LLM 强基线 |
| 七类工具 | Tool Use 接口原型，需替换/增加真实适配器 |
| T/F/U 验证 | CP-Cert 的三值基线 |
| Gate·Score | 仅作已验证路径严重度排序 |
| Web demo | 轨迹、证书和案例展示层 |

## 8. 立即执行顺序

1. ~~冻结数据来源注册表和接入规范；~~
2. ~~拉取 9 个固定来源、精选真实遥测及生产可靠性负对照候选；~~
3. ~~保存版本、下载时间、SHA-256、许可证及上游校验；~~
4. 已冻结：标签无关、来源/平台/家族分层的 19 案例运行时 pilot 及预注册门槛；
5. 正在进行：由两位不同的人独立完成运行时 pilot，并对全部分歧第三人裁决；
6. 待进行：pilot gate 通过后冻结 group-safe split，运行真实 LLM 主实验。

补充工程状态：无标签主条件执行审计已经覆盖全部 91 个非空真实运行实例以及
1,911 次冻结非 LLM 运行；执行失败、硬预算违规、线性/LangGraph 结果不一致
均为 0。这将“系统能否按冻结协议跑完”从待验证项变为已验证项，但不替代人工
gold，也不构成方法有效性证据。详见 `docs/unlabeled_main_dry_run.md`。
