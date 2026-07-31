# EC-ReAct 冻结主实验协议

## 1. 实验目标

主实验不再回答笼统的“Agent 是否更聪明”，而是检验：

> 在相同真实案例、工具、查询预算和模型条件下，证据约束与成本感知的
> EC-ReAct 是否能以更低查询成本发现更多人工确认的有效路径，同时减少无证据
> 结论和错误停止。

机器可读草案位于 `configs/ec_react_main_v2_draft.yaml`；人工 gold 与负对照
完成并提交后，冻结器产生不可覆盖的 `configs/ec_react_main_v2_frozen.yaml`
及其 manifest。任何主结果运行前必须同时通过输入预检和冻结绑定校验。

## 2. 方法矩阵

| 方法 | LLM | Pareto 守卫 | Sigma 先验 | 四值记忆 | 预算停止 | 证据证书 | 作用 |
|---|---:|---:|---:|---:|---:|---:|---|
| EC-ReAct | 是 | ✓ | ✓ | ✓ | ✓ | ✓ | 完整方法 |
| Vanilla ReAct | 是 | — | — | — | — | — | Agent 基线 |
| w/o Pareto | 是 | — | ✓ | ✓ | ✓ | ✓ | 消融跨工具非支配筛选 |
| w/o external prior | 是 | ✓ | — | ✓ | ✓ | ✓ | 消融外部规则增益 |
| w/o four-value | 是 | ✓ | ✓ | — | ✓ | ✓ | 消融冲突/未知记忆 |
| w/o budget stop | 是 | ✓ | ✓ | ✓ | — | ✓ | 消融成本停止 |
| w/o evidence cert | 是 | ✓ | ✓ | ✓ | ✓ | — | 原样记录无效路径，消融证据门禁 |
| Fixed order | 否 | — | — | — | — | 记录模式 | 非学习策略 |
| Random tool | 否 | — | — | — | — | 记录模式 | 种子随机策略 |
| Full query | 否 | — | — | — | — | 记录模式 | 高成本查询基线 |

所有方法共享：

- 同一冻结案例和 split；
- 同一工具 schema、原始观察范围和查询成本；
- 同一 `max_steps=12`；
- 同一 Top-K 上限 `max_path_candidates=5`；
- 同一 `evidence_path_proposal_v0.3` 结构化路径、受控类型本体与可执行证据
  断言输出 schema；
- 同一冻结动作空间 `cross_tool_visible_sigma_v0.3`；它从 policy 已见摘要与事件字段
  生成跨工具候选，不读取隐藏 gold；
- 同一预算网格 \(B\in\{10,20,30\}\)；
- LLM 方法使用相同模型、温度、system policy 外的任务描述；
- 评估器和隐藏 gold 对所有策略不可见。

方法差异只能来自表中的显式组件，不能给 EC-ReAct 更多工具或更完整日志。

完整方法对摘要、operation/service 搜索、事件详情、actor 时间线、status 搜索
和 visible request/response 派生的 resource 搜索联合计算

\[
u_t(a)=
\left(g_{\mathrm{ext}},g_{\mathrm{cov}},g_{\mathrm{res}},
-\widehat c_t\right),
\]

并只暴露非支配动作。`w/o Pareto` 接收相同生成规则产生的全部预算可行候选，
同时关闭前沿拒绝；这是唯一动作筛选差异。account/region/timestamp 等未由
生成器提出的自由参数动作不进入 Pareto 排序，此边界不得在看到测试结果后更改。
\(g_{\mathrm{ext}}\) 等于固定 SigmaHQ `r2026-07-01` 云检测规则中匹配当前
operation 的不同规则数，不做加权。派生过程仅遍历 AWS `eventName`、Azure
`operationName` 和 GCP audit `method_name` 的正向 selection；filter 分支、
人工标签和实验 gold 均不参与。

## 3. 主要度量

以人工标注的 edge-aware 路径集合 \(\mathcal P_i^*\) 为 gold。预算 \(B\) 下：

\[
R@K(B)=\frac{1}{N}\sum_{i=1}^{N}
\frac{\left|\hat{\mathcal P}_{i,K}(B)\cap\mathcal P_i^*\right|}
{\left|\mathcal P_i^*\right|}.
\]

预测 ID 与人工 ID 没有共享命名空间，因此主 exact match 使用冻结
`cloud_data_path_v1` 的细粒度 canonical 节点类型序列和边类型序列；edge F1
比较
`(source node type, edge type, target node type)` 多重集。不能把“节点相同、
权限边不同”的路径算正确。

令 \(\phi_f\) 为显式别名到细粒度 canonical type 的冻结映射，则：

\[
\mathrm{Exact}_f(\hat P,P^*)=
\mathbb 1[
\phi_f(V_{\hat P})=\phi_f(V_{P^*})
\land
\phi_f(E_{\hat P})=\phi_f(E_{P^*})
].
\]

未知类型直接判为不匹配；不使用 embedding、LLM judge 或运行后补写的同义词。
另外报告 literal exact 和 family-level coarse exact 作为敏感性分析，但它们不
参与主假设检验，也不能给细粒度错误路径记主指标正确。

首条有效路径成本：

\[
C_i^{\mathrm{first}}=
\min\left\{c_t:\hat P_{i,t}\in\mathcal P_i^*\right\},
\]

未发现时按右删失报告，并同时给出固定预算召回，不能只统计成功样本。

证据不支撑率与语义误报率分开：

\[
\mathrm{UER}=\frac{\#\{\hat P:\text{internal certificate invalid}\}}
{\#\{\hat P\}},\qquad
\mathrm{SFPR}=\frac{\#\{\hat P:\text{certificate valid}\land
\hat P\notin\mathcal P^*\}}{\#\{\hat P:\text{certificate valid}\}}.
\]

因此 CP-Cert 通过但不匹配人工 gold 的路径不会被算成正确发现。

外部负对照上的正确拒绝：

\[
\mathrm{CR}_{neg}=
\frac{1}{N_{neg}}\sum_i
\mathbb 1[\text{Agent 未输出内部认证的攻击路径}].
\]

另单独报告显式 `abstain/no_verified_path` 比例，不能把无证据路径通过
CP-Cert 但语义错误的输出计作正确。

不使用主观加权总分掩盖准确率—成本权衡；主文报告预算—召回 Pareto 曲线、
固定预算配对差和错误率。

## 4. 统计单位与推断

- 先对同一 runtime instance 的 5 次重复取均值，再对同一
  `independence_group` 内的实例取均值；推断单位是 independence group，不是
  边、episode 或重复运行；
- LLM/随机策略每个案例、预算、模型重复 5 次；
- 报告 group-cluster bootstrap 95% CI；
- EC-ReAct 与每个基线使用 group-level 配对置换检验；
- 多个主要指标使用 Holm 校正；
- 同时报均值、配对差的 group-bootstrap 95% CI、标准化配对效应量和
  Holm 校正 p 值；
- 按实际配对谱系 N 报告 80% 目标功效下的最小可检测 \(d_z\)，不使用观察效应
  反算事后功效；
- “错误 Reachable 不增加”同时要求组级事件率点差不大于 0，且配对
  bootstrap 95% CI 上界不大于 0；仅点估计更低不足以通过安全门槛；
- 分来源、平台和 held-out split 报告，不只给合并数字。

若某个攻击家族只有大量重复日志而没有多个独立 group，不得把重复日志当作
增大的统计样本量。

### 4.1 来源异质性与外部有效性

合并主效应之外，必须保留真实运行时来源标签并执行以下预注册分析：

- 分开保留 `scenario_source_id` 与 `runtime_evidence_source_id`：前者表示攻击
  场景的原始来源，后者表示日志发布者；二者都输出 group-level 指标和 95% CI；
- 对每个来源计算 EC-ReAct 相对 vanilla ReAct 的同组配对增益，不把来源规模
  差异变成样本权重优势；
- 仅当两个待比较来源各有至少 5 个独立 group 时，才执行来源×方法增益的
  置换异质性检验；样本不足只做描述，不宣称等效；
- 以 leave-one-source-out 方式汇报：调试与阈值选择不得读取被留出来源的 gold，
  固定方法直接在该来源上测试；
- Stratus 的 35 份日志中只有与云数据候选相交的 11 份可进入正向候选池，其余
  24 份不得为追求来源规模而自动改成正例；
- 同一上游 technique 的所有日志、变体和实例必须留在同一 independence group。

来源异质性显著时，主结论必须改写为“在特定来源成立”，不能用合并均值掩盖。
这项分析只在人工 gold 与 split 冻结后执行；当前 3 来源 pilot 仅用于校准标注
可靠性，不是方法效果证据。

以上约束已进入执行代码：每条 schedule/run/score 同时携带两类 source ID 和
platform；主分析器生成 `slice_summaries.csv`、`source_gain_summaries.csv` 与
`source_heterogeneity_tests.csv`。每来源少于 5 个 independence group 时只输出
描述性增益及置信区间，不生成异质性 p 值。

## 5. 冻结与泄漏门禁

预检必须同时确认：

1. gold release 全部为 `human_reviewed` 或 `human_adjudicated`；
2. source packet SHA-256 与 gold、split manifest 一致；
3. 同一 independence group 不跨 split；
4. 每种方法使用同一工具 schema、步骤和预算；
5. 模型名称、温度、随机种子、配置哈希已固定；
6. API key 只从环境变量读取，绝不写进报告；
7. smoke 输出带有 `research_effectiveness_result=false`，不能进入主表。
8. 每个可运行实例都有双人复核的 `instance_labels`，且人工标签只进入评估器；
9. Splunk 案例名、MITRE 号、Cross-Cloud 条件和人工路径在 policy 侧均不可见。
10. 至少 20 份生产可靠性报告由两人确认“云数据相关、非攻击、可作负对照”；
11. 固定 split 的构造不读取 path/edge/instance label，且 C 级材料不进测试集。
12. ontology ID、版本、SHA-256 与配置一致，人工 gold 和 Agent 输出均使用
    canonical type；coarse match 只能作为敏感性结果。
13. `pareto_action_space_id=cross_tool_visible_sigma_v0.3` 与执行代码一致；
    Sigma 原始压缩包及派生先验哈希均匹配；完整方法与
    消融只改变是否应用非支配筛选，不改变候选生成规则。

当前预检读取到 150 个真实上游候选、113 个 independence group；其中已冻结
主候选包 v0.5 有 91 个非空无标签真实运行实例（9 个 Splunk、70 个
Cross-Cloud 盲化实例、11 个 Stratus/Grimoire 真实爆破实例，以及 1 个 OTRF
发布的 CloudGoat 派生实例）。OTRF 实例仍归入
`cloudgoat-scenario:cloud_breach_s3`。v0.3 中两个零观测上游 episode 只保留在
来源/契约审计中，不进入正式人工 gold 或主实验运行实例。v0.5 还从同一固定
Cross-Cloud 归档和同一确定性盲化环境保存 schema、source IP、request、response
和 resource 详情，使所有 91 个实例都能公平使用 `resource_search`。
候选规模门已通过，但仍客观返回 `ready=false`，因为实例级双人人工 gold、
split manifest 和模型运行环境尚未齐备。密钥是执行条件；真正的研究阻塞项是
人工 gold、人工负对照筛选以及 C 级静态候选所需的隔离执行。

## 6. 运行规模

当前方法矩阵包含 7 个 LLM 方法、2 个确定性基线、1 个随机基线、2 个模型、
3 档预算。每个运行实例对应 231 次冻结条件运行；10 个实例需要 2,310 次。
配置的最低可运行目标是 30 个正向 runtime-backed 案例加 20 个外部负对照，
即至少 11,550 次；若案例含多个实例，实际规模按实例数增加。调度器不会把实例数
冒充独立 group。扩展池现有 150 个候选、
113 个独立组，但其中 93 个是尚无项目运行时观测的 C 级静态材料；候选数不能
冒充 gold 数。应先用首轮 10–20 个双人 gold 估算 API 成本和方差，再执行高价值
C 级场景并冻结正式集合；不能把 pilot 降格冒充主实验。

## 7. 当前验证边界

72 个真实遥测 episode 的双后端验证只能证明 LangGraph/线性一致和无已知标签
泄漏，不能证明攻击路径发现能力。当前 deterministic smoke policy 对
payload absent/present 没有区分力，因此它不会进入论文效果表。

同一批 episode 的跨工具动作空间审计中，2 个上游文件为零观测，70 个非空
episode 全部到达详情后候选状态；详情阶段完整候选均值 14.87，Pareto 前沿
均值 7.07，平均裁剪 46.84%。这是候选机制的工程审计，不使用人工 gold，
`research_effectiveness_result=false`，不得写成准确率或优越性结果。

同一审计显示 Sigma 先验只覆盖 105 个可见 platform-operation 组合中的 20 个
（19.05%），按事件量覆盖 13.53%；Azure 唯一操作覆盖为 70.59%，AWS 与 GCP
均为 9.09%。因此零命中只能解释为“无固定 Sigma 规则支持”，不能解释为安全；
主结果必须报告分平台结果并包含 `w/o external prior`，防止外部规则覆盖偏差
被误写成 Agent 能力。

### 无标签全实例主条件干跑

在人工 gold 冻结前，项目已对 v0.5 的 91 个非空真实运行实例执行
1,911 次非 LLM 主条件干跑，覆盖 `fixed_order`、`full_query`、
`random_tool`，预算为 10、20、30，并逐次核对线性与 LangGraph 后端。
当前执行失败、硬预算违规和后端不一致均为 0。该结果仅是执行契约审计，
始终带有 `research_effectiveness_result=false`，不得进入主效果表。
完整边界与复现命令见 `docs/unlabeled_main_dry_run.md`。

正式执行统一使用失败关闭流水线：

```powershell
& 'D:\anaconda\python.exe' scripts\experiments\run_research_pipeline_v2.py --mode status
& 'D:\anaconda\python.exe' scripts\experiments\run_research_pipeline_v2.py --mode plan
& 'D:\anaconda\python.exe' scripts\experiments\run_research_pipeline_v2.py --mode execute
```

`status` 只审计真人 release、负对照、密钥和冻结绑定，不授权模型调用；
`plan` 验证实例级 schedule，也不调用模型；`execute` 是唯一授权正式模型调用的
入口。若传入的是 draft，`execute` 会先调用协议冻结器，并在任何模型调用前
逐项核对：

1. 冻结 YAML 的实际 SHA-256 与 manifest 一致；
2. YAML 与 manifest 绑定同一个完整 Git commit；该 commit 必须是执行时 HEAD
   的祖先，且从该 commit 到 HEAD 的 `src/`、`scripts/`、其他 `configs/`
   不得变化（只允许提交冻结 YAML 本身），工作区也不得有相关未提交漂移；
3. 两者记录的 gold、split、本体、外部先验等输入哈希完全一致；
4. YAML 指向的 manifest 路径与本次执行参数一致；
5. 冻结配置再次通过主实验 preflight。

真人 release 与 split 必须先提交到 Git；存在相关未提交改动时冻结器会拒绝
写出 FROZEN 文件。流水线不会把 draft 直接当作主实验配置，也不会把
`claim_not_passed` 报告成 `ready=true`。通过后按 `schedule_id` 断点续跑
JSONL，随后生成 cluster bootstrap、配对置换/Holm 校正表、机器 claim decision
和复现压缩包。
