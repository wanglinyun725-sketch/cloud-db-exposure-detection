# EC-ReAct Agent 编排架构决策

## 结论

项目采用 LangGraph 作为正式编排后端，同时保留一个框架无关的线性运行器用于
单元测试和一致性基线。LangGraph 本身是工程依赖，不作为论文创新点。

## 分层

```text
LangGraph runtime
├── plan：LLM/策略提出 Thought + ToolCall / SubmitPath / Finish
├── guard_tool_update：动作校验、工具执行、预算扣减、路径证据更新
├── route：Continue / Finish / Abstain
└── checkpoint/trace：状态持久化与回放

EC-ReAct research layer
├── 部分可观测证据环境
├── case scope 与参数守卫
├── 重复/越权/幻觉引用拦截
├── 成本感知 Pareto 动作候选
├── 四值证据融合与冲突保持
├── Top-K 渐进路径提交与 claim-state 反馈
└── 可执行证据断言 + CP-Cert 最小覆盖证书
```

## 为什么不把研究逻辑绑定死在 LangGraph

1. 同一策略可在线性后端和 LangGraph 后端上运行，便于验证编排框架没有改变
   算法结论；
2. Agent 的创新应能写成状态、动作、约束和停止条件，而不是某个框架 API；
3. 工具、预算、证据和证书由确定性代码控制，LLM 不能绕过；
4. 后续可以加入 checkpoint、人类复核中断和并行候选路径，而不重写方法层。

## 当前状态

- 已实现真实 Splunk 与 DOI 跨云遥测工具环境；
- 已实现 DOI 生产可靠性事件的隐藏筛选 Tool 环境，用作外部误报对照；
- 已实现线性 EC-ReAct 控制器；
- 已实现 LangGraph 的 `plan → guard/tool/update → route` 分节点后端；
- 已实现无密钥离线 policy 和 OpenAI-compatible LLM policy；
- 已实现四值融合、精确/贪心 CP-Cert 与独立证书审计；
- 已实现结构化 `submit_path`：节点/边必须组成有向链，引用必须来自 Agent
  实际看到的 observation/call，证据断言必须在可见字段上执行通过；
- 已冻结 `cloud_data_path_v1`（16 类节点、27 类边）：Agent 只能提交 canonical
  type，API 操作名仍作为证据值而不能伪装成语义边；评分把细粒度 canonical
  exact 作为主结果，literal/coarse 仅作敏感性分析；
- 工具返回被截断时，只有渲染给 policy 的前 12 条成为可引用证据；查询成本按
  tool call 共享，不按返回事件数重复计费；
- 已冻结跨工具动作空间 `cross_tool_visible_sigma_v0.3`：摘要、operation/service
  查询、已见 observation 详情、已见 actor 时间线、已见 status 查询，以及仅从
  已见 request/response 提取的 resource 查询共同进入候选集；候选生成不读取
  隐藏标签或未返回字段；
- 动作的外部规则增益来自固定 SigmaHQ `r2026-07-01` 云检测规则：211 个
  AWS/Azure/GCP 规则文件中抽取 114 条含操作条件的规则、278 个操作模式；
  仅使用正向 detection selection，排除 filter 分支，不读人工 gold，也不设置
  主观关键词权重；
- 外部规则先验、四值 claim memory、Pareto guard、预算停止、严格/记录式证据守卫均有真实
  执行开关，可用于逐项消融，不是只写在配置里的布尔标签；
- 线性与 LangGraph 后端在 Top-K 路径、四值状态、证书、成本和停止结论上必须
  一致；
- 主候选包 v0.5 含 91 个无标签、非空真实运行实例：9 个 Splunk 实例、70 个
  Cross-Cloud 盲化实例、11 个 Stratus/Grimoire 真实爆破实例，以及
  1 个 OTRF 发布的 CloudGoat 派生实例。v0.3 中 2 个零观测上游 episode 被
  无标签准入规则排除；v0.5 又从同一固定归档保留了 Cross-Cloud 的 schema、
  source IP、request/response 和 resource 详情。候选案例与 independence group
  不变。OTRF 不另增
  independence group。源端
  `payload_present/absent` 不进入人工或 policy 可见实例；
- 已实现固定顺序、种子随机和全量查询三种同工具、同输出 schema 基线；
- 已实现预检门控、实例级调度、断点续跑、人工 gold 评分以及
  independence-group 聚类统计；
- 调度、评分与统计同时保留 `scenario_source_id`、
  `runtime_evidence_source_id` 和 platform，分析器输出分层 bootstrap 表及
  来源增益异质性置换/Holm 表；不会把 OTRF 发布者误写成新 CloudGoat 场景；
- 已在 12 个攻击家族、36 个 platform×attack 组、72 个真实 episode 上完成
  双后端协议验证：后端不一致 0，策略可见隐藏标签泄漏 0。该结果只证明工程协议，
  不证明方法有效性；
- 已在 v0.5 全部 91 个可执行实例、4 个运行证据发布者和 3 个云平台上执行
  共同 Tool-Use 契约与双后端审计：455 次工具调用，契约失败 0、后端不一致 0、
  策略泄漏 0；91 个实例均能从固定、无标签详情中执行正命中的
  `resource_search`。该结果同样不证明效果；
- 跨工具动作空间工程审计覆盖相同的 72 个真实 episode：其中 2 个上游文件为空
  遥测，余下 70/70 个均能沿“摘要→前沿搜索→前沿详情”到达跨工具候选状态，
  探针异常 0。详情阶段完整候选均值 14.87、非支配前沿均值 7.07，平均裁剪
  46.84%；该数字只证明动作生成与裁剪确实发生，不代表路径发现准确率；
- 当前确定性 smoke policy 在 payload absent/present 上均为 35/36
  `candidate_evidence_found`，没有区分力，已明确禁止作为论文准确率。

## 跨工具 Pareto 动作空间

对当前可见状态 \(s_t\) 生成可行集合 \(\mathcal A_t^{vis}\)。每个动作使用

\[
u_t(a)=
\left(
g_{\mathrm{ext}}(a),
g_{\mathrm{cov}}(a),
g_{\mathrm{res}}(a),
-\widehat c_t(a)
\right)
\]

描述，其中 \(g_{\mathrm{ext}}\) 是该操作命中的不同 Sigma 云检测规则数，
\(g_{\mathrm{cov}}\) 是可见覆盖增益，\(g_{\mathrm{res}}\) 是证据分辨率增益，
\(\widehat c_t(a)\) 是保守成本估计。Sigma 维度没有人工权重；未命中外部规则
只表示“无外部规则支持”，不表示该动作安全。若

\[
\forall j,\ u_{t,j}(a)\ge u_{t,j}(b)
\quad\land\quad
\exists j,\ u_{t,j}(a)>u_{t,j}(b),
\]

则 \(a\) 支配 \(b\)，完整方法只向 policy 暴露非支配前沿。无法预知返回量的
actor、status 和 resource 查询，使用当前可见 `observation_count` 计算保守
上界；硬预算仍由环境按实际返回量执行。

`pareto_guard=false` 时，policy 得到的是完整的预算可行生成集，并且确定性
控制器不再拒绝其中的被支配动作。因此 `w/o Pareto` 是真实动作筛选消融，而
不是“提示词里说关闭、实际仍只展示前沿”。当前边界是：使用自由输入构造、且
未由可见值生成的 account/region/timestamp 过滤仍由工具 schema、case scope、
重复和预算守卫约束，但不参与 Pareto 排序；主实验必须按该冻结边界报告。

机器可读审计位于 `output/pareto_action_space_audit.json`，复现入口为
`scripts/experiments/audit_pareto_action_space.py`。输出固定携带
`research_effectiveness_result=false`。

固定 72-episode 子集上，Sigma 先验的唯一 platform-operation 覆盖为 19.05%，
事件加权覆盖为 13.53%；其中 Azure 唯一操作覆盖 70.59%，AWS/GCP 均为 9.09%。
这是明确的平台覆盖偏差。因此完整实验增加 `external_rule_prior=false` 独立
消融，必须报告分平台结果；外部规则只作为一个 Pareto 维度，绝不充当安全判定器。

尚未完成的部分不能提前声称：

- LLM 主实验与跨模型结果；
- checkpoint 跨进程恢复实验；
- 相对 Vanilla ReAct 的统计显著优势。

## 证书边界

`evidence_certified_paths` 只表示：结构连通、引用可见、可执行字段断言通过、
四值前提为 support-only，且 CP-Cert 找到了充分且不可约的证据覆盖。它不表示
预测在语义上自动等于真实攻击路径。语义正确性只能由独立双人
`instance_labels` 评分；“内部证书通过但不匹配人工 Valid 路径”仍记为语义误报。
