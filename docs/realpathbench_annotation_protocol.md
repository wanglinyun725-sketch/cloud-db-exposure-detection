# RealPathBench-CD v2 人工标注协议

## 1. 原则

主数据集的路径和证据标签只能来自人工对官方原始材料的判断。解析脚本可以定位
候选实体、事件和文件，但不得填写 `path_labels.state` 或
`edges.evidence_state`。LLM 可以帮助检索材料，不得作为标注者或复核者。

## 2. 标注角色

- Primary annotator：阅读全部原始材料，独立建立节点、边和路径；
- Reviewer：不知道 primary 的最终状态时先独立判断关键路径，再核对结构；
- Adjudicator：解决分歧并记录原因，可由导师或第三名具备云安全知识的人员担任。

同一人不能同时充当 primary 和 reviewer。所有角色使用稳定匿名 ID，不收集姓名
等不必要个人信息。

## 3. 案例准入

### 来源等级

- A：可由权威原始记录直接复核的生产事件、官方审计记录或等价一手材料；
- B：由可信安全项目公开的、固定版本且带原始日志的隔离实验/攻击靶场观测；
- C：只有 Terraform、walkthrough、CTI 叙述或技术定义，尚无对应运行时观测。

等级表示证据来源形态，不代表标签正确率。C 级材料可以进入候选池，但不能单独
进入主测试集；经隔离执行并保存审计日志后可重新评为 B。Splunk Attack Data 的
attack-range 遥测保守记为 B，不得表述为真实生产事故。

### Accept

必须同时满足：

1. 有可定义的外部/低权限入口；
2. 有云身份、网络、资源或数据库关系构成的多步路径；
3. 有数据库、存储、备份、secret 或其他高价值数据终点；
4. 关键路径边均能引用原始 Terraform、日志、官方 walkthrough 或 CTI；
5. 与既有案例不是仅改时间、ID 或单个状态的同源变体。

### Needs execution

官方场景描述了一条路径，但仅靠静态材料无法证明运行时身份、可达性或访问行为。
此时标为 `needs_execution`，待隔离账号执行并收集日志后再决定。

### Reject

包括：

- 只有单点告警，没有多步路径；
- 只有普通主机行为，与云数据目标无关；
- 缺少可复核原始证据；
- 许可证或再分发边界不清；
- 与已纳入案例实质重复。

## 4. 节点与边

每个节点至少需要一个 `raw_ref`。规范化名称不得引入原文不存在的实体。

每条边记录：

```text
(edge_id, source, relation, target,
 evidence_state, evidence_items, time, raw_refs, rationale)
```

并行边必须保留独立 `edge_id`。例如同一用户到同一数据库之间的
`has_permission` 与 `access_data` 不能合并。

`evidence_items` 必须逐条记录
`(evidence_id, polarity, raw_ref, query_cost, source)`。其中 `polarity`
只能是 `support` 或 `refute`；不能只填写汇总状态而不区分哪一条原始
证据支持、哪一条反驳。该结构是 CP-Cert 重放四值融合和生成最小证书的输入。

### 4.1 冻结路径类型本体

节点和边的 `type` 不能自由填写，必须使用
`configs/path_ontology_v1.json` 中的 canonical ID。当前
`cloud_data_path_v1` 含 16 类节点和 27 类有向边，每类都有定义、粗粒度 family
与显式别名。别名只用于兼容性诊断和评分敏感性分析，人工 gold 必须写 canonical
ID，例如：

- 写 `identity`，不能写 `Identity`、`actor` 或 `principal`；
- 写 `database`，不能写 `DB`；
- 写 `access_data`，不能写 `accessed` 或 `data_access`；
- API 名（如 `GetObject`）属于可执行证据字段，不能直接充当语义边类型。

每份人工任务和最终 release 均保存 ontology ID、版本与 SHA-256。标注开始后若
本体改变，旧任务必须显式迁移并重新冻结，不能静默重解释既有标签。

## 5. 四值证据状态

| 状态 | 标注条件 |
|---|---|
| Supported | 至少一份原始证据明确支持，且未发现明确反证 |
| Contradicted | 原始材料明确表明关系不成立，如显式 Deny、失败调用、不可达 |
| Unknown | 当前材料未提供足够信息，不能从“没有日志”推断为反证 |
| Conflict | 同一时间范围和语义下同时存在支持与反证，且不能靠时间切片消解 |

时间范围不同的证据先切片；只有切片后仍矛盾才标 Conflict。
模式校验器同时强制以下对应关系：

- Supported：至少一个 `support` 且没有 `refute`；
- Contradicted：至少一个 `refute` 且没有 `support`；
- Unknown：`evidence_items` 为空，但 `raw_refs` 保留已检查范围；
- Conflict：至少各有一个 `support` 和 `refute`。

## 6. 路径状态

- Valid：所有硬前提均为 Supported，且不存在未消解 Conflict；
- Invalid：至少一个硬前提为 Contradicted；
- Insufficient：无明确反证，但至少一个硬前提为 Unknown；
- Conflict：结论依赖未消解的 Conflict 证据。

敏感程度或风险分数不得改变路径状态。

## 7. 原始证据引用

推荐格式：

```text
source_id@commit:path#selector
```

示例：

```text
splunk_attack_data@3821...:
datasets/attack_techniques/T1110.002/aws_rds_password_reset/
aws_cloudtrail_events.json#record=1
```

引用必须能由 manifest 中的 SHA-256 定位到唯一原始内容。

## 8. 工具任务

Agent 可调用工具不是随意编写的问答接口。每个工具任务需要定义：

- 工具名和版本；
- 可查询参数；
- 能看到哪些 raw observation；
- 不能看到哪些隐藏证据；
- 查询成本；
- 错误与空结果语义。

空结果默认是 Unknown，除非工具和数据源能够证明其查询范围完整。

## 9. 运行实例标签

案例级 graph 定义“可能的路径结构”，`runtime_instances` 定义 Agent 真正查询的
某一次冻结观测。两者不能混为一个标签。每个可运行实例必须填写：

- `instance_id`：只能引用冻结 source context 中已有的不透明实例；
- `path_states`：对该案例每条 path 分别填写
  Valid/Invalid/Insufficient/Conflict；
- `overall_state`：任一路径 Valid 则为 Valid；否则依次按
  Conflict、Insufficient、Invalid 判定；
- `evidence_raw_refs` 与 `annotator_rationale`。

Cross-Cloud 的两个配对实例必须分别阅读实际 observations 后判断；不得把上游
`y/n` 文件名或 payload 条件直接复制为 gold。缺少运行证据时应标
Insufficient 或将案例送入 `needs_execution`，不能用案例描述代替实例证据。

## 10. 一致性

至少计算：

- 案例 accept/reject：Cohen's kappa；
- 路径状态：在匹配路径上计算名义类别 Cohen's kappa 或 Krippendorff's
  alpha；四种状态没有天然顺序，不人为指定线性权重；
- edge identity：precision/recall/F1；
- 证据状态：在匹配边上计算 macro-F1，并与 edge identity 指标分开报告；
- 运行实例整体状态：在相同 `instance_id` 上计算 Cohen's kappa 和 macro-F1；
- 分歧率与仲裁后修改率。

一致性不足时先修订指南并重标 pilot，不能直接扩大数据量。运行时 pilot 的数值
门槛以任何人工结果产生前冻结的
`configs/human_annotation_pilot_gate_v2.json` 为准；实现位于
`src/annotation/pilot_gate.py`。不得在看到结果后改用更宽松的“明显偏低”等
主观判据。

## 11. 冻结

每个发布版本保存：

- source commit 和许可证；
- raw artifact SHA-256；
- 标注指南版本；
- primary/reviewer/adjudication 记录；
- 数据 split；
- 生成 release manifest 的代码 commit。

test 与 external_test 冻结后不得用于 prompt、阈值、预算或策略选择。
