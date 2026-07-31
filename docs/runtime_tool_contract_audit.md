# 四来源运行时 Tool-Use 契约审计

## 研究问题

已有 72 个 Cross-Cloud episode 的协议验证只能证明一种遥测形态下线性执行器与
LangGraph 等价，不能证明 Splunk、Stratus 和 OTRF 的日志也能进入同一套
ReAct/Tool-Use 接口。本审计对主候选池的每个运行实例执行相同的盲化、五工具探针
和双后端确定性 policy。

## 审计设计

`UnlabeledRuntimeInstanceEnvironment` 只接受：

- `annotation.status=pending` 且 `label_origin=null` 的案例；
- 空的 nodes、edges、path labels 和 instance labels；
- `path_label`、`evidence_state` 均为空的来源观测。

原始 case ID、candidate ID 和 instance ID 不进入 policy 视图。审计逐实例调用
`summarize_case`、`search_events`、`get_event_detail`、`actor_timeline` 和
`resource_search`，并分别运行线性 EC-ReAct 与 LangGraph EC-ReAct。比较使用
完整结构化结果，不只比较最终 decision。

## v0.3 发现与修订

v0.3 的 93 个实例均能遵守空结果语义并完成双后端审计，但其中 2 个上游 episode
含 0 条观测，只能 abstain，且不满足正式 `FrozenRuntimeInstanceEnvironment`
的非空准入条件。因此项目没有把它们写成负例，而是生成可追溯 v0.4：仅排除两个
空实例，保留其案例与来源谱系。

## v0.4 数据形状发现与 v0.5 结果

v0.4 的非空准入审计通过，但量化出只有 21/91 个实例的规范化视图含
request/response；70 个 Cross-Cloud 紧凑实例无法正向使用 `resource_search`。
v0.5 因而从同一固定 DOI 归档、同一成员 SHA-256 和同一确定性场景字面盲化层
保存 `get_event_detail` 字段，没有新增事件、路径或标签。

| 指标 | 结果 |
|---|---:|
| 运行案例 | 57 |
| 运行实例 | 91 |
| independence group | 32 |
| 运行证据发布者 | 4 |
| 云平台 | 3 |
| 工具契约调用 | 455 |
| 工具契约失败 | 0 |
| 线性/LangGraph 不一致 | 0 |
| policy 泄漏失败 | 0 |
| request/response/resource 详情可用实例 | 91 |
| `resource_search` 正命中实例 | 91 |
| payload 受限实例 | 0 |

分布为 Cross-Cloud 70、Splunk 9、Stratus 11、OTRF 1；平台为 AWS 42、
Azure 25、GCP 24。六种 schema 为 AWS CloudTrail、Azure Activity、
Azure AD Audit、GCP Audit Log、OCSF API Activity 和 Splunk key-value。
完整机器可读 v0.5 结果见 `output/runtime_tool_contract_audit.json`，v0.3 的
前序审计见 `output/runtime_tool_contract_audit_v0_3.json`。

## 可主张与不可主张

可主张：四个运行证据发布者可由同一 Tool-Use 合约处理，两个编排后端在该确定性
协议上语义等价，未发现 evaluator 字段或原始实例标识泄漏。

不可主张：EC-ReAct 已正确发现攻击路径、优于 vanilla ReAct、或者 91 个实例均为
正例。所有案例仍无人工 gold，机器输出显式保留
`research_effectiveness_result=false`。
