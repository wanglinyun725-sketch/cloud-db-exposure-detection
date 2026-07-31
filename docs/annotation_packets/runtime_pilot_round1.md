# Runtime annotation pilot v1

该 pilot 已在任何人工标注开始前被 v2 取代，原因是随后核验出第三个独立发布的
真实运行时来源 Stratus。它保留用于版本溯源，不再作为正式工作流校准集，也不是
已完成 gold。机器可读包为：

```text
data/real_sources/annotation/runtime_pilot_round1_unlabeled.json
```

## 冻结摘要

- 19 个案例、31 个真实运行实例、10 个完整 independence group；
- 317 条真实上游观测；
- 12 个 Cross-Cloud 案例，覆盖 4 个攻击家族 × AWS/Azure/GCP；
- 7 个 Splunk Attack Data 案例，覆盖 6 个完整独立组；
- 实例平台分布：AWS 14、Azure 9、GCP 8；
- 人工 gold、脚本标签、AI 标签均为 0。

基础扩展包 SHA-256 为
`25ebfe2b63c50225c071556d101f8f78e157b9f8a6eba04c5b4328ec062823db`；
pilot 文件 SHA-256 为
`da469be7946b66c7dd087549145fc6d466c9087121b57b3eaffb5c55aed31c7a`。
选择规则、组白名单和期望计数冻结在
`configs/runtime_annotation_pilot_v1.json`。构建器只读取来源、独立组、平台和
运行规模，不读取人工标签或模型输出；同一 independence group 不允许部分抽取。

## 盲法边界

Cross-Cloud 的上游 `episode_refs` 仅供 evaluator 核验完整配对。创建人工任务时，
该字段整体移除，因此标注者看不到 `source_condition`、`payload_present/absent`
或编码条件的 episode ID。标注者仍能看到冻结的真实 observations、运行实例 ID、
来源工件及 SHA-256。

## 质量门槛

原 v1 gate 同样留存，但主配置不再引用。正式工作流见
`docs/annotation_packets/runtime_pilot_round2.md`。
