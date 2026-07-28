# Runtime annotation pilot v2

这是 EC-ReAct/CP-Cert 正式人工工作流校准集，不是主测试集，也不是已完成 gold。
机器可读包为：

```text
data/real_sources/annotation/runtime_pilot_round2_unlabeled.json
```

## 冻结摘要

- 23 个案例、35 个真实运行实例、14 个完整 independence group；
- 389 条真实上游观测；
- 12 个 Cross-Cloud 案例，覆盖 4 个攻击家族 × AWS/Azure/GCP；
- 7 个 Splunk Attack Data 案例，覆盖 6 个完整独立组；
- 4 个 Stratus 案例，覆盖实例凭据、单/批量秘密读取与 RDS 快照外传；
- 来源案例数：Cross-Cloud 12、Splunk 7、Stratus 4；
- 实例平台分布：AWS 18、Azure 9、GCP 8；
- 人工 gold、脚本标签、AI 标签均为 0。

基础扩展包 SHA-256 为
`25ebfe2b63c50225c071556d101f8f78e157b9f8a6eba04c5b4328ec062823db`；
pilot 文件 SHA-256 为
`40edd6a3f0f0924a5a0b7434b5aa5d95a54bc4ae2234b0829688c1c201403114`。
选择规则、组白名单和期望计数冻结在
`configs/runtime_annotation_pilot_v2.json`。v2 明确记录其取代 v1 的原因：
第三来源在人工工作开始前得到验证，加入过程没有读取任何人工标签或模型输出。

## 盲法与完整组边界

构建器只读取来源、独立组、平台和运行规模；同一 independence group 不允许
部分抽取。Cross-Cloud 的 evaluator-only 条件不会进入人工任务；Stratus 使用
官方发布的完整 detonation-log member，不选择单条事件。人工任务中的准入、图、
路径、实例状态与证据状态字段全部为空。

## 质量门槛

`configs/human_annotation_pilot_gate_v2.json` 在结果产生前冻结一致性、有效样本
保留、三来源覆盖、平台覆盖和仲裁完整性门槛。最终 release 必须通过
`scripts/annotation/evaluate_pilot_gate.py`；失败时修订指南或来源后重做 pilot，
不能根据结果放宽阈值。
