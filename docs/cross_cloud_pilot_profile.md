# Cross-Cloud Pilot 真实遥测剖面

## 结论

- DOI 固定来源：`10.5281/zenodo.19933893`；许可：`CC-BY-4.0`。
- 6 个平台×攻击候选组，归属于 2 个攻击家族；
- 240 个公开日志 episode，构成 120 对 payload/no-payload 对照；
- 共 26404 条原始云审计观测；
- 代码只识别上游文件边界并统计事件字段，未生成路径或证据标签。

## 分布

| 维度 | 分布 |
|---|---|
| 平台 | {'AWS': 80, 'AZURE': 80, 'GCP': 80} |
| 条件 | {'payload_absent': 120, 'payload_present': 120} |
| 日志配置 | {'additional': 120, 'default': 120} |

## 实验使用边界

1. `source_condition` 只表示作者是否执行 payload，不等同于路径 Valid；
2. 同一攻击家族的所有平台、运行与日志配置必须放在同一 split；
3. 运行重复可用于估计方差，不可冒充独立攻击路径样本；
4. path/evidence gold labels 仍需人工阅读脚本和原始日志后建立。
