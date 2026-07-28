# Stratus Red Team 真实爆破日志溯源说明

## 结论

项目固定的 Stratus Red Team commit
`52db2f8bbbc85ca7c4292f0035180fc4fa8bfdb0` 内含 35 份非空
`docs/detonation-logs/*.json`，共 310 条 AWS CloudTrail 事件。每个对应技术文档
均明确说明：日志来自测试环境中的真实 detonation，由 Grimoire 收集并由
LogLicker 脱敏。

完整索引为：

```text
data/real_sources/stratus_detonation_log_index.json
```

- 原始归档 SHA-256：
  `fa2ad67871887a55f226f875a9c339b7e12987b83aa5a951631ce9f5036d0480`
- 派生索引 SHA-256：
  `c03c07b43809ea0526f49eb99537c7d4fa771d620b8d77725f947ba23419557e`
- 日志文件：35；
- CloudTrail 事件：310；
- 唯一 operation：54；
- 唯一 service：14。

## 路由与证据等级边界

现有云数据候选路由只与其中 11 个技术相交，共 139 条事件。这 11 个候选从仅有
技术文档的 C 级升级为带真实测试云运行观测的 B 级。其余 24 份日志、171 条事件
继续保存在完整索引中，但不会因为“存在攻击日志”就自动标为云数据路径正例。

脚本只执行归档 SHA 校验、成员 SHA 校验、CloudTrail 字段规范化和确定性候选
关联。它不生成事件，不生成准入、路径、边或四值证据标签；所有相关字段保持
`null`/空列表，等待双人独立标注。

## 可复核性

每条规范化 observation 保存原始归档路径和哈希、归档内 member 路径和哈希、
记录索引及上游 event ID。`scripts/data/profile_stratus_detonation_logs.py`
会重新读取固定归档，并拒绝以下情况：归档哈希变化、空/畸形日志、缺失对应技术
文档，或文档不再包含真实 detonation 声明。
