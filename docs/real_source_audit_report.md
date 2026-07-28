# RealPathBench-CD 首批真实来源审计

## 审计结论

- 固定原始工件：20 个；SHA-256 全部匹配：True。
- 本报告只做来源盘点与人工标注候选筛选，没有生成 benchmark 样本或标签。
- 候选数量不是最终样本量；必须经人工阅读、路径重建、证据回链和去重后才能纳入。

## 来源盘点

| 来源 | 官方内容规模 | 云数据相关候选 | 定位 |
|---|---:|---:|---|
| MITRE ATT&CK STIX | 25843 objects | 270 procedures | CTI/引用 |
| CloudGoat | 32 scenario manifests | 26 scenarios | 可执行靶场 |
| CloudFoxable | 20 challenges | 8 challenges | 可执行靶场 |
| Stratus Red Team | 99 techniques | 51 techniques | 可执行原子攻击 |
| Splunk Attack Data | 1244 dataset dirs | 9 telemetry groups | 公开攻击日志 |
| CloudFox | 51 command files | 18 tool modules | Agent 工具适配 |
| Cross-Cloud Observability | 35 attacks / 8327 JSON logs | 36 data-path groups | AWS/Azure/GCP 配对攻击遥测 |
| Cloud Incident Reports | 3087 production reports | 996 keyword-routed candidates | 仅 external negative control 人工候选 |

## Pilot 人工标注队列

| # | 来源 | 候选 ID | 类型 | 状态 |
|---:|---|---|---|---|
| 1 | cloudgoat | `cloudgoat:aws:codebuild_secrets` | executable_scenario | pending_human_review |
| 2 | cloudgoat | `cloudgoat:aws:rce_web_app` | executable_scenario | pending_human_review |
| 3 | cloudgoat | `cloudgoat:aws:vpc_peering_overexposed` | executable_scenario | pending_human_review |
| 4 | cloudgoat | `cloudgoat:aws:rds_snapshot` | executable_scenario | pending_human_review |
| 5 | cloudgoat | `cloudgoat:aws:secrets_in_the_cloud` | executable_scenario | pending_human_review |
| 6 | cloudfoxable | `cloudfoxable:aws:It's a secret` | executable_challenge | pending_human_review |
| 7 | cloudfoxable | `cloudfoxable:aws:Search 1` | executable_challenge | pending_human_review |
| 8 | cloudfoxable | `cloudfoxable:aws:Backwards` | executable_challenge | pending_human_review |
| 9 | cloudfoxable | `cloudfoxable:aws:It's another secret` | executable_challenge | pending_human_review |
| 10 | stratus_red_team | `stratus:aws.exfiltration.rds-share-snapshot` | executable_attack_technique | pending_human_review |
| 11 | stratus_red_team | `stratus:gcp.credential-access.secretmanager-retrieve-secrets` | executable_attack_technique | pending_human_review |
| 12 | stratus_red_team | `stratus:aws.credential-access.secretsmanager-retrieve-secrets` | executable_attack_technique | pending_human_review |
| 13 | stratus_red_team | `stratus:aws.impact.s3-ransomware-batch-deletion` | executable_attack_technique | pending_human_review |
| 14 | stratus_red_team | `stratus:aws.impact.s3-ransomware-individual-deletion` | executable_attack_technique | pending_human_review |
| 15 | splunk_attack_data | `splunk:datasets/attack_techniques/T1537/aws_snapshot_exfil` | published_attack_telemetry | pending_human_review |
| 16 | splunk_attack_data | `splunk:datasets/attack_techniques/T1110.002/aws_rds_password_reset` | published_attack_telemetry | pending_human_review |
| 17 | splunk_attack_data | `splunk:datasets/attack_techniques/T1530/aws_s3_public_bucket` | published_attack_telemetry | pending_human_review |
| 18 | splunk_attack_data | `splunk:datasets/attack_techniques/T1490/aws_bucket_version` | published_attack_telemetry | pending_human_review |
| 19 | splunk_attack_data | `splunk:datasets/attack_techniques/T1486/s3_file_encryption` | published_attack_telemetry | pending_human_review |
| 20 | mitre_attack_stix | `relationship--7e7151b1-8407-4cac-a843-f2605fb25377` | procedure_relationship | pending_human_review |
| 21 | mitre_attack_stix | `relationship--68929916-ab9f-4078-b959-e500f8cab3b8` | procedure_relationship | pending_human_review |
| 22 | mitre_attack_stix | `relationship--bb3c2843-b51f-4cfd-8189-0312337b8eb3` | procedure_relationship | pending_human_review |
| 23 | mitre_attack_stix | `relationship--2cf91706-674a-4ae0-8a4c-0d8d43eb6e1a` | procedure_relationship | pending_human_review |
| 24 | mitre_attack_stix | `relationship--ee1effa5-b256-4a6a-b7da-2d9066d7dccd` | procedure_relationship | pending_human_review |
| 25 | cross_cloud_observability_2026 | `crosscloud:aws:automated_exfiltration` | published_cross_cloud_paired_telemetry | pending_human_review |
| 26 | cross_cloud_observability_2026 | `crosscloud:aws:credentials_from_password_stores` | published_cross_cloud_paired_telemetry | pending_human_review |
| 27 | cross_cloud_observability_2026 | `crosscloud:azure:automated_exfiltration` | published_cross_cloud_paired_telemetry | pending_human_review |
| 28 | cross_cloud_observability_2026 | `crosscloud:azure:credentials_from_password_stores` | published_cross_cloud_paired_telemetry | pending_human_review |
| 29 | cross_cloud_observability_2026 | `crosscloud:gcp:automated_exfiltration` | published_cross_cloud_paired_telemetry | pending_human_review |
| 30 | cross_cloud_observability_2026 | `crosscloud:gcp:credentials_from_password_stores` | published_cross_cloud_paired_telemetry | pending_human_review |

## 准入门

每个候选只有同时满足以下条件才会成为 RealPathBench-CD 样本：

1. 至少存在一个可定义入口和一个高价值数据目标；
2. 多步关系能由原始 Terraform、日志、walkthrough 或 CTI 引用支持；
3. 每条 gold edge 保存原始证据定位；
4. 不依赖当前验证器自动生成标签；
5. 与已纳入案例不属于同一基础场景的轻微变体；
6. 人工审阅明确记录 `accept/reject/needs_execution` 及理由。
