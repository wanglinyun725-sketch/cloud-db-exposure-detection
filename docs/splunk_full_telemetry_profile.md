# Splunk Pilot 原始遥测画像

本文件由公开原始日志机械归一化得到；未生成攻击路径或证据标签。

- 案例组：9
- 原始事件：176
- 唯一操作：14
- 唯一服务：6

| 候选 | 发布日期 | 环境 | MITRE | 事件数 | 操作 |
|---|---|---|---|---:|---|
| `splunk:datasets/attack_techniques/T1098.001/azure_ad_federated_identity_credential` | 2026-06-10 | attack_range | T1098.001 | 2 | Update service principal×2 |
| `splunk:datasets/attack_techniques/T1110.002/aws_rds_password_reset` | 2022-08-08 | attack_range | T1110.002 | 5 | ModifyDBCluster×3, ModifyDBInstance×2 |
| `splunk:datasets/attack_techniques/T1119/aws_exfil_datasync` | 2023-04-10 | attack_range |  | 5 | CreateTask×2, JobCreated×2, PutBucketReplication×1 |
| `splunk:datasets/attack_techniques/T1486/s3_file_encryption` | 2021-01-11 | attack_range | T1486 | 2 | CopyObject×2 |
| `splunk:datasets/attack_techniques/T1490/aws_bucket_version` | 2023-04-12 | attack_range | T1490 | 4 | PutBucketVersioning×4 |
| `splunk:datasets/attack_techniques/T1530/aws_exfil_high_no_getobject` | 2023-04-12 | attack_range |  | 100 | GetObject×100 |
| `splunk:datasets/attack_techniques/T1530/aws_s3_public_bucket` | 2021-01-12 | attack_range | T1530 | 9 | PutBucketAcl×9 |
| `splunk:datasets/attack_techniques/T1537/aws_exfil_risk_events` | 2023-03-31 | attack_range | T1537 | 38 | ESCU - AWS EC2 Snapshot Shared Externally - Rule×20, ESCU - AWS Exfiltration via Anomalous GetObject API Activity - Rule×18 |
| `splunk:datasets/attack_techniques/T1537/aws_snapshot_exfil` | 2021-07-20 | attack_range | T1537 | 11 | ModifySnapshotAttribute×10, CreateSnapshot×1 |

所有 observation 均保存原始文件 SHA-256、Git blob SHA、LFS OID（如适用）
和 record index。`path_label` 与 `evidence_state` 保持 null，等待人工标注。
