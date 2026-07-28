# RealPathBench-CD v2 完整候选池人工标注包

> 该文件只整理固定上游版本中的真实发布遥测，不包含任何 AI/脚本生成的
> 准入决定、节点、边、证据状态或路径标签。请结合
> `docs/realpathbench_annotation_protocol.md` 完成人工标注。

## 标注顺序

1. 阅读案例元数据、全部原始文件和下面的观测索引；
2. 独立填写 `admission_screen`，先决定 accept / needs_execution / reject；
3. 仅对 accept 案例人工建立 nodes、edges、path_labels 与 tool_tasks；
4. 每条边逐项填写带 support/refute 极性的 evidence_items；
5. 填入稳定匿名标注者 ID，并将状态改为 `primary_complete`；
6. Reviewer 在不知道 primary 路径状态的条件下独立复核。

- 固定上游版本：`{'splunk_attack_data': '3821bdb77c66c95b4e529f62a9d00b168446d1a8', 'cross_cloud_observability_2026': 'record-19933893-v2'}`
- 待人工筛选案例数：45
- 自动生成标签数：0

## 1. `splunk:datasets/attack_techniques/T1098.001/azure_ad_federated_identity_credential`

- 描述：Added a federated identity credential to an Entra ID service principal, pointing the trust to an external GitHub Actions OIDC issuer/repo not controlled by the tenant. Includes one benign Update service principal event (DisplayName change) with no FederatedIdentityCredentials property, to validate filter specificity. Tenant specific details have been replaced in the dataset including tenant id, user names, ips, etc.
- 发布者：descambiado
- 发布日期：2026-06-10
- 环境：attack_range
- ATT&CK：T1098.001
- 原始文件数：2
- 规范化观测数：2
- 上游 episode 数：0

### 准入判断（人工填写）

- [ ] 有外部或低权限入口
- [ ] 存在多步关系，而非单点事件
- [ ] 终点为数据库、存储、备份、secret 或其他数据资产
- [ ] 关键边均有原始证据
- [ ] 不是近重复案例
- 决定：`<accept | needs_execution | reject>`
- 理由：`<人工填写>`

### 观测索引

| observation_id | timestamp | actor_type | service | operation | status | raw record |
|---|---:|---|---|---|---|---|
| obs-fd0c75c26aff8811d9c0e493 | 2026-06-10T09:14:22.1032456Z | user | Microsoft.aadiam | Update service principal | success | `datasets/attack_techniques/T1098.001/azure_ad_federated_identity_credential/azure-audit.log#record=0` |
| obs-b8baf8cc86fdbf4c03f17682 | 2026-06-10T09:11:07.7719321Z | user | Microsoft.aadiam | Update service principal | success | `datasets/attack_techniques/T1098.001/azure_ad_federated_identity_credential/azure-audit.log#record=1` |

### 原始文件完整性

- `datasets/attack_techniques/T1098.001/azure_ad_federated_identity_credential/azure_ad_federated_identity_credential.yml` — SHA-256 `8e7019fd99b044ca683f26edca1be4b4ae33f54a477a7074fb6b2fbad97e0330`
- `datasets/attack_techniques/T1098.001/azure_ad_federated_identity_credential/azure-audit.log` — SHA-256 `68a71da7b6ee2370fd29439c2590620061973f11f2938261b98e489017653425`

## 2. `splunk:datasets/attack_techniques/T1110.002/aws_rds_password_reset`

- 描述：Dataset which contains cloudtrail events with AWS RDS Database master password reset.
- 发布者：Gowthamaraj Rajendran, Splunk
- 发布日期：2022-08-08
- 环境：attack_range
- ATT&CK：T1110.002
- 原始文件数：3
- 规范化观测数：5
- 上游 episode 数：0

### 准入判断（人工填写）

- [ ] 有外部或低权限入口
- [ ] 存在多步关系，而非单点事件
- [ ] 终点为数据库、存储、备份、secret 或其他数据资产
- [ ] 关键边均有原始证据
- [ ] 不是近重复案例
- 决定：`<accept | needs_execution | reject>`
- 理由：`<人工填写>`

### 观测索引

| observation_id | timestamp | actor_type | service | operation | status | raw record |
|---|---:|---|---|---|---|---|
| obs-a8b3b31538c973092b26ba89 | 1734016508000 | AssumedRole | rds.amazonaws.com | ModifyDBCluster | Success | `datasets/attack_techniques/T1110.002/aws_rds_password_reset/asl_ocsf_cloudtrail.json#record=0` |
| obs-260de826d0c6490fde27dad4 | 1734012183000 | AssumedRole | rds.amazonaws.com | ModifyDBCluster | Success | `datasets/attack_techniques/T1110.002/aws_rds_password_reset/asl_ocsf_cloudtrail.json#record=1` |
| obs-a958f683985819391ecd1635 | 1734010450000 | AssumedRole | rds.amazonaws.com | ModifyDBCluster | Success | `datasets/attack_techniques/T1110.002/aws_rds_password_reset/asl_ocsf_cloudtrail.json#record=2` |
| obs-4d5be49f9305895447a76aaa | 2022-08-05T09:19:15Z | AssumedRole | rds.amazonaws.com | ModifyDBInstance | Success | `datasets/attack_techniques/T1110.002/aws_rds_password_reset/aws_cloudtrail_events.json#record=0` |
| obs-7238985c9d8fd8747f66c77e | 2022-08-05T09:08:03Z | AssumedRole | rds.amazonaws.com | ModifyDBInstance | Success | `datasets/attack_techniques/T1110.002/aws_rds_password_reset/aws_cloudtrail_events.json#record=1` |

### 原始文件完整性

- `datasets/attack_techniques/T1110.002/aws_rds_password_reset/aws_rds_password_reset.yml` — SHA-256 `237786d5ce75d76fda7e6b476f5247732745a6493e058078dfa06cf82c148016`
- `datasets/attack_techniques/T1110.002/aws_rds_password_reset/asl_ocsf_cloudtrail.json` — SHA-256 `c7f16b51efd6a80ebb9beeeab3a2f64f94aed6a2a852706f9063e03e6653e38a`
- `datasets/attack_techniques/T1110.002/aws_rds_password_reset/aws_cloudtrail_events.json` — SHA-256 `7015688e41e2afca485d25fcf1fc2e655402fc036e372ca0ad6d2fefc9430c1f`

## 3. `splunk:datasets/attack_techniques/T1119/aws_exfil_datasync`

- 描述：Dataset which contains cloudtrail logs for creating a datasync job, batch job creation and bucket replication for AWS exfiltration
- 发布者：Bhavin Patel
- 发布日期：2023-04-10
- 环境：attack_range
- ATT&CK：
- 原始文件数：2
- 规范化观测数：5
- 上游 episode 数：0

### 准入判断（人工填写）

- [ ] 有外部或低权限入口
- [ ] 存在多步关系，而非单点事件
- [ ] 终点为数据库、存储、备份、secret 或其他数据资产
- [ ] 关键边均有原始证据
- [ ] 不是近重复案例
- 决定：`<accept | needs_execution | reject>`
- 理由：`<人工填写>`

### 观测索引

| observation_id | timestamp | actor_type | service | operation | status | raw record |
|---|---:|---|---|---|---|---|
| obs-a21a31359d1a3a402b485d5e | 2023-03-14T22:05:36Z | AssumedRole | datasync.amazonaws.com | CreateTask | Success | `datasets/attack_techniques/T1119/aws_exfil_datasync/cloudtrail.json#record=0` |
| obs-072d9550f27fa709179ad6be | 2023-03-14T22:05:36Z | AssumedRole | datasync.amazonaws.com | CreateTask | Success | `datasets/attack_techniques/T1119/aws_exfil_datasync/cloudtrail.json#record=1` |
| obs-feadde0a30b2b9112c6078e7 | 2023-04-24T23:51:17Z | None | s3.amazonaws.com | JobCreated | Success | `datasets/attack_techniques/T1119/aws_exfil_datasync/cloudtrail.json#record=2` |
| obs-2b0f45a3b2afae0056d5c8bb | 2023-04-24T23:45:02Z | None | s3.amazonaws.com | JobCreated | Success | `datasets/attack_techniques/T1119/aws_exfil_datasync/cloudtrail.json#record=3` |
| obs-3472ac55773227d610bdd0ae | 2023-04-24T23:49:33Z | AssumedRole | s3.amazonaws.com | PutBucketReplication | Success | `datasets/attack_techniques/T1119/aws_exfil_datasync/cloudtrail.json#record=4` |

### 原始文件完整性

- `datasets/attack_techniques/T1119/aws_exfil_datasync/aws_exfil_datasync_old.yml` — SHA-256 `98e142aeb9ff9881a686375230f8d619a506622c0a946dafb0fde0f512835f1d`
- `datasets/attack_techniques/T1119/aws_exfil_datasync/cloudtrail.json` — SHA-256 `3e61b4eba628eaf58e86401d834e2fa277a01e5fa65e30c34f8c60138332707c`

## 4. `splunk:datasets/attack_techniques/T1486/s3_file_encryption`

- 描述：Cloudtrail dataset with an s3 copy and encrypt operation. This is often used in S3 ransomware attacks.
- 发布者：Patrick Bareiss
- 发布日期：2021-01-11
- 环境：attack_range
- ATT&CK：T1486
- 原始文件数：2
- 规范化观测数：2
- 上游 episode 数：0

### 准入判断（人工填写）

- [ ] 有外部或低权限入口
- [ ] 存在多步关系，而非单点事件
- [ ] 终点为数据库、存储、备份、secret 或其他数据资产
- [ ] 关键边均有原始证据
- [ ] 不是近重复案例
- 决定：`<accept | needs_execution | reject>`
- 理由：`<人工填写>`

### 观测索引

| observation_id | timestamp | actor_type | service | operation | status | raw record |
|---|---:|---|---|---|---|---|
| obs-acc97c3a1f4929120197c440 | 2021-01-11T12:40:47Z | IAMUser | s3.amazonaws.com | CopyObject | Success | `datasets/attack_techniques/T1486/s3_file_encryption/aws_cloudtrail_events.json#record=0` |
| obs-1bab005e3dee7b4f90c21d90 | 2021-01-11T12:40:10Z | IAMUser | s3.amazonaws.com | CopyObject | Error | `datasets/attack_techniques/T1486/s3_file_encryption/aws_cloudtrail_events.json#record=1` |

### 原始文件完整性

- `datasets/attack_techniques/T1486/s3_file_encryption/s3_file_encryption.yml` — SHA-256 `ffe639a34b94d1240a1047b4c235d53e85ef1006914000c1293d628c1cabb358`
- `datasets/attack_techniques/T1486/s3_file_encryption/aws_cloudtrail_events.json` — SHA-256 `29c65aedfdb0a8b8ef56cb77af24842ec7ac5a9ad0497a186a3bda8acc411647`

## 5. `splunk:datasets/attack_techniques/T1490/aws_bucket_version`

- 描述：Dataset which contains an event for suspension of AWS bucket versioning.
- 发布者：Bhavin Patel
- 发布日期：2023-04-12
- 环境：attack_range
- ATT&CK：T1490
- 原始文件数：3
- 规范化观测数：4
- 上游 episode 数：0

### 准入判断（人工填写）

- [ ] 有外部或低权限入口
- [ ] 存在多步关系，而非单点事件
- [ ] 终点为数据库、存储、备份、secret 或其他数据资产
- [ ] 关键边均有原始证据
- [ ] 不是近重复案例
- 决定：`<accept | needs_execution | reject>`
- 理由：`<人工填写>`

### 观测索引

| observation_id | timestamp | actor_type | service | operation | status | raw record |
|---|---:|---|---|---|---|---|
| obs-9276557294535dd63e9a76c6 | 1734422984000 | AssumedRole | s3.amazonaws.com | PutBucketVersioning | Success | `datasets/attack_techniques/T1490/aws_bucket_version/asl_ocsf_cloudtrail.json#record=0` |
| obs-6db6bbd8db2e618be9dd82b1 | 1734422975000 | AssumedRole | s3.amazonaws.com | PutBucketVersioning | Success | `datasets/attack_techniques/T1490/aws_bucket_version/asl_ocsf_cloudtrail.json#record=1` |
| obs-138c152ebc29029752b46ace | 2022-08-04T15:19:25Z | AssumedRole | s3.amazonaws.com | PutBucketVersioning | Success | `datasets/attack_techniques/T1490/aws_bucket_version/cloudtrail.json#record=0` |
| obs-c97600b6d701133630b206d1 | 2022-08-04T15:19:25Z | AssumedRole | s3.amazonaws.com | PutBucketVersioning | Success | `datasets/attack_techniques/T1490/aws_bucket_version/cloudtrail.json#record=1` |

### 原始文件完整性

- `datasets/attack_techniques/T1490/aws_bucket_version/aws_bucket_version.yml` — SHA-256 `0cd364667524a7de3d2daa484e5f6f2840b9824a209e739547114f81cfc5fec4`
- `datasets/attack_techniques/T1490/aws_bucket_version/asl_ocsf_cloudtrail.json` — SHA-256 `7152b9a992acfd3da25af37fee7c16caf211d6c51a4037177f79df6d94b88515`
- `datasets/attack_techniques/T1490/aws_bucket_version/cloudtrail.json` — SHA-256 `1abe5a2bb8f10e54253ada63d4a6ecee62faf4969bb6df93181e5f1fa19ff8b6`

## 6. `splunk:datasets/attack_techniques/T1530/aws_exfil_high_no_getobject`

- 描述：Dataset which contains an AWS exfiltration attempt from S3 buckets, high number of file downloads using GetObject
- 发布者：Bhavin Patel
- 发布日期：2023-04-12
- 环境：attack_range
- ATT&CK：
- 原始文件数：2
- 规范化观测数：100
- 上游 episode 数：0

### 准入判断（人工填写）

- [ ] 有外部或低权限入口
- [ ] 存在多步关系，而非单点事件
- [ ] 终点为数据库、存储、备份、secret 或其他数据资产
- [ ] 关键边均有原始证据
- [ ] 不是近重复案例
- 决定：`<accept | needs_execution | reject>`
- 理由：`<人工填写>`

### 观测索引

| observation_id | timestamp | actor_type | service | operation | status | raw record |
|---|---:|---|---|---|---|---|
| obs-68eb19bd68f50a9dbc0795ec | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=0` |
| obs-1897fe6ffe8922a540b9128e | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=1` |
| obs-d47fb6012d7409b8ade9d6b6 | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=2` |
| obs-866ce9c5b21b2fbbed703b86 | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=3` |
| obs-06c002b7a99e5be99ccd91c5 | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=4` |
| obs-a3c89890f841ce5fde37bdad | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=5` |
| obs-520db79c600b4984a98be30c | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=6` |
| obs-c3b8cc2396ba72803948645b | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=7` |
| obs-cb83fa8acdd1a4ec63701dfb | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=8` |
| obs-d6a49930bdca13ce48b182ae | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=9` |
| obs-dbe2dfc15624df911a5683e0 | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=10` |
| obs-50d4d7a3c5decca78d330aef | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=11` |
| obs-9dca211b03e1b091984b97a2 | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=12` |
| obs-ba868484bfbb548a3a69b322 | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=13` |
| obs-084f7cc8c18c8218bf1faac3 | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=14` |
| obs-9f6df06276bf802808d088ad | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=15` |
| obs-de186b32d79fc932558a7bb2 | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=16` |
| obs-da962f47cc6830526d315e71 | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=17` |
| obs-910eac48668845270590e8bd | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=18` |
| obs-f9e236a56550ba27b065108d | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=19` |
| obs-05311c6e367743b2ec5e40d9 | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=20` |
| obs-5017ac16fb21d1edd54d8dc0 | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=21` |
| obs-492b016ed8166adf52a025bd | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=22` |
| obs-90bc2a0ea48ea4ec6102ecc0 | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=23` |
| obs-1cfa72dddee132d4afc80607 | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=24` |
| obs-81f70609d5d84fe762a37fc8 | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=25` |
| obs-f1380b9ed9f815b953958a8c | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=26` |
| obs-6ef95d33b8b7d0cedf0e88b8 | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=27` |
| obs-3dc7efd35ebd420d3802dd31 | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=28` |
| obs-5aa0db10e7c020e757bef506 | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=29` |
| obs-edb2cb662e355f79320ce3bb | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=30` |
| obs-d2e2e5c424b36048d76cb981 | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=31` |
| obs-26ce9e3107c17571beb4c2dc | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=32` |
| obs-ef3ca42a52fd9135d791a99c | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=33` |
| obs-e26e6b6989f71cf22dfdbea8 | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=34` |
| obs-f74d5cc9d01d975d88309dda | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=35` |
| obs-a39008fa6a39902284f5bea9 | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=36` |
| obs-c7490a6d06ecc41fcb337ddb | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=37` |
| obs-03b7bc512a400f24b88d4abd | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=38` |
| obs-8c52e1c31f5af5fc9419876c | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=39` |
| obs-c7fcf4af57f8bbab90afad0f | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=40` |
| obs-2e5a2cc6b162eb9df27ac62b | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=41` |
| obs-65733470cee1d14ec730559d | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=42` |
| obs-e565de1af9ea70bb1da8e878 | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=43` |
| obs-b1f91d879e5ac9f8d211e585 | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=44` |
| obs-7a9e1016257161d03e19af20 | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=45` |
| obs-0966750ca53d05d5231418a3 | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=46` |
| obs-ab83da4f01a84d97410f03bf | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=47` |
| obs-42abc230f6544efe71aa0c10 | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=48` |
| obs-68508ecf6f2f02f8e581a369 | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=49` |
| obs-f6044e1f81438e9c76776426 | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=50` |
| obs-9a03565f9e38166e77b18fa7 | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=51` |
| obs-955e91b5cb41e99609cf6818 | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=52` |
| obs-d7247361bcd5c86eeae69d8e | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=53` |
| obs-57a9daab2cd32783502893af | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=54` |
| obs-165edca764a75d23d84502b4 | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=55` |
| obs-131c5616b35d269c6a63e7f9 | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=56` |
| obs-bf7fb1cd57372ad111154be6 | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=57` |
| obs-8e858c724b324454641b7a55 | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=58` |
| obs-50a88fcb32d815c12d200770 | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=59` |
| obs-cb143060df8725550f00f628 | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=60` |
| obs-a39198832a7941cec1b2b14a | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=61` |
| obs-9970068b854ace29b6a553b9 | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=62` |
| obs-05d5e0c29fd29e8b7efe1757 | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=63` |
| obs-2d5bdf15c86c520b3a76e840 | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=64` |
| obs-f23729e1c0478db9f65b5c7f | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=65` |
| obs-1580dedf11f736a55987497e | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=66` |
| obs-8d2f8db8670829b1b70a8b62 | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=67` |
| obs-3353e0526bd197b19f1425c0 | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=68` |
| obs-35e808816dd212286906a4c3 | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=69` |
| obs-217391bdb07892fe50a3e23d | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=70` |
| obs-2f362beeb9152cf4e460f0ac | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=71` |
| obs-1606cabbb9f51582de0862f6 | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=72` |
| obs-61db7cf5116b16bf46f20f20 | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=73` |
| obs-bef3de1e32f9ab939cfda73a | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=74` |
| obs-2e2f2c0ee78dd38671e75bc1 | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=75` |
| obs-557f58b564ab0c0b9d493776 | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=76` |
| obs-67912c3cedfc10cfe72e4ec4 | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=77` |
| obs-f457ac531269a7a3a9504e28 | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=78` |
| obs-5212aaeaf22838bafea090ab | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=79` |
| obs-198429b82ac02a502db758c2 | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=80` |
| obs-f5cee7bbcdd87e6e58df7e33 | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=81` |
| obs-42c9b9991fcf1d3fbf5db8bf | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=82` |
| obs-9b4753b5da1e29c2806a29c3 | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=83` |
| obs-d99d5792523d3adfc9b8ad6f | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=84` |
| obs-49dbb94c53398015785c4719 | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=85` |
| obs-0ce5b3e3c21f74f678cf53f7 | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=86` |
| obs-e94d2e88914af87389852e54 | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=87` |
| obs-ceb919562da4e6c1dfbbf330 | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=88` |
| obs-22f5a2e48b7f927cc23aba99 | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=89` |
| obs-2cb5e9483ca1e39e6ff13191 | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=90` |
| obs-803949406fdee84312bdebcc | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=91` |
| obs-b4d1321628ccdaba76f21370 | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=92` |
| obs-597679a023d64149b6794af9 | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=93` |
| obs-65834e2848c9c1d9e06f7704 | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=94` |
| obs-559077db17ebe6230f264702 | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=95` |
| obs-4d3864e214fc254f5f7d60fe | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=96` |
| obs-34f17c8d3ed8245068363a1d | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=97` |
| obs-b34794807ec4a403f3a41aa2 | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=98` |
| obs-0827bb5d5784c5297ca23be7 | 2023-04-11T01:18:47Z | IAMUser | s3.amazonaws.com | GetObject | Success | `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json#record=99` |

### 原始文件完整性

- `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/aws_exfil_high_no_getobject_old.yml` — SHA-256 `cdc0e11a3aeb66390d7ed1cd1a6adb4ac6356a01ffecf1d336e6ee33e76ec8af`
- `datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json` — SHA-256 `c71e5bf5d092955415d3a94f446681a1bc55a66f0d765b2cf9b3718edbf7461b`

## 7. `splunk:datasets/attack_techniques/T1530/aws_s3_public_bucket`

- 描述：Dataset which contains cloudtrail logs and the creation of a public S3 bucket.
- 发布者：Patrick Bareiss
- 发布日期：2021-01-12
- 环境：attack_range
- ATT&CK：T1530
- 原始文件数：2
- 规范化观测数：9
- 上游 episode 数：0

### 准入判断（人工填写）

- [ ] 有外部或低权限入口
- [ ] 存在多步关系，而非单点事件
- [ ] 终点为数据库、存储、备份、secret 或其他数据资产
- [ ] 关键边均有原始证据
- [ ] 不是近重复案例
- 决定：`<accept | needs_execution | reject>`
- 理由：`<人工填写>`

### 观测索引

| observation_id | timestamp | actor_type | service | operation | status | raw record |
|---|---:|---|---|---|---|---|
| obs-10fd4efb2e1cf751ba15c64f | 2021-01-12T14:03:17Z | IAMUser | s3.amazonaws.com | PutBucketAcl | Success | `datasets/attack_techniques/T1530/aws_s3_public_bucket/aws_cloudtrail_events.json#record=0` |
| obs-e45dec1375e3c98e67ddd53d | 2021-01-12T14:03:05Z | IAMUser | s3.amazonaws.com | PutBucketAcl | Success | `datasets/attack_techniques/T1530/aws_s3_public_bucket/aws_cloudtrail_events.json#record=1` |
| obs-113b3e71c0b3948d4599ec0d | 2021-01-12T14:02:52Z | IAMUser | s3.amazonaws.com | PutBucketAcl | Success | `datasets/attack_techniques/T1530/aws_s3_public_bucket/aws_cloudtrail_events.json#record=2` |
| obs-fc386dc34a873c06f939f40b | 2021-01-12T14:02:39Z | IAMUser | s3.amazonaws.com | PutBucketAcl | Success | `datasets/attack_techniques/T1530/aws_s3_public_bucket/aws_cloudtrail_events.json#record=3` |
| obs-0cdc4dd06fb2f7ae85f4c5e0 | 2021-01-12T14:02:16Z | IAMUser | s3.amazonaws.com | PutBucketAcl | Success | `datasets/attack_techniques/T1530/aws_s3_public_bucket/aws_cloudtrail_events.json#record=4` |
| obs-e32cc392ff94aac763b6c30e | 2021-01-12T12:55:53Z | IAMUser | s3.amazonaws.com | PutBucketAcl | Success | `datasets/attack_techniques/T1530/aws_s3_public_bucket/aws_cloudtrail_events.json#record=5` |
| obs-be9f74dbd6420998600e2e00 | 2021-01-12T12:54:55Z | IAMUser | s3.amazonaws.com | PutBucketAcl | Success | `datasets/attack_techniques/T1530/aws_s3_public_bucket/aws_cloudtrail_events.json#record=6` |
| obs-8f9b06aa2af25b283f76c28d | 2021-01-12T12:29:59Z | AssumedRole | s3.amazonaws.com | PutBucketAcl | Success | `datasets/attack_techniques/T1530/aws_s3_public_bucket/aws_cloudtrail_events.json#record=7` |
| obs-e6c483388cda85690cdfdc29 | 2021-01-12T12:29:14Z | AssumedRole | s3.amazonaws.com | PutBucketAcl | Success | `datasets/attack_techniques/T1530/aws_s3_public_bucket/aws_cloudtrail_events.json#record=8` |

### 原始文件完整性

- `datasets/attack_techniques/T1530/aws_s3_public_bucket/aws_s3_public_bucket.yml` — SHA-256 `943720fbe6c83e840e2397b3816315943f16b575921391b0af824c8707333d8f`
- `datasets/attack_techniques/T1530/aws_s3_public_bucket/aws_cloudtrail_events.json` — SHA-256 `a7812406c446a6a2c9864f2fe3b07e6b177c18b893dbd2ed0b11b649ddfc7eda`

## 8. `splunk:datasets/attack_techniques/T1537/aws_exfil_risk_events`

- 描述：This dataset contains Risk events created by the detection analytics related Collection and Exfiltration techniques in Enterprise Security
- 发布者：Bhavin Patel
- 发布日期：2023-03-31
- 环境：attack_range
- ATT&CK：T1537
- 原始文件数：2
- 规范化观测数：38
- 上游 episode 数：0

### 准入判断（人工填写）

- [ ] 有外部或低权限入口
- [ ] 存在多步关系，而非单点事件
- [ ] 终点为数据库、存储、备份、secret 或其他数据资产
- [ ] 关键边均有原始证据
- [ ] 不是近重复案例
- 决定：`<accept | needs_execution | reject>`
- 理由：`<人工填写>`

### 观测索引

| observation_id | timestamp | actor_type | service | operation | status | raw record |
|---|---:|---|---|---|---|---|
| obs-fdb5cd9692acb024694ee52d | 1681175400 | IAMUser | splunk_enterprise_security | ESCU - AWS Exfiltration via Anomalous GetObject API Activity - Rule | DerivedRiskEvent | `datasets/attack_techniques/T1537/aws_exfil_risk_events/aws_risk.log#record=0` |
| obs-08b1a85189c56ec24c8ed01a | 1681175400 | IAMUser | splunk_enterprise_security | ESCU - AWS Exfiltration via Anomalous GetObject API Activity - Rule | DerivedRiskEvent | `datasets/attack_techniques/T1537/aws_exfil_risk_events/aws_risk.log#record=1` |
| obs-668aec922c573d190dcf68d2 | 1681175400 | IAMUser | splunk_enterprise_security | ESCU - AWS Exfiltration via Anomalous GetObject API Activity - Rule | DerivedRiskEvent | `datasets/attack_techniques/T1537/aws_exfil_risk_events/aws_risk.log#record=2` |
| obs-f88a92a25a273ed5ff0665f2 | 1681175400 | IAMUser | splunk_enterprise_security | ESCU - AWS Exfiltration via Anomalous GetObject API Activity - Rule | DerivedRiskEvent | `datasets/attack_techniques/T1537/aws_exfil_risk_events/aws_risk.log#record=3` |
| obs-3710647722757fc63df40226 | 1681175400 | IAMUser | splunk_enterprise_security | ESCU - AWS Exfiltration via Anomalous GetObject API Activity - Rule | DerivedRiskEvent | `datasets/attack_techniques/T1537/aws_exfil_risk_events/aws_risk.log#record=4` |
| obs-89be19f69079163ff655d443 | 1681175400 | IAMUser | splunk_enterprise_security | ESCU - AWS Exfiltration via Anomalous GetObject API Activity - Rule | DerivedRiskEvent | `datasets/attack_techniques/T1537/aws_exfil_risk_events/aws_risk.log#record=5` |
| obs-1b29b1ab21a08bf3dcd8deee | 1681174800 | IAMUser | splunk_enterprise_security | ESCU - AWS Exfiltration via Anomalous GetObject API Activity - Rule | DerivedRiskEvent | `datasets/attack_techniques/T1537/aws_exfil_risk_events/aws_risk.log#record=6` |
| obs-6254dc1a1cb53e6bcd0c671b | 1681174800 | IAMUser | splunk_enterprise_security | ESCU - AWS Exfiltration via Anomalous GetObject API Activity - Rule | DerivedRiskEvent | `datasets/attack_techniques/T1537/aws_exfil_risk_events/aws_risk.log#record=7` |
| obs-61123fe7216cc550e242fa39 | 1681174800 | IAMUser | splunk_enterprise_security | ESCU - AWS Exfiltration via Anomalous GetObject API Activity - Rule | DerivedRiskEvent | `datasets/attack_techniques/T1537/aws_exfil_risk_events/aws_risk.log#record=8` |
| obs-4aed671d20125a10eb8ba876 | 1679351496 | None | splunk_enterprise_security | ESCU - AWS EC2 Snapshot Shared Externally - Rule | DerivedRiskEvent | `datasets/attack_techniques/T1537/aws_exfil_risk_events/aws_risk.log#record=9` |
| obs-5ad806fb801f57deafda5283 | 1679351496 | None | splunk_enterprise_security | ESCU - AWS EC2 Snapshot Shared Externally - Rule | DerivedRiskEvent | `datasets/attack_techniques/T1537/aws_exfil_risk_events/aws_risk.log#record=10` |
| obs-a7d107512b1eb4e824dd1b94 | 1680633876 | None | splunk_enterprise_security | ESCU - AWS EC2 Snapshot Shared Externally - Rule | DerivedRiskEvent | `datasets/attack_techniques/T1537/aws_exfil_risk_events/aws_risk.log#record=11` |
| obs-8e1fd9dc27518ff8b36c14ee | 1680633876 | None | splunk_enterprise_security | ESCU - AWS EC2 Snapshot Shared Externally - Rule | DerivedRiskEvent | `datasets/attack_techniques/T1537/aws_exfil_risk_events/aws_risk.log#record=12` |
| obs-fa2dd27c9237580f3a2b5454 | 1680633113 | None | splunk_enterprise_security | ESCU - AWS EC2 Snapshot Shared Externally - Rule | DerivedRiskEvent | `datasets/attack_techniques/T1537/aws_exfil_risk_events/aws_risk.log#record=13` |
| obs-73d3308e59cd76fdc5639fba | 1680633113 | None | splunk_enterprise_security | ESCU - AWS EC2 Snapshot Shared Externally - Rule | DerivedRiskEvent | `datasets/attack_techniques/T1537/aws_exfil_risk_events/aws_risk.log#record=14` |
| obs-a2f17a6d96a0b906aa35cc21 | 1680632969 | None | splunk_enterprise_security | ESCU - AWS EC2 Snapshot Shared Externally - Rule | DerivedRiskEvent | `datasets/attack_techniques/T1537/aws_exfil_risk_events/aws_risk.log#record=15` |
| obs-6270d4b536c35336f94fd404 | 1680632969 | None | splunk_enterprise_security | ESCU - AWS EC2 Snapshot Shared Externally - Rule | DerivedRiskEvent | `datasets/attack_techniques/T1537/aws_exfil_risk_events/aws_risk.log#record=16` |
| obs-fce619db50c9d6eba9e4a59c | 1680632364 | None | splunk_enterprise_security | ESCU - AWS EC2 Snapshot Shared Externally - Rule | DerivedRiskEvent | `datasets/attack_techniques/T1537/aws_exfil_risk_events/aws_risk.log#record=17` |
| obs-37ec28b5d592683b450acc70 | 1680632364 | None | splunk_enterprise_security | ESCU - AWS EC2 Snapshot Shared Externally - Rule | DerivedRiskEvent | `datasets/attack_techniques/T1537/aws_exfil_risk_events/aws_risk.log#record=18` |
| obs-8784040a6af2c61d885e13c8 | 1681175400 | IAMUser | splunk_enterprise_security | ESCU - AWS Exfiltration via Anomalous GetObject API Activity - Rule | DerivedRiskEvent | `datasets/attack_techniques/T1537/aws_exfil_risk_events/aws_risk.log#record=19` |
| obs-a8f0b0475ca0c4f47090e820 | 1681175400 | IAMUser | splunk_enterprise_security | ESCU - AWS Exfiltration via Anomalous GetObject API Activity - Rule | DerivedRiskEvent | `datasets/attack_techniques/T1537/aws_exfil_risk_events/aws_risk.log#record=20` |
| obs-f4d45f3960c73d0728516d76 | 1681175400 | IAMUser | splunk_enterprise_security | ESCU - AWS Exfiltration via Anomalous GetObject API Activity - Rule | DerivedRiskEvent | `datasets/attack_techniques/T1537/aws_exfil_risk_events/aws_risk.log#record=21` |
| obs-eb27325813cd3d69f7165d71 | 1681175400 | IAMUser | splunk_enterprise_security | ESCU - AWS Exfiltration via Anomalous GetObject API Activity - Rule | DerivedRiskEvent | `datasets/attack_techniques/T1537/aws_exfil_risk_events/aws_risk.log#record=22` |
| obs-f10519d68a5447e78a023b18 | 1681175400 | IAMUser | splunk_enterprise_security | ESCU - AWS Exfiltration via Anomalous GetObject API Activity - Rule | DerivedRiskEvent | `datasets/attack_techniques/T1537/aws_exfil_risk_events/aws_risk.log#record=23` |
| obs-83c621c4bcd03892e351966a | 1681175400 | IAMUser | splunk_enterprise_security | ESCU - AWS Exfiltration via Anomalous GetObject API Activity - Rule | DerivedRiskEvent | `datasets/attack_techniques/T1537/aws_exfil_risk_events/aws_risk.log#record=24` |
| obs-3004802d6b368b8dffe7ebbd | 1681174800 | IAMUser | splunk_enterprise_security | ESCU - AWS Exfiltration via Anomalous GetObject API Activity - Rule | DerivedRiskEvent | `datasets/attack_techniques/T1537/aws_exfil_risk_events/aws_risk.log#record=25` |
| obs-4128d073b6eaaad1c8e69905 | 1681174800 | IAMUser | splunk_enterprise_security | ESCU - AWS Exfiltration via Anomalous GetObject API Activity - Rule | DerivedRiskEvent | `datasets/attack_techniques/T1537/aws_exfil_risk_events/aws_risk.log#record=26` |
| obs-12f7307de21ec8a0c90f218f | 1681174800 | IAMUser | splunk_enterprise_security | ESCU - AWS Exfiltration via Anomalous GetObject API Activity - Rule | DerivedRiskEvent | `datasets/attack_techniques/T1537/aws_exfil_risk_events/aws_risk.log#record=27` |
| obs-0d10faa50c7280bebd50a598 | 1679351496 | None | splunk_enterprise_security | ESCU - AWS EC2 Snapshot Shared Externally - Rule | DerivedRiskEvent | `datasets/attack_techniques/T1537/aws_exfil_risk_events/aws_risk.log#record=28` |
| obs-337e6eda1c1a0788904f6297 | 1679351496 | None | splunk_enterprise_security | ESCU - AWS EC2 Snapshot Shared Externally - Rule | DerivedRiskEvent | `datasets/attack_techniques/T1537/aws_exfil_risk_events/aws_risk.log#record=29` |
| obs-4e9bd5274fd599bd59233b57 | 1680633876 | None | splunk_enterprise_security | ESCU - AWS EC2 Snapshot Shared Externally - Rule | DerivedRiskEvent | `datasets/attack_techniques/T1537/aws_exfil_risk_events/aws_risk.log#record=30` |
| obs-f23b92ca4913a0ed8ef8499b | 1680633876 | None | splunk_enterprise_security | ESCU - AWS EC2 Snapshot Shared Externally - Rule | DerivedRiskEvent | `datasets/attack_techniques/T1537/aws_exfil_risk_events/aws_risk.log#record=31` |
| obs-9ef377dc0550efc5815b0bfb | 1680633113 | None | splunk_enterprise_security | ESCU - AWS EC2 Snapshot Shared Externally - Rule | DerivedRiskEvent | `datasets/attack_techniques/T1537/aws_exfil_risk_events/aws_risk.log#record=32` |
| obs-b05ecb83339773aa56e1c9c1 | 1680633113 | None | splunk_enterprise_security | ESCU - AWS EC2 Snapshot Shared Externally - Rule | DerivedRiskEvent | `datasets/attack_techniques/T1537/aws_exfil_risk_events/aws_risk.log#record=33` |
| obs-d02717dbdaaedfb071c0fd98 | 1680632969 | None | splunk_enterprise_security | ESCU - AWS EC2 Snapshot Shared Externally - Rule | DerivedRiskEvent | `datasets/attack_techniques/T1537/aws_exfil_risk_events/aws_risk.log#record=34` |
| obs-6eaa8d145f24d44a21fa4197 | 1680632969 | None | splunk_enterprise_security | ESCU - AWS EC2 Snapshot Shared Externally - Rule | DerivedRiskEvent | `datasets/attack_techniques/T1537/aws_exfil_risk_events/aws_risk.log#record=35` |
| obs-11ca6c9898227f07868cdc79 | 1680632364 | None | splunk_enterprise_security | ESCU - AWS EC2 Snapshot Shared Externally - Rule | DerivedRiskEvent | `datasets/attack_techniques/T1537/aws_exfil_risk_events/aws_risk.log#record=36` |
| obs-fe774ac50d8781a164ba701c | 1680632364 | None | splunk_enterprise_security | ESCU - AWS EC2 Snapshot Shared Externally - Rule | DerivedRiskEvent | `datasets/attack_techniques/T1537/aws_exfil_risk_events/aws_risk.log#record=37` |

### 原始文件完整性

- `datasets/attack_techniques/T1537/aws_exfil_risk_events/aws_exfil_risk_events.yml` — SHA-256 `24d8d9115c70d1f88f77612a95f53c2fd8f59631dcb76cf286c15f918f4a7bf4`
- `datasets/attack_techniques/T1537/aws_exfil_risk_events/aws_risk.log` — SHA-256 `44d5e85a9b293178fa05301414cbd4ae84b5d7228ee08e3ad87ecaa346ea31d2`

## 9. `splunk:datasets/attack_techniques/T1537/aws_snapshot_exfil`

- 描述：Adversaries may exfiltrate data by transferring the data, including backups of cloud environments, to another cloud account they control on the same service to avoid typical file transfers/downloads and network-based exfiltration detection.
- 发布者：Bhavin Patel
- 发布日期：2021-07-20
- 环境：attack_range
- ATT&CK：T1537
- 原始文件数：3
- 规范化观测数：11
- 上游 episode 数：0

### 准入判断（人工填写）

- [ ] 有外部或低权限入口
- [ ] 存在多步关系，而非单点事件
- [ ] 终点为数据库、存储、备份、secret 或其他数据资产
- [ ] 关键边均有原始证据
- [ ] 不是近重复案例
- 决定：`<accept | needs_execution | reject>`
- 理由：`<人工填写>`

### 观测索引

| observation_id | timestamp | actor_type | service | operation | status | raw record |
|---|---:|---|---|---|---|---|
| obs-3871b275388585bb44899bdb | 1734441912000 | AssumedRole | ec2.amazonaws.com | ModifySnapshotAttribute | Success | `datasets/attack_techniques/T1537/aws_snapshot_exfil/asl_ocsf_cloudtrail.json#record=0` |
| obs-156339950338bd72dd749418 | 1734441912000 | AssumedRole | ec2.amazonaws.com | ModifySnapshotAttribute | Success | `datasets/attack_techniques/T1537/aws_snapshot_exfil/asl_ocsf_cloudtrail.json#record=1` |
| obs-86fa861f0cde28b4ccd5ffec | 2021-06-22T22:57:37Z | AssumedRole | ec2.amazonaws.com | ModifySnapshotAttribute | Success | `datasets/attack_techniques/T1537/aws_snapshot_exfil/aws_cloudtrail_events.json#record=0` |
| obs-fa2fdb5866f86d386195678e | 2021-06-22T22:57:21Z | AssumedRole | ec2.amazonaws.com | ModifySnapshotAttribute | Success | `datasets/attack_techniques/T1537/aws_snapshot_exfil/aws_cloudtrail_events.json#record=1` |
| obs-ec9346ae2dbe434ef8e425d9 | 2021-06-22T21:04:59Z | AssumedRole | ec2.amazonaws.com | ModifySnapshotAttribute | Success | `datasets/attack_techniques/T1537/aws_snapshot_exfil/aws_cloudtrail_events.json#record=2` |
| obs-896f2467e9ed7fb874ba5251 | 2021-06-22T21:04:59Z | AssumedRole | ec2.amazonaws.com | ModifySnapshotAttribute | Success | `datasets/attack_techniques/T1537/aws_snapshot_exfil/aws_cloudtrail_events.json#record=3` |
| obs-dcd97fd46d8b667c6f4ae75b | 2021-06-22T21:03:16Z | IAMUser | ec2.amazonaws.com | ModifySnapshotAttribute | Error | `datasets/attack_techniques/T1537/aws_snapshot_exfil/aws_cloudtrail_events.json#record=4` |
| obs-06c434004f6cce35419fffa7 | 2021-06-22T20:59:26Z | IAMUser | ec2.amazonaws.com | ModifySnapshotAttribute | Success | `datasets/attack_techniques/T1537/aws_snapshot_exfil/aws_cloudtrail_events.json#record=5` |
| obs-9328dcc3e571fbdc2d1380a0 | 2021-06-22T20:58:37Z | IAMUser | ec2.amazonaws.com | ModifySnapshotAttribute | Success | `datasets/attack_techniques/T1537/aws_snapshot_exfil/aws_cloudtrail_events.json#record=6` |
| obs-cd0fd9442842a5afef3a10e4 | 2023-03-20T22:31:36Z | IAMUser | ec2.amazonaws.com | ModifySnapshotAttribute | Success | `datasets/attack_techniques/T1537/aws_snapshot_exfil/aws_cloudtrail_events.json#record=7` |
| obs-d265f65c727aa8aba3533452 | 2023-03-20T22:31:18Z | IAMUser | ec2.amazonaws.com | CreateSnapshot | Success | `datasets/attack_techniques/T1537/aws_snapshot_exfil/aws_cloudtrail_events.json#record=8` |

### 原始文件完整性

- `datasets/attack_techniques/T1537/aws_snapshot_exfil/aws_snapshot_exfil.yml` — SHA-256 `31b0a2c4e1c0b52a4e844b47e932f121f2ad3da9230b6b7b666164ac134d09c1`
- `datasets/attack_techniques/T1537/aws_snapshot_exfil/asl_ocsf_cloudtrail.json` — SHA-256 `dec5e0ff02540423cc1e46df46277d4cc50102a174e7c01d8c148528e3aee7d6`
- `datasets/attack_techniques/T1537/aws_snapshot_exfil/aws_cloudtrail_events.json` — SHA-256 `ac343623bd299b4cbd29b1d718e91b51f00da71fee4fe3de26dca83205676cca`

## 10. `crosscloud:aws:archive_collected_data`

- 描述：DOI-published paired payload/no-payload AWS telemetry for archive_collected_data.
- 发布者：Dhooghe et al.
- 发布日期：2026-04-30
- 环境：controlled cloud subscription
- ATT&CK：
- 原始文件数：4
- 规范化观测数：0
- 上游 episode 数：40

### 准入判断（人工填写）

- [ ] 有外部或低权限入口
- [ ] 存在多步关系，而非单点事件
- [ ] 终点为数据库、存储、备份、secret 或其他数据资产
- [ ] 关键边均有原始证据
- [ ] 不是近重复案例
- 决定：`<accept | needs_execution | reject>`
- 理由：`<人工填写>`

### 观测索引

| observation_id | timestamp | actor_type | service | operation | status | raw record |
|---|---:|---|---|---|---|---|

### 上游配对 episode

| episode_id | profile | run | source condition | observations | member SHA-256 |
|---|---|---:|---|---:|---|
| crosscloud:aws:archive_collected_data:additional:run-0:n | additional | 0 | payload_absent | 53 | `e4d308e2c37d97852dfd61292d1449f0c422a68c280a6858e515676fc3f0120f` |
| crosscloud:aws:archive_collected_data:additional:run-0:y | additional | 0 | payload_present | 44 | `c799c5f98e2257d7ce82d35f5429f95941a5a9d97d0505a1c15aad193dadefdf` |
| crosscloud:aws:archive_collected_data:additional:run-1:n | additional | 1 | payload_absent | 26 | `cb92308526d9bd3e81a56fb5ce688e0f7160a7e573762bf8e77a9297c31cc18c` |
| crosscloud:aws:archive_collected_data:additional:run-1:y | additional | 1 | payload_present | 32 | `39dc48a2e9f7b50e1c59aa6436ded32b8ed113be618fb9036ad784d66e8d8645` |
| crosscloud:aws:archive_collected_data:additional:run-2:n | additional | 2 | payload_absent | 37 | `3e9a2b5fe65f10ce588f98e0e609fbd43007c216e49b93be5eaf274e68e435e4` |
| crosscloud:aws:archive_collected_data:additional:run-2:y | additional | 2 | payload_present | 31 | `de689c5e272628be3054c1f25f1bfef4c5c5b8d7b30a6d4b2ca58c26cbfcc87f` |
| crosscloud:aws:archive_collected_data:additional:run-3:n | additional | 3 | payload_absent | 20 | `4024a8774818c37850c3678fb94250bd93debf24b4a9f0098d960f65e36b9d71` |
| crosscloud:aws:archive_collected_data:additional:run-3:y | additional | 3 | payload_present | 25 | `14809d85bbd4a653899602816149ecbe89d532cf9ec522a7fbf88e008960a70e` |
| crosscloud:aws:archive_collected_data:additional:run-4:n | additional | 4 | payload_absent | 18 | `e1fc03ccdbd263735e2cef936dd93e84c9976a0da8b2783828504e21319978a1` |
| crosscloud:aws:archive_collected_data:additional:run-4:y | additional | 4 | payload_present | 27 | `b1581e50502edaa038b6dd9ae01394bedf3a13311b708c364b7634ff03e5fc5b` |
| crosscloud:aws:archive_collected_data:additional:run-5:n | additional | 5 | payload_absent | 22 | `34f97053b3c10a08b4b71cd64acf8ceb1c3b28e938211ecef7b196d242f42d89` |
| crosscloud:aws:archive_collected_data:additional:run-5:y | additional | 5 | payload_present | 43 | `f101dba84a9e0d5444b999c2065eb96c7cafd6b8cb759f8f5c526bac16721845` |
| crosscloud:aws:archive_collected_data:additional:run-6:n | additional | 6 | payload_absent | 25 | `5b30450d1319de7c176b35f02df41c72715a64daaef23360c142931066003055` |
| crosscloud:aws:archive_collected_data:additional:run-6:y | additional | 6 | payload_present | 27 | `7fff7d82bbb1ccd43d18dfd49e13f63376d3ba85de536625821d074555ec3c92` |
| crosscloud:aws:archive_collected_data:additional:run-7:n | additional | 7 | payload_absent | 24 | `f449384ea43bd4b191c9bfc93843eaef0eb559a0f2fc29321f67fc136407ac1e` |
| crosscloud:aws:archive_collected_data:additional:run-7:y | additional | 7 | payload_present | 27 | `e63ecc2940289e6b5b73d9f116961afeba3ce438041d0fa7957932c9e6257fa0` |
| crosscloud:aws:archive_collected_data:additional:run-8:n | additional | 8 | payload_absent | 16 | `f830d6bb073fc82ea2651eec30db292fc67e9420c4c0fc1561ecbcf5aef96496` |
| crosscloud:aws:archive_collected_data:additional:run-8:y | additional | 8 | payload_present | 32 | `b45699928beb5942913cb991d90c7136c5ac827be8c3642256c94a70de2492a4` |
| crosscloud:aws:archive_collected_data:additional:run-9:n | additional | 9 | payload_absent | 23 | `20fbca660fea271732eb33545acce8c857e6f25aaf0b6d515eec68631c431a05` |
| crosscloud:aws:archive_collected_data:additional:run-9:y | additional | 9 | payload_present | 24 | `940d471713a9c9b13a7c946bf3d7143c05bd15e24378c9ff4a9ebeaebb17bb40` |
| crosscloud:aws:archive_collected_data:default:run-0:n | default | 0 | payload_absent | 6 | `f58a445b4cd5bc8e423dbf96ff58174a33ba40ca3f93570e20436e28f70d8462` |
| crosscloud:aws:archive_collected_data:default:run-0:y | default | 0 | payload_present | 10 | `10684f0a93e6f425abe4a3d4a48251818be7992517234383eeb072ea8a5de7a8` |
| crosscloud:aws:archive_collected_data:default:run-1:n | default | 1 | payload_absent | 7 | `532f55009a1987e14edb011d5c0e32c73ad1d467a39be6e686043565a9c39059` |
| crosscloud:aws:archive_collected_data:default:run-1:y | default | 1 | payload_present | 9 | `f28eeef85fc361029ae338496855d4ab26f8e91b8ce5fe1708d50df217070f31` |
| crosscloud:aws:archive_collected_data:default:run-2:n | default | 2 | payload_absent | 7 | `7af578695db6d4be973dd3cea90700239b3791ed3f7b745bf898165f2b8f13bc` |
| crosscloud:aws:archive_collected_data:default:run-2:y | default | 2 | payload_present | 8 | `9dc0bf2b7c33cde3f6649e5dda6b4e3fa44ec53b3a8937e4face7f87c22d35ac` |
| crosscloud:aws:archive_collected_data:default:run-3:n | default | 3 | payload_absent | 6 | `3357bb4b80fb3ec66ec1aaf2800d95ac124427898796d392873f78458639eea5` |
| crosscloud:aws:archive_collected_data:default:run-3:y | default | 3 | payload_present | 10 | `6604e8fb93511ff0402bb5e8f161594d9a19e3e3b9712f2e6e2f293d0fe28f38` |
| crosscloud:aws:archive_collected_data:default:run-4:n | default | 4 | payload_absent | 6 | `5413971a08139bf0461575baef14d72b87e16e56aab4a7cbe666b354902ce57f` |
| crosscloud:aws:archive_collected_data:default:run-4:y | default | 4 | payload_present | 10 | `df394fd5b9a4d6c6ae8d0984bc57e9e3a0d67fc00dacfa645c70c5cc4753ecd1` |
| crosscloud:aws:archive_collected_data:default:run-5:n | default | 5 | payload_absent | 6 | `e4d0355de094777d0236d2071085c68c59fc5040e37d7b199939114b8810b062` |
| crosscloud:aws:archive_collected_data:default:run-5:y | default | 5 | payload_present | 10 | `1166e3754ee03a8a9a185e6c074622e26202cdd5f73acb63409708ce55fec5a8` |
| crosscloud:aws:archive_collected_data:default:run-6:n | default | 6 | payload_absent | 7 | `81b3b9970de12d7235cffaf9a397d8afd055422edc993694207ea72fa6999493` |
| crosscloud:aws:archive_collected_data:default:run-6:y | default | 6 | payload_present | 10 | `9e9bbb8f0efae9420747da15e7e6afa041a392fae6d4241e1ff207188010ce12` |
| crosscloud:aws:archive_collected_data:default:run-7:n | default | 7 | payload_absent | 7 | `9f2663f3d74b8efc9d74a2372b509125547312747d6a1e3ae3ea052da2da284c` |
| crosscloud:aws:archive_collected_data:default:run-7:y | default | 7 | payload_present | 10 | `73cf3016dee287f2934c73207d7d5edfbc4482b67c417c3d824730a0e3f50c86` |
| crosscloud:aws:archive_collected_data:default:run-8:n | default | 8 | payload_absent | 6 | `4c74d95db7ded50b58ea64b7d004e7f21ef7a5b63ac4d781a6a9769f8ca21d14` |
| crosscloud:aws:archive_collected_data:default:run-8:y | default | 8 | payload_present | 10 | `15dd14853a532a70a8d23f6b763d8c7dec8afcd8bfd5d55c2d6b9859bcffbb9c` |
| crosscloud:aws:archive_collected_data:default:run-9:n | default | 9 | payload_absent | 7 | `678114069587b16cd1ae9d59874c8939d0c3ceb4b020bd04bb4c606122cd4ad1` |
| crosscloud:aws:archive_collected_data:default:run-9:y | default | 9 | payload_present | 9 | `e433db2473659ed8a634864ba492e6f5e072a33e27fa4d2a0e3b2ea9a81c7f80` |

### 原始文件完整性

- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/README.md` — SHA-256 `b073b2e97aea4073fec2bf387e2c255d987dd8f3710e84f2df3cc59947e510f8`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/attack_scripts.zip` — SHA-256 `4599be3e224f3b9b43e76ab4ec1bfa8e3b209ebe529fb218ae4e65dd22417900`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/aws_logs_redacted.zip` — SHA-256 `f75046f8660e648981040d5180950867a7e82cb8b799708ff572a927d2d35f5b`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/log_analysis.zip` — SHA-256 `23b41863cc2ece4936277a1ee1fc6f64b4fea9f3c0f698cefbf5626eeca00fcf`

## 11. `crosscloud:aws:automated_collection`

- 描述：DOI-published paired payload/no-payload AWS telemetry for automated_collection.
- 发布者：Dhooghe et al.
- 发布日期：2026-04-30
- 环境：controlled cloud subscription
- ATT&CK：
- 原始文件数：4
- 规范化观测数：0
- 上游 episode 数：40

### 准入判断（人工填写）

- [ ] 有外部或低权限入口
- [ ] 存在多步关系，而非单点事件
- [ ] 终点为数据库、存储、备份、secret 或其他数据资产
- [ ] 关键边均有原始证据
- [ ] 不是近重复案例
- 决定：`<accept | needs_execution | reject>`
- 理由：`<人工填写>`

### 观测索引

| observation_id | timestamp | actor_type | service | operation | status | raw record |
|---|---:|---|---|---|---|---|

### 上游配对 episode

| episode_id | profile | run | source condition | observations | member SHA-256 |
|---|---|---:|---|---:|---|
| crosscloud:aws:automated_collection:additional:run-0:n | additional | 0 | payload_absent | 19 | `72ded938f080f47bbd17ce257992bc2c921a8f66bd8078797830c19d45c9dcf6` |
| crosscloud:aws:automated_collection:additional:run-0:y | additional | 0 | payload_present | 23 | `7a6f752e20df9ab25d294f1f297c98a3f666c42a4f5900a39fa68be303b7a0b5` |
| crosscloud:aws:automated_collection:additional:run-1:n | additional | 1 | payload_absent | 18 | `83bd0f3038c2cac28fcdda8d9d53d89efb58f8ea30b2e1ed55cff2e0449580f0` |
| crosscloud:aws:automated_collection:additional:run-1:y | additional | 1 | payload_present | 27 | `d7b8b7897d0b592e9f0c740319a2a547df3c8781392df9f1760b15785677ab93` |
| crosscloud:aws:automated_collection:additional:run-2:n | additional | 2 | payload_absent | 20 | `a61072fd31097a31685bc9eb7ffe47ba72b612bda49d49732c13f18f9e3db214` |
| crosscloud:aws:automated_collection:additional:run-2:y | additional | 2 | payload_present | 37 | `9d9cfdba98070ec35d4c7f11439867c85ec9997bde485ec32a4f7554ef1ca229` |
| crosscloud:aws:automated_collection:additional:run-3:n | additional | 3 | payload_absent | 18 | `2d2ac0c3e856f0ea8b5d754002aa91a62a5b233c08e488bc9b073694eb756f62` |
| crosscloud:aws:automated_collection:additional:run-3:y | additional | 3 | payload_present | 18 | `15f5824c60a43a2a2e76b60bad9024b19010c56b22c308f01aa858b1033d4fe1` |
| crosscloud:aws:automated_collection:additional:run-4:n | additional | 4 | payload_absent | 31 | `b466e9ed2b4784e674baae9c0672c867ce42b81a4b632bc629b27a3b6447c84e` |
| crosscloud:aws:automated_collection:additional:run-4:y | additional | 4 | payload_present | 25 | `173f2aff1ad53ea145f595570d1956bf06901009c66f1e5ee5bf8d95c2fca1f2` |
| crosscloud:aws:automated_collection:additional:run-5:n | additional | 5 | payload_absent | 15 | `806f9e390863aa9cf1aea23a9e2d6135bbae5a86f3e9df851ae85ce65b622d4e` |
| crosscloud:aws:automated_collection:additional:run-5:y | additional | 5 | payload_present | 23 | `9c0279530876f4b435a541bfdeecf3df7a9f1fb0a093f3b591fa1ea9bb1c2d88` |
| crosscloud:aws:automated_collection:additional:run-6:n | additional | 6 | payload_absent | 25 | `b4e2588ce04843c08e16029db3909db5c9c97863f2f3dc0bbc0aab012df7d217` |
| crosscloud:aws:automated_collection:additional:run-6:y | additional | 6 | payload_present | 19 | `4c488943861aecb34afcc4867a1c56dca31b09d3725eeb302e7b754844edcb33` |
| crosscloud:aws:automated_collection:additional:run-7:n | additional | 7 | payload_absent | 36 | `8685922df64ce42bca37c1f2726d583fb94ba8ffaa5d0620c588188bec3b2744` |
| crosscloud:aws:automated_collection:additional:run-7:y | additional | 7 | payload_present | 25 | `7e496e674b3850f2202c74bdf404d17fe6b0bb1048d2aa30ece060e51c52cf04` |
| crosscloud:aws:automated_collection:additional:run-8:n | additional | 8 | payload_absent | 58 | `2315ec6e175cb082637ac2f6d9d58c34bd85ccb04e1b2fa4edf33f41ab7c2d8c` |
| crosscloud:aws:automated_collection:additional:run-8:y | additional | 8 | payload_present | 21 | `e8215d2a2f8b8cf93217071c922c14b8d24a6a11086e15f3439e6e7408333eda` |
| crosscloud:aws:automated_collection:additional:run-9:n | additional | 9 | payload_absent | 26 | `8611c7c4e0631626746db0de2bd9475e9227e64c453639ddb3d160cbe6b2f817` |
| crosscloud:aws:automated_collection:additional:run-9:y | additional | 9 | payload_present | 30 | `697e96c0cf7260f1dad1233b42cebcfe8cd349b4592c3296c594f98eb4c8d685` |
| crosscloud:aws:automated_collection:default:run-0:n | default | 0 | payload_absent | 6 | `3e03689b1161a99a84c59848a11641462a6a50707d35a4a39a20903a4e503031` |
| crosscloud:aws:automated_collection:default:run-0:y | default | 0 | payload_present | 7 | `ad05123ddcf3295db91e52578020436d6222f289daf295f1e704dc651898be43` |
| crosscloud:aws:automated_collection:default:run-1:n | default | 1 | payload_absent | 4 | `75bef7a1f9450276a45393b405b9e0b36536acf7e8bb49ba530ac35a49749729` |
| crosscloud:aws:automated_collection:default:run-1:y | default | 1 | payload_present | 6 | `323303f79f9c1e9a2d05d2137aa7a977ca616226f801c4fae9bee4deb3d252a2` |
| crosscloud:aws:automated_collection:default:run-2:n | default | 2 | payload_absent | 5 | `fa78c82abde92b894b4f000da7b8594565f09732970751e1c08e99d353c14dac` |
| crosscloud:aws:automated_collection:default:run-2:y | default | 2 | payload_present | 6 | `17c553e49e3fafd0ad9b1a8fb256d65ec00ff94ab98be5ed6572d21473f9e891` |
| crosscloud:aws:automated_collection:default:run-3:n | default | 3 | payload_absent | 7 | `c1d4cac37edfa0e41b454af0dfca37f4d2e04c82dbc7f6d0c047fa6e283f85b8` |
| crosscloud:aws:automated_collection:default:run-3:y | default | 3 | payload_present | 6 | `bc4b82fbcee4cc9609ad89da5de85c57cc532afb08e7c327cc618719500b0744` |
| crosscloud:aws:automated_collection:default:run-4:n | default | 4 | payload_absent | 5 | `5d329bf3f17b4eb2830aa15ebccbc9d18f12ff496aafb38a13cbe339ba509d1e` |
| crosscloud:aws:automated_collection:default:run-4:y | default | 4 | payload_present | 6 | `eead0b71486197d4e826366eb1c37f3c40388bb652d76a6db92d8a154d3cda08` |
| crosscloud:aws:automated_collection:default:run-5:n | default | 5 | payload_absent | 7 | `4d0507033018680e1c8e82d2772f025ef2f7f269cc46efcdb96c0faaa381c946` |
| crosscloud:aws:automated_collection:default:run-5:y | default | 5 | payload_present | 6 | `814e3ed136ec5fad83530b5fad08058280a6ef5707d7fa5682cb33ad73242b7f` |
| crosscloud:aws:automated_collection:default:run-6:n | default | 6 | payload_absent | 6 | `38b89dbab09c682dcc99984336fafd5f883b08a48911cfa9bf6169e587d1d1f8` |
| crosscloud:aws:automated_collection:default:run-6:y | default | 6 | payload_present | 6 | `a543e58b73eede8b4493c40c609e9afe694a278f475ac1ffbec80da33085f19b` |
| crosscloud:aws:automated_collection:default:run-7:n | default | 7 | payload_absent | 6 | `fa042f29bf7580ccc255689e6485d819ad43cd3a90c59b9ef034ef43ec51acc5` |
| crosscloud:aws:automated_collection:default:run-7:y | default | 7 | payload_present | 7 | `ad2a6db0ca7c925131049ba38b91b761ed14fba2347e0f30396a6a51d6ab0330` |
| crosscloud:aws:automated_collection:default:run-8:n | default | 8 | payload_absent | 5 | `ae8acb72be41e72469baa682cd2f2a5deb601d1d905c65e5e8ba7281f4ced65d` |
| crosscloud:aws:automated_collection:default:run-8:y | default | 8 | payload_present | 6 | `159903975359f4223f0d4e9a533b92df8f14515c32668dbec67ef2163470669d` |
| crosscloud:aws:automated_collection:default:run-9:n | default | 9 | payload_absent | 6 | `4bc8bab2320f6e159ace7f1231060b517b0c8dd66f4d89ac1bd56b0e508f81e6` |
| crosscloud:aws:automated_collection:default:run-9:y | default | 9 | payload_present | 5 | `426f090c951a851475c6fd331088853e58a585da5f51ad15e7ef4096843ebad3` |

### 原始文件完整性

- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/README.md` — SHA-256 `b073b2e97aea4073fec2bf387e2c255d987dd8f3710e84f2df3cc59947e510f8`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/attack_scripts.zip` — SHA-256 `4599be3e224f3b9b43e76ab4ec1bfa8e3b209ebe529fb218ae4e65dd22417900`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/aws_logs_redacted.zip` — SHA-256 `f75046f8660e648981040d5180950867a7e82cb8b799708ff572a927d2d35f5b`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/log_analysis.zip` — SHA-256 `23b41863cc2ece4936277a1ee1fc6f64b4fea9f3c0f698cefbf5626eeca00fcf`

## 12. `crosscloud:aws:automated_exfiltration`

- 描述：DOI-published paired payload/no-payload AWS telemetry for automated_exfiltration.
- 发布者：Dhooghe et al.
- 发布日期：2026-04-30
- 环境：controlled cloud subscription
- ATT&CK：
- 原始文件数：4
- 规范化观测数：0
- 上游 episode 数：40

### 准入判断（人工填写）

- [ ] 有外部或低权限入口
- [ ] 存在多步关系，而非单点事件
- [ ] 终点为数据库、存储、备份、secret 或其他数据资产
- [ ] 关键边均有原始证据
- [ ] 不是近重复案例
- 决定：`<accept | needs_execution | reject>`
- 理由：`<人工填写>`

### 观测索引

| observation_id | timestamp | actor_type | service | operation | status | raw record |
|---|---:|---|---|---|---|---|

### 上游配对 episode

| episode_id | profile | run | source condition | observations | member SHA-256 |
|---|---|---:|---|---:|---|
| crosscloud:aws:automated_exfiltration:additional:run-0:n | additional | 0 | payload_absent | 110 | `7762d742b52b2ba5c7c5fb891367502aed06948536b19b4820c9fd87915126e6` |
| crosscloud:aws:automated_exfiltration:additional:run-0:y | additional | 0 | payload_present | 117 | `b5e7fa7e360b5d5436a9efceaa7b739560b690d601d6e282a59ccd7b3cb82cfd` |
| crosscloud:aws:automated_exfiltration:additional:run-1:n | additional | 1 | payload_absent | 79 | `a9b8d07717e098594e936b4be4aaad9d9ca550da3a75c559745aeecc55b77a14` |
| crosscloud:aws:automated_exfiltration:additional:run-1:y | additional | 1 | payload_present | 62 | `a0b12eb2eb9181a56b957aa129f09f2b687845ad9af77842f3c0cb9a564b720e` |
| crosscloud:aws:automated_exfiltration:additional:run-2:n | additional | 2 | payload_absent | 101 | `ae845b7278009dbe84c9b9be72e7a51ee8e6796303c7cd1cd31a13f64d0a3f76` |
| crosscloud:aws:automated_exfiltration:additional:run-2:y | additional | 2 | payload_present | 2110 | `d07411bb368e1ff9a5b037665dff3c9fc3aeb1ba40fa428f4bd2968255b210ca` |
| crosscloud:aws:automated_exfiltration:additional:run-3:n | additional | 3 | payload_absent | 129 | `8f78d578e34be1c053dc81c6b8d20e3c34dd8799166776e4775d72dd70bbe48d` |
| crosscloud:aws:automated_exfiltration:additional:run-3:y | additional | 3 | payload_present | 83 | `d772e05b20d988674e6e5ef8f06e562b4881222699102e644df91d7d2c8b7abd` |
| crosscloud:aws:automated_exfiltration:additional:run-4:n | additional | 4 | payload_absent | 150 | `7c2a56aecbe198bf2f017b57d9ef60df742b50c0feaa9361e6338bc57e767b60` |
| crosscloud:aws:automated_exfiltration:additional:run-4:y | additional | 4 | payload_present | 98 | `71f64de5b36a2ec817bd67a5a6d000794b2c2551afbea21f959a9b1534c4db4c` |
| crosscloud:aws:automated_exfiltration:additional:run-5:n | additional | 5 | payload_absent | 103 | `7c5b6120fb850a467858f8d7914966f4b53a3857175d8daecaa532938056e452` |
| crosscloud:aws:automated_exfiltration:additional:run-5:y | additional | 5 | payload_present | 78 | `ed6f8363b6f444d2f1b3c9da7ff835289265bc2b93ba2a4ff07f7745b0dcf2b3` |
| crosscloud:aws:automated_exfiltration:additional:run-6:n | additional | 6 | payload_absent | 135 | `1cdda129db72bade59d87d3d9d276f85b4e6d0aa034172c9e3a2e21b4e3582a9` |
| crosscloud:aws:automated_exfiltration:additional:run-6:y | additional | 6 | payload_present | 102 | `b878ea8248e62fdf486961c25849696f4fa950b1acd2476ca4af5024ec777d70` |
| crosscloud:aws:automated_exfiltration:additional:run-7:n | additional | 7 | payload_absent | 142 | `93aeaf8d00d9bdf6380d0f9cc9bc37bef3450160219f33a16b098a025c99aa23` |
| crosscloud:aws:automated_exfiltration:additional:run-7:y | additional | 7 | payload_present | 60 | `bea25ae63fbf2a19f3cc036a744df9127bc2786e221efae236b0e8b438e41ad7` |
| crosscloud:aws:automated_exfiltration:additional:run-8:n | additional | 8 | payload_absent | 88 | `664d9d178d248a3af454ad6173e1ffee36a0870f2c409b8019bac875edfd215d` |
| crosscloud:aws:automated_exfiltration:additional:run-8:y | additional | 8 | payload_present | 65 | `9596e00158a05d86ce75b6cf3cd2f47cbc41f09c4c0ca82e5adbd30290f74935` |
| crosscloud:aws:automated_exfiltration:additional:run-9:n | additional | 9 | payload_absent | 90 | `f0ebe92b718e5c472cbb7a1afef979ed0532ab00abf8fe39f08dfb351ea22fa0` |
| crosscloud:aws:automated_exfiltration:additional:run-9:y | additional | 9 | payload_present | 75 | `0f65f930cfa954a30d48f04a43d34b6bb0b8073a9e0d9efd24b3cfd24a83e084` |
| crosscloud:aws:automated_exfiltration:default:run-0:n | default | 0 | payload_absent | 110 | `7762d742b52b2ba5c7c5fb891367502aed06948536b19b4820c9fd87915126e6` |
| crosscloud:aws:automated_exfiltration:default:run-0:y | default | 0 | payload_present | 117 | `b5e7fa7e360b5d5436a9efceaa7b739560b690d601d6e282a59ccd7b3cb82cfd` |
| crosscloud:aws:automated_exfiltration:default:run-1:n | default | 1 | payload_absent | 79 | `a9b8d07717e098594e936b4be4aaad9d9ca550da3a75c559745aeecc55b77a14` |
| crosscloud:aws:automated_exfiltration:default:run-1:y | default | 1 | payload_present | 62 | `a0b12eb2eb9181a56b957aa129f09f2b687845ad9af77842f3c0cb9a564b720e` |
| crosscloud:aws:automated_exfiltration:default:run-2:n | default | 2 | payload_absent | 101 | `ae845b7278009dbe84c9b9be72e7a51ee8e6796303c7cd1cd31a13f64d0a3f76` |
| crosscloud:aws:automated_exfiltration:default:run-2:y | default | 2 | payload_present | 2110 | `d07411bb368e1ff9a5b037665dff3c9fc3aeb1ba40fa428f4bd2968255b210ca` |
| crosscloud:aws:automated_exfiltration:default:run-3:n | default | 3 | payload_absent | 129 | `8f78d578e34be1c053dc81c6b8d20e3c34dd8799166776e4775d72dd70bbe48d` |
| crosscloud:aws:automated_exfiltration:default:run-3:y | default | 3 | payload_present | 83 | `d772e05b20d988674e6e5ef8f06e562b4881222699102e644df91d7d2c8b7abd` |
| crosscloud:aws:automated_exfiltration:default:run-4:n | default | 4 | payload_absent | 150 | `7c2a56aecbe198bf2f017b57d9ef60df742b50c0feaa9361e6338bc57e767b60` |
| crosscloud:aws:automated_exfiltration:default:run-4:y | default | 4 | payload_present | 98 | `71f64de5b36a2ec817bd67a5a6d000794b2c2551afbea21f959a9b1534c4db4c` |
| crosscloud:aws:automated_exfiltration:default:run-5:n | default | 5 | payload_absent | 103 | `7c5b6120fb850a467858f8d7914966f4b53a3857175d8daecaa532938056e452` |
| crosscloud:aws:automated_exfiltration:default:run-5:y | default | 5 | payload_present | 78 | `ed6f8363b6f444d2f1b3c9da7ff835289265bc2b93ba2a4ff07f7745b0dcf2b3` |
| crosscloud:aws:automated_exfiltration:default:run-6:n | default | 6 | payload_absent | 135 | `1cdda129db72bade59d87d3d9d276f85b4e6d0aa034172c9e3a2e21b4e3582a9` |
| crosscloud:aws:automated_exfiltration:default:run-6:y | default | 6 | payload_present | 102 | `b878ea8248e62fdf486961c25849696f4fa950b1acd2476ca4af5024ec777d70` |
| crosscloud:aws:automated_exfiltration:default:run-7:n | default | 7 | payload_absent | 142 | `93aeaf8d00d9bdf6380d0f9cc9bc37bef3450160219f33a16b098a025c99aa23` |
| crosscloud:aws:automated_exfiltration:default:run-7:y | default | 7 | payload_present | 60 | `bea25ae63fbf2a19f3cc036a744df9127bc2786e221efae236b0e8b438e41ad7` |
| crosscloud:aws:automated_exfiltration:default:run-8:n | default | 8 | payload_absent | 88 | `664d9d178d248a3af454ad6173e1ffee36a0870f2c409b8019bac875edfd215d` |
| crosscloud:aws:automated_exfiltration:default:run-8:y | default | 8 | payload_present | 65 | `9596e00158a05d86ce75b6cf3cd2f47cbc41f09c4c0ca82e5adbd30290f74935` |
| crosscloud:aws:automated_exfiltration:default:run-9:n | default | 9 | payload_absent | 90 | `f0ebe92b718e5c472cbb7a1afef979ed0532ab00abf8fe39f08dfb351ea22fa0` |
| crosscloud:aws:automated_exfiltration:default:run-9:y | default | 9 | payload_present | 75 | `0f65f930cfa954a30d48f04a43d34b6bb0b8073a9e0d9efd24b3cfd24a83e084` |

### 原始文件完整性

- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/README.md` — SHA-256 `b073b2e97aea4073fec2bf387e2c255d987dd8f3710e84f2df3cc59947e510f8`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/attack_scripts.zip` — SHA-256 `4599be3e224f3b9b43e76ab4ec1bfa8e3b209ebe529fb218ae4e65dd22417900`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/aws_logs_redacted.zip` — SHA-256 `f75046f8660e648981040d5180950867a7e82cb8b799708ff572a927d2d35f5b`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/log_analysis.zip` — SHA-256 `23b41863cc2ece4936277a1ee1fc6f64b4fea9f3c0f698cefbf5626eeca00fcf`

## 13. `crosscloud:aws:credentials_from_password_stores`

- 描述：DOI-published paired payload/no-payload AWS telemetry for credentials_from_password_stores.
- 发布者：Dhooghe et al.
- 发布日期：2026-04-30
- 环境：controlled cloud subscription
- ATT&CK：
- 原始文件数：4
- 规范化观测数：0
- 上游 episode 数：40

### 准入判断（人工填写）

- [ ] 有外部或低权限入口
- [ ] 存在多步关系，而非单点事件
- [ ] 终点为数据库、存储、备份、secret 或其他数据资产
- [ ] 关键边均有原始证据
- [ ] 不是近重复案例
- 决定：`<accept | needs_execution | reject>`
- 理由：`<人工填写>`

### 观测索引

| observation_id | timestamp | actor_type | service | operation | status | raw record |
|---|---:|---|---|---|---|---|

### 上游配对 episode

| episode_id | profile | run | source condition | observations | member SHA-256 |
|---|---|---:|---|---:|---|
| crosscloud:aws:credentials_from_password_stores:additional:run-0:n | additional | 0 | payload_absent | 20 | `677de11e04922b00d73e7ee4054ebe754398577e35b1b3f6711fbd58507a18ef` |
| crosscloud:aws:credentials_from_password_stores:additional:run-0:y | additional | 0 | payload_present | 50 | `9a4c149ade5d5d0c45097b0d27304b7fd774c0386d24372ef89a748b3d7224c8` |
| crosscloud:aws:credentials_from_password_stores:additional:run-1:n | additional | 1 | payload_absent | 19 | `8184f7f4b7763a899bf3f884cba3b0219cf3a18092dd60534f8cc2478fb322fa` |
| crosscloud:aws:credentials_from_password_stores:additional:run-1:y | additional | 1 | payload_present | 75 | `e11334ecf08439debcb43b882be719ea54c2b5f556883716c817d81e0574d52b` |
| crosscloud:aws:credentials_from_password_stores:additional:run-2:n | additional | 2 | payload_absent | 23 | `7eb553906e7b106d1023b0f5970f7f7744db432b49e185ea900a908a347afb4e` |
| crosscloud:aws:credentials_from_password_stores:additional:run-2:y | additional | 2 | payload_present | 70 | `f0254f28d8172541c9a653dc98645f2e7711b9712c9d79eaec3f32aced381bcd` |
| crosscloud:aws:credentials_from_password_stores:additional:run-3:n | additional | 3 | payload_absent | 19 | `82f6847f3652c036238b04de4821d382b5cbd1005a1732bd7ce845c233dceee4` |
| crosscloud:aws:credentials_from_password_stores:additional:run-3:y | additional | 3 | payload_present | 29 | `30563cb7bff2593e25474379f45a21a57a766186adad31732fc434b15968df2b` |
| crosscloud:aws:credentials_from_password_stores:additional:run-4:n | additional | 4 | payload_absent | 19 | `3276684f98a197e6a5024ba52fded8e600c969ab4c1aadaccc4cee340326c5a8` |
| crosscloud:aws:credentials_from_password_stores:additional:run-4:y | additional | 4 | payload_present | 28 | `4c01b24e8973d71f2fb193edc24cd2111c842dad4afebcaf5606c07b10d8e113` |
| crosscloud:aws:credentials_from_password_stores:additional:run-5:n | additional | 5 | payload_absent | 23 | `03ac20ac532e7ad5503dc1023cde34b854ff4c6b2b1a6c168276c08b4608b8ee` |
| crosscloud:aws:credentials_from_password_stores:additional:run-5:y | additional | 5 | payload_present | 28 | `31022bb6dacd9f2877056d508fe7bb4f7487c9deb0c68630996a9430cd677e05` |
| crosscloud:aws:credentials_from_password_stores:additional:run-6:n | additional | 6 | payload_absent | 19 | `4ee958a20e965db070eae2bf88d01eaa000f8fb1ffa3233945bbca04f7b8a42c` |
| crosscloud:aws:credentials_from_password_stores:additional:run-6:y | additional | 6 | payload_present | 36 | `d7ea72021866cfe18c3dbb7b079c386c71dcd6f715541832eceea6b0a9ae3a32` |
| crosscloud:aws:credentials_from_password_stores:additional:run-7:n | additional | 7 | payload_absent | 36 | `0ec93aa5e1c17d16ae53505ed4ff730627ba3424230d23389d07d47a475b3a3f` |
| crosscloud:aws:credentials_from_password_stores:additional:run-7:y | additional | 7 | payload_present | 31 | `ae0db31dafb9fc58dae556fdc4d401440c1ada78e915e629941ee699564039d8` |
| crosscloud:aws:credentials_from_password_stores:additional:run-8:n | additional | 8 | payload_absent | 23 | `b54f503c24cfd48db761aa9cde080ec10d68ece33f03638186f0ee9e568a2268` |
| crosscloud:aws:credentials_from_password_stores:additional:run-8:y | additional | 8 | payload_present | 32 | `3a1e5c3bf9a6200735acee9f168474fef6a13219021a52fcb1462cdf105802c7` |
| crosscloud:aws:credentials_from_password_stores:additional:run-9:n | additional | 9 | payload_absent | 20 | `2476a10b8b4fe05010f3acee7f6853b9d17f5f79caf97fb76a5823d81339956d` |
| crosscloud:aws:credentials_from_password_stores:additional:run-9:y | additional | 9 | payload_present | 39 | `e9c748a0606d6b1f3f9080c3e7ca37068c8d8afc8e6aa15b0714cf97b960a409` |
| crosscloud:aws:credentials_from_password_stores:default:run-0:n | default | 0 | payload_absent | 0 | `37517e5f3dc66819f61f5a7bb8ace1921282415f10551d2defa5c3eb0985b570` |
| crosscloud:aws:credentials_from_password_stores:default:run-0:y | default | 0 | payload_present | 18 | `776d63deb7e6c3a9d5a6444aaafbc811555531f57e5f8f8efc97cfafeca5ee50` |
| crosscloud:aws:credentials_from_password_stores:default:run-1:n | default | 1 | payload_absent | 5 | `ca6b38acb027f5db43d2afe09d7d44bb020aa13b726dac497bb620109ed93ce9` |
| crosscloud:aws:credentials_from_password_stores:default:run-1:y | default | 1 | payload_present | 19 | `b265ced5e5d4ca10983c533f7ee838af88f2c1495e0ba42abbf2f1daefe46bfe` |
| crosscloud:aws:credentials_from_password_stores:default:run-2:n | default | 2 | payload_absent | 20 | `21aae3905063a7ec34363c11f6c215daf2b3ebe20df674d8bb8142f3e566e247` |
| crosscloud:aws:credentials_from_password_stores:default:run-2:y | default | 2 | payload_present | 21 | `a0ea5e5afe78b9a0193ef0f247ca0e175ab860a56e9aabda0dc15e864bdb731a` |
| crosscloud:aws:credentials_from_password_stores:default:run-3:n | default | 3 | payload_absent | 22 | `9dbad4456feef815c68db6822a12b5b8a28279d27ce8f0f0ae5a51f2ff3552d6` |
| crosscloud:aws:credentials_from_password_stores:default:run-3:y | default | 3 | payload_present | 19 | `01a4895942ceb4a8e2c015d7e43e2ac996ed06b475e3c4967b438a3e1e749f0c` |
| crosscloud:aws:credentials_from_password_stores:default:run-4:n | default | 4 | payload_absent | 25 | `ccd01afff63cce7dc08132d11b36b184ba8a75511364098abbec352578af4774` |
| crosscloud:aws:credentials_from_password_stores:default:run-4:y | default | 4 | payload_present | 21 | `7a0536e96c59bd2fd8d9fecde6eacc4d9c05ce501c18fdadfdef6d675d18fadf` |
| crosscloud:aws:credentials_from_password_stores:default:run-5:n | default | 5 | payload_absent | 19 | `6a5e7bfa5f9b053f267b00a701d604eed2f4ba8b5f5d3d6ff9d01c30f73b4ec9` |
| crosscloud:aws:credentials_from_password_stores:default:run-5:y | default | 5 | payload_present | 20 | `ad565f6e504a8675e2ee0bde2b62fcda57ab6c3c15b144a72c8a7244e601c73d` |
| crosscloud:aws:credentials_from_password_stores:default:run-6:n | default | 6 | payload_absent | 22 | `bfb3121e8c3cb5e5978d068a5a5f7e0ad0ff425c47a9cdb0d3185a88165e25d8` |
| crosscloud:aws:credentials_from_password_stores:default:run-6:y | default | 6 | payload_present | 18 | `a726b104b7b3bf3b246d5da4760c34d71b221bd9bd7a5941be9544078462321f` |
| crosscloud:aws:credentials_from_password_stores:default:run-7:n | default | 7 | payload_absent | 33 | `5ecbada21b0d1ec853d451046804c41a0049312913ed472e197fe27f9c6d29ae` |
| crosscloud:aws:credentials_from_password_stores:default:run-7:y | default | 7 | payload_present | 21 | `34a2cc465aff30a9fce730562341784b219bc293de29164f1c4f40a036fe8965` |
| crosscloud:aws:credentials_from_password_stores:default:run-8:n | default | 8 | payload_absent | 24 | `1490ffb1afd689858f709f6c0d4edb40edec3ab8c6fc05e9b5f95b656a268f3a` |
| crosscloud:aws:credentials_from_password_stores:default:run-8:y | default | 8 | payload_present | 19 | `a01eae8d6cb57d3b48beaafc0b7298363d438c8f6188f8657e19d2c364326eb0` |
| crosscloud:aws:credentials_from_password_stores:default:run-9:n | default | 9 | payload_absent | 22 | `f1c70626332bb2aae8a6d7cdced2600defcd860b89880455c69a0a5cdc48d89d` |
| crosscloud:aws:credentials_from_password_stores:default:run-9:y | default | 9 | payload_present | 21 | `5b2ba43fbb367977f69aa3701aae0df7715d00eb2f6aa64a7c708ba976d70a86` |

### 原始文件完整性

- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/README.md` — SHA-256 `b073b2e97aea4073fec2bf387e2c255d987dd8f3710e84f2df3cc59947e510f8`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/attack_scripts.zip` — SHA-256 `4599be3e224f3b9b43e76ab4ec1bfa8e3b209ebe529fb218ae4e65dd22417900`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/aws_logs_redacted.zip` — SHA-256 `f75046f8660e648981040d5180950867a7e82cb8b799708ff572a927d2d35f5b`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/log_analysis.zip` — SHA-256 `23b41863cc2ece4936277a1ee1fc6f64b4fea9f3c0f698cefbf5626eeca00fcf`

## 14. `crosscloud:aws:data_destruction`

- 描述：DOI-published paired payload/no-payload AWS telemetry for data_destruction.
- 发布者：Dhooghe et al.
- 发布日期：2026-04-30
- 环境：controlled cloud subscription
- ATT&CK：
- 原始文件数：4
- 规范化观测数：0
- 上游 episode 数：34

### 准入判断（人工填写）

- [ ] 有外部或低权限入口
- [ ] 存在多步关系，而非单点事件
- [ ] 终点为数据库、存储、备份、secret 或其他数据资产
- [ ] 关键边均有原始证据
- [ ] 不是近重复案例
- 决定：`<accept | needs_execution | reject>`
- 理由：`<人工填写>`

### 观测索引

| observation_id | timestamp | actor_type | service | operation | status | raw record |
|---|---:|---|---|---|---|---|

### 上游配对 episode

| episode_id | profile | run | source condition | observations | member SHA-256 |
|---|---|---:|---|---:|---|
| crosscloud:aws:data_destruction:additional:run-0:n | additional | 0 | payload_absent | 20 | `e96d3b93af039b519d4de65f651a6be9d3b4a8bf982a01d084e8c3e72e80ed3c` |
| crosscloud:aws:data_destruction:additional:run-0:y | additional | 0 | payload_present | 14 | `61937d6e05c0bf37ae90d84d6fc7c1ff8f4265b48294b362808224f4af6fa2d5` |
| crosscloud:aws:data_destruction:additional:run-1:n | additional | 1 | payload_absent | 12 | `e4c8f5313fb10af0fc1dba88f32e565786d08e41bd02279529860d7aebba175e` |
| crosscloud:aws:data_destruction:additional:run-1:y | additional | 1 | payload_present | 26 | `cfe507713d2db3e619bf96ace2fd49b11047adc1a433c3ea26ba300017b92213` |
| crosscloud:aws:data_destruction:additional:run-2:n | additional | 2 | payload_absent | 28 | `3684a01fe7c8ed632faeffc2e86286dc6828a9134fa227de9abaf5beb4ceb16c` |
| crosscloud:aws:data_destruction:additional:run-2:y | additional | 2 | payload_present | 19 | `ddd816b7df3bea496158798f0fe44b8b45b215f9e36ad0bfd3d2c11834b23f73` |
| crosscloud:aws:data_destruction:additional:run-3:n | additional | 3 | payload_absent | 16 | `aefbe36c3c23105aa9e7e58c5d4780fc2dc4e88e5e8316dbae01a7bff9519917` |
| crosscloud:aws:data_destruction:additional:run-3:y | additional | 3 | payload_present | 16 | `dec442bf192ddebba6e98d44b6b92acff1844b532c2c904206061f4f6bac8473` |
| crosscloud:aws:data_destruction:additional:run-4:n | additional | 4 | payload_absent | 25 | `901e9467b742e7d98e62dcd06c4e69cb475fe4ae89967a51cf57702c1340f8df` |
| crosscloud:aws:data_destruction:additional:run-4:y | additional | 4 | payload_present | 16 | `c9ae73a759d5d4acc0a0d16213bf0da1651499cb2ed81516024389d1e4a8078e` |
| crosscloud:aws:data_destruction:additional:run-5:n | additional | 5 | payload_absent | 22 | `364333c47717483668d8973755a59f4925559bb5db7f7009c94e025df2d10df6` |
| crosscloud:aws:data_destruction:additional:run-5:y | additional | 5 | payload_present | 25 | `75447ea02b3624bcc49deca97c180dbf5fdb6cd3f17a8378658542a72cf5c2bf` |
| crosscloud:aws:data_destruction:additional:run-6:n | additional | 6 | payload_absent | 21 | `ddff5c03727df10ae44b5460a9ec7770c5205f4c02cf13fb6c543535138aa34d` |
| crosscloud:aws:data_destruction:additional:run-6:y | additional | 6 | payload_present | 20 | `8b36cb124d88b608642663e4595221025fb66554a5311adf43c7b9b912aeec6a` |
| crosscloud:aws:data_destruction:default:run-0:n | default | 0 | payload_absent | 20 | `e96d3b93af039b519d4de65f651a6be9d3b4a8bf982a01d084e8c3e72e80ed3c` |
| crosscloud:aws:data_destruction:default:run-0:y | default | 0 | payload_present | 14 | `61937d6e05c0bf37ae90d84d6fc7c1ff8f4265b48294b362808224f4af6fa2d5` |
| crosscloud:aws:data_destruction:default:run-1:n | default | 1 | payload_absent | 12 | `e4c8f5313fb10af0fc1dba88f32e565786d08e41bd02279529860d7aebba175e` |
| crosscloud:aws:data_destruction:default:run-1:y | default | 1 | payload_present | 26 | `cfe507713d2db3e619bf96ace2fd49b11047adc1a433c3ea26ba300017b92213` |
| crosscloud:aws:data_destruction:default:run-2:n | default | 2 | payload_absent | 28 | `3684a01fe7c8ed632faeffc2e86286dc6828a9134fa227de9abaf5beb4ceb16c` |
| crosscloud:aws:data_destruction:default:run-2:y | default | 2 | payload_present | 19 | `ddd816b7df3bea496158798f0fe44b8b45b215f9e36ad0bfd3d2c11834b23f73` |
| crosscloud:aws:data_destruction:default:run-3:n | default | 3 | payload_absent | 16 | `aefbe36c3c23105aa9e7e58c5d4780fc2dc4e88e5e8316dbae01a7bff9519917` |
| crosscloud:aws:data_destruction:default:run-3:y | default | 3 | payload_present | 16 | `dec442bf192ddebba6e98d44b6b92acff1844b532c2c904206061f4f6bac8473` |
| crosscloud:aws:data_destruction:default:run-4:n | default | 4 | payload_absent | 25 | `901e9467b742e7d98e62dcd06c4e69cb475fe4ae89967a51cf57702c1340f8df` |
| crosscloud:aws:data_destruction:default:run-4:y | default | 4 | payload_present | 16 | `c9ae73a759d5d4acc0a0d16213bf0da1651499cb2ed81516024389d1e4a8078e` |
| crosscloud:aws:data_destruction:default:run-5:n | default | 5 | payload_absent | 22 | `364333c47717483668d8973755a59f4925559bb5db7f7009c94e025df2d10df6` |
| crosscloud:aws:data_destruction:default:run-5:y | default | 5 | payload_present | 25 | `75447ea02b3624bcc49deca97c180dbf5fdb6cd3f17a8378658542a72cf5c2bf` |
| crosscloud:aws:data_destruction:default:run-6:n | default | 6 | payload_absent | 21 | `ddff5c03727df10ae44b5460a9ec7770c5205f4c02cf13fb6c543535138aa34d` |
| crosscloud:aws:data_destruction:default:run-6:y | default | 6 | payload_present | 20 | `8b36cb124d88b608642663e4595221025fb66554a5311adf43c7b9b912aeec6a` |
| crosscloud:aws:data_destruction:default:run-7:n | default | 7 | payload_absent | 16 | `23d0b2a1e789c9235e005173417d4c2ece4269a8df1a235f2eb4d857f82e37f9` |
| crosscloud:aws:data_destruction:default:run-7:y | default | 7 | payload_present | 2 | `3adc3f9ddbdccc661636d455d61f0ec1698292dce3cf8390a271f0aa7d32b654` |
| crosscloud:aws:data_destruction:default:run-8:n | default | 8 | payload_absent | 21 | `216aa00762717accccf17b0b1c254302fa281f856fae422066e5e01f08ab8638` |
| crosscloud:aws:data_destruction:default:run-8:y | default | 8 | payload_present | 2 | `48e1ebcfe2915bc4d62df5347b257782259a76d2523259d1dd14f1df4978cbae` |
| crosscloud:aws:data_destruction:default:run-9:n | default | 9 | payload_absent | 19 | `ed82a2e401849f93d96f8ec639a34c92bd4c7472a860ce39b875739802fdfde3` |
| crosscloud:aws:data_destruction:default:run-9:y | default | 9 | payload_present | 1 | `fc2278010b86b955cd2f9bf5729877db1b1257233c0ec2047209ad3f668b1fae` |

### 原始文件完整性

- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/README.md` — SHA-256 `b073b2e97aea4073fec2bf387e2c255d987dd8f3710e84f2df3cc59947e510f8`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/attack_scripts.zip` — SHA-256 `4599be3e224f3b9b43e76ab4ec1bfa8e3b209ebe529fb218ae4e65dd22417900`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/aws_logs_redacted.zip` — SHA-256 `f75046f8660e648981040d5180950867a7e82cb8b799708ff572a927d2d35f5b`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/log_analysis.zip` — SHA-256 `23b41863cc2ece4936277a1ee1fc6f64b4fea9f3c0f698cefbf5626eeca00fcf`

## 15. `crosscloud:aws:data_encrypted_for_impact`

- 描述：DOI-published paired payload/no-payload AWS telemetry for data_encrypted_for_impact.
- 发布者：Dhooghe et al.
- 发布日期：2026-04-30
- 环境：controlled cloud subscription
- ATT&CK：
- 原始文件数：4
- 规范化观测数：0
- 上游 episode 数：40

### 准入判断（人工填写）

- [ ] 有外部或低权限入口
- [ ] 存在多步关系，而非单点事件
- [ ] 终点为数据库、存储、备份、secret 或其他数据资产
- [ ] 关键边均有原始证据
- [ ] 不是近重复案例
- 决定：`<accept | needs_execution | reject>`
- 理由：`<人工填写>`

### 观测索引

| observation_id | timestamp | actor_type | service | operation | status | raw record |
|---|---:|---|---|---|---|---|

### 上游配对 episode

| episode_id | profile | run | source condition | observations | member SHA-256 |
|---|---|---:|---|---:|---|
| crosscloud:aws:data_encrypted_for_impact:additional:run-0:n | additional | 0 | payload_absent | 23 | `cae6684a4a717621ca2650bab0f2b34804e6403444db3d079d74b92ac9e319b4` |
| crosscloud:aws:data_encrypted_for_impact:additional:run-0:y | additional | 0 | payload_present | 21 | `b32e48f4f841429be902e4e8faf0564daaa21c2324d132687dadf08db8d71257` |
| crosscloud:aws:data_encrypted_for_impact:additional:run-1:n | additional | 1 | payload_absent | 14 | `5b53c6d8facb4dbf80eed56d847a672c6ddbabc36e53175e8f2799917f04bc17` |
| crosscloud:aws:data_encrypted_for_impact:additional:run-1:y | additional | 1 | payload_present | 21 | `e9cfaffe7ba3ee4f6394bc5934de4658a64bcef1ac369028c14b12bddb3ce346` |
| crosscloud:aws:data_encrypted_for_impact:additional:run-2:n | additional | 2 | payload_absent | 15 | `7275ba79b8e22cb27bd309aeacbb5b1337df86ddc77f8a8c49b3c2d64f2c7f7b` |
| crosscloud:aws:data_encrypted_for_impact:additional:run-2:y | additional | 2 | payload_present | 19 | `3e7bc535199fbc9a41d4c64aa43d9affd0a39032b70037032b0a0a400edc77bb` |
| crosscloud:aws:data_encrypted_for_impact:additional:run-3:n | additional | 3 | payload_absent | 28 | `886ad7498fc718d475490d91e9195269aeb629ba7c347c5fccba802b28f5cee5` |
| crosscloud:aws:data_encrypted_for_impact:additional:run-3:y | additional | 3 | payload_present | 20 | `48e14a32f4193ef2b62cbe034ffdc56518576f3aa0e1911aabb7f29d14f69cc3` |
| crosscloud:aws:data_encrypted_for_impact:additional:run-4:n | additional | 4 | payload_absent | 15 | `73c01bec5cad910937bcb21c1312a77acd00e5297536367b18e268d4356a5f27` |
| crosscloud:aws:data_encrypted_for_impact:additional:run-4:y | additional | 4 | payload_present | 20 | `3cfb4905e5392f9f3668c7605a90609f966d4a1629a819249c88c7df88560750` |
| crosscloud:aws:data_encrypted_for_impact:additional:run-5:n | additional | 5 | payload_absent | 13 | `a7c17fba3ff56851cc47a20cd23dbd02684ecd53b178aad23bd02efbaf53c04d` |
| crosscloud:aws:data_encrypted_for_impact:additional:run-5:y | additional | 5 | payload_present | 17 | `9536b171370a50031249e9bc0ce17b81a7a63bfa2e9a44ff6a3b50a2744540bd` |
| crosscloud:aws:data_encrypted_for_impact:additional:run-6:n | additional | 6 | payload_absent | 11 | `e0ba836f9761769bb8b26df305c3fdac761f373ffb32c39cbd03ff89490f65c5` |
| crosscloud:aws:data_encrypted_for_impact:additional:run-6:y | additional | 6 | payload_present | 36 | `c082cec5e2613579f390e4ff40ad200fc250a08f927af1b094c7cae30c5e64b8` |
| crosscloud:aws:data_encrypted_for_impact:additional:run-7:n | additional | 7 | payload_absent | 15 | `87dd4144fb6ff6c136da0c94b449802e728fcd527d90cedbfd379c7fd3ec468d` |
| crosscloud:aws:data_encrypted_for_impact:additional:run-7:y | additional | 7 | payload_present | 18 | `cd82f1737eda87a63734551ba067e4cfeaa25ec61f135971965088b75cd784a6` |
| crosscloud:aws:data_encrypted_for_impact:additional:run-8:n | additional | 8 | payload_absent | 30 | `93b39438b2fae278ab0e78a9ad7d83677bb25b34a31b7c21f78c8fcaa76a7d98` |
| crosscloud:aws:data_encrypted_for_impact:additional:run-8:y | additional | 8 | payload_present | 22 | `f1ac2f3a1a22bd4a5ede45cdb2190f2b52dc82ac1c83d4daaca5f6bf764fe67c` |
| crosscloud:aws:data_encrypted_for_impact:additional:run-9:n | additional | 9 | payload_absent | 16 | `2fc4d86250bf5c6c518b1335cb2cfd38455bb27b363a18dc479c9f4833c0d512` |
| crosscloud:aws:data_encrypted_for_impact:additional:run-9:y | additional | 9 | payload_present | 21 | `b9ab0ee34bd4a37632c0613219edcc7159bf89d75f8271db4d6a3a52cf10b8a1` |
| crosscloud:aws:data_encrypted_for_impact:default:run-0:n | default | 0 | payload_absent | 3 | `75c060b440c4f1eb4aa10922f2b595d060f9866b328dce077d6b4bc5270692e2` |
| crosscloud:aws:data_encrypted_for_impact:default:run-0:y | default | 0 | payload_present | 5 | `287d1c7a9334a73944642436b3af1bf93ac23add7c0ef9016c22a405a565de91` |
| crosscloud:aws:data_encrypted_for_impact:default:run-1:n | default | 1 | payload_absent | 3 | `55312cb00f44cdff7b08736f108eed04aee1117d501c72e9921257120f5115fc` |
| crosscloud:aws:data_encrypted_for_impact:default:run-1:y | default | 1 | payload_present | 5 | `c7ad01eaa39c518453f9ea84a05aa5d307e547b3f3789dd5ba3db8e30112dd4b` |
| crosscloud:aws:data_encrypted_for_impact:default:run-2:n | default | 2 | payload_absent | 2 | `90437e64e8b955c55f7fc24769263088a90b6c6013fc353b2990256a532fc06b` |
| crosscloud:aws:data_encrypted_for_impact:default:run-2:y | default | 2 | payload_present | 5 | `5bce83b25c9c3fb79ff490fc59ea4fcec809f2ef986efc5ccd92de4f91974dfe` |
| crosscloud:aws:data_encrypted_for_impact:default:run-3:n | default | 3 | payload_absent | 2 | `48d56086250c6cbb293386dcdc9af6b76ea1a32414a982cfb282ec2adf4aa10d` |
| crosscloud:aws:data_encrypted_for_impact:default:run-3:y | default | 3 | payload_present | 6 | `b1f3aa217fc49328b26e5c56c99c538a11055080e7e8da9471f304d459916669` |
| crosscloud:aws:data_encrypted_for_impact:default:run-4:n | default | 4 | payload_absent | 1 | `8cb2bb4a8474939813d52286a7c0b27219cc8ac6f6e1cea0a2d8ff39f30a1926` |
| crosscloud:aws:data_encrypted_for_impact:default:run-4:y | default | 4 | payload_present | 5 | `874feb663bfe03c3e87bc3f5544d45bf9887690a0b11523973e3f02f13f1c89e` |
| crosscloud:aws:data_encrypted_for_impact:default:run-5:n | default | 5 | payload_absent | 3 | `179e64bdcca95feaca595f88d8c3d943386ab3f7d64c9c7720bdc8a627477ff6` |
| crosscloud:aws:data_encrypted_for_impact:default:run-5:y | default | 5 | payload_present | 5 | `f2cd1a6d656dc5d0cf13130bc948b8d1ae653aea6d1198e976affa296b3c2e58` |
| crosscloud:aws:data_encrypted_for_impact:default:run-6:n | default | 6 | payload_absent | 2 | `b618bb6a4dad07764840e9ef08cc8b37ecc1063e1cd988aabd0f8542e6f68e65` |
| crosscloud:aws:data_encrypted_for_impact:default:run-6:y | default | 6 | payload_present | 4 | `d00f74540af60e91abdb5deb69919c3018e3f7cba780a06ee44eaa4584b86152` |
| crosscloud:aws:data_encrypted_for_impact:default:run-7:n | default | 7 | payload_absent | 1 | `38a6a1d0b0be8a1209e08a314b150766b6c97b3d73d6b37a930f10efdc858e0b` |
| crosscloud:aws:data_encrypted_for_impact:default:run-7:y | default | 7 | payload_present | 4 | `87be6105821d1dea533ec8c9fb7275ef9988a4162e6d7281122d2f52f6a999da` |
| crosscloud:aws:data_encrypted_for_impact:default:run-8:n | default | 8 | payload_absent | 2 | `7e497f0f26e327ba5e4dbd0ceaedbbb359fef0e3ed7bf078f5018da6f911422d` |
| crosscloud:aws:data_encrypted_for_impact:default:run-8:y | default | 8 | payload_present | 5 | `daef483f87f2593939e098ccaa00d4ab757b7177cf7699245fc771c83c526640` |
| crosscloud:aws:data_encrypted_for_impact:default:run-9:n | default | 9 | payload_absent | 2 | `3ced1f700f6bb779ea81cd7ca43bf282dbf12dfd8b4d0cb12a5153a4e39af00e` |
| crosscloud:aws:data_encrypted_for_impact:default:run-9:y | default | 9 | payload_present | 6 | `ef55cc5a5d43ea1e088bdb4bd498ed0e7dc0cfc18d7c9e35dd24807c3c97201a` |

### 原始文件完整性

- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/README.md` — SHA-256 `b073b2e97aea4073fec2bf387e2c255d987dd8f3710e84f2df3cc59947e510f8`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/attack_scripts.zip` — SHA-256 `4599be3e224f3b9b43e76ab4ec1bfa8e3b209ebe529fb218ae4e65dd22417900`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/aws_logs_redacted.zip` — SHA-256 `f75046f8660e648981040d5180950867a7e82cb8b799708ff572a927d2d35f5b`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/log_analysis.zip` — SHA-256 `23b41863cc2ece4936277a1ee1fc6f64b4fea9f3c0f698cefbf5626eeca00fcf`

## 16. `crosscloud:aws:data_manipulation`

- 描述：DOI-published paired payload/no-payload AWS telemetry for data_manipulation.
- 发布者：Dhooghe et al.
- 发布日期：2026-04-30
- 环境：controlled cloud subscription
- ATT&CK：
- 原始文件数：4
- 规范化观测数：0
- 上游 episode 数：40

### 准入判断（人工填写）

- [ ] 有外部或低权限入口
- [ ] 存在多步关系，而非单点事件
- [ ] 终点为数据库、存储、备份、secret 或其他数据资产
- [ ] 关键边均有原始证据
- [ ] 不是近重复案例
- 决定：`<accept | needs_execution | reject>`
- 理由：`<人工填写>`

### 观测索引

| observation_id | timestamp | actor_type | service | operation | status | raw record |
|---|---:|---|---|---|---|---|

### 上游配对 episode

| episode_id | profile | run | source condition | observations | member SHA-256 |
|---|---|---:|---|---:|---|
| crosscloud:aws:data_manipulation:additional:run-0:n | additional | 0 | payload_absent | 18 | `0fb5a8acf3baef54d56e1d3410ba9d24c01af4c41cb77a1142fb8a53894250c2` |
| crosscloud:aws:data_manipulation:additional:run-0:y | additional | 0 | payload_present | 25 | `785a433981fc82d2c13c2f3e556ce938dda5f4f5335518c5fca6f7e00e0474c4` |
| crosscloud:aws:data_manipulation:additional:run-1:n | additional | 1 | payload_absent | 19 | `9dde1d0c9aaa948941b09df6297f9830c9caf3e9a5152a42ac15cf3fd45aa191` |
| crosscloud:aws:data_manipulation:additional:run-1:y | additional | 1 | payload_present | 17 | `65154e758c2604fffef3b13dc29becb24725e6f984833a345562000878d3b80d` |
| crosscloud:aws:data_manipulation:additional:run-2:n | additional | 2 | payload_absent | 20 | `749fd824139a455ce14db73d0ca1cb06c0fc06058a3d6f729d2487ada5146e75` |
| crosscloud:aws:data_manipulation:additional:run-2:y | additional | 2 | payload_present | 19 | `8ca737f87c8c55866d547424aed47a330f084f4f5275c93f5d33ef23d6ee52a9` |
| crosscloud:aws:data_manipulation:additional:run-3:n | additional | 3 | payload_absent | 19 | `1f96ce4f88cc9f855f0cdb919a70fd3d0467eff3e32413f0daca224cdc766a97` |
| crosscloud:aws:data_manipulation:additional:run-3:y | additional | 3 | payload_present | 34 | `f2fbeec899ceaa25f4f2a27eefb9572e675d8560da24c1c00b55f44aed8157fa` |
| crosscloud:aws:data_manipulation:additional:run-4:n | additional | 4 | payload_absent | 19 | `e222538381b6522a48a85045de4a210f06de5d2dda30917cd70c6433ebc7fe1d` |
| crosscloud:aws:data_manipulation:additional:run-4:y | additional | 4 | payload_present | 23 | `49e3e54c144d39557fb829b581d636174f74d07776094fcbf2888bb6173b009e` |
| crosscloud:aws:data_manipulation:additional:run-5:n | additional | 5 | payload_absent | 29 | `cb2f8d9f14e4d049517c8dc35e744aaaaf812b076415967bdb03662be61899d5` |
| crosscloud:aws:data_manipulation:additional:run-5:y | additional | 5 | payload_present | 20 | `1d9942355e9410cd1b116d7e9a9178b60b816db4360de6846e2caf724b80b69c` |
| crosscloud:aws:data_manipulation:additional:run-6:n | additional | 6 | payload_absent | 18 | `241f2e50f4460185e610c095e4d1712c7ab7740717489c31f30b96313c555326` |
| crosscloud:aws:data_manipulation:additional:run-6:y | additional | 6 | payload_present | 18 | `206083025469941e7cb36937fb7a848be644ad776f56f767f55912ca8bf4fa96` |
| crosscloud:aws:data_manipulation:additional:run-7:n | additional | 7 | payload_absent | 16 | `e17e9b7b2c5d265b469e076a73e3ad7435fd79a9b0e8655311039b1fb9562b59` |
| crosscloud:aws:data_manipulation:additional:run-7:y | additional | 7 | payload_present | 11 | `b2de0a0e244f414a90f0ad6f92e943dccd6138be43f37707d5a891d39f2f5e61` |
| crosscloud:aws:data_manipulation:additional:run-8:n | additional | 8 | payload_absent | 15 | `cf05af98b8fe1f30c4734786b2b4d39d454fde3f5879ae4b31f737ad87ce8b9f` |
| crosscloud:aws:data_manipulation:additional:run-8:y | additional | 8 | payload_present | 30 | `e3a69ebce952d8385741289d8466015fe0315e8c2ab158dadb194ae2759afc53` |
| crosscloud:aws:data_manipulation:additional:run-9:n | additional | 9 | payload_absent | 12 | `3c64dc91d58887ca0b76a84071c678525dad87cf45b2af5a75e02c72e057176a` |
| crosscloud:aws:data_manipulation:additional:run-9:y | additional | 9 | payload_present | 18 | `326dce716d391eec3bce0cc83c97edaddbad85d321cca9cbc7f79dabc9b19c78` |
| crosscloud:aws:data_manipulation:default:run-0:n | default | 0 | payload_absent | 6 | `81864e3e7d454ddd1d2fd2da47222b102af11ba7c0918426a5df446bd6eba429` |
| crosscloud:aws:data_manipulation:default:run-0:y | default | 0 | payload_present | 6 | `742245de9ce8e27e6761eebbb582cb8f19b1afa571256a0598c591f46bff11a7` |
| crosscloud:aws:data_manipulation:default:run-1:n | default | 1 | payload_absent | 5 | `c00dc79cd9fc4310ceba5d611c4c00eb32599d22f82aabd7aba70f1a6025cda4` |
| crosscloud:aws:data_manipulation:default:run-1:y | default | 1 | payload_present | 4 | `2f63e780f624d4dd1d515a8b589386fc1a1d75ef618482a8897ed2a20a2b694d` |
| crosscloud:aws:data_manipulation:default:run-2:n | default | 2 | payload_absent | 7 | `6e8ab39977a8da5f86030536915be6a5976d3c30bcc0f8fd37acbb028aa5cb88` |
| crosscloud:aws:data_manipulation:default:run-2:y | default | 2 | payload_present | 7 | `2843ce215a940920f896e35536e068fa374effd5ddb2ab5ab24462e8f7658ac8` |
| crosscloud:aws:data_manipulation:default:run-3:n | default | 3 | payload_absent | 7 | `cb2a7c7ce16c58cbc087d2499bed7a54dc1fe0d506935eb7652aea48b301cb7c` |
| crosscloud:aws:data_manipulation:default:run-3:y | default | 3 | payload_present | 5 | `a1c8f0e058b50e4ce9be3cd4390691a7b05e0b7817caca9f017ce577b440d244` |
| crosscloud:aws:data_manipulation:default:run-4:n | default | 4 | payload_absent | 6 | `5e30b54c67a527d688d36058df5231db91cf25accdf7877e8a511e111c79a9af` |
| crosscloud:aws:data_manipulation:default:run-4:y | default | 4 | payload_present | 7 | `a450031b7ef35f73f97e56b0d8df1db73349758ce693939d49e3fba5db30a7b0` |
| crosscloud:aws:data_manipulation:default:run-5:n | default | 5 | payload_absent | 3 | `146e9454cc292a6b5e7d02364870ebeabaf72a50092509dd18e1f39dc42cdab7` |
| crosscloud:aws:data_manipulation:default:run-5:y | default | 5 | payload_present | 4 | `57b0cb9bb7735ea584b474d122200db6e44c7237454cc2139e6c914ab1bd0328` |
| crosscloud:aws:data_manipulation:default:run-6:n | default | 6 | payload_absent | 6 | `6e29c1f0ba96011786c168f07bd06fc8f586489617a719551fddc8dd29a8f021` |
| crosscloud:aws:data_manipulation:default:run-6:y | default | 6 | payload_present | 5 | `9f0be42c387d0142af53ab1db2b3c62268112b09e4891c2a71e45cd7e2abb31a` |
| crosscloud:aws:data_manipulation:default:run-7:n | default | 7 | payload_absent | 7 | `b7aa1430729b60b7919b973347d43a108d6f6b7ad025def633214caa8bceea9b` |
| crosscloud:aws:data_manipulation:default:run-7:y | default | 7 | payload_present | 6 | `f3d85f5b20944e4691bea3b154ea0c500ada2d51de550f91709f8a918734ffee` |
| crosscloud:aws:data_manipulation:default:run-8:n | default | 8 | payload_absent | 6 | `214b5f71c6374e6de42a23b044bc091be1cb27f674c65e0c031d001a5c73d98a` |
| crosscloud:aws:data_manipulation:default:run-8:y | default | 8 | payload_present | 7 | `fbae614b7a78b2e0b18be675678c2aa7a28a04119e37eec96ad520e0e53701f9` |
| crosscloud:aws:data_manipulation:default:run-9:n | default | 9 | payload_absent | 6 | `44f0854286b5dcb66e738baaf731a3ed52e748a2ee8c6085425844a1a2fc7701` |
| crosscloud:aws:data_manipulation:default:run-9:y | default | 9 | payload_present | 5 | `01a41811edd520c5fc878601ca7e3eb6f3b7d3b589131393ce7a2d222f22710c` |

### 原始文件完整性

- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/README.md` — SHA-256 `b073b2e97aea4073fec2bf387e2c255d987dd8f3710e84f2df3cc59947e510f8`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/attack_scripts.zip` — SHA-256 `4599be3e224f3b9b43e76ab4ec1bfa8e3b209ebe529fb218ae4e65dd22417900`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/aws_logs_redacted.zip` — SHA-256 `f75046f8660e648981040d5180950867a7e82cb8b799708ff572a927d2d35f5b`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/log_analysis.zip` — SHA-256 `23b41863cc2ece4936277a1ee1fc6f64b4fea9f3c0f698cefbf5626eeca00fcf`

## 17. `crosscloud:aws:data_staged`

- 描述：DOI-published paired payload/no-payload AWS telemetry for data_staged.
- 发布者：Dhooghe et al.
- 发布日期：2026-04-30
- 环境：controlled cloud subscription
- ATT&CK：
- 原始文件数：4
- 规范化观测数：0
- 上游 episode 数：40

### 准入判断（人工填写）

- [ ] 有外部或低权限入口
- [ ] 存在多步关系，而非单点事件
- [ ] 终点为数据库、存储、备份、secret 或其他数据资产
- [ ] 关键边均有原始证据
- [ ] 不是近重复案例
- 决定：`<accept | needs_execution | reject>`
- 理由：`<人工填写>`

### 观测索引

| observation_id | timestamp | actor_type | service | operation | status | raw record |
|---|---:|---|---|---|---|---|

### 上游配对 episode

| episode_id | profile | run | source condition | observations | member SHA-256 |
|---|---|---:|---|---:|---|
| crosscloud:aws:data_staged:additional:run-0:n | additional | 0 | payload_absent | 18 | `0f5cfa0d6de7385ae4fb6b56fa32a293ce28ffd2247bb84eae30e5c58f7ec80f` |
| crosscloud:aws:data_staged:additional:run-0:y | additional | 0 | payload_present | 15 | `ac70fa72f3ef1fb5e8c05dace9f5b90294170174c0c1daeb8d0cf6c28b29f153` |
| crosscloud:aws:data_staged:additional:run-1:n | additional | 1 | payload_absent | 35 | `30b84a4e6973f7b21ff965bdc753004faba6b4026d5d497a100efe88b98e34bc` |
| crosscloud:aws:data_staged:additional:run-1:y | additional | 1 | payload_present | 21 | `2885976526053725f3acdf1b9210e71f5a9ff1b5201c7b8736fda5f902842016` |
| crosscloud:aws:data_staged:additional:run-2:n | additional | 2 | payload_absent | 19 | `e481bbfe1b7588387a83bf0b4d4961494fc20e762e369074d353fc1c7c9dcdcd` |
| crosscloud:aws:data_staged:additional:run-2:y | additional | 2 | payload_present | 21 | `29e64f82c875c7168a12a2e0940bb9170e7dd2730d7f1901410a89fad3aed79b` |
| crosscloud:aws:data_staged:additional:run-3:n | additional | 3 | payload_absent | 21 | `9637e74221ef7322827fc07ac79f3c25eee3d5ae846cdb2cc6184ce81e093cfe` |
| crosscloud:aws:data_staged:additional:run-3:y | additional | 3 | payload_present | 27 | `b294d1aa6b0e772b90234f219f4c0f2661c25b8360b44a92ea5d22604b24759b` |
| crosscloud:aws:data_staged:additional:run-4:n | additional | 4 | payload_absent | 26 | `4ca75e6e9f6638502860998bd24553ec6822cf980f7be13f8a42f2fd55be6399` |
| crosscloud:aws:data_staged:additional:run-4:y | additional | 4 | payload_present | 24 | `8d418f58e76ee6c51689172a69218e652bd4be986a05ae1335111d1f4bc2d08d` |
| crosscloud:aws:data_staged:additional:run-5:n | additional | 5 | payload_absent | 25 | `b91a7c98af110e7050db38f2f4ad8709fb915ca2f38b304b50d9e687531af056` |
| crosscloud:aws:data_staged:additional:run-5:y | additional | 5 | payload_present | 19 | `fff9f435b45dbce526b457b8bf65a07623494465eaff9d9aa0d7ea691a7091d4` |
| crosscloud:aws:data_staged:additional:run-6:n | additional | 6 | payload_absent | 18 | `59159728b90ff31f9239d13cf9e5783924f7ca5292b4d0ab18c930cf40eceb47` |
| crosscloud:aws:data_staged:additional:run-6:y | additional | 6 | payload_present | 22 | `68b0d2922fa26aefde954ab36562d53e787580feef584a498eac749a89928db2` |
| crosscloud:aws:data_staged:additional:run-7:n | additional | 7 | payload_absent | 20 | `e5b21c91a72db9af2f742b003adec9f0f819809cc0f8922307e2a892060dc1f0` |
| crosscloud:aws:data_staged:additional:run-7:y | additional | 7 | payload_present | 34 | `9d9a0a0d3dafaa54d07f2785b095cbeec37e6d0cde839ac2360ef46edd358c0a` |
| crosscloud:aws:data_staged:additional:run-8:n | additional | 8 | payload_absent | 24 | `67801b23e2597757b5deb1f6dcecc6a5ae3ee8a1ff3bacdb16f363cde35e8a90` |
| crosscloud:aws:data_staged:additional:run-8:y | additional | 8 | payload_present | 22 | `b22e78ddd1326d76568333b945de43a214f90633e41d256554b512911eb1ea2f` |
| crosscloud:aws:data_staged:additional:run-9:n | additional | 9 | payload_absent | 33 | `2129f6ece415a04baec8bcd49125d35be3c4dc007910c152625d490744f11832` |
| crosscloud:aws:data_staged:additional:run-9:y | additional | 9 | payload_present | 21 | `fd06abf7ac94f284c0b4557c27d78052e58a03b0a6847c8de4cc22922e2ae4cd` |
| crosscloud:aws:data_staged:default:run-0:n | default | 0 | payload_absent | 6 | `5d278cef31a13e2c684eaa0c5c7fe59c19b9fc3eb2a15ad71b63c9cfe33b5f8e` |
| crosscloud:aws:data_staged:default:run-0:y | default | 0 | payload_present | 5 | `51285ed2458c9fbe1843c901bbacaf6b4e8663315f58e950752f190475fd283c` |
| crosscloud:aws:data_staged:default:run-1:n | default | 1 | payload_absent | 6 | `5c1be6e19d1c907cea331fd0510216c6d155263d804cef9050b215f07c7b1256` |
| crosscloud:aws:data_staged:default:run-1:y | default | 1 | payload_present | 5 | `80c35b36b3cd744ec5c03b6eb1ab79efd7557280040c964584b4b4d5d92a40da` |
| crosscloud:aws:data_staged:default:run-2:n | default | 2 | payload_absent | 6 | `7b7986a58eeb13404ba950ad6714931a6925a8ca280ce7aa3db516978f10c168` |
| crosscloud:aws:data_staged:default:run-2:y | default | 2 | payload_present | 6 | `d1c71590982f0883d14301bec7a75b4410d0983fa04aca10cbb3c44178eecb46` |
| crosscloud:aws:data_staged:default:run-3:n | default | 3 | payload_absent | 7 | `aa3d4f44250380a338f1a3607b2e3a3bc77eded927f924f53ba4c8955ce23b01` |
| crosscloud:aws:data_staged:default:run-3:y | default | 3 | payload_present | 5 | `14b0b7154dca2a69115f62cc869b519b9784c01527ce81c9370e79a7c2f71e5e` |
| crosscloud:aws:data_staged:default:run-4:n | default | 4 | payload_absent | 5 | `271db0688fa054c1b52224add814b4aa19d7e82a8e9e88d1657511a5cf0c587d` |
| crosscloud:aws:data_staged:default:run-4:y | default | 4 | payload_present | 5 | `a85efd855a7b75490e9fcc462c3e410b46be528b170fd40833500d4ac3de3dfb` |
| crosscloud:aws:data_staged:default:run-5:n | default | 5 | payload_absent | 5 | `9898d0a3f43e8a86ba14c7870ce1248a66a69c514a384511fbadccd641ef6128` |
| crosscloud:aws:data_staged:default:run-5:y | default | 5 | payload_present | 4 | `989449428a75baf566f724ec414bb8f15805b46e45d06dcdb2e2b9c1c339bd72` |
| crosscloud:aws:data_staged:default:run-6:n | default | 6 | payload_absent | 6 | `3b97c3861460e4e676a25959158ae00f7bb01b28595d550708062de727f5f91f` |
| crosscloud:aws:data_staged:default:run-6:y | default | 6 | payload_present | 4 | `1430273d245fb358ac754dcd6a26b73ed08bf3795d1d3f7a338f3d08dc8494ad` |
| crosscloud:aws:data_staged:default:run-7:n | default | 7 | payload_absent | 7 | `6095a71ca13fe726055fa6ba937a5d2585bee258e9f88cc7f481ee53795dd49f` |
| crosscloud:aws:data_staged:default:run-7:y | default | 7 | payload_present | 6 | `f0164f3bfae93f9205aea3bfe2916cdaa71cd3400bd7fd4c0636faa45d8899de` |
| crosscloud:aws:data_staged:default:run-8:n | default | 8 | payload_absent | 5 | `70d834986275d871fb8b51d2ff222cfcad919ce61dd9ca11ed1adccd43695d20` |
| crosscloud:aws:data_staged:default:run-8:y | default | 8 | payload_present | 6 | `90be00090f177871d5a8ce2caae9a7ae301e4697608217403b3d31785f75403d` |
| crosscloud:aws:data_staged:default:run-9:n | default | 9 | payload_absent | 7 | `6529809d64e8f5ab3a406c94f482fb99e0eb71a9c821f9cf90c375cf6851a93c` |
| crosscloud:aws:data_staged:default:run-9:y | default | 9 | payload_present | 5 | `971b688e2195f8fbe1ee7f965de48a961ca5a0313670998b49f707cbf75f2425` |

### 原始文件完整性

- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/README.md` — SHA-256 `b073b2e97aea4073fec2bf387e2c255d987dd8f3710e84f2df3cc59947e510f8`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/attack_scripts.zip` — SHA-256 `4599be3e224f3b9b43e76ab4ec1bfa8e3b209ebe529fb218ae4e65dd22417900`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/aws_logs_redacted.zip` — SHA-256 `f75046f8660e648981040d5180950867a7e82cb8b799708ff572a927d2d35f5b`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/log_analysis.zip` — SHA-256 `23b41863cc2ece4936277a1ee1fc6f64b4fea9f3c0f698cefbf5626eeca00fcf`

## 18. `crosscloud:aws:inhibit_system_recovery`

- 描述：DOI-published paired payload/no-payload AWS telemetry for inhibit_system_recovery.
- 发布者：Dhooghe et al.
- 发布日期：2026-04-30
- 环境：controlled cloud subscription
- ATT&CK：
- 原始文件数：4
- 规范化观测数：0
- 上游 episode 数：40

### 准入判断（人工填写）

- [ ] 有外部或低权限入口
- [ ] 存在多步关系，而非单点事件
- [ ] 终点为数据库、存储、备份、secret 或其他数据资产
- [ ] 关键边均有原始证据
- [ ] 不是近重复案例
- 决定：`<accept | needs_execution | reject>`
- 理由：`<人工填写>`

### 观测索引

| observation_id | timestamp | actor_type | service | operation | status | raw record |
|---|---:|---|---|---|---|---|

### 上游配对 episode

| episode_id | profile | run | source condition | observations | member SHA-256 |
|---|---|---:|---|---:|---|
| crosscloud:aws:inhibit_system_recovery:additional:run-0:n | additional | 0 | payload_absent | 27 | `c128134b46be46a4503b1cafc73d5b565f97a0263fdf60efdf66ef5eed2d9677` |
| crosscloud:aws:inhibit_system_recovery:additional:run-0:y | additional | 0 | payload_present | 18 | `fcaf5df6b3ca67eca71de1baa3bbe10e2386f5b1123f6e95c58d81cbd5865b94` |
| crosscloud:aws:inhibit_system_recovery:additional:run-1:n | additional | 1 | payload_absent | 11 | `78788e2bee9a320b02f11dffa2ae1b3ce4efb3a51915b3f9085e9d0a9d1d46e3` |
| crosscloud:aws:inhibit_system_recovery:additional:run-1:y | additional | 1 | payload_present | 16 | `5627769be636751773346fcf9733dc434d4c65b27fb8c1732eb7089bce48beee` |
| crosscloud:aws:inhibit_system_recovery:additional:run-2:n | additional | 2 | payload_absent | 20 | `047c457fabf17353a0da2c64a47452734a5beeea7f51b78ab39d333756fb3d0d` |
| crosscloud:aws:inhibit_system_recovery:additional:run-2:y | additional | 2 | payload_present | 19 | `b630b76c2f103b232a8600a3be064b2cbfe734e273f17cde662483eaf39754c4` |
| crosscloud:aws:inhibit_system_recovery:additional:run-3:n | additional | 3 | payload_absent | 18 | `7e3eff2281dd4c63619d2eeaaa8fb9f840f29d121608681e7118d8800102ac5d` |
| crosscloud:aws:inhibit_system_recovery:additional:run-3:y | additional | 3 | payload_present | 29 | `29f6f56557d911f4c9a1f91d6db3d087077e3b8b998f8401ff042b8610d5e5d3` |
| crosscloud:aws:inhibit_system_recovery:additional:run-4:n | additional | 4 | payload_absent | 53 | `5618d82a8a6573df65fffd351a646838f7c95cba3739f4cb2c3f4dd404648525` |
| crosscloud:aws:inhibit_system_recovery:additional:run-4:y | additional | 4 | payload_present | 19 | `3667229587a30c843e50af5997a3496b472b4b6d35e411712823f85509626553` |
| crosscloud:aws:inhibit_system_recovery:additional:run-5:n | additional | 5 | payload_absent | 21 | `9dd0e75859049478031fca00d963be8b59d71a34503ecaba31df894dbb02a238` |
| crosscloud:aws:inhibit_system_recovery:additional:run-5:y | additional | 5 | payload_present | 16 | `4548fb9a53e7039e20f9204378b5307e165b69017c1adb1f9097b105776e3265` |
| crosscloud:aws:inhibit_system_recovery:additional:run-6:n | additional | 6 | payload_absent | 16 | `8c4342dad4eb07c8e7cd271a89edc7317806b9a9a079e4508f8ed9c5733c6679` |
| crosscloud:aws:inhibit_system_recovery:additional:run-6:y | additional | 6 | payload_present | 26 | `85084d5cfbad61c03453719b4c05f539300c2a72e13717774dbe20766597c1ab` |
| crosscloud:aws:inhibit_system_recovery:additional:run-7:n | additional | 7 | payload_absent | 14 | `079b37d3829b53e48bd0fb76fd74cc9c52cc2a860aa65ab794b3290e72f36878` |
| crosscloud:aws:inhibit_system_recovery:additional:run-7:y | additional | 7 | payload_present | 15 | `efc7acadbb1f5227d046e3719c98fdbc55842fe20ce20e00c0d3a808d6fce68d` |
| crosscloud:aws:inhibit_system_recovery:additional:run-8:n | additional | 8 | payload_absent | 13 | `20c34dfda59e1ea80f53544a2c2d1b4546ffd80b78c1fbd4811c43164a445815` |
| crosscloud:aws:inhibit_system_recovery:additional:run-8:y | additional | 8 | payload_present | 20 | `3c2dd6fd139e2787d79551eb23020cd0f9208f54902513ae032c357312648806` |
| crosscloud:aws:inhibit_system_recovery:additional:run-9:n | additional | 9 | payload_absent | 12 | `c08a3605ba10629a93007150fb6d913e853c742d28912a3b3214e5939d1ddf70` |
| crosscloud:aws:inhibit_system_recovery:additional:run-9:y | additional | 9 | payload_present | 28 | `baf2767fc429507059200953f88fe3d6f3cd3fc17bd7a68c16179e8276dc794d` |
| crosscloud:aws:inhibit_system_recovery:default:run-0:n | default | 0 | payload_absent | 28 | `48ba4624337b3ecfedde8289f82f3067b744598b15f7f069f580f47d029cff36` |
| crosscloud:aws:inhibit_system_recovery:default:run-0:y | default | 0 | payload_present | 35 | `0667605f032329789dd11f8d7866d646884d88348bd596b6ac26c1475992b148` |
| crosscloud:aws:inhibit_system_recovery:default:run-1:n | default | 1 | payload_absent | 38 | `786e69c084ab868e558a20d80d9643e0893148a6f7304ec397acd63a6e637cb2` |
| crosscloud:aws:inhibit_system_recovery:default:run-1:y | default | 1 | payload_present | 34 | `61f5be954a39af8531f34457eb75ecd9dd8ce180d0ca7c9cfb1e9f85333d9a80` |
| crosscloud:aws:inhibit_system_recovery:default:run-2:n | default | 2 | payload_absent | 22 | `52db9832a323e31abddab2f43c860b2c942330de8bcdb3fe3513f35125e65574` |
| crosscloud:aws:inhibit_system_recovery:default:run-2:y | default | 2 | payload_present | 34 | `e7db06afdd2db1a2a20443ee0a04700c77c25a6940d76cad997e67e593e26ab4` |
| crosscloud:aws:inhibit_system_recovery:default:run-3:n | default | 3 | payload_absent | 27 | `91579d83833ea93772ce295a76045ea41fd6a1c1f88a7c3743e832132f0c62cb` |
| crosscloud:aws:inhibit_system_recovery:default:run-3:y | default | 3 | payload_present | 28 | `c2ffd37fc283a8c9c9844ba75dec7c0f8ba676c30931275637aa8dc938859a6b` |
| crosscloud:aws:inhibit_system_recovery:default:run-4:n | default | 4 | payload_absent | 44 | `96cb4af2bcbdd6b70930746be2a08dd8e42e5ec6904e96fda092a3efdb361701` |
| crosscloud:aws:inhibit_system_recovery:default:run-4:y | default | 4 | payload_present | 34 | `3fa20eedbf6739ac425f97ac4af8122b739a363b36191c8e1ba471bfa5e6f949` |
| crosscloud:aws:inhibit_system_recovery:default:run-5:n | default | 5 | payload_absent | 28 | `7823289c0767f21b2cbb37ed1f6087484a38095cfbfabc0e7c8a840e0fc6244a` |
| crosscloud:aws:inhibit_system_recovery:default:run-5:y | default | 5 | payload_present | 27 | `04e9e07647652151f3d65af99354534d5d83426fe752993c1c21839dbf3ee95b` |
| crosscloud:aws:inhibit_system_recovery:default:run-6:n | default | 6 | payload_absent | 19 | `ce6bef9fe142f51f3b95ea5495c6cc5287c8e621fd1cf94671bc00c6a2d3ba15` |
| crosscloud:aws:inhibit_system_recovery:default:run-6:y | default | 6 | payload_present | 23 | `7fe46ea80e7fad1fc7d5ef10c5d7d8867db5a530d37d94331357a84f176e4f3b` |
| crosscloud:aws:inhibit_system_recovery:default:run-7:n | default | 7 | payload_absent | 39 | `87d6e022ac3c1fedafebcffa3d82b6827badbdd4488061c07d54492b2af17516` |
| crosscloud:aws:inhibit_system_recovery:default:run-7:y | default | 7 | payload_present | 28 | `2180d8aeceed50b066cbd2d34acc266c7e2482518dacb222a4b030bd820fd870` |
| crosscloud:aws:inhibit_system_recovery:default:run-8:n | default | 8 | payload_absent | 25 | `890d9f81f10aa06479f7bfad51ab92e69332f7823740189458fe813d9c279005` |
| crosscloud:aws:inhibit_system_recovery:default:run-8:y | default | 8 | payload_present | 19 | `7994865fa36ed5015d1143d0e6eb30f7196b1f92709941657d0859890bb8868c` |
| crosscloud:aws:inhibit_system_recovery:default:run-9:n | default | 9 | payload_absent | 20 | `e3e65f852abb433f2d5c77b41aedb21745ab52d57c0dd1c9f7f19968787db210` |
| crosscloud:aws:inhibit_system_recovery:default:run-9:y | default | 9 | payload_present | 24 | `4cd488dcc64623b397c2adddac312b82f0a1ad310575fcc44df63e3212d14b7e` |

### 原始文件完整性

- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/README.md` — SHA-256 `b073b2e97aea4073fec2bf387e2c255d987dd8f3710e84f2df3cc59947e510f8`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/attack_scripts.zip` — SHA-256 `4599be3e224f3b9b43e76ab4ec1bfa8e3b209ebe529fb218ae4e65dd22417900`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/aws_logs_redacted.zip` — SHA-256 `f75046f8660e648981040d5180950867a7e82cb8b799708ff572a927d2d35f5b`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/log_analysis.zip` — SHA-256 `23b41863cc2ece4936277a1ee1fc6f64b4fea9f3c0f698cefbf5626eeca00fcf`

## 19. `crosscloud:aws:scheduled_transfer`

- 描述：DOI-published paired payload/no-payload AWS telemetry for scheduled_transfer.
- 发布者：Dhooghe et al.
- 发布日期：2026-04-30
- 环境：controlled cloud subscription
- ATT&CK：
- 原始文件数：4
- 规范化观测数：0
- 上游 episode 数：30

### 准入判断（人工填写）

- [ ] 有外部或低权限入口
- [ ] 存在多步关系，而非单点事件
- [ ] 终点为数据库、存储、备份、secret 或其他数据资产
- [ ] 关键边均有原始证据
- [ ] 不是近重复案例
- 决定：`<accept | needs_execution | reject>`
- 理由：`<人工填写>`

### 观测索引

| observation_id | timestamp | actor_type | service | operation | status | raw record |
|---|---:|---|---|---|---|---|

### 上游配对 episode

| episode_id | profile | run | source condition | observations | member SHA-256 |
|---|---|---:|---|---:|---|
| crosscloud:aws:scheduled_transfer:additional:run-2:n | additional | 2 | payload_absent | 117 | `039469b5d5c6189653d4e1834f17b50715b66b862ddca8637ae8807f9734b456` |
| crosscloud:aws:scheduled_transfer:additional:run-2:y | additional | 2 | payload_present | 81 | `b52164149a98966d392af306a79a60bfb16fd3930244c38f61f354394d847956` |
| crosscloud:aws:scheduled_transfer:additional:run-4:n | additional | 4 | payload_absent | 125 | `b7d1c2e594b4352aa3b7d29fc59550297db957a5b5261e05fc9ac8478c9ee04c` |
| crosscloud:aws:scheduled_transfer:additional:run-4:y | additional | 4 | payload_present | 106 | `14f7585db838f955009d3981c316d50834c8d6bd03fc2134a8637954292b921c` |
| crosscloud:aws:scheduled_transfer:additional:run-5:n | additional | 5 | payload_absent | 78 | `c0a3d6217ec390838bca700b6ae2fb62583d3b55a5f857dbe5f7ef8063cf6a0f` |
| crosscloud:aws:scheduled_transfer:additional:run-5:y | additional | 5 | payload_present | 158 | `a0c5a1d7c6f0c32d4b02565b1572436ee2dc41bbe594e35aa33e1bcd3aeacf99` |
| crosscloud:aws:scheduled_transfer:additional:run-6:n | additional | 6 | payload_absent | 71 | `b95b392dce34c2dd3455008444bd7227737f908eef75a102679606854484526d` |
| crosscloud:aws:scheduled_transfer:additional:run-6:y | additional | 6 | payload_present | 56 | `f31afe37bf439f68cb20c3455214d9230950d4569a27fb3e7436cff3b83b1de9` |
| crosscloud:aws:scheduled_transfer:additional:run-7:n | additional | 7 | payload_absent | 84 | `47b450bf797ee656908089020a5d8f33a9f82899031cc3081967b25d14216829` |
| crosscloud:aws:scheduled_transfer:additional:run-7:y | additional | 7 | payload_present | 95 | `49c39ac230b1e675e135d32272fe4e4006e6d986aba6a8a6c612750e79d7ab6a` |
| crosscloud:aws:scheduled_transfer:additional:run-8:n | additional | 8 | payload_absent | 150 | `0711b96fdc7f4ccec10f2299e71919dec43306857d5584ec8d94aa5c45370bfe` |
| crosscloud:aws:scheduled_transfer:additional:run-8:y | additional | 8 | payload_present | 85 | `d318c1d0973d13c4f30ff4c45bd8dadf64995684177eefd44f0736306270a263` |
| crosscloud:aws:scheduled_transfer:default:run-0:n | default | 0 | payload_absent | 117 | `24fe5a8d33835ef76ac7bd1079ec4636e32748bef6c2d7d3f249af24fc44916e` |
| crosscloud:aws:scheduled_transfer:default:run-0:y | default | 0 | payload_present | 63 | `7e796db3a77d251b6b39edf30c04daadb605dade1b31cc8f817770ecda65b829` |
| crosscloud:aws:scheduled_transfer:default:run-1:n | default | 1 | payload_absent | 138 | `5be541feee3ee88ad353ca8e61be577eb319095a77dba5784fb75e506103e0a9` |
| crosscloud:aws:scheduled_transfer:default:run-1:y | default | 1 | payload_present | 72 | `5df2510fb7ed057fed3dc9ae02f947de76d9214511745c6513e362825a408b5e` |
| crosscloud:aws:scheduled_transfer:default:run-2:n | default | 2 | payload_absent | 117 | `039469b5d5c6189653d4e1834f17b50715b66b862ddca8637ae8807f9734b456` |
| crosscloud:aws:scheduled_transfer:default:run-2:y | default | 2 | payload_present | 81 | `b52164149a98966d392af306a79a60bfb16fd3930244c38f61f354394d847956` |
| crosscloud:aws:scheduled_transfer:default:run-4:n | default | 4 | payload_absent | 125 | `b7d1c2e594b4352aa3b7d29fc59550297db957a5b5261e05fc9ac8478c9ee04c` |
| crosscloud:aws:scheduled_transfer:default:run-4:y | default | 4 | payload_present | 106 | `14f7585db838f955009d3981c316d50834c8d6bd03fc2134a8637954292b921c` |
| crosscloud:aws:scheduled_transfer:default:run-5:n | default | 5 | payload_absent | 78 | `c0a3d6217ec390838bca700b6ae2fb62583d3b55a5f857dbe5f7ef8063cf6a0f` |
| crosscloud:aws:scheduled_transfer:default:run-5:y | default | 5 | payload_present | 158 | `a0c5a1d7c6f0c32d4b02565b1572436ee2dc41bbe594e35aa33e1bcd3aeacf99` |
| crosscloud:aws:scheduled_transfer:default:run-6:n | default | 6 | payload_absent | 71 | `b95b392dce34c2dd3455008444bd7227737f908eef75a102679606854484526d` |
| crosscloud:aws:scheduled_transfer:default:run-6:y | default | 6 | payload_present | 56 | `f31afe37bf439f68cb20c3455214d9230950d4569a27fb3e7436cff3b83b1de9` |
| crosscloud:aws:scheduled_transfer:default:run-7:n | default | 7 | payload_absent | 84 | `47b450bf797ee656908089020a5d8f33a9f82899031cc3081967b25d14216829` |
| crosscloud:aws:scheduled_transfer:default:run-7:y | default | 7 | payload_present | 95 | `49c39ac230b1e675e135d32272fe4e4006e6d986aba6a8a6c612750e79d7ab6a` |
| crosscloud:aws:scheduled_transfer:default:run-8:n | default | 8 | payload_absent | 150 | `0711b96fdc7f4ccec10f2299e71919dec43306857d5584ec8d94aa5c45370bfe` |
| crosscloud:aws:scheduled_transfer:default:run-8:y | default | 8 | payload_present | 85 | `d318c1d0973d13c4f30ff4c45bd8dadf64995684177eefd44f0736306270a263` |
| crosscloud:aws:scheduled_transfer:default:run-9:n | default | 9 | payload_absent | 77 | `5f103569e8749363f901b25823e9654b2c805976f98d26f1492cc6b6a6d8bb67` |
| crosscloud:aws:scheduled_transfer:default:run-9:y | default | 9 | payload_present | 61 | `3ba3b5d16e90044ff9f2496ba9cd0a0ddb82ee5b5ec860060e81a012d9e8cd18` |

### 原始文件完整性

- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/README.md` — SHA-256 `b073b2e97aea4073fec2bf387e2c255d987dd8f3710e84f2df3cc59947e510f8`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/attack_scripts.zip` — SHA-256 `4599be3e224f3b9b43e76ab4ec1bfa8e3b209ebe529fb218ae4e65dd22417900`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/aws_logs_redacted.zip` — SHA-256 `f75046f8660e648981040d5180950867a7e82cb8b799708ff572a927d2d35f5b`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/log_analysis.zip` — SHA-256 `23b41863cc2ece4936277a1ee1fc6f64b4fea9f3c0f698cefbf5626eeca00fcf`

## 20. `crosscloud:aws:steal_application_access_token`

- 描述：DOI-published paired payload/no-payload AWS telemetry for steal_application_access_token.
- 发布者：Dhooghe et al.
- 发布日期：2026-04-30
- 环境：controlled cloud subscription
- ATT&CK：
- 原始文件数：4
- 规范化观测数：0
- 上游 episode 数：40

### 准入判断（人工填写）

- [ ] 有外部或低权限入口
- [ ] 存在多步关系，而非单点事件
- [ ] 终点为数据库、存储、备份、secret 或其他数据资产
- [ ] 关键边均有原始证据
- [ ] 不是近重复案例
- 决定：`<accept | needs_execution | reject>`
- 理由：`<人工填写>`

### 观测索引

| observation_id | timestamp | actor_type | service | operation | status | raw record |
|---|---:|---|---|---|---|---|

### 上游配对 episode

| episode_id | profile | run | source condition | observations | member SHA-256 |
|---|---|---:|---|---:|---|
| crosscloud:aws:steal_application_access_token:additional:run-0:n | additional | 0 | payload_absent | 17 | `96f7a59053f25edbeedef3c0fb0bf4a0a512a1dda240e19178c1bc4cec7f0d5e` |
| crosscloud:aws:steal_application_access_token:additional:run-0:y | additional | 0 | payload_present | 28 | `09f3789998345de934a36a724c0becf21c9d151ffd57ca7bf04fc04ef1890731` |
| crosscloud:aws:steal_application_access_token:additional:run-1:n | additional | 1 | payload_absent | 13 | `3330eae7812480534c41350aacbed8adb8980d4513fd9616f65052882c0f78f0` |
| crosscloud:aws:steal_application_access_token:additional:run-1:y | additional | 1 | payload_present | 24 | `55a6ef09f20c249364290abf7f6d0700d7516f90ea479a65a961740130f34f3f` |
| crosscloud:aws:steal_application_access_token:additional:run-2:n | additional | 2 | payload_absent | 11 | `338c62bc3b639064e940a99089c617cc77b2f29e2af53a829c05ebb3d6528edc` |
| crosscloud:aws:steal_application_access_token:additional:run-2:y | additional | 2 | payload_present | 21 | `0bf0bea1a170f8e404db46c21079143bf9ab6346656eaa1462140f51d43b70af` |
| crosscloud:aws:steal_application_access_token:additional:run-3:n | additional | 3 | payload_absent | 18 | `1da46a2d786e5bfd863c0e17e1f48cb5893a802742a425854374dcf2429ba7a1` |
| crosscloud:aws:steal_application_access_token:additional:run-3:y | additional | 3 | payload_present | 22 | `46ecdb7b79b1d99c6a103b87c5dcce3430220b389f0b25f89626d59bfa856d4f` |
| crosscloud:aws:steal_application_access_token:additional:run-4:n | additional | 4 | payload_absent | 14 | `88bb4521d0be7f35ee6d621e6be159f8bc27bf65c2a2fb3b6e8f9a651d4e95da` |
| crosscloud:aws:steal_application_access_token:additional:run-4:y | additional | 4 | payload_present | 21 | `95f8af88d927214bf55137225e68761ac3d7e3143686cd3ffa0eddc76f81f525` |
| crosscloud:aws:steal_application_access_token:additional:run-5:n | additional | 5 | payload_absent | 12 | `c8d79cbb10b0838e37c4dc21828903c80907aef339f180da636284998bea0cda` |
| crosscloud:aws:steal_application_access_token:additional:run-5:y | additional | 5 | payload_present | 23 | `5b27b5e0574de0edb333066561452ab6d95f571441d81efcce19d46cbebdd298` |
| crosscloud:aws:steal_application_access_token:additional:run-6:n | additional | 6 | payload_absent | 31 | `b8d3cda0357e3fdf5edce6ffb3ddaa79467e2f520a61ea5d29d9b2f3bf11735f` |
| crosscloud:aws:steal_application_access_token:additional:run-6:y | additional | 6 | payload_present | 26 | `d254a5a312502f713b602a1881b69dd0e6903d4a29d5653f8b5b5c942139a2cd` |
| crosscloud:aws:steal_application_access_token:additional:run-7:n | additional | 7 | payload_absent | 13 | `b22392c01f1ec32a158f853a4e43160c4aa32e51aa7132b991b597803f5c4ed9` |
| crosscloud:aws:steal_application_access_token:additional:run-7:y | additional | 7 | payload_present | 34 | `3940b2ce67daec776e7bf733ec0fa4a09d76dccfa19016d292fd9eaaf3257b13` |
| crosscloud:aws:steal_application_access_token:additional:run-8:n | additional | 8 | payload_absent | 14 | `815edba461c3f510da21c79ff876777feed54ff5f2b6da7613c027be8d046c22` |
| crosscloud:aws:steal_application_access_token:additional:run-8:y | additional | 8 | payload_present | 23 | `a7012a65bc312431415a9da7a1935ca85748150a7100181f907fb3b0a5ac3c1b` |
| crosscloud:aws:steal_application_access_token:additional:run-9:n | additional | 9 | payload_absent | 12 | `cbe9cdce63d934401902c44f20995ba84da1cc236bfb4f00da691ecda3dcb097` |
| crosscloud:aws:steal_application_access_token:additional:run-9:y | additional | 9 | payload_present | 28 | `50489c3a644f9b926626109406d404965a5031d151db949d899b652cb79b1e99` |
| crosscloud:aws:steal_application_access_token:default:run-0:n | default | 0 | payload_absent | 13 | `f3323ff82732cccbe106c97536066dec6423adf4e2e60507d382bc474f42f13f` |
| crosscloud:aws:steal_application_access_token:default:run-0:y | default | 0 | payload_present | 11 | `7caa6e7f3922d3f16f132f5ff83330a2a046ad46855dd475a428256d9b0c16ac` |
| crosscloud:aws:steal_application_access_token:default:run-1:n | default | 1 | payload_absent | 18 | `6377fd306aad9adf772c435e5f794f96c51c1cced9112d8fa9b0e060375b4d46` |
| crosscloud:aws:steal_application_access_token:default:run-1:y | default | 1 | payload_present | 11 | `5a1d09a4783894dfec8ac37fe9202ad9195296254b6176fb0d2bce8a549c749e` |
| crosscloud:aws:steal_application_access_token:default:run-2:n | default | 2 | payload_absent | 17 | `c2f4fed62d7f4bf95a5bec5e27ce854c4b73a67067b61d24a93f48ad51cad698` |
| crosscloud:aws:steal_application_access_token:default:run-2:y | default | 2 | payload_present | 11 | `585ba54589e8254320805975b50867938f95bb6b7934fc8f0fd7ccc78874712c` |
| crosscloud:aws:steal_application_access_token:default:run-3:n | default | 3 | payload_absent | 15 | `68f3029517e7727c574e68319c7c10f66e8411c6ead0d4d1c03dea4ca079dcd0` |
| crosscloud:aws:steal_application_access_token:default:run-3:y | default | 3 | payload_present | 9 | `6ad4607c2adc446c6958af0f640f69393d21af48fa95a34d7b14372dd46c05f3` |
| crosscloud:aws:steal_application_access_token:default:run-4:n | default | 4 | payload_absent | 14 | `abdb1d2625a30ecf40c27e94a2e86102f6011aac777f76a186a4cfd3d66cf84c` |
| crosscloud:aws:steal_application_access_token:default:run-4:y | default | 4 | payload_present | 9 | `5134f722e1afdc05f0ea48bae0512493d188bff46a3a343e50665ee4db0b233c` |
| crosscloud:aws:steal_application_access_token:default:run-5:n | default | 5 | payload_absent | 12 | `4d7a019743997c5262a616eb7aaf7958080c739c8dda1a5245d8640148079238` |
| crosscloud:aws:steal_application_access_token:default:run-5:y | default | 5 | payload_present | 10 | `8fffce8e1757ca453f94153bd69a39de844061d8f4b64d1af49f2e2f27138f9e` |
| crosscloud:aws:steal_application_access_token:default:run-6:n | default | 6 | payload_absent | 26 | `a51f6882b47e19cd40e73a990b19663d780b758493fe41115da2cffdaf6a4d96` |
| crosscloud:aws:steal_application_access_token:default:run-6:y | default | 6 | payload_present | 11 | `ef07b9e468dc6de3c55d0b36dfecf22abd3a57d7d1f62fa35b4f9f517cfaaf2d` |
| crosscloud:aws:steal_application_access_token:default:run-7:n | default | 7 | payload_absent | 19 | `650beb2bc670ddbfa89587d39d754023f5cfadb138442bda61322c1f96656c16` |
| crosscloud:aws:steal_application_access_token:default:run-7:y | default | 7 | payload_present | 11 | `8cb532510ea9e191c57a77ef3ffd89faaa34ff1a0f22db6d201c23fa0df8f648` |
| crosscloud:aws:steal_application_access_token:default:run-8:n | default | 8 | payload_absent | 16 | `49cc4d7ed08498b5fed395a36be4a6a64bc13c6182ccc7ef59b1d6a9b685f737` |
| crosscloud:aws:steal_application_access_token:default:run-8:y | default | 8 | payload_present | 10 | `a9cbb2f01085fa250828ccd5a38edc672a186aaecbc470c64bcb021aa4fcabc2` |
| crosscloud:aws:steal_application_access_token:default:run-9:n | default | 9 | payload_absent | 15 | `a7e7a0f6a21158875f1545f381131765d2a1ab37f2899b875b388f34e3cfe1aa` |
| crosscloud:aws:steal_application_access_token:default:run-9:y | default | 9 | payload_present | 10 | `b8913e3df1d48d4a3e78a25b8dd5fadc1a8361566cc5d4eea6aa0e48bca03f2e` |

### 原始文件完整性

- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/README.md` — SHA-256 `b073b2e97aea4073fec2bf387e2c255d987dd8f3710e84f2df3cc59947e510f8`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/attack_scripts.zip` — SHA-256 `4599be3e224f3b9b43e76ab4ec1bfa8e3b209ebe529fb218ae4e65dd22417900`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/aws_logs_redacted.zip` — SHA-256 `f75046f8660e648981040d5180950867a7e82cb8b799708ff572a927d2d35f5b`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/log_analysis.zip` — SHA-256 `23b41863cc2ece4936277a1ee1fc6f64b4fea9f3c0f698cefbf5626eeca00fcf`

## 21. `crosscloud:aws:unsecured_credentials`

- 描述：DOI-published paired payload/no-payload AWS telemetry for unsecured_credentials.
- 发布者：Dhooghe et al.
- 发布日期：2026-04-30
- 环境：controlled cloud subscription
- ATT&CK：
- 原始文件数：4
- 规范化观测数：0
- 上游 episode 数：40

### 准入判断（人工填写）

- [ ] 有外部或低权限入口
- [ ] 存在多步关系，而非单点事件
- [ ] 终点为数据库、存储、备份、secret 或其他数据资产
- [ ] 关键边均有原始证据
- [ ] 不是近重复案例
- 决定：`<accept | needs_execution | reject>`
- 理由：`<人工填写>`

### 观测索引

| observation_id | timestamp | actor_type | service | operation | status | raw record |
|---|---:|---|---|---|---|---|

### 上游配对 episode

| episode_id | profile | run | source condition | observations | member SHA-256 |
|---|---|---:|---|---:|---|
| crosscloud:aws:unsecured_credentials:additional:run-0:n | additional | 0 | payload_absent | 15 | `d7cf83f5fa59b4a2a943e895f9bdaa21a14b4efb326eb922a3c6720f5ff2b377` |
| crosscloud:aws:unsecured_credentials:additional:run-0:y | additional | 0 | payload_present | 25 | `569456c04eeca680885824f666e16fc56d9be3ea9bd23438cf715b38e715e8dd` |
| crosscloud:aws:unsecured_credentials:additional:run-1:n | additional | 1 | payload_absent | 15 | `2aabc37308d66fa00180444420fd862c191e2e64348ab248afff5503de1020a1` |
| crosscloud:aws:unsecured_credentials:additional:run-1:y | additional | 1 | payload_present | 11 | `64804f2bc794747e7c7cace42914ed436fc9c6b9319c88b2f5080974ad4da3de` |
| crosscloud:aws:unsecured_credentials:additional:run-2:n | additional | 2 | payload_absent | 10 | `9df4108b152f025970fe953189c5351f84a644479c58a81fc84cd08f5b39d286` |
| crosscloud:aws:unsecured_credentials:additional:run-2:y | additional | 2 | payload_present | 10 | `cd35d789d73e0a358234613d0a6a660988cbfe7419d0b8e9288e87270b9b6637` |
| crosscloud:aws:unsecured_credentials:additional:run-3:n | additional | 3 | payload_absent | 7 | `09a75cbbe4b6e0deb3942c04867490b34c5cf41d3a5b33f7c6d82a1ac5ce3290` |
| crosscloud:aws:unsecured_credentials:additional:run-3:y | additional | 3 | payload_present | 26 | `1edd011a88b329f7ed1b4375cf78bcd85756bd174e4145642a3c51b22bc111c7` |
| crosscloud:aws:unsecured_credentials:additional:run-4:n | additional | 4 | payload_absent | 9 | `1d9446204721e36048895248b9853a29489d01342eb3c8ee7ad5d11a103b130a` |
| crosscloud:aws:unsecured_credentials:additional:run-4:y | additional | 4 | payload_present | 11 | `9d31b4d50396251d3d0f604d83e5258769d15a7cb28ca1ad911eb87888dd90b8` |
| crosscloud:aws:unsecured_credentials:additional:run-5:n | additional | 5 | payload_absent | 4 | `7c1917369d9d0dd2c5b2d1582df69e8ce0f4a5c772438150394d1f571bb7163b` |
| crosscloud:aws:unsecured_credentials:additional:run-5:y | additional | 5 | payload_present | 8 | `a201ab4ab822af54d9a94498af0475faf22ebb1a04e76c7d80691cc2f10fd273` |
| crosscloud:aws:unsecured_credentials:additional:run-6:n | additional | 6 | payload_absent | 7 | `dd74552bde750b192ca5afbade3acb393590cf1add6ee5d983b2f5089d32bd6a` |
| crosscloud:aws:unsecured_credentials:additional:run-6:y | additional | 6 | payload_present | 27 | `3ccc2d39d7e8f6d74b45c47564aed4a5740d38d37cecdd6f200738f6a9eeeb74` |
| crosscloud:aws:unsecured_credentials:additional:run-7:n | additional | 7 | payload_absent | 5 | `689f531a90ca77769030e42920f4f62405ded81d58ed9e38b6d5a34f54e10faf` |
| crosscloud:aws:unsecured_credentials:additional:run-7:y | additional | 7 | payload_present | 11 | `9875c8fbcd7b3dbe9adfbd9314ea8038a71d4f17f6ca86f2ff36021c079b4b4f` |
| crosscloud:aws:unsecured_credentials:additional:run-8:n | additional | 8 | payload_absent | 3 | `519fc1d74a5d701f26bc2675bbf1bfdfcb7efc037f07a2f49c0570cf5e4c972f` |
| crosscloud:aws:unsecured_credentials:additional:run-8:y | additional | 8 | payload_present | 10 | `5f053c4e67f03e85bd8caf791e683817da3e6043ad0e88e2bef6c3fc21594e04` |
| crosscloud:aws:unsecured_credentials:additional:run-9:n | additional | 9 | payload_absent | 5 | `809e261532e565bb1c42f22b527770911abdb58c9a52b9c66da173d0473a547d` |
| crosscloud:aws:unsecured_credentials:additional:run-9:y | additional | 9 | payload_present | 28 | `a787cc92dbe1b251b946a26dfbf33854a02be36d1bed699fee83db581591d886` |
| crosscloud:aws:unsecured_credentials:default:run-0:n | default | 0 | payload_absent | 4 | `0a5b0e326e2932878eec25fb87d2872659ec80cb956fd4874a331ee444e9e729` |
| crosscloud:aws:unsecured_credentials:default:run-0:y | default | 0 | payload_present | 0 | `37517e5f3dc66819f61f5a7bb8ace1921282415f10551d2defa5c3eb0985b570` |
| crosscloud:aws:unsecured_credentials:default:run-1:n | default | 1 | payload_absent | 1 | `0ae201cf26184d2829396a97084aa4dddd2b80e91e920e5518a0f2173c37f972` |
| crosscloud:aws:unsecured_credentials:default:run-1:y | default | 1 | payload_present | 0 | `37517e5f3dc66819f61f5a7bb8ace1921282415f10551d2defa5c3eb0985b570` |
| crosscloud:aws:unsecured_credentials:default:run-2:n | default | 2 | payload_absent | 0 | `37517e5f3dc66819f61f5a7bb8ace1921282415f10551d2defa5c3eb0985b570` |
| crosscloud:aws:unsecured_credentials:default:run-2:y | default | 2 | payload_present | 0 | `37517e5f3dc66819f61f5a7bb8ace1921282415f10551d2defa5c3eb0985b570` |
| crosscloud:aws:unsecured_credentials:default:run-3:n | default | 3 | payload_absent | 2 | `aa3693bf480de352ecb69473b17188681d3135c1aabd5a4fb93d0f3a1d17acb3` |
| crosscloud:aws:unsecured_credentials:default:run-3:y | default | 3 | payload_present | 1 | `3985dc0805604809ed086f2b46183588fc6a1817a42a63d4f5a9a08a54ca7bd7` |
| crosscloud:aws:unsecured_credentials:default:run-4:n | default | 4 | payload_absent | 1 | `adb8a0c96fe7c0a3185788c12728e1378f3dfabaa77f302a55c969ceba3c571a` |
| crosscloud:aws:unsecured_credentials:default:run-4:y | default | 4 | payload_present | 0 | `37517e5f3dc66819f61f5a7bb8ace1921282415f10551d2defa5c3eb0985b570` |
| crosscloud:aws:unsecured_credentials:default:run-5:n | default | 5 | payload_absent | 2 | `f00df5b406d3e4a7d520d37f3ca75082a5343991381eeb293918bb2db2319a1f` |
| crosscloud:aws:unsecured_credentials:default:run-5:y | default | 5 | payload_present | 0 | `37517e5f3dc66819f61f5a7bb8ace1921282415f10551d2defa5c3eb0985b570` |
| crosscloud:aws:unsecured_credentials:default:run-6:n | default | 6 | payload_absent | 4 | `b0bf4bbb6988b18436d056ad40b0240bf9c3c79fed17dbae11c7f163c9f89c7b` |
| crosscloud:aws:unsecured_credentials:default:run-6:y | default | 6 | payload_present | 0 | `37517e5f3dc66819f61f5a7bb8ace1921282415f10551d2defa5c3eb0985b570` |
| crosscloud:aws:unsecured_credentials:default:run-7:n | default | 7 | payload_absent | 9 | `e4b98015a535eb097ba304a346f0064afedfcd8d7854eb29fcda85c601b69f67` |
| crosscloud:aws:unsecured_credentials:default:run-7:y | default | 7 | payload_present | 0 | `37517e5f3dc66819f61f5a7bb8ace1921282415f10551d2defa5c3eb0985b570` |
| crosscloud:aws:unsecured_credentials:default:run-8:n | default | 8 | payload_absent | 4 | `27cb2648bcc872d347c8f4da439e63fa03bd975f1cc2b784097b5bf8c443f433` |
| crosscloud:aws:unsecured_credentials:default:run-8:y | default | 8 | payload_present | 1 | `b47cd93441b93398d1a78d59651a97b776b97d4da99e613e4a4e8dd3cec62661` |
| crosscloud:aws:unsecured_credentials:default:run-9:n | default | 9 | payload_absent | 5 | `3b1b92d1d77a7fdb0a1eda917d1fb45546012979486225112f32653a74dfbfbf` |
| crosscloud:aws:unsecured_credentials:default:run-9:y | default | 9 | payload_present | 0 | `37517e5f3dc66819f61f5a7bb8ace1921282415f10551d2defa5c3eb0985b570` |

### 原始文件完整性

- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/README.md` — SHA-256 `b073b2e97aea4073fec2bf387e2c255d987dd8f3710e84f2df3cc59947e510f8`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/attack_scripts.zip` — SHA-256 `4599be3e224f3b9b43e76ab4ec1bfa8e3b209ebe529fb218ae4e65dd22417900`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/aws_logs_redacted.zip` — SHA-256 `f75046f8660e648981040d5180950867a7e82cb8b799708ff572a927d2d35f5b`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/log_analysis.zip` — SHA-256 `23b41863cc2ece4936277a1ee1fc6f64b4fea9f3c0f698cefbf5626eeca00fcf`

## 22. `crosscloud:azure:archive_collected_data`

- 描述：DOI-published paired payload/no-payload AZURE telemetry for archive_collected_data.
- 发布者：Dhooghe et al.
- 发布日期：2026-04-30
- 环境：controlled cloud subscription
- ATT&CK：
- 原始文件数：4
- 规范化观测数：0
- 上游 episode 数：40

### 准入判断（人工填写）

- [ ] 有外部或低权限入口
- [ ] 存在多步关系，而非单点事件
- [ ] 终点为数据库、存储、备份、secret 或其他数据资产
- [ ] 关键边均有原始证据
- [ ] 不是近重复案例
- 决定：`<accept | needs_execution | reject>`
- 理由：`<人工填写>`

### 观测索引

| observation_id | timestamp | actor_type | service | operation | status | raw record |
|---|---:|---|---|---|---|---|

### 上游配对 episode

| episode_id | profile | run | source condition | observations | member SHA-256 |
|---|---|---:|---|---:|---|
| crosscloud:azure:archive_collected_data:additional:run-0:n | additional | 0 | payload_absent | 28 | `6826eb66ccc33616c71bd515ef08d0ee8fc70eff088faca8ba2c50e1201f9015` |
| crosscloud:azure:archive_collected_data:additional:run-0:y | additional | 0 | payload_present | 44 | `41966f39332c9de60e2f8f39d64693165077a238b5fb14d1a3b0d3551bd27409` |
| crosscloud:azure:archive_collected_data:additional:run-1:n | additional | 1 | payload_absent | 28 | `a3ccf6cb84fca2b99071fd99fb13f89770cf19194a5c48fa5763d22aca55109a` |
| crosscloud:azure:archive_collected_data:additional:run-1:y | additional | 1 | payload_present | 43 | `144025eb7a56453ea187d59ada8a3e9bc8605c3045b14e9301f112aa9b0668a4` |
| crosscloud:azure:archive_collected_data:additional:run-2:n | additional | 2 | payload_absent | 28 | `14a340555f53be180f90da1ac4c18f885e1fd45f5303c174ccdff55eb2aa68a2` |
| crosscloud:azure:archive_collected_data:additional:run-2:y | additional | 2 | payload_present | 44 | `db5bb4000304a847354b373619e5c883b77185c998a84848031a84cc82114364` |
| crosscloud:azure:archive_collected_data:additional:run-3:n | additional | 3 | payload_absent | 28 | `6d2fbc55cff67c9023d1db777f7ca1072f00869b3360ca00fe74f3c6ebf4022b` |
| crosscloud:azure:archive_collected_data:additional:run-3:y | additional | 3 | payload_present | 43 | `54813431a1d3a380927e8908efd84c87fac61e85ef5363f485fa7e5e02578dda` |
| crosscloud:azure:archive_collected_data:additional:run-4:n | additional | 4 | payload_absent | 28 | `952f218045268678fe1c6c3f7c0e496816bd83404c6f17f4690e72702176551d` |
| crosscloud:azure:archive_collected_data:additional:run-4:y | additional | 4 | payload_present | 43 | `f469b4b721752ea4f396f6b9115044f9311d44454563888711dcd0bf624514fd` |
| crosscloud:azure:archive_collected_data:additional:run-5:n | additional | 5 | payload_absent | 29 | `3128dc46d44a9a322cd413bd1cdbe771943d401aa920c6ec3a663e6c018c23f8` |
| crosscloud:azure:archive_collected_data:additional:run-5:y | additional | 5 | payload_present | 43 | `b12e9d4ae72bf39623770d2a7e7bc410c4d5895a4e2759d36c329ecd016bcd85` |
| crosscloud:azure:archive_collected_data:additional:run-6:n | additional | 6 | payload_absent | 28 | `35d924c7d2ce9556dd44ef05a883d692db032a676cce8d59a81f53c9e60ff77c` |
| crosscloud:azure:archive_collected_data:additional:run-6:y | additional | 6 | payload_present | 43 | `184747db5a522b53bd2639a10e0becc71a8ef9c5ef18776cc3a32d4da97edab8` |
| crosscloud:azure:archive_collected_data:additional:run-7:n | additional | 7 | payload_absent | 29 | `267842e53070048c8b836d9871d65a026367990ba5a34795fa5c8b29d2940b9e` |
| crosscloud:azure:archive_collected_data:additional:run-7:y | additional | 7 | payload_present | 44 | `57bc55dec31b49fd33e693344fda4dfc47529fd551eaae2b76e3bdc9a9782a2c` |
| crosscloud:azure:archive_collected_data:additional:run-8:n | additional | 8 | payload_absent | 29 | `ef2a0350b332c3d43dc73b427bf1c3aecc51c535c8ea1ed7fe0f20f0fc842ea4` |
| crosscloud:azure:archive_collected_data:additional:run-8:y | additional | 8 | payload_present | 43 | `1d7fb7f4951f479da4c4357f095b75f3460ffa5001df0ab3b60a95d15bcc6c5b` |
| crosscloud:azure:archive_collected_data:additional:run-9:n | additional | 9 | payload_absent | 29 | `551d7b77eec6b95d27824d946182669068ffa2dcb6e273b524dea68ab3fe30bc` |
| crosscloud:azure:archive_collected_data:additional:run-9:y | additional | 9 | payload_present | 46 | `06ac5239a243649cbe53bec9cecd9f4252cbe60dffd0056de141cf4c12b8e558` |
| crosscloud:azure:archive_collected_data:default:run-0:n | default | 0 | payload_absent | 25 | `ab2448d5ff0a137086b9220afe02fa4a2652059b1c3f828fd1d7fad135015420` |
| crosscloud:azure:archive_collected_data:default:run-0:y | default | 0 | payload_present | 39 | `c2188876b964de98b97cc463b0dbafe2bec7aa53c652dca874ed761b63bd87d6` |
| crosscloud:azure:archive_collected_data:default:run-1:n | default | 1 | payload_absent | 25 | `f71546d5f94b56786d2749679438a4afebc64cbeaf18877b46fb75206884f616` |
| crosscloud:azure:archive_collected_data:default:run-1:y | default | 1 | payload_present | 40 | `343c244e5f8fdf7d59642629995c9692227d82415c0f7b5d1c512bfa778d9085` |
| crosscloud:azure:archive_collected_data:default:run-2:n | default | 2 | payload_absent | 25 | `8a701a197fac8118ea141e95f663fd6416b2af53f6cc08982312971911096798` |
| crosscloud:azure:archive_collected_data:default:run-2:y | default | 2 | payload_present | 39 | `ca6ac2375c5aad1aa2098478fd68135cf8be56c8623f958e337b619e65248c74` |
| crosscloud:azure:archive_collected_data:default:run-3:n | default | 3 | payload_absent | 25 | `e8ce81e8ff153eb6d61af55503cde0848cd323271a4d0dff4318c43930823203` |
| crosscloud:azure:archive_collected_data:default:run-3:y | default | 3 | payload_present | 39 | `76c7eaaf980cdc73637fa251f2778cf93e54fb6f8132538251010479e53a9020` |
| crosscloud:azure:archive_collected_data:default:run-4:n | default | 4 | payload_absent | 25 | `3046250791f7923f3618f77a91a1088bffa10b194345f21dd081101512375e70` |
| crosscloud:azure:archive_collected_data:default:run-4:y | default | 4 | payload_present | 40 | `8f3cba14ce9e45b1270c4fde3ace674bd5baa73af7fe9bd6dc6722ff79aec80a` |
| crosscloud:azure:archive_collected_data:default:run-5:n | default | 5 | payload_absent | 25 | `aeee6d90447286b05b5e45190c68cb479399d64a927233c88c617f738b44ed45` |
| crosscloud:azure:archive_collected_data:default:run-5:y | default | 5 | payload_present | 39 | `ddeadcea9b8050b4d90f6aa59288de8b6a1df08b5bc1a4e0839b0c427855dd03` |
| crosscloud:azure:archive_collected_data:default:run-6:n | default | 6 | payload_absent | 25 | `378434a4c1bd56a709fd3ccd16a2548b7da3f4dddb9e36cdf9d537f5eb59c0aa` |
| crosscloud:azure:archive_collected_data:default:run-6:y | default | 6 | payload_present | 39 | `8146bcce8d2858f72df231fb76fa0e66fac44f3d461252fdd5b09a4650c37d03` |
| crosscloud:azure:archive_collected_data:default:run-7:n | default | 7 | payload_absent | 23 | `a7877f735f20f11ad5181046fdc74e1e0a6bd7ac587c686f8d64e22d10a68c34` |
| crosscloud:azure:archive_collected_data:default:run-7:y | default | 7 | payload_present | 39 | `904025b8f673d29a67122ad51f8495b93864948fe72d7e8611f6e589b267250b` |
| crosscloud:azure:archive_collected_data:default:run-8:n | default | 8 | payload_absent | 25 | `f0d965292cac07aa0f0252e8e90269850825c6fb8e95474eb8941bc8f2f6c941` |
| crosscloud:azure:archive_collected_data:default:run-8:y | default | 8 | payload_present | 40 | `822b5f768cfbfda261855c0906e32aee0543bca1d122d9be9082ca8e3919e1b7` |
| crosscloud:azure:archive_collected_data:default:run-9:n | default | 9 | payload_absent | 23 | `7e957664b4808a0fdb701575022b8594f593083ba8614226644489c1fa512e14` |
| crosscloud:azure:archive_collected_data:default:run-9:y | default | 9 | payload_present | 40 | `c93ef686cc0e8e04c15f860f36a96b9ed9d9916ce94841187327d1ae86513c9f` |

### 原始文件完整性

- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/README.md` — SHA-256 `b073b2e97aea4073fec2bf387e2c255d987dd8f3710e84f2df3cc59947e510f8`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/attack_scripts.zip` — SHA-256 `4599be3e224f3b9b43e76ab4ec1bfa8e3b209ebe529fb218ae4e65dd22417900`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/azure_logs_redacted.zip` — SHA-256 `5a94d05e4877593bad1602a68a6f4e775f72323e9e408ae0d0480d7126789dee`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/log_analysis.zip` — SHA-256 `23b41863cc2ece4936277a1ee1fc6f64b4fea9f3c0f698cefbf5626eeca00fcf`

## 23. `crosscloud:azure:automated_collection`

- 描述：DOI-published paired payload/no-payload AZURE telemetry for automated_collection.
- 发布者：Dhooghe et al.
- 发布日期：2026-04-30
- 环境：controlled cloud subscription
- ATT&CK：
- 原始文件数：4
- 规范化观测数：0
- 上游 episode 数：40

### 准入判断（人工填写）

- [ ] 有外部或低权限入口
- [ ] 存在多步关系，而非单点事件
- [ ] 终点为数据库、存储、备份、secret 或其他数据资产
- [ ] 关键边均有原始证据
- [ ] 不是近重复案例
- 决定：`<accept | needs_execution | reject>`
- 理由：`<人工填写>`

### 观测索引

| observation_id | timestamp | actor_type | service | operation | status | raw record |
|---|---:|---|---|---|---|---|

### 上游配对 episode

| episode_id | profile | run | source condition | observations | member SHA-256 |
|---|---|---:|---|---:|---|
| crosscloud:azure:automated_collection:additional:run-0:n | additional | 0 | payload_absent | 29 | `bc7aac2931d84cbc938e55da3bead9989c3529cde75549537b7eff4e89cbce4e` |
| crosscloud:azure:automated_collection:additional:run-0:y | additional | 0 | payload_present | 39 | `11ef79284081e2e0088e760929caa8c5d0463721884dc6e6bd030c11a1029166` |
| crosscloud:azure:automated_collection:additional:run-1:n | additional | 1 | payload_absent | 29 | `dbf7de37eaf8709b454c17df3bfa34456403dcb5ef8b82d571729e95860d46bf` |
| crosscloud:azure:automated_collection:additional:run-1:y | additional | 1 | payload_present | 40 | `f66428ab563006fd3e19b4e18ac0043a33a2b828d8aa5bfde2bca8149b92af42` |
| crosscloud:azure:automated_collection:additional:run-2:n | additional | 2 | payload_absent | 29 | `1782feac0657f445b0ebb61be79a8f67bcddaad9f3e35b8ff8878dfbabb282c8` |
| crosscloud:azure:automated_collection:additional:run-2:y | additional | 2 | payload_present | 39 | `183642e7add5e40499b6e1f831bf3c8d56c1ebc1dc165129940358bf852a0452` |
| crosscloud:azure:automated_collection:additional:run-3:n | additional | 3 | payload_absent | 29 | `d580a097ec7e289e999cefd16bd959134d714ad39830cb14f31825175ac5f2c8` |
| crosscloud:azure:automated_collection:additional:run-3:y | additional | 3 | payload_present | 39 | `609206ce2dfd759cf3bcda0d433fd1be2b37c3a45de3f7fb5203a81ac6fbc476` |
| crosscloud:azure:automated_collection:additional:run-4:n | additional | 4 | payload_absent | 29 | `e3b3f48e50cc34143952b836067011329cbd5ca7b2cd45a36ff33e3db9d18cce` |
| crosscloud:azure:automated_collection:additional:run-4:y | additional | 4 | payload_present | 39 | `de2843b345d97d74d5eca8458602effb6fc1e5350f484ba88742312ada7f41ae` |
| crosscloud:azure:automated_collection:additional:run-5:n | additional | 5 | payload_absent | 30 | `20a96f22375f04147653d0ac462cebfd794e272ddb324a83a3febc586a2ea78b` |
| crosscloud:azure:automated_collection:additional:run-5:y | additional | 5 | payload_present | 40 | `41315477f0fd810a52114a3628186d79e857576b0921cb68496a9cb4e1ec89bb` |
| crosscloud:azure:automated_collection:additional:run-6:n | additional | 6 | payload_absent | 29 | `7771abcfea5b594d4484bcf47502122058d76fb51091c67c232bb88e908c480a` |
| crosscloud:azure:automated_collection:additional:run-6:y | additional | 6 | payload_present | 39 | `3e98d1ff8fff56dfbff598ec6e73de287f7f18b42ed1646d97bfab943d6e2fe1` |
| crosscloud:azure:automated_collection:additional:run-7:n | additional | 7 | payload_absent | 30 | `4778823e6de64a02ca61294eb966e4b6c538f140271f4770b99bd8ab1970376a` |
| crosscloud:azure:automated_collection:additional:run-7:y | additional | 7 | payload_present | 40 | `0d5af01637f231130d17d9796602527bb827baf97ed4a2e158b311faca42a145` |
| crosscloud:azure:automated_collection:additional:run-8:n | additional | 8 | payload_absent | 29 | `3f1984a3a91d1265fc836e2a8b5739fb18345cf0a07c2a9f9c308c2cfc3eebe1` |
| crosscloud:azure:automated_collection:additional:run-8:y | additional | 8 | payload_present | 40 | `187ccd9bdd3d834d537a31202f53ddd589dbc4847f691a9d78adfc268d11d81d` |
| crosscloud:azure:automated_collection:additional:run-9:n | additional | 9 | payload_absent | 30 | `8d05835d6bd023716b43d9097fe67a978cb188734fc38dc8fe176f0ed925dd11` |
| crosscloud:azure:automated_collection:additional:run-9:y | additional | 9 | payload_present | 40 | `744e2901db36f91fc5cc2fdd356ee7666da046335b94ed3709783ccacc9e066c` |
| crosscloud:azure:automated_collection:default:run-0:n | default | 0 | payload_absent | 21 | `cce03e9d3092c0ce69a7d2ef27b55999c607cbceffc2eb62daba616cfce4f479` |
| crosscloud:azure:automated_collection:default:run-0:y | default | 0 | payload_present | 32 | `1caf0274a49e9b196bbf442dacd257cd3362bdf0e259ce4f69cf7d2f3f03e537` |
| crosscloud:azure:automated_collection:default:run-1:n | default | 1 | payload_absent | 21 | `34ba69b4f14b66e23303fea90e7109998d49ad8d826c3e567b33d752bad6b123` |
| crosscloud:azure:automated_collection:default:run-1:y | default | 1 | payload_present | 31 | `ec4a75e78b2c14ea486d5be3ffd51fe4729b096e91801b9d9aeccaf8497a35c8` |
| crosscloud:azure:automated_collection:default:run-2:n | default | 2 | payload_absent | 21 | `d5b2b3b3104d17960bd4609adf50d6a0a92c328b96f4451ea656b3184956f1fb` |
| crosscloud:azure:automated_collection:default:run-2:y | default | 2 | payload_present | 31 | `525a1a8437aac0c6b0b200dbd646f57b37ea7c41d6a27b1eb21a3ee4ec229688` |
| crosscloud:azure:automated_collection:default:run-3:n | default | 3 | payload_absent | 22 | `a142a3190f865f5f624712e185f3bf8fe23f11b9d1bae6d80e0a8b6a077cec0b` |
| crosscloud:azure:automated_collection:default:run-3:y | default | 3 | payload_present | 31 | `c940e559d19cc4f776f9e415fc98e301327136976a0da9903c585d9cae9e8084` |
| crosscloud:azure:automated_collection:default:run-4:n | default | 4 | payload_absent | 21 | `5a6d464acd30f4a8db02db9e60939318c8994de029e9ab0fae889517bbd41516` |
| crosscloud:azure:automated_collection:default:run-4:y | default | 4 | payload_present | 32 | `c519a5feed3644f71f10e5aadac3db6a5deed78bf337c0344fbfd5e4b431babc` |
| crosscloud:azure:automated_collection:default:run-5:n | default | 5 | payload_absent | 21 | `1ad9859f626b97c4679e39632c7310c669841c5c403326f36abd74ddf8368f8f` |
| crosscloud:azure:automated_collection:default:run-5:y | default | 5 | payload_present | 32 | `993e00d2116537d7d34d4d37b16978278426a182a94f887a3575db122d208a3a` |
| crosscloud:azure:automated_collection:default:run-6:n | default | 6 | payload_absent | 22 | `fda1a306eab230d341ac058528619e6310b0861254814d9c89ae2b70b2fa4dce` |
| crosscloud:azure:automated_collection:default:run-6:y | default | 6 | payload_present | 32 | `c16513c0b1bd65ba7b46006aa9d27caccdd46e8c2928acce785283afa51bdb81` |
| crosscloud:azure:automated_collection:default:run-7:n | default | 7 | payload_absent | 22 | `ad2205a8808c3beb83bf7b3329412df6fd7d8d73cad45bb3594aea3d980e4930` |
| crosscloud:azure:automated_collection:default:run-7:y | default | 7 | payload_present | 31 | `5ccf80ee5b6f38d489cead3f71ac45463d58518c1b2ba1390702953007823782` |
| crosscloud:azure:automated_collection:default:run-8:n | default | 8 | payload_absent | 21 | `c1630b6d7591d14285c814c4147829f069f91b4a2555bf4122a881036502caf6` |
| crosscloud:azure:automated_collection:default:run-8:y | default | 8 | payload_present | 32 | `71af5413907afea62972256027942b7136e513b3a8179f26db0acd29efcaaf68` |
| crosscloud:azure:automated_collection:default:run-9:n | default | 9 | payload_absent | 22 | `ad55a6a3e385065461d65f80dff9ba9975d89790ec2acc433dee8c05575f5b3c` |
| crosscloud:azure:automated_collection:default:run-9:y | default | 9 | payload_present | 31 | `7aeb58cb4cd22d7056edd22b9bd0f0a537b3678b8bc13eaf6934efbfcecff65c` |

### 原始文件完整性

- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/README.md` — SHA-256 `b073b2e97aea4073fec2bf387e2c255d987dd8f3710e84f2df3cc59947e510f8`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/attack_scripts.zip` — SHA-256 `4599be3e224f3b9b43e76ab4ec1bfa8e3b209ebe529fb218ae4e65dd22417900`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/azure_logs_redacted.zip` — SHA-256 `5a94d05e4877593bad1602a68a6f4e775f72323e9e408ae0d0480d7126789dee`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/log_analysis.zip` — SHA-256 `23b41863cc2ece4936277a1ee1fc6f64b4fea9f3c0f698cefbf5626eeca00fcf`

## 24. `crosscloud:azure:automated_exfiltration`

- 描述：DOI-published paired payload/no-payload AZURE telemetry for automated_exfiltration.
- 发布者：Dhooghe et al.
- 发布日期：2026-04-30
- 环境：controlled cloud subscription
- ATT&CK：
- 原始文件数：4
- 规范化观测数：0
- 上游 episode 数：40

### 准入判断（人工填写）

- [ ] 有外部或低权限入口
- [ ] 存在多步关系，而非单点事件
- [ ] 终点为数据库、存储、备份、secret 或其他数据资产
- [ ] 关键边均有原始证据
- [ ] 不是近重复案例
- 决定：`<accept | needs_execution | reject>`
- 理由：`<人工填写>`

### 观测索引

| observation_id | timestamp | actor_type | service | operation | status | raw record |
|---|---:|---|---|---|---|---|

### 上游配对 episode

| episode_id | profile | run | source condition | observations | member SHA-256 |
|---|---|---:|---|---:|---|
| crosscloud:azure:automated_exfiltration:additional:run-0:n | additional | 0 | payload_absent | 25 | `7d79e37a2353626e3dbfd6c239f518847ada3f95165b49a952fd949b95dd8501` |
| crosscloud:azure:automated_exfiltration:additional:run-0:y | additional | 0 | payload_present | 41 | `dfa12da7352b4265c9b0cd5236ed5af83d1a8a434ca5e3d9edb59f59d25210e0` |
| crosscloud:azure:automated_exfiltration:additional:run-1:n | additional | 1 | payload_absent | 24 | `97f114fbb6427f5d3a5e13f7c300702eeebda5a511c2668a2176eb9f9d631f58` |
| crosscloud:azure:automated_exfiltration:additional:run-1:y | additional | 1 | payload_present | 43 | `b1b0cac942c02ab3e7f612d70074528daac6d9a6865d9234f83a7918c7b598ba` |
| crosscloud:azure:automated_exfiltration:additional:run-2:n | additional | 2 | payload_absent | 25 | `bf3ecbbaf14a51e2c9ebca61a997e8b3f1160032652c22357e88e874962767b9` |
| crosscloud:azure:automated_exfiltration:additional:run-2:y | additional | 2 | payload_present | 39 | `3eade2114917243f75030a8412c1c17c826d6a20912c19c8ea5f850c84c986de` |
| crosscloud:azure:automated_exfiltration:additional:run-3:n | additional | 3 | payload_absent | 25 | `4f401eae672af6c988e51c09e98caceb6f382ad86aeb67e4b2297c0ff2fc63f6` |
| crosscloud:azure:automated_exfiltration:additional:run-3:y | additional | 3 | payload_present | 39 | `194963f31fc267c5b610a35e460a1282cb724b56512623d3d4e46522bef363d9` |
| crosscloud:azure:automated_exfiltration:additional:run-4:n | additional | 4 | payload_absent | 25 | `e94ba41929879a5096f1a204f3f1ae612cfef48a76d23c0edfde7b66005bb458` |
| crosscloud:azure:automated_exfiltration:additional:run-4:y | additional | 4 | payload_present | 41 | `4a7d41daded52541d8d649d5f90801afa9059dc75c4fada79231b8463353622f` |
| crosscloud:azure:automated_exfiltration:additional:run-5:n | additional | 5 | payload_absent | 25 | `d520b1f0392c9d404450d3becc42fa3b0bff2d66bff37152750ef89f0833e45c` |
| crosscloud:azure:automated_exfiltration:additional:run-5:y | additional | 5 | payload_present | 41 | `1b49b96e96fb4446468fc8ab9ffb225def4e407e38fbdc872056c36f17419374` |
| crosscloud:azure:automated_exfiltration:additional:run-6:n | additional | 6 | payload_absent | 23 | `94e39678566a3e6a1a635ba3289c1492624d4d37db90b780a2eaae1404f23b63` |
| crosscloud:azure:automated_exfiltration:additional:run-6:y | additional | 6 | payload_present | 32 | `2325e983aab4ed017bdf24e1ab001d96d704311619321a324a560e96f76fb343` |
| crosscloud:azure:automated_exfiltration:additional:run-7:n | additional | 7 | payload_absent | 25 | `89feeeb63e0cf854743914b7e5ebf70dee3b5e48ed4be6a22f4531b00bdd99a1` |
| crosscloud:azure:automated_exfiltration:additional:run-7:y | additional | 7 | payload_present | 42 | `8f3a012ae59981c252e88bb081d3ccd47e19eea07dcbcffeb5dfe61822ff8689` |
| crosscloud:azure:automated_exfiltration:additional:run-8:n | additional | 8 | payload_absent | 25 | `d354761c07c0f260bba810e664dff2205095172ff4ba0faa3e082563677257e8` |
| crosscloud:azure:automated_exfiltration:additional:run-8:y | additional | 8 | payload_present | 38 | `5796583cb8e05e9cb677693c22d32e5f564e47b8c3e08d72d9ebbf28f8dea538` |
| crosscloud:azure:automated_exfiltration:additional:run-9:n | additional | 9 | payload_absent | 26 | `5dcc8b2e0adc9e3b319f2b4cb1b322c694f9d4f4b6e371317dbfe2429137988e` |
| crosscloud:azure:automated_exfiltration:additional:run-9:y | additional | 9 | payload_present | 39 | `757953575dc5dc010ce19ff158d4c2193c1ce94413d12f4278134d00ff9271ef` |
| crosscloud:azure:automated_exfiltration:default:run-0:n | default | 0 | payload_absent | 18 | `5a6d1bd4040bce1e4e31c92a8d99f195ecae572a49dafb604c7aba8c652b88d8` |
| crosscloud:azure:automated_exfiltration:default:run-0:y | default | 0 | payload_present | 31 | `6bd057d4686a28c0e972ac3426fee65d1116621ceb37ee9c70c8ded13dccd7dd` |
| crosscloud:azure:automated_exfiltration:default:run-1:n | default | 1 | payload_absent | 17 | `0b2f925deb4af9cba9ba510373644d3f5b7d15d17971ad659e5ff8394ec7e5b4` |
| crosscloud:azure:automated_exfiltration:default:run-1:y | default | 1 | payload_present | 35 | `fbef40f35900fa6b29c9c34c4c807b2bd60ce93a35a72df6dabc79b539a9fd76` |
| crosscloud:azure:automated_exfiltration:default:run-2:n | default | 2 | payload_absent | 17 | `cf05ed0f1592c1bb7d8d008f7d7fa57b378c17ae9ffa89b9880f42274221dc7d` |
| crosscloud:azure:automated_exfiltration:default:run-2:y | default | 2 | payload_present | 33 | `c5cd04b4b4d14f63213759d168ce4f31dc7c54aab7352cf9866843d7b762235e` |
| crosscloud:azure:automated_exfiltration:default:run-3:n | default | 3 | payload_absent | 17 | `694f4afde96e219a75bdf18446df0c66a7577a5a98cc4fe80fc23af70f0ec411` |
| crosscloud:azure:automated_exfiltration:default:run-3:y | default | 3 | payload_present | 28 | `f6099e5c606742716c4e4e9bcfc44e18dd03f2ce80703fbecec8285bbb58b369` |
| crosscloud:azure:automated_exfiltration:default:run-4:n | default | 4 | payload_absent | 16 | `9ec7420fa40813bbc5531c877e6a9c513a36475bac0a4b0056f3caaca7ecb102` |
| crosscloud:azure:automated_exfiltration:default:run-4:y | default | 4 | payload_present | 32 | `d56c2cdc7ab9900c03fbbc5e2a5173b811ae13f615da52db63717576def925c2` |
| crosscloud:azure:automated_exfiltration:default:run-5:n | default | 5 | payload_absent | 17 | `014dab6b4173b0177b4c4f06cdb101c958fbb9152d7cc0af8d201b74590bf117` |
| crosscloud:azure:automated_exfiltration:default:run-5:y | default | 5 | payload_present | 31 | `2c92e5ae5435a5a318b885acb17e869b3fffb69c22c2c520eb25249da447ce50` |
| crosscloud:azure:automated_exfiltration:default:run-6:n | default | 6 | payload_absent | 17 | `9e7060337c9baf7b1038300e04085135ef4c19c276360f41bbc37f4d9560e3a7` |
| crosscloud:azure:automated_exfiltration:default:run-6:y | default | 6 | payload_present | 33 | `5eabfdb8bb9c35306b70f26341f6df55b58c9a71d84c8c5f1b103f444a969f57` |
| crosscloud:azure:automated_exfiltration:default:run-7:n | default | 7 | payload_absent | 17 | `a6ccc8c806b0b5b39b9fc562386d753e559cc9e0e383becc711141767ff19cb2` |
| crosscloud:azure:automated_exfiltration:default:run-7:y | default | 7 | payload_present | 32 | `1e89a6d8ecd04269c630f01e66244d200955368d30b2c7f762d51edd89b4aab0` |
| crosscloud:azure:automated_exfiltration:default:run-8:n | default | 8 | payload_absent | 17 | `37a37c9f394981c48a53c93b4ac70ae83918dff5d9f21393c93abb0163117e77` |
| crosscloud:azure:automated_exfiltration:default:run-8:y | default | 8 | payload_present | 31 | `39bb61bd1a329ca113502965e7e4b5b3cb6f8a3f26e0e77ac262af4ad759c476` |
| crosscloud:azure:automated_exfiltration:default:run-9:n | default | 9 | payload_absent | 17 | `88de65d0153df2488f35eb2e9ac7634d73b790c3d4b69c870bcf52fe669c91af` |
| crosscloud:azure:automated_exfiltration:default:run-9:y | default | 9 | payload_present | 33 | `bee3e19f7f06afa7f50eea603c0a2515fa07edc772c4903965714cc5e9d6f1b5` |

### 原始文件完整性

- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/README.md` — SHA-256 `b073b2e97aea4073fec2bf387e2c255d987dd8f3710e84f2df3cc59947e510f8`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/attack_scripts.zip` — SHA-256 `4599be3e224f3b9b43e76ab4ec1bfa8e3b209ebe529fb218ae4e65dd22417900`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/azure_logs_redacted.zip` — SHA-256 `5a94d05e4877593bad1602a68a6f4e775f72323e9e408ae0d0480d7126789dee`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/log_analysis.zip` — SHA-256 `23b41863cc2ece4936277a1ee1fc6f64b4fea9f3c0f698cefbf5626eeca00fcf`

## 25. `crosscloud:azure:credentials_from_password_stores`

- 描述：DOI-published paired payload/no-payload AZURE telemetry for credentials_from_password_stores.
- 发布者：Dhooghe et al.
- 发布日期：2026-04-30
- 环境：controlled cloud subscription
- ATT&CK：
- 原始文件数：4
- 规范化观测数：0
- 上游 episode 数：40

### 准入判断（人工填写）

- [ ] 有外部或低权限入口
- [ ] 存在多步关系，而非单点事件
- [ ] 终点为数据库、存储、备份、secret 或其他数据资产
- [ ] 关键边均有原始证据
- [ ] 不是近重复案例
- 决定：`<accept | needs_execution | reject>`
- 理由：`<人工填写>`

### 观测索引

| observation_id | timestamp | actor_type | service | operation | status | raw record |
|---|---:|---|---|---|---|---|

### 上游配对 episode

| episode_id | profile | run | source condition | observations | member SHA-256 |
|---|---|---:|---|---:|---|
| crosscloud:azure:credentials_from_password_stores:additional:run-0:n | additional | 0 | payload_absent | 12 | `4de6ae04a44fc6e5f141c80b486a94be3e3897ff9c2268ea7aa5c3a0fcada7be` |
| crosscloud:azure:credentials_from_password_stores:additional:run-0:y | additional | 0 | payload_present | 12 | `bf05675442b3288fc8c8f21001eb7bd08a5a77949399de8e29c8c6520e73ebd6` |
| crosscloud:azure:credentials_from_password_stores:additional:run-1:n | additional | 1 | payload_absent | 12 | `057117eaa7e108ac33fdd2f00e61721e18240511b334a310f1d55c729f9b7930` |
| crosscloud:azure:credentials_from_password_stores:additional:run-1:y | additional | 1 | payload_present | 12 | `3a7d662c74f97c2d66f9f324c5e0eb098e054561e114c16f287b44fb3563c4d0` |
| crosscloud:azure:credentials_from_password_stores:additional:run-2:n | additional | 2 | payload_absent | 12 | `75e66d6b5a1ea7637727342c43b0aae06381a2fbd2fcebeceffa85763b1d4a71` |
| crosscloud:azure:credentials_from_password_stores:additional:run-2:y | additional | 2 | payload_present | 12 | `6a09d32194f7b4e26e1e2c4d4680dc274f803b6f60ac3f0bb38bd71385eca43b` |
| crosscloud:azure:credentials_from_password_stores:additional:run-3:n | additional | 3 | payload_absent | 12 | `e7aa7a023ea47cad50bd0a4d19a7457f4709bcab5ecaf110fb0d6d9fc91ddf36` |
| crosscloud:azure:credentials_from_password_stores:additional:run-3:y | additional | 3 | payload_present | 12 | `b36fab3f84d34568250b1e6e367ed44f3208c1f7e7de25ccb7f33e40565aef65` |
| crosscloud:azure:credentials_from_password_stores:additional:run-4:n | additional | 4 | payload_absent | 12 | `74829fa6a6dd1ec5e61cc7d56f67595a38a675005323ada1b8f7fb303bbb17f8` |
| crosscloud:azure:credentials_from_password_stores:additional:run-4:y | additional | 4 | payload_present | 12 | `68b74e0d9f74971ea5b7152fd7215395c3be644048de0ea913dcdacf05c7df57` |
| crosscloud:azure:credentials_from_password_stores:additional:run-5:n | additional | 5 | payload_absent | 14 | `777710cfaaf506a780fa06fae5fa33f693dd0bb9336845809e42465ce978d371` |
| crosscloud:azure:credentials_from_password_stores:additional:run-5:y | additional | 5 | payload_present | 12 | `579e64b6b25a6d40358806e18d058665d3b78ca8a95aaa9f95a49ea5af4cc8e4` |
| crosscloud:azure:credentials_from_password_stores:additional:run-6:n | additional | 6 | payload_absent | 12 | `49eb457323a757d8423f17c5858ff733b0b566c337de2b7deca6fb5fb68b0ab0` |
| crosscloud:azure:credentials_from_password_stores:additional:run-6:y | additional | 6 | payload_present | 12 | `05021bc7cd129274f25b4540b2e17a26d25d5f5c0ba5690282ce6c417d0ea6b7` |
| crosscloud:azure:credentials_from_password_stores:additional:run-7:n | additional | 7 | payload_absent | 12 | `4b569c5cf2ba192aa55c6619440d604fc01ad61f124355ee0e1c13aef7a6133e` |
| crosscloud:azure:credentials_from_password_stores:additional:run-7:y | additional | 7 | payload_present | 12 | `27c74a389b20b5354e0d03fe8c9eba647ea47cbdf7164fe0189185bf181a5fe5` |
| crosscloud:azure:credentials_from_password_stores:additional:run-8:n | additional | 8 | payload_absent | 12 | `39c55323f0fe7a1aaa522dfb60a1b8200b8a47c3778f7cb724efba0171b93027` |
| crosscloud:azure:credentials_from_password_stores:additional:run-8:y | additional | 8 | payload_present | 12 | `bbe05e021c6fd5a13cc187bd0ef00f3b446f24cee3fc228ca180284af1d88c0e` |
| crosscloud:azure:credentials_from_password_stores:additional:run-9:n | additional | 9 | payload_absent | 12 | `4b436bf1dfaf270f846f1d518bfc2987a71f77940e0a80fb5bd2854af0711336` |
| crosscloud:azure:credentials_from_password_stores:additional:run-9:y | additional | 9 | payload_present | 12 | `e616fa9b64d58357e1d9f490184437dd88bdeac79573ff1531e17f1dfecf642f` |
| crosscloud:azure:credentials_from_password_stores:default:run-0:n | default | 0 | payload_absent | 14 | `e82a33a25af91e24e2e631af6b5e9e7d9a9bc4d7d87d38067751289cd7882c39` |
| crosscloud:azure:credentials_from_password_stores:default:run-0:y | default | 0 | payload_present | 14 | `b839a44d6d9e75f89c47ac1866a9869734a79f49d1041e5736fca5e73c3935a8` |
| crosscloud:azure:credentials_from_password_stores:default:run-1:n | default | 1 | payload_absent | 14 | `da24cfb6d15827f0d7142fb4f83d0f3016534d975584f7918dc81d6874effb56` |
| crosscloud:azure:credentials_from_password_stores:default:run-1:y | default | 1 | payload_present | 14 | `40782135bd2e480212eeb5ebdf25cbab28ef8dd018ea6efb81d5b6bf7985dd1a` |
| crosscloud:azure:credentials_from_password_stores:default:run-2:n | default | 2 | payload_absent | 14 | `9dda9532e51c941202db538f4ca098dce9699bbf54567968d0392798752cec1f` |
| crosscloud:azure:credentials_from_password_stores:default:run-2:y | default | 2 | payload_present | 14 | `d7961d2780bd74f7b6192442cb00ede4cdd1c7ed2951314490b12cc6dea43a4f` |
| crosscloud:azure:credentials_from_password_stores:default:run-3:n | default | 3 | payload_absent | 14 | `801ee4f446782101be2c8945ad65a5c9d794074a19a1f3145b392084cff4e27a` |
| crosscloud:azure:credentials_from_password_stores:default:run-3:y | default | 3 | payload_present | 14 | `fbcab3121d7985b0d954fafc211b151b28abd8b7048e126716dada6003b1feb0` |
| crosscloud:azure:credentials_from_password_stores:default:run-4:n | default | 4 | payload_absent | 14 | `8428e7c4e02364f6c3463b5e8732264d59371b853de2b7e3f9e7923b858e2975` |
| crosscloud:azure:credentials_from_password_stores:default:run-4:y | default | 4 | payload_present | 14 | `f2f3797e84ade30f55b0442e3a58f8235c25adbab63329da05e48ee0c127743c` |
| crosscloud:azure:credentials_from_password_stores:default:run-5:n | default | 5 | payload_absent | 12 | `6863c5fa75cc78068f1fb44abf233f9d7181dc021119be901d9c0cdc6b598aba` |
| crosscloud:azure:credentials_from_password_stores:default:run-5:y | default | 5 | payload_present | 14 | `7f7fa648a8e78138de43ba336f4be1513e7d44ddd5fa92cff4abe7fb991971b6` |
| crosscloud:azure:credentials_from_password_stores:default:run-6:n | default | 6 | payload_absent | 14 | `d4e514db2c9c248f37331ab2dd8198475ff4a8cd07c504bffb54d32e4cc3b324` |
| crosscloud:azure:credentials_from_password_stores:default:run-6:y | default | 6 | payload_present | 14 | `a3c28830e326bebe0c479466e1e8961ec14487c9b49f700e952541610e243f23` |
| crosscloud:azure:credentials_from_password_stores:default:run-7:n | default | 7 | payload_absent | 14 | `8e4399412beeb7d2ff8c321f47c6c802320882a5ada76224f115ebc17d132298` |
| crosscloud:azure:credentials_from_password_stores:default:run-7:y | default | 7 | payload_present | 14 | `0ae1e67e108a54d1c35cdc1b36399bac75a69b5d768dfcde92ba69382bf5e453` |
| crosscloud:azure:credentials_from_password_stores:default:run-8:n | default | 8 | payload_absent | 14 | `e171f3ba181e69dcff839e17b1dd7f8f4e3fc09116c95a0edbd2b9c8944183d9` |
| crosscloud:azure:credentials_from_password_stores:default:run-8:y | default | 8 | payload_present | 14 | `4389707a1c9d740d564ab7d2cb91b571a02309a2db23d09685f95c832f7a512b` |
| crosscloud:azure:credentials_from_password_stores:default:run-9:n | default | 9 | payload_absent | 14 | `f749014caaf15249d62310add2c37a0335f91edacb3fe1d345777297f2e16948` |
| crosscloud:azure:credentials_from_password_stores:default:run-9:y | default | 9 | payload_present | 14 | `38f8ed0d6e5a7abc16919fc208927c6688bc49dfa03ae3137622bb8ab99a3eda` |

### 原始文件完整性

- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/README.md` — SHA-256 `b073b2e97aea4073fec2bf387e2c255d987dd8f3710e84f2df3cc59947e510f8`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/attack_scripts.zip` — SHA-256 `4599be3e224f3b9b43e76ab4ec1bfa8e3b209ebe529fb218ae4e65dd22417900`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/azure_logs_redacted.zip` — SHA-256 `5a94d05e4877593bad1602a68a6f4e775f72323e9e408ae0d0480d7126789dee`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/log_analysis.zip` — SHA-256 `23b41863cc2ece4936277a1ee1fc6f64b4fea9f3c0f698cefbf5626eeca00fcf`

## 26. `crosscloud:azure:data_destruction`

- 描述：DOI-published paired payload/no-payload AZURE telemetry for data_destruction.
- 发布者：Dhooghe et al.
- 发布日期：2026-04-30
- 环境：controlled cloud subscription
- ATT&CK：
- 原始文件数：4
- 规范化观测数：0
- 上游 episode 数：40

### 准入判断（人工填写）

- [ ] 有外部或低权限入口
- [ ] 存在多步关系，而非单点事件
- [ ] 终点为数据库、存储、备份、secret 或其他数据资产
- [ ] 关键边均有原始证据
- [ ] 不是近重复案例
- 决定：`<accept | needs_execution | reject>`
- 理由：`<人工填写>`

### 观测索引

| observation_id | timestamp | actor_type | service | operation | status | raw record |
|---|---:|---|---|---|---|---|

### 上游配对 episode

| episode_id | profile | run | source condition | observations | member SHA-256 |
|---|---|---:|---|---:|---|
| crosscloud:azure:data_destruction:additional:run-0:n | additional | 0 | payload_absent | 22 | `3f5132c3bf1274fb609c2d0ed37e0f1636d5594e0ae766c9dde40f64d3fadc75` |
| crosscloud:azure:data_destruction:additional:run-0:y | additional | 0 | payload_present | 22 | `538a40249446861076b41d2861bc9f4c9cc7983204d88cfc85d754db132ec61a` |
| crosscloud:azure:data_destruction:additional:run-1:n | additional | 1 | payload_absent | 22 | `92aed520bcceb23e5d53ecd2bd5b485a9d605e76ae75010a9fc5770ea85083e6` |
| crosscloud:azure:data_destruction:additional:run-1:y | additional | 1 | payload_present | 22 | `336bf7a1f5953b47458d8a2383e9d06c5888cca5ced1affb9c6389c4b5704258` |
| crosscloud:azure:data_destruction:additional:run-2:n | additional | 2 | payload_absent | 20 | `7ab680de214832c544d1b4a103d4fa253fd955af58001138cc18dfb8d6f20696` |
| crosscloud:azure:data_destruction:additional:run-2:y | additional | 2 | payload_present | 21 | `40271fd2f174dee5b4f37424ae879c4ac853fd5d04a18f5b719603fd8077cd19` |
| crosscloud:azure:data_destruction:additional:run-3:n | additional | 3 | payload_absent | 19 | `9e821d994f8cf6122bbde0577ccb2231c857694adf450f7fa968a0b6a644b4e8` |
| crosscloud:azure:data_destruction:additional:run-3:y | additional | 3 | payload_present | 21 | `f2a45eaf6b2964c58b60b5f866b4f948c1d150437f318dc4ea366e4d7d1204db` |
| crosscloud:azure:data_destruction:additional:run-4:n | additional | 4 | payload_absent | 22 | `da497a965469d2ee6880fc10b2de2f11f6d367d7a49a509318644cb7925d2e29` |
| crosscloud:azure:data_destruction:additional:run-4:y | additional | 4 | payload_present | 22 | `b48a5b61cec13312d113d38a66ec23f4dfc6d297b8a5d41372f8779991edeffd` |
| crosscloud:azure:data_destruction:additional:run-5:n | additional | 5 | payload_absent | 21 | `a928042b5dbc76fe98118e0a0e137fafc6b463d1cececb03e3b798fbd147314e` |
| crosscloud:azure:data_destruction:additional:run-5:y | additional | 5 | payload_present | 21 | `007bfa0976521b750edf1fab0744190283085db39cd5e9d0806ffe993f3ee9d5` |
| crosscloud:azure:data_destruction:additional:run-6:n | additional | 6 | payload_absent | 21 | `1de5a4068a6c4b6d853025f45ff0abb4e00678e09e0a0f85203681b45c97b087` |
| crosscloud:azure:data_destruction:additional:run-6:y | additional | 6 | payload_present | 22 | `c12406d6c2d32d137a1affc2fc5db81cb27f34ab53d2ad3ec8392833c58818e9` |
| crosscloud:azure:data_destruction:additional:run-7:n | additional | 7 | payload_absent | 21 | `f2cc056959329ab041e2e96aeae7d9b09a920435b407582a0f31e12669bacb5d` |
| crosscloud:azure:data_destruction:additional:run-7:y | additional | 7 | payload_present | 21 | `fe7e075202f6431a14d493b46a219c2c495a6e8e9c819d40afa359524d27dd8d` |
| crosscloud:azure:data_destruction:additional:run-8:n | additional | 8 | payload_absent | 21 | `b83114971c34c8ab0e4bcaf373a48d54cfa2fc05e022af876c84505cb30b598d` |
| crosscloud:azure:data_destruction:additional:run-8:y | additional | 8 | payload_present | 21 | `4efb34c9e6af4448ee86c32f56a1073c01f25af7e43d35a28e12a82fc4124ef5` |
| crosscloud:azure:data_destruction:additional:run-9:n | additional | 9 | payload_absent | 19 | `6244654576e64a8cd77a6d6075acdcc71cc99fca7207661349bab9b62207d9b0` |
| crosscloud:azure:data_destruction:additional:run-9:y | additional | 9 | payload_present | 22 | `39f24c8a8cecf5b769cb611426e7ba561e6f474567e50f585ae4c74ea8b65b12` |
| crosscloud:azure:data_destruction:default:run-0:n | default | 0 | payload_absent | 13 | `ca1da0e78bc2fcf04e8f101e1600e8c4e918bdd692c3cf88d6217357c3f4c7e3` |
| crosscloud:azure:data_destruction:default:run-0:y | default | 0 | payload_present | 15 | `bfc78b055094a1f2e5b3d10b32566017168cf5bac66aba3f6e0a3ca0b75d4ce6` |
| crosscloud:azure:data_destruction:default:run-1:n | default | 1 | payload_absent | 13 | `f3e81119221d67fe69a8976f71f3b2adabbda205883be9dbcc424ed9f54306dd` |
| crosscloud:azure:data_destruction:default:run-1:y | default | 1 | payload_present | 16 | `1dab08f4e7a2b5362a386e4aa15af877fc8701defffdb323807c14977074f4ba` |
| crosscloud:azure:data_destruction:default:run-2:n | default | 2 | payload_absent | 14 | `760a1e8b1a71beb4f7a536bd99006a908536fc05d46d8c2418598aa5eb53ccbc` |
| crosscloud:azure:data_destruction:default:run-2:y | default | 2 | payload_present | 13 | `b1f866938a261fa5012c2d5f46819b637409add0dce431f62e447d5e1c3efabc` |
| crosscloud:azure:data_destruction:default:run-3:n | default | 3 | payload_absent | 13 | `f3314d324ba0b2211bd46cae1f03017653afd574c5a94b6cb9bc5208ed04ab72` |
| crosscloud:azure:data_destruction:default:run-3:y | default | 3 | payload_present | 16 | `95d41184b2a4504209f0af4bcae16f98b899f36f7fac2ca7e3a5aea6367d884d` |
| crosscloud:azure:data_destruction:default:run-4:n | default | 4 | payload_absent | 50 | `128baf5e2ea052716b3ee237ab7ced7a3c66bb56f0551ccb02bcdd5b8d3d5203` |
| crosscloud:azure:data_destruction:default:run-4:y | default | 4 | payload_present | 13 | `d1b59ca07cd0615205a78ee205300b6757f3bb90b2cc92d9c526196f1f5e4c85` |
| crosscloud:azure:data_destruction:default:run-5:n | default | 5 | payload_absent | 13 | `835e48a549a0f058f07d3c2f80aeb47f3bb6360d23a9ae27789401b340678473` |
| crosscloud:azure:data_destruction:default:run-5:y | default | 5 | payload_present | 13 | `4feaf57885ef104a64b25bb037b1287b1221f7705123323001f96544551a5921` |
| crosscloud:azure:data_destruction:default:run-6:n | default | 6 | payload_absent | 13 | `ed0ec46f84622a6ef9a07522870ff5a7caba4e67714a3410e8ce406bfff312d3` |
| crosscloud:azure:data_destruction:default:run-6:y | default | 6 | payload_present | 13 | `5732f8c97000499aba6cdfda423bfa4d4d2c1d63e9dd64387c7b4d1fe3246f61` |
| crosscloud:azure:data_destruction:default:run-7:n | default | 7 | payload_absent | 13 | `677f0ed0be64ab4cac8991996892a01ae54573c13c6cfa7c393faa42044d7ab0` |
| crosscloud:azure:data_destruction:default:run-7:y | default | 7 | payload_present | 16 | `63a0950b0fb491cc532ba1e1ad4cf53201a93a3fe4fc6d5b06bc93622a347f62` |
| crosscloud:azure:data_destruction:default:run-8:n | default | 8 | payload_absent | 15 | `35e90a0a8e82639c0623d3a29daa76d30bd7514839b9ae71836b0375ed7bd737` |
| crosscloud:azure:data_destruction:default:run-8:y | default | 8 | payload_present | 15 | `2e82c4c96879e4bd7e45a1f8f6eb7dd3ce2352df3bf86412f4e1e9a591ea18b6` |
| crosscloud:azure:data_destruction:default:run-9:n | default | 9 | payload_absent | 13 | `5de187926c1c8a4a8b814d55560248cb53b6af9c558c9686b8b5f11238612415` |
| crosscloud:azure:data_destruction:default:run-9:y | default | 9 | payload_present | 13 | `3659616e928267c0937d3c5196605d1bfd7d5e7631d2ffc6451cc87804a947a5` |

### 原始文件完整性

- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/README.md` — SHA-256 `b073b2e97aea4073fec2bf387e2c255d987dd8f3710e84f2df3cc59947e510f8`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/attack_scripts.zip` — SHA-256 `4599be3e224f3b9b43e76ab4ec1bfa8e3b209ebe529fb218ae4e65dd22417900`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/azure_logs_redacted.zip` — SHA-256 `5a94d05e4877593bad1602a68a6f4e775f72323e9e408ae0d0480d7126789dee`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/log_analysis.zip` — SHA-256 `23b41863cc2ece4936277a1ee1fc6f64b4fea9f3c0f698cefbf5626eeca00fcf`

## 27. `crosscloud:azure:data_encrypted_for_impact`

- 描述：DOI-published paired payload/no-payload AZURE telemetry for data_encrypted_for_impact.
- 发布者：Dhooghe et al.
- 发布日期：2026-04-30
- 环境：controlled cloud subscription
- ATT&CK：
- 原始文件数：4
- 规范化观测数：0
- 上游 episode 数：40

### 准入判断（人工填写）

- [ ] 有外部或低权限入口
- [ ] 存在多步关系，而非单点事件
- [ ] 终点为数据库、存储、备份、secret 或其他数据资产
- [ ] 关键边均有原始证据
- [ ] 不是近重复案例
- 决定：`<accept | needs_execution | reject>`
- 理由：`<人工填写>`

### 观测索引

| observation_id | timestamp | actor_type | service | operation | status | raw record |
|---|---:|---|---|---|---|---|

### 上游配对 episode

| episode_id | profile | run | source condition | observations | member SHA-256 |
|---|---|---:|---|---:|---|
| crosscloud:azure:data_encrypted_for_impact:additional:run-0:n | additional | 0 | payload_absent | 19 | `edb43474f0cbe49ee12d5ccbeb6a7f1b994163bcb3f9ee8dac377b73a98c31a4` |
| crosscloud:azure:data_encrypted_for_impact:additional:run-0:y | additional | 0 | payload_present | 19 | `bc61ffd05cfe6d73fa6202e1f247c1dd86ac6c063bbd47eb3c60c769e2cff46c` |
| crosscloud:azure:data_encrypted_for_impact:additional:run-1:n | additional | 1 | payload_absent | 20 | `be7f69e4860519e44180562b985fd18bb2ee91ea67eb657ec7310ffb89b1f428` |
| crosscloud:azure:data_encrypted_for_impact:additional:run-1:y | additional | 1 | payload_present | 20 | `fa8493a1cce51bab95f065c72cb16fdfc75f82673e85f5c6254fa93ffb12a28c` |
| crosscloud:azure:data_encrypted_for_impact:additional:run-2:n | additional | 2 | payload_absent | 18 | `96a518493d2834d6dee8613bdcfe38c40fbf900a6ea8294a480d18c6165bf8bf` |
| crosscloud:azure:data_encrypted_for_impact:additional:run-2:y | additional | 2 | payload_present | 21 | `d54f9ec670628d343db48b1d4ef97ac3d77f87150f2c10bbb1ae5eab6512fcfe` |
| crosscloud:azure:data_encrypted_for_impact:additional:run-3:n | additional | 3 | payload_absent | 20 | `620dae92abf0fcae3865f815afff6fa21cedd08c846bdc18b24fc52686900094` |
| crosscloud:azure:data_encrypted_for_impact:additional:run-3:y | additional | 3 | payload_present | 21 | `0cbf4b745ef010d5783d2cf16e313d0236eefc0374f9d62a13f2d83cb40e78b1` |
| crosscloud:azure:data_encrypted_for_impact:additional:run-4:n | additional | 4 | payload_absent | 19 | `8666a72ec54b21b65a7aedb4f0613345b1265891a7eb6cf4de1cc92052d42ccf` |
| crosscloud:azure:data_encrypted_for_impact:additional:run-4:y | additional | 4 | payload_present | 21 | `ab63b6f30b273b60bcf90c718a90b499752b8879c8fda2d5142f64840c1de0e6` |
| crosscloud:azure:data_encrypted_for_impact:additional:run-5:n | additional | 5 | payload_absent | 19 | `caacc67e695294da8308c5b583dca243ad9ab9157b2fc0ddf5eed29b24023723` |
| crosscloud:azure:data_encrypted_for_impact:additional:run-5:y | additional | 5 | payload_present | 19 | `0f20124d45685cd54a79d552446a7be86819ebc5bf75af2b8cfdf432d67c6772` |
| crosscloud:azure:data_encrypted_for_impact:additional:run-6:n | additional | 6 | payload_absent | 17 | `e2babefbfd6dfd5e0f58d19e3065404b033cd5e24531d2041242046fb66fd024` |
| crosscloud:azure:data_encrypted_for_impact:additional:run-6:y | additional | 6 | payload_present | 19 | `e6f84b99cb77f0d7800d9f340edd5dbc7acbd39da99d59cc524ce231f939b558` |
| crosscloud:azure:data_encrypted_for_impact:additional:run-7:n | additional | 7 | payload_absent | 19 | `682ddd3d33d03d12acd3e9eaf49e2b10740d30e5ab44bb9baf11dddad8948baa` |
| crosscloud:azure:data_encrypted_for_impact:additional:run-7:y | additional | 7 | payload_present | 21 | `e4c8ee0b247b6a16f6dbfe5b6fde41d3277a940e2b23598c139dcc04da6ea530` |
| crosscloud:azure:data_encrypted_for_impact:additional:run-8:n | additional | 8 | payload_absent | 19 | `fa6b051ff8e5b2031b6cc24ca72c604d1f5377b79c8a4942de068cd104f8a867` |
| crosscloud:azure:data_encrypted_for_impact:additional:run-8:y | additional | 8 | payload_present | 19 | `eb8ac4ae6d79dcb6764112975d0a3bb604e06eeeb2f8ad681b6d72865cab223e` |
| crosscloud:azure:data_encrypted_for_impact:additional:run-9:n | additional | 9 | payload_absent | 18 | `7893b23bd0369aa64a591da8789ec43b05cb1d3f015bd846e6c5c3a7af4b672a` |
| crosscloud:azure:data_encrypted_for_impact:additional:run-9:y | additional | 9 | payload_present | 21 | `73cbe534bed0faef28ffca1d6aa19a225fc131db33d33c2bd84fb692692d0e6d` |
| crosscloud:azure:data_encrypted_for_impact:default:run-0:n | default | 0 | payload_absent | 21 | `19e44fe83b7b2a900e39f78788a4dee61fb9b3f958298fcd8626267ade9b3f04` |
| crosscloud:azure:data_encrypted_for_impact:default:run-0:y | default | 0 | payload_present | 13 | `ac7c07fcc18d42425a13326561ddce7a56a8c82e32b6f7da7f8e7b5baf23bf83` |
| crosscloud:azure:data_encrypted_for_impact:default:run-1:n | default | 1 | payload_absent | 11 | `4fc63d12d3d0ff3f90cd3f8463472e37bbbf3215cedf272e2eec277eb3ce3959` |
| crosscloud:azure:data_encrypted_for_impact:default:run-1:y | default | 1 | payload_present | 13 | `49ad155cf80cc60392f9338f1d52f0afb5944f788647c2433cf3ae42fe78b980` |
| crosscloud:azure:data_encrypted_for_impact:default:run-2:n | default | 2 | payload_absent | 16 | `3c4795d1a4f54e54c493df47ef194d1c5c8f0c05ce54d309adc7b05b8f155c50` |
| crosscloud:azure:data_encrypted_for_impact:default:run-2:y | default | 2 | payload_present | 13 | `6acc887e1380fb7197eff836d9a7322f1f71a7336360d605ab1f31ceb71b496e` |
| crosscloud:azure:data_encrypted_for_impact:default:run-3:n | default | 3 | payload_absent | 13 | `8411afce98ce856a30d0304ee275d16355efd767d1c2b6d3c31481b80d4f263f` |
| crosscloud:azure:data_encrypted_for_impact:default:run-3:y | default | 3 | payload_present | 13 | `e207712ad71cbbd5e75175d50316bc2b888a371657dd06dfbe3105785622126b` |
| crosscloud:azure:data_encrypted_for_impact:default:run-4:n | default | 4 | payload_absent | 10 | `b83f553a971c60b33eb32fe0e5748c1f82afd5fa2d9af0d9f3a8bfcd19122808` |
| crosscloud:azure:data_encrypted_for_impact:default:run-4:y | default | 4 | payload_present | 13 | `1c009f3f61ee55cd965c016dba25813d8f8ce87e4c763507fb72984a4b8c6d9d` |
| crosscloud:azure:data_encrypted_for_impact:default:run-5:n | default | 5 | payload_absent | 12 | `698aaf483287208eb5ad218a99eb8697b1e48420f906a60ba0475a1e5b87735f` |
| crosscloud:azure:data_encrypted_for_impact:default:run-5:y | default | 5 | payload_present | 13 | `d9f91c22ccae48740f69e111ba22dc87e34b68d356d7005ffcd6c962b95b222c` |
| crosscloud:azure:data_encrypted_for_impact:default:run-6:n | default | 6 | payload_absent | 13 | `4e032a4d66ab8916040eb4b9dad240502fefbbc044978e8fe72f38c481b3696f` |
| crosscloud:azure:data_encrypted_for_impact:default:run-6:y | default | 6 | payload_present | 13 | `9af07c555da507fb56a88e8a07703297caa8326d2f1265aa152b94fd0893f134` |
| crosscloud:azure:data_encrypted_for_impact:default:run-7:n | default | 7 | payload_absent | 11 | `8909e48e9e046edb326f56148cf59af08af62754bbc43c0d0af6d78bdadde4f3` |
| crosscloud:azure:data_encrypted_for_impact:default:run-7:y | default | 7 | payload_present | 13 | `fcecdc9952222815271fd9841f058701b38d20fbeb68663623e64f52e51e5be9` |
| crosscloud:azure:data_encrypted_for_impact:default:run-8:n | default | 8 | payload_absent | 11 | `3962838e0b92c731634fa9a62f614c511e4958491f56c8a39a263a233b27e5af` |
| crosscloud:azure:data_encrypted_for_impact:default:run-8:y | default | 8 | payload_present | 13 | `9d21b53f99845c7440b1b782c8f19874a4b9c7160d17ab260e7807b788127e19` |
| crosscloud:azure:data_encrypted_for_impact:default:run-9:n | default | 9 | payload_absent | 13 | `47615d813cf0c431fe802cddf67cd1ab80b791129682e380830e31a5a3a5edf8` |
| crosscloud:azure:data_encrypted_for_impact:default:run-9:y | default | 9 | payload_present | 13 | `e2b29cc0472da4caba4262ea6091effa529e41d090024579f40575584aa741ac` |

### 原始文件完整性

- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/README.md` — SHA-256 `b073b2e97aea4073fec2bf387e2c255d987dd8f3710e84f2df3cc59947e510f8`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/attack_scripts.zip` — SHA-256 `4599be3e224f3b9b43e76ab4ec1bfa8e3b209ebe529fb218ae4e65dd22417900`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/azure_logs_redacted.zip` — SHA-256 `5a94d05e4877593bad1602a68a6f4e775f72323e9e408ae0d0480d7126789dee`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/log_analysis.zip` — SHA-256 `23b41863cc2ece4936277a1ee1fc6f64b4fea9f3c0f698cefbf5626eeca00fcf`

## 28. `crosscloud:azure:data_manipulation`

- 描述：DOI-published paired payload/no-payload AZURE telemetry for data_manipulation.
- 发布者：Dhooghe et al.
- 发布日期：2026-04-30
- 环境：controlled cloud subscription
- ATT&CK：
- 原始文件数：4
- 规范化观测数：0
- 上游 episode 数：40

### 准入判断（人工填写）

- [ ] 有外部或低权限入口
- [ ] 存在多步关系，而非单点事件
- [ ] 终点为数据库、存储、备份、secret 或其他数据资产
- [ ] 关键边均有原始证据
- [ ] 不是近重复案例
- 决定：`<accept | needs_execution | reject>`
- 理由：`<人工填写>`

### 观测索引

| observation_id | timestamp | actor_type | service | operation | status | raw record |
|---|---:|---|---|---|---|---|

### 上游配对 episode

| episode_id | profile | run | source condition | observations | member SHA-256 |
|---|---|---:|---|---:|---|
| crosscloud:azure:data_manipulation:additional:run-0:n | additional | 0 | payload_absent | 20 | `f7dcb40de2907f077d4576c38ac695bad654356f0117fb9720d49c27a9a59159` |
| crosscloud:azure:data_manipulation:additional:run-0:y | additional | 0 | payload_present | 18 | `b3cc19c015da04f234c771116fd40045a77d9a428c06a2335dd51022af2627be` |
| crosscloud:azure:data_manipulation:additional:run-1:n | additional | 1 | payload_absent | 20 | `b5e696382eb857e5baf5dc671d12c07643d09c07db216d0a56cb8794cc5742a0` |
| crosscloud:azure:data_manipulation:additional:run-1:y | additional | 1 | payload_present | 19 | `ae9e2a0555d2ac9a53f8b227558fb1809aec96485f75657f512498ea228248c1` |
| crosscloud:azure:data_manipulation:additional:run-2:n | additional | 2 | payload_absent | 19 | `c25d8d1d61508fc47ac82f1303cc20ab67b67b9caa6f6688754e44d9c04cc36d` |
| crosscloud:azure:data_manipulation:additional:run-2:y | additional | 2 | payload_present | 19 | `e27eaa402c9427b15db80ebffe94d6ad80c57dee5d63be50cce838ab4eaa2df1` |
| crosscloud:azure:data_manipulation:additional:run-3:n | additional | 3 | payload_absent | 20 | `7623915d58462abff824d556e79122a4962eb199a18ae3d2dfe2b9a314c78c3e` |
| crosscloud:azure:data_manipulation:additional:run-3:y | additional | 3 | payload_present | 19 | `49abbcbac4225f74392600b58fa8d3aa5a67ae931f6ea7f0eed784aa9c1f8c3c` |
| crosscloud:azure:data_manipulation:additional:run-4:n | additional | 4 | payload_absent | 20 | `38fef5e9d8889837a98d398995a1fd866dea3989c44d3731a4331fec246182e3` |
| crosscloud:azure:data_manipulation:additional:run-4:y | additional | 4 | payload_present | 19 | `041e773a98f034845a66df89a6d9a66209a0e7b1a40282850f06c875b51ad3b1` |
| crosscloud:azure:data_manipulation:additional:run-5:n | additional | 5 | payload_absent | 20 | `6fbc4139c7d85dabb24a009af270ebfecf42fb7f3a6200e3b3f3688e6a957444` |
| crosscloud:azure:data_manipulation:additional:run-5:y | additional | 5 | payload_present | 19 | `41243191a00aa6f28c28d4abf72bed3a531c50caad655e263c09a9e1ab4485f7` |
| crosscloud:azure:data_manipulation:additional:run-6:n | additional | 6 | payload_absent | 19 | `bad86c5fa1f47e07105d61c3fc1b102a39665a8312808b816073e3c818dd04d3` |
| crosscloud:azure:data_manipulation:additional:run-6:y | additional | 6 | payload_present | 19 | `b1c102d64506ba644a6c90b5b0124c79a59105d47b5db7181215f79f067f211a` |
| crosscloud:azure:data_manipulation:additional:run-7:n | additional | 7 | payload_absent | 19 | `5836595e2694f361d6a44631bd5938bc695fedd605df71213579d44a64199fab` |
| crosscloud:azure:data_manipulation:additional:run-7:y | additional | 7 | payload_present | 19 | `a1a05c4a201bd34596d37ecd17e1275adfe3d23ae55eeb095dc53206f0b79039` |
| crosscloud:azure:data_manipulation:additional:run-8:n | additional | 8 | payload_absent | 19 | `f336bb68567b79c396d9023c1b7a102f1c6bf75da8cda6621a7c80393e0a57b4` |
| crosscloud:azure:data_manipulation:additional:run-8:y | additional | 8 | payload_present | 20 | `6bc633f50f9627302d483f91a6c92d37fd724125938a1b954b47638016340f21` |
| crosscloud:azure:data_manipulation:additional:run-9:n | additional | 9 | payload_absent | 19 | `15538439d2f265bc73d1d470a2f2d46859cf140c85b914fd9d5bb47418691611` |
| crosscloud:azure:data_manipulation:additional:run-9:y | additional | 9 | payload_present | 20 | `7cf196c23c978c258daaf0ab1aab5a4ef8e4baf3712d044338e0285b7a2d38c3` |
| crosscloud:azure:data_manipulation:default:run-0:n | default | 0 | payload_absent | 11 | `7326150e67711dfd69a1a16b79e4cf96c008aca50b5ced8456ec29feb475f213` |
| crosscloud:azure:data_manipulation:default:run-0:y | default | 0 | payload_present | 13 | `7a3f3103b4dd1eb3e161594a72c55545a5ea577e0b75fc1ed6381dc248eebc21` |
| crosscloud:azure:data_manipulation:default:run-1:n | default | 1 | payload_absent | 11 | `7178ee1ae8ade241857d477743d5dc411326668e0d6d3a4e85f4d453ce237e70` |
| crosscloud:azure:data_manipulation:default:run-1:y | default | 1 | payload_present | 13 | `7613d22ae2611b720c08a6de609d022c679b707e8fff57653f2d01a39454607b` |
| crosscloud:azure:data_manipulation:default:run-2:n | default | 2 | payload_absent | 14 | `9f84de8a949db7081257adaaca7ad5cf72057686da918dd2026ea1e4e91ac993` |
| crosscloud:azure:data_manipulation:default:run-2:y | default | 2 | payload_present | 13 | `1991e235ffc5e1338978b6eae59a8604d884b8228cb5ab55bb59e662c6cf9c65` |
| crosscloud:azure:data_manipulation:default:run-3:n | default | 3 | payload_absent | 11 | `029045a99da16a992d737bb30e2b3c174c3f5a9a342b38b2954f23181292339a` |
| crosscloud:azure:data_manipulation:default:run-3:y | default | 3 | payload_present | 11 | `f2f555b1043aabd3eb763de7634d2ac116188147ae6e744dd47b0d8c7afe37fe` |
| crosscloud:azure:data_manipulation:default:run-4:n | default | 4 | payload_absent | 21 | `c834a20781bf824acad9283afcab1db583af4a3a46d7c54020912e07d96e80bb` |
| crosscloud:azure:data_manipulation:default:run-4:y | default | 4 | payload_present | 13 | `2dd3ecce504c5f9bc14556415a2704ca92023b556d94d335b319f1fb21c14ed2` |
| crosscloud:azure:data_manipulation:default:run-5:n | default | 5 | payload_absent | 13 | `aeafe4793990ac30b7deceac5262f41e83073bdc0375c414ea0d1c72b8f2c5c3` |
| crosscloud:azure:data_manipulation:default:run-5:y | default | 5 | payload_present | 13 | `2a589270e7f999d1e9c72e7265c3ffa74294ef2e147505ee618b1048beb2437b` |
| crosscloud:azure:data_manipulation:default:run-6:n | default | 6 | payload_absent | 11 | `35433d2147cc646bae454df9a2ba73b39254459478fa89c505ed66186cb68ffc` |
| crosscloud:azure:data_manipulation:default:run-6:y | default | 6 | payload_present | 13 | `7cad33b127f3e19a7f0af6d528ade01875828b6d0bf9ea7b9ae8e831473e9e60` |
| crosscloud:azure:data_manipulation:default:run-7:n | default | 7 | payload_absent | 13 | `648e4a71d81cc27ea9d84e5e75cba12192d31b1ddc78926a3952e5abae4cda74` |
| crosscloud:azure:data_manipulation:default:run-7:y | default | 7 | payload_present | 13 | `077203d2943c71cf15940a3e29e944f75ac093c1884d04ab5320559864205b46` |
| crosscloud:azure:data_manipulation:default:run-8:n | default | 8 | payload_absent | 11 | `2cc5e950f43ffa0710a1494dfbefeb4f95a39999244ce7b5a543476836d62555` |
| crosscloud:azure:data_manipulation:default:run-8:y | default | 8 | payload_present | 13 | `853356a82734eebc047bb4178cbcd39ea3a25de291f61827531a5d36f90df0db` |
| crosscloud:azure:data_manipulation:default:run-9:n | default | 9 | payload_absent | 11 | `e01e60ed63e3a59c150d37b58d2fc2ce9ddd187a1355ecacad950b71cd8e3346` |
| crosscloud:azure:data_manipulation:default:run-9:y | default | 9 | payload_present | 13 | `52316bb37d3d1d9a2d9d5569780087d2795247959530769a663e3a7396a8dbc1` |

### 原始文件完整性

- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/README.md` — SHA-256 `b073b2e97aea4073fec2bf387e2c255d987dd8f3710e84f2df3cc59947e510f8`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/attack_scripts.zip` — SHA-256 `4599be3e224f3b9b43e76ab4ec1bfa8e3b209ebe529fb218ae4e65dd22417900`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/azure_logs_redacted.zip` — SHA-256 `5a94d05e4877593bad1602a68a6f4e775f72323e9e408ae0d0480d7126789dee`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/log_analysis.zip` — SHA-256 `23b41863cc2ece4936277a1ee1fc6f64b4fea9f3c0f698cefbf5626eeca00fcf`

## 29. `crosscloud:azure:data_staged`

- 描述：DOI-published paired payload/no-payload AZURE telemetry for data_staged.
- 发布者：Dhooghe et al.
- 发布日期：2026-04-30
- 环境：controlled cloud subscription
- ATT&CK：
- 原始文件数：4
- 规范化观测数：0
- 上游 episode 数：40

### 准入判断（人工填写）

- [ ] 有外部或低权限入口
- [ ] 存在多步关系，而非单点事件
- [ ] 终点为数据库、存储、备份、secret 或其他数据资产
- [ ] 关键边均有原始证据
- [ ] 不是近重复案例
- 决定：`<accept | needs_execution | reject>`
- 理由：`<人工填写>`

### 观测索引

| observation_id | timestamp | actor_type | service | operation | status | raw record |
|---|---:|---|---|---|---|---|

### 上游配对 episode

| episode_id | profile | run | source condition | observations | member SHA-256 |
|---|---|---:|---|---:|---|
| crosscloud:azure:data_staged:additional:run-0:n | additional | 0 | payload_absent | 22 | `0aa23b8096473ce3f5836c95c828235b9c0165714df82b2e4a7c0c117d3fac90` |
| crosscloud:azure:data_staged:additional:run-0:y | additional | 0 | payload_present | 22 | `81367c8cf19489c5ef6edba7cbfd02239afc954c64b71cfded2e07525f3fc2c8` |
| crosscloud:azure:data_staged:additional:run-1:n | additional | 1 | payload_absent | 22 | `040debdaecebfe0f488c430d392be3daa4a824d7f352d7f7aef40aa08b6a6900` |
| crosscloud:azure:data_staged:additional:run-1:y | additional | 1 | payload_present | 21 | `58a36ed883575b231287e2e1c34575eeccdd0967b7645c9c904322aa134e2914` |
| crosscloud:azure:data_staged:additional:run-2:n | additional | 2 | payload_absent | 20 | `d1f8decf8f43a9727ca523a254fcfdb5cdade29919e78b558b285ec821bcb4e4` |
| crosscloud:azure:data_staged:additional:run-2:y | additional | 2 | payload_present | 22 | `3ffdb270c1a5d44bd4218d83e95c37ad265ed8b700675abb47742f49e1827855` |
| crosscloud:azure:data_staged:additional:run-3:n | additional | 3 | payload_absent | 21 | `e1e6dd6828fcf4778f9831c8140a1cc2053c7f0def096488a32a211aa63a3cba` |
| crosscloud:azure:data_staged:additional:run-3:y | additional | 3 | payload_present | 21 | `203246c11e05cf9c3cf45a8ccafe71e962a2b92c22b30ae7e9b7b5f81e5fd946` |
| crosscloud:azure:data_staged:additional:run-4:n | additional | 4 | payload_absent | 21 | `ea6a24a8c21e8ed53d94032f9e022f084926b8da9c816ed55e55bdd360d1b9e8` |
| crosscloud:azure:data_staged:additional:run-4:y | additional | 4 | payload_present | 21 | `5eb0c0771ab3ce0cd2ed8ac2d7c82eed09ffb0dfaf89733047e353a445d5cee1` |
| crosscloud:azure:data_staged:additional:run-5:n | additional | 5 | payload_absent | 22 | `e0024c16fc14e54474d93baffe59745238e4e809d6e01e2f393be0151a109aa0` |
| crosscloud:azure:data_staged:additional:run-5:y | additional | 5 | payload_present | 21 | `0a82a3e27dd5a86b932f63fca51e9bd3195e1f223c62a295cb5b34430e8105f6` |
| crosscloud:azure:data_staged:additional:run-6:n | additional | 6 | payload_absent | 19 | `044e438ea2af74d4836fdc0276d08e7a2c3f41b92c5bd342c48902c6db6012fa` |
| crosscloud:azure:data_staged:additional:run-6:y | additional | 6 | payload_present | 21 | `add4efaf22daec56d9f48a7bbf51cf6a14160765a1313a2317154b40699887f3` |
| crosscloud:azure:data_staged:additional:run-7:n | additional | 7 | payload_absent | 22 | `37f00b5dea6c169ab0fe113f0eceadca92f04d6c5c943b8df1789d9fd71d96a0` |
| crosscloud:azure:data_staged:additional:run-7:y | additional | 7 | payload_present | 22 | `cea0db0dea6bea554aeb2df5977d89b2a9380d6a84cd2e30a88269a6b1e42c14` |
| crosscloud:azure:data_staged:additional:run-8:n | additional | 8 | payload_absent | 22 | `bc6e64cc11e6e74a206d760601e1f3c6f0362aa8d2ccc62137d6adba58e811be` |
| crosscloud:azure:data_staged:additional:run-8:y | additional | 8 | payload_present | 22 | `1856abc30b68ca3c481d7c629d2c5625001b8abde2f9139fef975990f960cc57` |
| crosscloud:azure:data_staged:additional:run-9:n | additional | 9 | payload_absent | 22 | `d8d426eb0d15158c03ad59bf70f4c942854cde2fcb95fe650db8c1f8f884712b` |
| crosscloud:azure:data_staged:additional:run-9:y | additional | 9 | payload_present | 22 | `bc4b485b013907120c4795aaec902eefc80ad645f750846062d46b30e28a5d25` |
| crosscloud:azure:data_staged:default:run-0:n | default | 0 | payload_absent | 13 | `20719d741c456d6e74d0984e64c7d8a1485c41109544dc9b51a30a621c93ed8b` |
| crosscloud:azure:data_staged:default:run-0:y | default | 0 | payload_present | 15 | `f0519a00c7e8b0587be97cde7f988f573267f37eb6b88527880efd00a5db1091` |
| crosscloud:azure:data_staged:default:run-1:n | default | 1 | payload_absent | 13 | `5364dd88a85180d15cf4f036b3a9a2da8be3ed17240a41190de87efe371112ef` |
| crosscloud:azure:data_staged:default:run-1:y | default | 1 | payload_present | 13 | `0576beec1273352bef3d925ec67dc5ef210a7b6fbf020eddcefdde6d65b7481c` |
| crosscloud:azure:data_staged:default:run-2:n | default | 2 | payload_absent | 13 | `8e2c4bc0c01fb3344f1bc93a9c74db7c35644d62eb4589eaa216e5c05bb1392a` |
| crosscloud:azure:data_staged:default:run-2:y | default | 2 | payload_present | 13 | `33623002293f75d3f15459b3eb7b7f6a1831aef4ef850e1a43508591b0c8e9c3` |
| crosscloud:azure:data_staged:default:run-3:n | default | 3 | payload_absent | 13 | `c3a057c6fc81c44bb7c62053f65442117bc71e1d83dac649b446736a5651de07` |
| crosscloud:azure:data_staged:default:run-3:y | default | 3 | payload_present | 15 | `49c30de8769cff892e1fe017eb3c053813dae824ac6a31c55b413815179ede84` |
| crosscloud:azure:data_staged:default:run-4:n | default | 4 | payload_absent | 13 | `79742ef789d7b3a94f1f688e3a8479432eeb20f1337705c7569f5ba88f86bbad` |
| crosscloud:azure:data_staged:default:run-4:y | default | 4 | payload_present | 15 | `5805a1e1ca562a5191511aede1c44c04d8bbcc4e3d2a0f2394669c22cbde2d48` |
| crosscloud:azure:data_staged:default:run-5:n | default | 5 | payload_absent | 15 | `65f2303d2d25b7f474e724a0af71c58ab7da485c966eefccfc6a9a16b9fa3fee` |
| crosscloud:azure:data_staged:default:run-5:y | default | 5 | payload_present | 13 | `925eedee2f1d69332b1ffb156691f7c1c78e18ce4d19441d4369a3661e87a02f` |
| crosscloud:azure:data_staged:default:run-6:n | default | 6 | payload_absent | 13 | `9da948a97848693e2af6f980d872724304242cfafca77139bd1c924ef9b30ead` |
| crosscloud:azure:data_staged:default:run-6:y | default | 6 | payload_present | 25 | `2533476a9eeabbdb3c258db056e536f29c84a0fa57bf285d0b024a05889ac3aa` |
| crosscloud:azure:data_staged:default:run-7:n | default | 7 | payload_absent | 13 | `bb7f2fe25ddfa3f5243b76b2189aaf1f9415b23f556faf8a1e2c032f0dfa6bf1` |
| crosscloud:azure:data_staged:default:run-7:y | default | 7 | payload_present | 15 | `c64cc6bcc83c8535038bac02e8e99c964397b19eb667a48b9f653e3f83246ff4` |
| crosscloud:azure:data_staged:default:run-8:n | default | 8 | payload_absent | 14 | `463ae9145ee7ee27bbb96d45b5d7d7639f260b3066b6338d855c9f9c450cb4cd` |
| crosscloud:azure:data_staged:default:run-8:y | default | 8 | payload_present | 50 | `cfe5705776595dc2975212ba280507a328e525b0171d90fc7d956cb55d89521d` |
| crosscloud:azure:data_staged:default:run-9:n | default | 9 | payload_absent | 18 | `5be392948ea0d7aa0b9f9859dbf5f8a7be9d6685372fa48b10fad953872fa8fe` |
| crosscloud:azure:data_staged:default:run-9:y | default | 9 | payload_present | 13 | `d427742849a36de28d92043b96fd8f01643d0d114e33fe859898225de16765d3` |

### 原始文件完整性

- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/README.md` — SHA-256 `b073b2e97aea4073fec2bf387e2c255d987dd8f3710e84f2df3cc59947e510f8`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/attack_scripts.zip` — SHA-256 `4599be3e224f3b9b43e76ab4ec1bfa8e3b209ebe529fb218ae4e65dd22417900`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/azure_logs_redacted.zip` — SHA-256 `5a94d05e4877593bad1602a68a6f4e775f72323e9e408ae0d0480d7126789dee`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/log_analysis.zip` — SHA-256 `23b41863cc2ece4936277a1ee1fc6f64b4fea9f3c0f698cefbf5626eeca00fcf`

## 30. `crosscloud:azure:inhibit_system_recovery`

- 描述：DOI-published paired payload/no-payload AZURE telemetry for inhibit_system_recovery.
- 发布者：Dhooghe et al.
- 发布日期：2026-04-30
- 环境：controlled cloud subscription
- ATT&CK：
- 原始文件数：4
- 规范化观测数：0
- 上游 episode 数：40

### 准入判断（人工填写）

- [ ] 有外部或低权限入口
- [ ] 存在多步关系，而非单点事件
- [ ] 终点为数据库、存储、备份、secret 或其他数据资产
- [ ] 关键边均有原始证据
- [ ] 不是近重复案例
- 决定：`<accept | needs_execution | reject>`
- 理由：`<人工填写>`

### 观测索引

| observation_id | timestamp | actor_type | service | operation | status | raw record |
|---|---:|---|---|---|---|---|

### 上游配对 episode

| episode_id | profile | run | source condition | observations | member SHA-256 |
|---|---|---:|---|---:|---|
| crosscloud:azure:inhibit_system_recovery:additional:run-0:n | additional | 0 | payload_absent | 21 | `fbd8fe13c2b40788cbfdc84a1218da513add6d5ceab40a3d67aea86493694bf9` |
| crosscloud:azure:inhibit_system_recovery:additional:run-0:y | additional | 0 | payload_present | 23 | `b8f5c4f04c0168cfe6cdbb692d991659440bf8982472ce2566ff44c1826ae493` |
| crosscloud:azure:inhibit_system_recovery:additional:run-1:n | additional | 1 | payload_absent | 22 | `8bf4ad4ca37d7f0bfa132694a046dee846b3e0cddc2dc966e986aeb2be7ea031` |
| crosscloud:azure:inhibit_system_recovery:additional:run-1:y | additional | 1 | payload_present | 23 | `6d42073113acb529507f2be76573b6f6f7e3c9121fc5ab5de647d55bc6d550bd` |
| crosscloud:azure:inhibit_system_recovery:additional:run-2:n | additional | 2 | payload_absent | 22 | `439102f573fd2a5b1dee372d2537219282cc8b9f96a0e49dcb8e0e0e01f41623` |
| crosscloud:azure:inhibit_system_recovery:additional:run-2:y | additional | 2 | payload_present | 23 | `4d721ef60f836b5118d02ca1ea8bca72c67b9574641a2489f54232998c730ea0` |
| crosscloud:azure:inhibit_system_recovery:additional:run-3:n | additional | 3 | payload_absent | 21 | `9db11127eb0acdc2e00803bc7e0b2bb04396e30b56d457a6bbf787ebdebd410b` |
| crosscloud:azure:inhibit_system_recovery:additional:run-3:y | additional | 3 | payload_present | 22 | `37e617e81ff255da7bb569374a977df1ef7fda7e5b3d6a11fdd4f2e44720f760` |
| crosscloud:azure:inhibit_system_recovery:additional:run-4:n | additional | 4 | payload_absent | 22 | `21d6531893d49ff3636734d345ea49625062c6ff6ca57fdc6b9cef572dfca492` |
| crosscloud:azure:inhibit_system_recovery:additional:run-4:y | additional | 4 | payload_present | 24 | `9df0ffcf58963094143803e7153a9f9611f0431c82b9b5d48f76ed5a743bff26` |
| crosscloud:azure:inhibit_system_recovery:additional:run-5:n | additional | 5 | payload_absent | 21 | `f969d546dccee10da69d5dfe481fa4a1b5bb91286eaca69abd2f92d8e373c9a0` |
| crosscloud:azure:inhibit_system_recovery:additional:run-5:y | additional | 5 | payload_present | 23 | `bbccebe65611338e10f99ab22400fd74023cb387ff5d2cbe7380acc0a47da97a` |
| crosscloud:azure:inhibit_system_recovery:additional:run-6:n | additional | 6 | payload_absent | 21 | `6d68a3b25ee83b460c8c6df073a73fd39d8ed1b359595e2f8601b2ea31ce5090` |
| crosscloud:azure:inhibit_system_recovery:additional:run-6:y | additional | 6 | payload_present | 21 | `e83d6750d4eb628d8b32ffaeec1729044ddd71ac0f1bf5101ebdc1897152237c` |
| crosscloud:azure:inhibit_system_recovery:additional:run-7:n | additional | 7 | payload_absent | 21 | `5c689b536cf73cc25c7aa825bbab3119f05e811cb2cee41964a19a191a0c95eb` |
| crosscloud:azure:inhibit_system_recovery:additional:run-7:y | additional | 7 | payload_present | 23 | `bbfbb1c8af1128b8f4832eb1cbbf901f903e42d09f9c79b5df64bd28f098b17b` |
| crosscloud:azure:inhibit_system_recovery:additional:run-8:n | additional | 8 | payload_absent | 22 | `a8eb1441cf833192a4f3c43945d74a4b38e42833a910896db6ee0291a0de1f05` |
| crosscloud:azure:inhibit_system_recovery:additional:run-8:y | additional | 8 | payload_present | 24 | `38d20d26ab7d01a0c1e9fb3e68210e3240c820abd161b8c5616dc13ffdc59858` |
| crosscloud:azure:inhibit_system_recovery:additional:run-9:n | additional | 9 | payload_absent | 22 | `c56ec522db291c0da57d4b7e715d3b8b307e90262e778eb74d7bed819dc318b9` |
| crosscloud:azure:inhibit_system_recovery:additional:run-9:y | additional | 9 | payload_present | 24 | `6f1ee56c5340770ceb5b98b546c44eab53dbdc9daeab7873ed9ea206cc055fc7` |
| crosscloud:azure:inhibit_system_recovery:default:run-0:n | default | 0 | payload_absent | 15 | `849cd3a6ced175d3f491be523bbe9ed5733f856bf18df14657032d8c0d452206` |
| crosscloud:azure:inhibit_system_recovery:default:run-0:y | default | 0 | payload_present | 15 | `42616ec6c5abcbb3483c36c9d4d522df376c285f6a4e1291da2643386edf0908` |
| crosscloud:azure:inhibit_system_recovery:default:run-1:n | default | 1 | payload_absent | 13 | `0acfa8afbc13725abb96ae192c19a5b1a18db3cba40d20d63c92b9e537829f4b` |
| crosscloud:azure:inhibit_system_recovery:default:run-1:y | default | 1 | payload_present | 15 | `406f7613fda15f49565185ffe3368f7bf42151e95140bf4cc5058cdb238cf804` |
| crosscloud:azure:inhibit_system_recovery:default:run-2:n | default | 2 | payload_absent | 15 | `f759495678d1aa314eb972195eb9e2a0fe4c1ef5108f80b6300572bf4f1f80ef` |
| crosscloud:azure:inhibit_system_recovery:default:run-2:y | default | 2 | payload_present | 20 | `9dfa6f2cb094396f69a43dfd5864a27005223fc511e60f9096a505eb379051ea` |
| crosscloud:azure:inhibit_system_recovery:default:run-3:n | default | 3 | payload_absent | 15 | `b58083b910b71deaf35694dc371cf2db4d6d05740b50f87402152cb12a17a82a` |
| crosscloud:azure:inhibit_system_recovery:default:run-3:y | default | 3 | payload_present | 17 | `440b172e1ca8e6ed30e9442bc623a84222ae9d4e09b88f34c4ad90dd78e709b7` |
| crosscloud:azure:inhibit_system_recovery:default:run-4:n | default | 4 | payload_absent | 13 | `80d6e1b9dfaf6eef03fe2772c52242beacc44191395303c32c7f1fb819328ce9` |
| crosscloud:azure:inhibit_system_recovery:default:run-4:y | default | 4 | payload_present | 15 | `9dd70707337a00a4745cf9e539ae0627bc0b9b9afe179622c2afeb9d42301290` |
| crosscloud:azure:inhibit_system_recovery:default:run-5:n | default | 5 | payload_absent | 14 | `9484aa80739790b5848051b95c36f3cbb732bbb65d575550fb275ac813d590b9` |
| crosscloud:azure:inhibit_system_recovery:default:run-5:y | default | 5 | payload_present | 15 | `4b9e2beda49052a1cbbff2c355cd851ed5f978f6b9e4af35eb1e975971f95a8a` |
| crosscloud:azure:inhibit_system_recovery:default:run-6:n | default | 6 | payload_absent | 13 | `ea40336c8688c5f3633e2e8845ce957d2a99e709efb199ad62a0b6b6d48aa00e` |
| crosscloud:azure:inhibit_system_recovery:default:run-6:y | default | 6 | payload_present | 17 | `894ca6bda055191eab678f791cb8dbc0437d32a07465e4ba4fb935716feb89e8` |
| crosscloud:azure:inhibit_system_recovery:default:run-7:n | default | 7 | payload_absent | 13 | `0d0ea58797ccd25e570fb5ce89447a0e4ddffbb1e1eeeaf470bf304b7166ae6d` |
| crosscloud:azure:inhibit_system_recovery:default:run-7:y | default | 7 | payload_present | 16 | `e48d14cb50f7e70f84bd77da0e206397dae9be84d91d8148fd7680b98ec86f2d` |
| crosscloud:azure:inhibit_system_recovery:default:run-8:n | default | 8 | payload_absent | 14 | `3aaf408b31c5872a5a257db6e6ba1756d547a0c37894efd5d555cdee5d3a7a0c` |
| crosscloud:azure:inhibit_system_recovery:default:run-8:y | default | 8 | payload_present | 20 | `8091f86af2aea33164a98dcbf20c760c168ecede312377ef1890b7569769d94e` |
| crosscloud:azure:inhibit_system_recovery:default:run-9:n | default | 9 | payload_absent | 15 | `bdabda07bb9123a766893fa2eb6b7c87bd1192ff8e4a05f92ac26d5b06ee2079` |
| crosscloud:azure:inhibit_system_recovery:default:run-9:y | default | 9 | payload_present | 17 | `9c0d75d9f670818e120fd188bd6d0e062f143669e289c07228517675f0851b49` |

### 原始文件完整性

- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/README.md` — SHA-256 `b073b2e97aea4073fec2bf387e2c255d987dd8f3710e84f2df3cc59947e510f8`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/attack_scripts.zip` — SHA-256 `4599be3e224f3b9b43e76ab4ec1bfa8e3b209ebe529fb218ae4e65dd22417900`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/azure_logs_redacted.zip` — SHA-256 `5a94d05e4877593bad1602a68a6f4e775f72323e9e408ae0d0480d7126789dee`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/log_analysis.zip` — SHA-256 `23b41863cc2ece4936277a1ee1fc6f64b4fea9f3c0f698cefbf5626eeca00fcf`

## 31. `crosscloud:azure:scheduled_transfer`

- 描述：DOI-published paired payload/no-payload AZURE telemetry for scheduled_transfer.
- 发布者：Dhooghe et al.
- 发布日期：2026-04-30
- 环境：controlled cloud subscription
- ATT&CK：
- 原始文件数：4
- 规范化观测数：0
- 上游 episode 数：40

### 准入判断（人工填写）

- [ ] 有外部或低权限入口
- [ ] 存在多步关系，而非单点事件
- [ ] 终点为数据库、存储、备份、secret 或其他数据资产
- [ ] 关键边均有原始证据
- [ ] 不是近重复案例
- 决定：`<accept | needs_execution | reject>`
- 理由：`<人工填写>`

### 观测索引

| observation_id | timestamp | actor_type | service | operation | status | raw record |
|---|---:|---|---|---|---|---|

### 上游配对 episode

| episode_id | profile | run | source condition | observations | member SHA-256 |
|---|---|---:|---|---:|---|
| crosscloud:azure:scheduled_transfer:additional:run-0:n | additional | 0 | payload_absent | 25 | `f93e438ccf469fc4de31ad2b0927dce9b8c3a663825e00fa9e41273514fbc1f9` |
| crosscloud:azure:scheduled_transfer:additional:run-0:y | additional | 0 | payload_present | 37 | `ed2789929a9112169abc44f1a32b2e15442179d57f62365d844cc5a8e7bedba2` |
| crosscloud:azure:scheduled_transfer:additional:run-1:n | additional | 1 | payload_absent | 25 | `8796a9f53e0d9a60726cb39a1813f84eaf1e80643118c07ed5d2d0cbab5363ea` |
| crosscloud:azure:scheduled_transfer:additional:run-1:y | additional | 1 | payload_present | 34 | `82399d9bb5982d9e68602bb66eb7fca2d5e6241e010a92f23b40a0ab785a5c17` |
| crosscloud:azure:scheduled_transfer:additional:run-2:n | additional | 2 | payload_absent | 8 | `14d1ba022260f3884de4ec334a82b45ef634205a47bb0f547f6241b63a9250e3` |
| crosscloud:azure:scheduled_transfer:additional:run-2:y | additional | 2 | payload_present | 32 | `3dabf86e55e3b0da3709af2100ea84af9f60de6468c0d21be5be418b05a8f002` |
| crosscloud:azure:scheduled_transfer:additional:run-3:n | additional | 3 | payload_absent | 25 | `72d42aca9ffae7f95113c3e8e658aad5dd5728d23ca9ef9a33cf360509e02876` |
| crosscloud:azure:scheduled_transfer:additional:run-3:y | additional | 3 | payload_present | 37 | `c083e00c407dde8226f878d2b3ca0d647c4c3d98c41704b1aea45ab5441f816d` |
| crosscloud:azure:scheduled_transfer:additional:run-4:n | additional | 4 | payload_absent | 25 | `d11028c34966b16cae3ff4ad78d76756c5969617fd5889b626983792fc6d387d` |
| crosscloud:azure:scheduled_transfer:additional:run-4:y | additional | 4 | payload_present | 36 | `f3139f8388de68327e5fdb7640eecf4b3e6f1ee3702092c15bc83be9f97bce4c` |
| crosscloud:azure:scheduled_transfer:additional:run-5:n | additional | 5 | payload_absent | 25 | `fdab60a01d63cd1b64081cf060a89b9721c0f83e1dfec44d3f3eb4fdaf8ffa58` |
| crosscloud:azure:scheduled_transfer:additional:run-5:y | additional | 5 | payload_present | 36 | `279c895c24d19124c7e7c91ad57ec008ab3267c592e5f355cb4f35f39464e390` |
| crosscloud:azure:scheduled_transfer:additional:run-6:n | additional | 6 | payload_absent | 26 | `b2abc616f8c6ad293740ebca1df739e62c65fe869edb0ea1091f209be1f73e92` |
| crosscloud:azure:scheduled_transfer:additional:run-6:y | additional | 6 | payload_present | 36 | `f2a802ba63a4e9ff8afff74c8e415a62e638ff1cdd995407b598f0cc08b0e638` |
| crosscloud:azure:scheduled_transfer:additional:run-7:n | additional | 7 | payload_absent | 26 | `54ba9244366981cdc292fe15e93e2675621b36cb690fb346a337053e42ab7469` |
| crosscloud:azure:scheduled_transfer:additional:run-7:y | additional | 7 | payload_present | 36 | `abc47d360dea0671c89e05dd00a8f66b814f49111ec4fe0b634a6c3b76b22b80` |
| crosscloud:azure:scheduled_transfer:additional:run-8:n | additional | 8 | payload_absent | 26 | `d636430dcacaba8597c9d45f72e8c2d5ca929bb254cc4186a9d2e3cc2df6fb2b` |
| crosscloud:azure:scheduled_transfer:additional:run-8:y | additional | 8 | payload_present | 36 | `bc48be0469bdfd71b28c5df03a3addc5a2ad65865398038ebbe3da90afd8f8ee` |
| crosscloud:azure:scheduled_transfer:additional:run-9:n | additional | 9 | payload_absent | 25 | `12053ad710bf5a721ca84c084649780bfbe8945445ce6cf652ed832cec501b5f` |
| crosscloud:azure:scheduled_transfer:additional:run-9:y | additional | 9 | payload_present | 34 | `e9078b0f801884ccab7969b758ddd3f3d661db0e02958f88e040db0f91849db9` |
| crosscloud:azure:scheduled_transfer:default:run-0:n | default | 0 | payload_absent | 24 | `f1250b1574e7722b9c2ebaca8caf71ca75b3f02d95fade99769ee2e7ef92a0c7` |
| crosscloud:azure:scheduled_transfer:default:run-0:y | default | 0 | payload_present | 23 | `4801b9699750f84b91b38ed18c2970665a0a97b828f409fd983225bc31077e11` |
| crosscloud:azure:scheduled_transfer:default:run-1:n | default | 1 | payload_absent | 17 | `4b2c80b36dbb8ed93960766b889b8884e78e138542fead635e5765ad84af750c` |
| crosscloud:azure:scheduled_transfer:default:run-1:y | default | 1 | payload_present | 28 | `ed5ef461f602d74232433d815d75cdfc46dec5014f627b3066f24948171dae37` |
| crosscloud:azure:scheduled_transfer:default:run-2:n | default | 2 | payload_absent | 17 | `1045063b62d85cee93c64a6b0cc3d6d1bbdfdeb316c5d6bfcb61973ae631891c` |
| crosscloud:azure:scheduled_transfer:default:run-2:y | default | 2 | payload_present | 26 | `dc24649eefa0aa38403efce3af590dbe70d42ce4bebd0079e1eda8ab4ba1b58c` |
| crosscloud:azure:scheduled_transfer:default:run-3:n | default | 3 | payload_absent | 7 | `f23c8ae6e087f71a43072e4e02dde9606d6b21fc8e34565c0603d422749a09e7` |
| crosscloud:azure:scheduled_transfer:default:run-3:y | default | 3 | payload_present | 29 | `9173eb43fc366e3c9f50a4b2280cdb8b3a9b75c87f1b2dcab378a98d3d9d2349` |
| crosscloud:azure:scheduled_transfer:default:run-4:n | default | 4 | payload_absent | 17 | `aa8f8d3ffd6c9450bc5150775fa73e11483f0c3dbdc3cd6863a6ded2bbea58f9` |
| crosscloud:azure:scheduled_transfer:default:run-4:y | default | 4 | payload_present | 28 | `ce5f9ea00f4136bdabc8eecca52faaee24149d395e9174501bcf7bcf83734834` |
| crosscloud:azure:scheduled_transfer:default:run-5:n | default | 5 | payload_absent | 17 | `1b25898eb33a283c16c6b137f85b69310481f3019ec4d51d74333f53f3aeffff` |
| crosscloud:azure:scheduled_transfer:default:run-5:y | default | 5 | payload_present | 28 | `683e4bfe587f4511bf1099087d7321c4a63d6fe9f415255356566f3ed6ee4ac5` |
| crosscloud:azure:scheduled_transfer:default:run-6:n | default | 6 | payload_absent | 17 | `c0747cfb11379ae18cb58ab7954d8c39bfc5c15b5453d28eba7393833f4708ed` |
| crosscloud:azure:scheduled_transfer:default:run-6:y | default | 6 | payload_present | 28 | `341f3c8c15895b631c48a8e18df3e1e06f5c424a320681a0bb137c7b264e9a41` |
| crosscloud:azure:scheduled_transfer:default:run-7:n | default | 7 | payload_absent | 17 | `0ab6e643573dc87bad18755c4aea53003428aaa0839f6a6d3fcbc09065f01074` |
| crosscloud:azure:scheduled_transfer:default:run-7:y | default | 7 | payload_present | 28 | `6369c8c6794cb0757d4678bf1a0472153be513a9bfbacea1a71d7c081c40ce49` |
| crosscloud:azure:scheduled_transfer:default:run-8:n | default | 8 | payload_absent | 17 | `03ef5602f7ba28574f813236a3987ff9a582a547bb4a04d50c306f18d96dfa07` |
| crosscloud:azure:scheduled_transfer:default:run-8:y | default | 8 | payload_present | 28 | `93135090aac93b299570aa2fb3c614dbfd103ff48f12d3d6c83652a62a5cee88` |
| crosscloud:azure:scheduled_transfer:default:run-9:n | default | 9 | payload_absent | 17 | `a9071e76db3abf721ccd60556d332d8be01ce0f41065342892efa9a98b19d7c6` |
| crosscloud:azure:scheduled_transfer:default:run-9:y | default | 9 | payload_present | 28 | `1ca406cb105ec5c016f1c3854d011b774e932cb6afc0718b30825145268a47f1` |

### 原始文件完整性

- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/README.md` — SHA-256 `b073b2e97aea4073fec2bf387e2c255d987dd8f3710e84f2df3cc59947e510f8`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/attack_scripts.zip` — SHA-256 `4599be3e224f3b9b43e76ab4ec1bfa8e3b209ebe529fb218ae4e65dd22417900`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/azure_logs_redacted.zip` — SHA-256 `5a94d05e4877593bad1602a68a6f4e775f72323e9e408ae0d0480d7126789dee`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/log_analysis.zip` — SHA-256 `23b41863cc2ece4936277a1ee1fc6f64b4fea9f3c0f698cefbf5626eeca00fcf`

## 32. `crosscloud:azure:steal_application_access_token`

- 描述：DOI-published paired payload/no-payload AZURE telemetry for steal_application_access_token.
- 发布者：Dhooghe et al.
- 发布日期：2026-04-30
- 环境：controlled cloud subscription
- ATT&CK：
- 原始文件数：4
- 规范化观测数：0
- 上游 episode 数：40

### 准入判断（人工填写）

- [ ] 有外部或低权限入口
- [ ] 存在多步关系，而非单点事件
- [ ] 终点为数据库、存储、备份、secret 或其他数据资产
- [ ] 关键边均有原始证据
- [ ] 不是近重复案例
- 决定：`<accept | needs_execution | reject>`
- 理由：`<人工填写>`

### 观测索引

| observation_id | timestamp | actor_type | service | operation | status | raw record |
|---|---:|---|---|---|---|---|

### 上游配对 episode

| episode_id | profile | run | source condition | observations | member SHA-256 |
|---|---|---:|---|---:|---|
| crosscloud:azure:steal_application_access_token:additional:run-0:n | additional | 0 | payload_absent | 24 | `d9ead78445b975f33f32f328df007cdcb3eb1c6ac6cc3304118fe0108a25f9d9` |
| crosscloud:azure:steal_application_access_token:additional:run-0:y | additional | 0 | payload_present | 27 | `e6381a29eb182480f672a29fd6fa0334c0a12bdb42e33d34caed44f9155efa2f` |
| crosscloud:azure:steal_application_access_token:additional:run-1:n | additional | 1 | payload_absent | 27 | `a3d707ff22feda08a16a83646e64a0f6246aacb343c1fb64ab4b13ba389880a6` |
| crosscloud:azure:steal_application_access_token:additional:run-1:y | additional | 1 | payload_present | 25 | `43ce3d93df57995e2b1498ff156a3b097caa04466b11bf48b39c69826924d216` |
| crosscloud:azure:steal_application_access_token:additional:run-2:n | additional | 2 | payload_absent | 26 | `6f84dbbf9a4ee8ebe07cb3321c7a44be8482f40aee93bd376ead1234f62e9789` |
| crosscloud:azure:steal_application_access_token:additional:run-2:y | additional | 2 | payload_present | 26 | `74c39ff06360f06e014cb66ed8ff7150aed61d4b92d6c0ff1d2e312ac7a9d438` |
| crosscloud:azure:steal_application_access_token:additional:run-3:n | additional | 3 | payload_absent | 27 | `d08e720f7736c77887f1b6789d89abb4ecc43827df3b8140c1aab0b6dfd230bd` |
| crosscloud:azure:steal_application_access_token:additional:run-3:y | additional | 3 | payload_present | 24 | `a233f04e8d004a018fc03c0ea1f99a5cd7c77e8583de4182f1faa1f3fcce244a` |
| crosscloud:azure:steal_application_access_token:additional:run-4:n | additional | 4 | payload_absent | 26 | `faf78d728639dffd6d5ff0d4d2ecb5bb33e4409ad4ea1b3c162d950f1099e472` |
| crosscloud:azure:steal_application_access_token:additional:run-4:y | additional | 4 | payload_present | 26 | `bdddbc1bb9a8414824a3074e8aa584094d7d62ef043321c1d94e190aaffffa9b` |
| crosscloud:azure:steal_application_access_token:additional:run-5:n | additional | 5 | payload_absent | 26 | `3d469eb25b32bb0cfa788c5eb8cdf5c655b8fd3f53cc01037fcd5a092a107b24` |
| crosscloud:azure:steal_application_access_token:additional:run-5:y | additional | 5 | payload_present | 27 | `e6ea580aa2ef41ed8a9f79f3ae96af355b286678dbda19cbde513e9bbac2869c` |
| crosscloud:azure:steal_application_access_token:additional:run-6:n | additional | 6 | payload_absent | 26 | `4429556f2336bae0ad1752fe8bf4e44002d217f8b4764df7db1604e27fc63695` |
| crosscloud:azure:steal_application_access_token:additional:run-6:y | additional | 6 | payload_present | 27 | `a37814654e34482db63628ecd7030c92702f3fbb3c21150b38e268573bd83ff6` |
| crosscloud:azure:steal_application_access_token:additional:run-7:n | additional | 7 | payload_absent | 24 | `a9c58dd381c22d98c8e6793882e44a8b3d93c33adb599fb0e63ea14d3dae53be` |
| crosscloud:azure:steal_application_access_token:additional:run-7:y | additional | 7 | payload_present | 26 | `bac23190a8da345ae921084bc9ac40069090d375e565cc27f71ca2c19ece3f40` |
| crosscloud:azure:steal_application_access_token:additional:run-8:n | additional | 8 | payload_absent | 26 | `8d8fc2d3466fc26151ed5f1ec0b693e9616717bb5e9d868366ec413d80647954` |
| crosscloud:azure:steal_application_access_token:additional:run-8:y | additional | 8 | payload_present | 26 | `43f41ef9c8d70527dbd9cc3cd2dc66d1d93678c065f42183e010b593a5c6d1e7` |
| crosscloud:azure:steal_application_access_token:additional:run-9:n | additional | 9 | payload_absent | 24 | `22c41873f54c733a1086732a4dbb49210570fc1df5d1e899b96413f58dca7916` |
| crosscloud:azure:steal_application_access_token:additional:run-9:y | additional | 9 | payload_present | 27 | `462fa9efc5abdfd346f50aae450ed8f88f4c4601ccb06a8184fd4a6e57a851bb` |
| crosscloud:azure:steal_application_access_token:default:run-0:n | default | 0 | payload_absent | 17 | `47a7196a7a0cb9c0c2359b3869f1edaecba55295c435e3b1b4b8195e47b55167` |
| crosscloud:azure:steal_application_access_token:default:run-0:y | default | 0 | payload_present | 19 | `6124afac1704eab71c4501aaf8277b0d858051db408ce3cc8e1fa21dccdcc300` |
| crosscloud:azure:steal_application_access_token:default:run-1:n | default | 1 | payload_absent | 18 | `6929d8f324c08ed8f8454d557a2692f4f743b504b6f1148fffd4ef9b5659640e` |
| crosscloud:azure:steal_application_access_token:default:run-1:y | default | 1 | payload_present | 41 | `36230eae39c6e0979ca124a9a3a59d2d714cbfaee8d02396735f559abae9a1f8` |
| crosscloud:azure:steal_application_access_token:default:run-2:n | default | 2 | payload_absent | 20 | `b5d39d5d98d747ff2ecd60e8bded7bd335d719f63f261a00524ba3cd6a969bc5` |
| crosscloud:azure:steal_application_access_token:default:run-2:y | default | 2 | payload_present | 17 | `f725a9d2a6acd5f7e76b3c6ca90bff8e88481a14d9ed52a2b7e7621c669f0d1e` |
| crosscloud:azure:steal_application_access_token:default:run-3:n | default | 3 | payload_absent | 50 | `4d569c9ed707bced69b84f479234485ef8a46ca0ff4afb67bc4f9cd83092872f` |
| crosscloud:azure:steal_application_access_token:default:run-3:y | default | 3 | payload_present | 18 | `f27ce35fd2c3182c36f9fdd7ec4d62c4a7ed8fbdf24d24cc1453929ae488a2ef` |
| crosscloud:azure:steal_application_access_token:default:run-4:n | default | 4 | payload_absent | 27 | `e1ed999ab73b7527c0cbc9c29439d0fea28ae09a6c576ec41e1742eba2d86423` |
| crosscloud:azure:steal_application_access_token:default:run-4:y | default | 4 | payload_present | 17 | `708639c5b156ba823433c1e4f8f73074d5cabdaefa2b09b91810e41c6bcb3cb0` |
| crosscloud:azure:steal_application_access_token:default:run-5:n | default | 5 | payload_absent | 17 | `6b24f8852243ca0d98d3a60cb22192771c8df55b42ca3fca54784ea9501232a2` |
| crosscloud:azure:steal_application_access_token:default:run-5:y | default | 5 | payload_present | 20 | `27b143492e8d7c831db76ff403d56a06f2e19d52d76ceb2876f83498ebb7dacd` |
| crosscloud:azure:steal_application_access_token:default:run-6:n | default | 6 | payload_absent | 16 | `39bd2a79575f94f7de7b2f0b388dcb5292839e606bc9b37d8babed94b25b47f3` |
| crosscloud:azure:steal_application_access_token:default:run-6:y | default | 6 | payload_present | 19 | `dec9032a0fde9813efc0c6e7ac227d5af2916c70fd869b5a6cfe06058203129d` |
| crosscloud:azure:steal_application_access_token:default:run-7:n | default | 7 | payload_absent | 17 | `efe698b84d6c43393eb4ac14711fec695a9ad1bf5574441e4ea908148da04e71` |
| crosscloud:azure:steal_application_access_token:default:run-7:y | default | 7 | payload_present | 19 | `cf80137cb7a8bf4dd4c779db2662cefe4f2857d6efbd6429f3d92d770f54cb17` |
| crosscloud:azure:steal_application_access_token:default:run-8:n | default | 8 | payload_absent | 17 | `4fd3496bdd519df7caff6db56c16a9f18f45d34194fe1fbff43115d3d1c774a4` |
| crosscloud:azure:steal_application_access_token:default:run-8:y | default | 8 | payload_present | 20 | `b62fcfddd36940afd5e7efcc8b6423b560bb46d63bccc1472436bea56fba5a94` |
| crosscloud:azure:steal_application_access_token:default:run-9:n | default | 9 | payload_absent | 17 | `c9c493e2a2693ac4c1b318f7bb60ec3cd98cc9b9f37815838d5d41dca3dcb4c1` |
| crosscloud:azure:steal_application_access_token:default:run-9:y | default | 9 | payload_present | 19 | `030d2cb72fa18dfec1cce6b579b7ff1b8e66fd959497ccd0569ab00a8f658fef` |

### 原始文件完整性

- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/README.md` — SHA-256 `b073b2e97aea4073fec2bf387e2c255d987dd8f3710e84f2df3cc59947e510f8`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/attack_scripts.zip` — SHA-256 `4599be3e224f3b9b43e76ab4ec1bfa8e3b209ebe529fb218ae4e65dd22417900`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/azure_logs_redacted.zip` — SHA-256 `5a94d05e4877593bad1602a68a6f4e775f72323e9e408ae0d0480d7126789dee`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/log_analysis.zip` — SHA-256 `23b41863cc2ece4936277a1ee1fc6f64b4fea9f3c0f698cefbf5626eeca00fcf`

## 33. `crosscloud:azure:unsecured_credentials`

- 描述：DOI-published paired payload/no-payload AZURE telemetry for unsecured_credentials.
- 发布者：Dhooghe et al.
- 发布日期：2026-04-30
- 环境：controlled cloud subscription
- ATT&CK：
- 原始文件数：4
- 规范化观测数：0
- 上游 episode 数：40

### 准入判断（人工填写）

- [ ] 有外部或低权限入口
- [ ] 存在多步关系，而非单点事件
- [ ] 终点为数据库、存储、备份、secret 或其他数据资产
- [ ] 关键边均有原始证据
- [ ] 不是近重复案例
- 决定：`<accept | needs_execution | reject>`
- 理由：`<人工填写>`

### 观测索引

| observation_id | timestamp | actor_type | service | operation | status | raw record |
|---|---:|---|---|---|---|---|

### 上游配对 episode

| episode_id | profile | run | source condition | observations | member SHA-256 |
|---|---|---:|---|---:|---|
| crosscloud:azure:unsecured_credentials:additional:run-0:n | additional | 0 | payload_absent | 21 | `79c55f5e847d1f9311c50a3e8c6408678905d91df51b69ae0e74f8c49f37da6a` |
| crosscloud:azure:unsecured_credentials:additional:run-0:y | additional | 0 | payload_present | 22 | `da4c1930f7821676c78360362f23fad5d4624032a19c8b160bff5af826e6be17` |
| crosscloud:azure:unsecured_credentials:additional:run-1:n | additional | 1 | payload_absent | 18 | `2ff018209b273b7c9258b5b2d9b56272843def3ceec9987032ed166690b84d27` |
| crosscloud:azure:unsecured_credentials:additional:run-1:y | additional | 1 | payload_present | 23 | `0b1b76c8f79e4f610d4dfd702ab5de10837be17b1e11ca18c2e1ab191c66aba1` |
| crosscloud:azure:unsecured_credentials:additional:run-2:n | additional | 2 | payload_absent | 21 | `1e142ab42477f589cc8d0443fcba3b722141a40ddde7c3dc3b1fa81cff073954` |
| crosscloud:azure:unsecured_credentials:additional:run-2:y | additional | 2 | payload_present | 22 | `51f01b80757848fa1358a827e65ede77edc12130d242e04f7a9d71268d4bb841` |
| crosscloud:azure:unsecured_credentials:additional:run-3:n | additional | 3 | payload_absent | 21 | `0a87568fa975cebfd20f4b6aceb6637e304c403bfcb4ebf0f99fbf09c6e34c8b` |
| crosscloud:azure:unsecured_credentials:additional:run-3:y | additional | 3 | payload_present | 23 | `f1947ee2f64d84b9d09399ed0817d66690dfa3be4570eb89bffdd2f19ae98208` |
| crosscloud:azure:unsecured_credentials:additional:run-4:n | additional | 4 | payload_absent | 21 | `4f9f4cb284c0221b3de20deada417f1e114abe6afd931b38ada7b53031c54314` |
| crosscloud:azure:unsecured_credentials:additional:run-4:y | additional | 4 | payload_present | 22 | `32c0ba58089bc50b99bab4c97632cd60efca5e80aa016da26ef39ffbcf0b3511` |
| crosscloud:azure:unsecured_credentials:additional:run-5:n | additional | 5 | payload_absent | 20 | `17ba68bd3ec5930980e03a23e9bd3148e10b2dc429701936325c5c8a39f75d13` |
| crosscloud:azure:unsecured_credentials:additional:run-5:y | additional | 5 | payload_present | 23 | `0fc9903db35773d676179a19535dcf6ba4421492b498373f1eacc23b161f6c26` |
| crosscloud:azure:unsecured_credentials:additional:run-6:n | additional | 6 | payload_absent | 20 | `f7b047be7267c67b66f6960a2312cd0d222c474b1a7ac15fa1a77797bcc6cc5c` |
| crosscloud:azure:unsecured_credentials:additional:run-6:y | additional | 6 | payload_present | 21 | `c97ae7217b8db42114107599102211360b6736e9510c87d038426f53bc8063f1` |
| crosscloud:azure:unsecured_credentials:additional:run-7:n | additional | 7 | payload_absent | 18 | `5c18ef5a389da6566800d977d781c6b598acb8b4eceb434b1369723ce4e1bc51` |
| crosscloud:azure:unsecured_credentials:additional:run-7:y | additional | 7 | payload_present | 22 | `9181bce78cfe34c0ef3bbc0de79b9ab2943ba7fe3df1d2d3ff00d8572018b934` |
| crosscloud:azure:unsecured_credentials:additional:run-8:n | additional | 8 | payload_absent | 20 | `12e0107a8bfc9e8b60e70b0bcbe4d2f701d3581b21db8b598031de05affdc575` |
| crosscloud:azure:unsecured_credentials:additional:run-8:y | additional | 8 | payload_present | 23 | `4ad93946ac0c0efdba28ce5aa319b0cbd205ba04d3c7d1eb3d993bfda72029a7` |
| crosscloud:azure:unsecured_credentials:additional:run-9:n | additional | 9 | payload_absent | 21 | `dbf816bbe2d581fe1518458f99167528791c566f95154826a61c0cdc5053cde9` |
| crosscloud:azure:unsecured_credentials:additional:run-9:y | additional | 9 | payload_present | 22 | `9cb0aaff20754ca7529b55b10068f8813c8946166f3c0f163c74a7b69c618e29` |
| crosscloud:azure:unsecured_credentials:default:run-0:n | default | 0 | payload_absent | 11 | `406aa0da6766f7fa64bf5a3e0d636c21f28374a03d310c5f5407105baa6fdf3d` |
| crosscloud:azure:unsecured_credentials:default:run-0:y | default | 0 | payload_present | 14 | `de4660449a3b98ace358f7d431f7af8323592578c8db7900298f2653a41ca9f9` |
| crosscloud:azure:unsecured_credentials:default:run-1:n | default | 1 | payload_absent | 11 | `7a0c6a8fcf5ae82cbbac61d0cb1f512a258c0571a354bd8ec99e981ee80bc5ac` |
| crosscloud:azure:unsecured_credentials:default:run-1:y | default | 1 | payload_present | 13 | `edd5eb71b0325211fc5992958c2f36b15dac114c014cc724fa317459f1ce37df` |
| crosscloud:azure:unsecured_credentials:default:run-2:n | default | 2 | payload_absent | 12 | `929025d62bd2acf100d398bd6d04e1ad3290004e3a4509a0ac8aab53396b9c55` |
| crosscloud:azure:unsecured_credentials:default:run-2:y | default | 2 | payload_present | 15 | `4f7336764649c209814cca99dd838c221de130282926c3b559fa2314554a907c` |
| crosscloud:azure:unsecured_credentials:default:run-3:n | default | 3 | payload_absent | 11 | `a99df201879ab1caecbab8a09e82a22643e9d03af6be16bc9c0cacd028236abb` |
| crosscloud:azure:unsecured_credentials:default:run-3:y | default | 3 | payload_present | 13 | `c0bf640ea34ab14572b8eb1671768d23b8a378ace9b3c421597382c75d3b53b6` |
| crosscloud:azure:unsecured_credentials:default:run-4:n | default | 4 | payload_absent | 50 | `1b1fd2d88a764ce82673986b749a29cdeb3e58cbb0b587bf10d650a9f2cf62ba` |
| crosscloud:azure:unsecured_credentials:default:run-4:y | default | 4 | payload_present | 13 | `a66f45df4156a82cd2a6d2adb3751abb397bbc9aa4e7ba57e0aafa36f628700a` |
| crosscloud:azure:unsecured_credentials:default:run-5:n | default | 5 | payload_absent | 11 | `c808f5d58ad23899cb85304189a5ca1647352efbde448488bbee4f1c9af34622` |
| crosscloud:azure:unsecured_credentials:default:run-5:y | default | 5 | payload_present | 14 | `d9a1b3aec2c9be94a07d799230084c77407e36c8268721d93b49dcd828ad1b71` |
| crosscloud:azure:unsecured_credentials:default:run-6:n | default | 6 | payload_absent | 11 | `f0fc76f15d0bd3170d350740b429edfcd2909e01e61e95cea9d4695cef8072e0` |
| crosscloud:azure:unsecured_credentials:default:run-6:y | default | 6 | payload_present | 13 | `c2ce1d5e67e03949802cac3ce0bc6facbed1c521753f2d01e104880ea1e2fa4b` |
| crosscloud:azure:unsecured_credentials:default:run-7:n | default | 7 | payload_absent | 50 | `abd0aa1548c4ce5cb9055717133ee347b552e050486b6b64cd6d1aeba6a39b16` |
| crosscloud:azure:unsecured_credentials:default:run-7:y | default | 7 | payload_present | 12 | `f2692c98b2542c44b67b156ea2ed9440af512cbc7771006e3b7c44ef70fe825a` |
| crosscloud:azure:unsecured_credentials:default:run-8:n | default | 8 | payload_absent | 11 | `3cf5c8bb337f9a352ef9212dd7c36d66fa33c8b8e633d335943f136c2ae8aa35` |
| crosscloud:azure:unsecured_credentials:default:run-8:y | default | 8 | payload_present | 15 | `381524a027eaae6c34c4d72377753af2bd877fcb44ed8503a0ee212a512d36d4` |
| crosscloud:azure:unsecured_credentials:default:run-9:n | default | 9 | payload_absent | 12 | `1a896253ea7691c0cbcce5fad2e71ae5d75d43d37f9fdd3957762fc91e0f709b` |
| crosscloud:azure:unsecured_credentials:default:run-9:y | default | 9 | payload_present | 13 | `f6be3d6a1918121c36c9daad62575357efd4d962d7ef50f93dfbffb6fd4b9f44` |

### 原始文件完整性

- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/README.md` — SHA-256 `b073b2e97aea4073fec2bf387e2c255d987dd8f3710e84f2df3cc59947e510f8`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/attack_scripts.zip` — SHA-256 `4599be3e224f3b9b43e76ab4ec1bfa8e3b209ebe529fb218ae4e65dd22417900`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/azure_logs_redacted.zip` — SHA-256 `5a94d05e4877593bad1602a68a6f4e775f72323e9e408ae0d0480d7126789dee`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/log_analysis.zip` — SHA-256 `23b41863cc2ece4936277a1ee1fc6f64b4fea9f3c0f698cefbf5626eeca00fcf`

## 34. `crosscloud:gcp:archive_collected_data`

- 描述：DOI-published paired payload/no-payload GCP telemetry for archive_collected_data.
- 发布者：Dhooghe et al.
- 发布日期：2026-04-30
- 环境：controlled cloud subscription
- ATT&CK：
- 原始文件数：4
- 规范化观测数：0
- 上游 episode 数：40

### 准入判断（人工填写）

- [ ] 有外部或低权限入口
- [ ] 存在多步关系，而非单点事件
- [ ] 终点为数据库、存储、备份、secret 或其他数据资产
- [ ] 关键边均有原始证据
- [ ] 不是近重复案例
- 决定：`<accept | needs_execution | reject>`
- 理由：`<人工填写>`

### 观测索引

| observation_id | timestamp | actor_type | service | operation | status | raw record |
|---|---:|---|---|---|---|---|

### 上游配对 episode

| episode_id | profile | run | source condition | observations | member SHA-256 |
|---|---|---:|---|---:|---|
| crosscloud:gcp:archive_collected_data:additional:run-0:n | additional | 0 | payload_absent | 12 | `0befe740730f9eee817ee7e7ab115d94d200b21267d083f98703c7ffe0a5f58a` |
| crosscloud:gcp:archive_collected_data:additional:run-0:y | additional | 0 | payload_present | 36 | `a83d066bd75aaea72809e7bf2bee7dc4a2b275e8f39ec56203cbaef482588a8d` |
| crosscloud:gcp:archive_collected_data:additional:run-1:n | additional | 1 | payload_absent | 12 | `ec469743bac3d0a7a4fb50595e2e20d837f242dd9087482512b8658affaf17a7` |
| crosscloud:gcp:archive_collected_data:additional:run-1:y | additional | 1 | payload_present | 36 | `1454a0670448699432710640ccde33c979dcc00de1bdc572cb8dbcee616bc2de` |
| crosscloud:gcp:archive_collected_data:additional:run-2:n | additional | 2 | payload_absent | 12 | `9c59cb6f741fadb1d34e27eddc96f8d59a34f1f95f03a1293b2ee37d99455357` |
| crosscloud:gcp:archive_collected_data:additional:run-2:y | additional | 2 | payload_present | 46 | `02e0d84e22bd45b05123a73849e92bcf9d6a14f0a4abfb6b7224254c0e116010` |
| crosscloud:gcp:archive_collected_data:additional:run-3:n | additional | 3 | payload_absent | 12 | `4257193788603d0b56ad4b5a6058601fef2106b05459fb08c0c601c45b65fc16` |
| crosscloud:gcp:archive_collected_data:additional:run-3:y | additional | 3 | payload_present | 36 | `8d5e61794250c29b43fb1e04b25d8e858968040bbb1d0dc49a8e458432a854e4` |
| crosscloud:gcp:archive_collected_data:additional:run-4:n | additional | 4 | payload_absent | 12 | `2420104bcd923031d003ba3aecddcb2841dee116e8349bea6f755f369f1d4980` |
| crosscloud:gcp:archive_collected_data:additional:run-4:y | additional | 4 | payload_present | 46 | `6acbe9a62267f3aeec27024a96c5f1d11890c7b54fd5b45979693b93ada6bc3d` |
| crosscloud:gcp:archive_collected_data:additional:run-5:n | additional | 5 | payload_absent | 12 | `8fa4cad29f4995f7d7a4ca7083e32c82228601a861dcc159b6fcf5b57b1a829f` |
| crosscloud:gcp:archive_collected_data:additional:run-5:y | additional | 5 | payload_present | 36 | `09baef143c1879d2bf969239f3834815811dab8d689c7909106edef1a7c90507` |
| crosscloud:gcp:archive_collected_data:additional:run-6:n | additional | 6 | payload_absent | 12 | `952f38ad626bc647431ce443529737886da06ca939ea811aecb3ecc47787179f` |
| crosscloud:gcp:archive_collected_data:additional:run-6:y | additional | 6 | payload_present | 36 | `a05262d4ee98fd0670356378f11c63df9aab7fc3b672d088377674e72402db9c` |
| crosscloud:gcp:archive_collected_data:additional:run-7:n | additional | 7 | payload_absent | 12 | `acc3632c105d0a6779e3a92a4391752a0ee6dc1d5f09219f9f2041a1a178165d` |
| crosscloud:gcp:archive_collected_data:additional:run-7:y | additional | 7 | payload_present | 36 | `b879d433cb85ba9f7802607390bc82ddec793b9f6a45b7cdecf28063be55a9a9` |
| crosscloud:gcp:archive_collected_data:additional:run-8:n | additional | 8 | payload_absent | 12 | `a229f8f3972b3148be788b71961b7181458da34ee35d3fb9f2bc0750ba6bef86` |
| crosscloud:gcp:archive_collected_data:additional:run-8:y | additional | 8 | payload_present | 46 | `28dd31694a41951a955d19f60bb5f44ed83571dc6006886ff40e6b7db3eadfcc` |
| crosscloud:gcp:archive_collected_data:additional:run-9:n | additional | 9 | payload_absent | 12 | `a9ae275c6c7c7d2f60b7c3018e8e6293eb3ed193c6a61cd5473c977ed99e1766` |
| crosscloud:gcp:archive_collected_data:additional:run-9:y | additional | 9 | payload_present | 36 | `c24d5bcb293d0fb7dd1a08850aa5e1fa2f004aa52f60cafb41b1b76b8b113c89` |
| crosscloud:gcp:archive_collected_data:default:run-0:n | default | 0 | payload_absent | 2 | `51ede93fe849fc330a97bee5978380c9b83ebefe2a52201e28f05b89ca33be3c` |
| crosscloud:gcp:archive_collected_data:default:run-0:y | default | 0 | payload_present | 6 | `b3395ff999ba9bb6cf7db2f55dd657afd8d819b59523d9db38e75d3fed601fa4` |
| crosscloud:gcp:archive_collected_data:default:run-1:n | default | 1 | payload_absent | 2 | `f2a48efaeb4454ea3f5e095005bde606040be941f9bb8d7f46563d79f6f3361e` |
| crosscloud:gcp:archive_collected_data:default:run-1:y | default | 1 | payload_present | 6 | `aaefec385b2cce745387474b38c63b2e1f53509666d3d2227e5ec541d47723c6` |
| crosscloud:gcp:archive_collected_data:default:run-2:n | default | 2 | payload_absent | 2 | `e2094cf80672f64dc0bc0ef9f40d6210a2076804aef9fc6ad4d516e0da06ef8d` |
| crosscloud:gcp:archive_collected_data:default:run-2:y | default | 2 | payload_present | 6 | `c2ae3eb1243ccd9b804ab77f4399c0d6b9f272d5b040f232ba28086463b82c6d` |
| crosscloud:gcp:archive_collected_data:default:run-3:n | default | 3 | payload_absent | 2 | `f6161bd29e9a68179511fa5833b2d374214d506a1405a2db690a23f67c1f08ce` |
| crosscloud:gcp:archive_collected_data:default:run-3:y | default | 3 | payload_present | 6 | `2624a66be2611e02e28cd6c190d8bd1e03bede7bfeef531c827214aef851c5c2` |
| crosscloud:gcp:archive_collected_data:default:run-4:n | default | 4 | payload_absent | 2 | `9dde92471108db15ffa122ecedbecdfd51081accbefc63304f3117977651905a` |
| crosscloud:gcp:archive_collected_data:default:run-4:y | default | 4 | payload_present | 6 | `95ab6e94fbe430c19cd987bee1bb51f7a5fc619f19c9cf7346880e765edf733f` |
| crosscloud:gcp:archive_collected_data:default:run-5:n | default | 5 | payload_absent | 2 | `984eb5b2ae4b1868c2d696b63752b35933f359807f411e1d68f368f81350226f` |
| crosscloud:gcp:archive_collected_data:default:run-5:y | default | 5 | payload_present | 6 | `e35134861ca451d01f4f083d0d4f0202ca2a8ddeb9b02843c4b2b84b5a68037c` |
| crosscloud:gcp:archive_collected_data:default:run-6:n | default | 6 | payload_absent | 2 | `27687610a6bd675edd766115a3017a2f5c5e55ca7186d31e47f37cb42c1142da` |
| crosscloud:gcp:archive_collected_data:default:run-6:y | default | 6 | payload_present | 6 | `1db952c560b5ec780e021c758fa81db2342590baa08df84ff6da615c53d1b0df` |
| crosscloud:gcp:archive_collected_data:default:run-7:n | default | 7 | payload_absent | 2 | `52daae61837c6edc5f0aaa77e066221c7320c71bec35b32ec2dfa703b2d6f0c2` |
| crosscloud:gcp:archive_collected_data:default:run-7:y | default | 7 | payload_present | 6 | `d38638b9b864fd68ce7806bcf02050dfa3088e33c82bd02f16fce9fb0708e64d` |
| crosscloud:gcp:archive_collected_data:default:run-8:n | default | 8 | payload_absent | 2 | `202a9e4050aa99a185338222ac4fda1990876877121984f110bf9f4a37476e70` |
| crosscloud:gcp:archive_collected_data:default:run-8:y | default | 8 | payload_present | 6 | `7fe0c64383c787ec80a44b6c0ff96b4df083bdaaf2bc5869666bccd6859c88bf` |
| crosscloud:gcp:archive_collected_data:default:run-9:n | default | 9 | payload_absent | 2 | `bf7e36234f8a51fa44e116ef0f40f842a07d65249cae44f946077e24b53fb25a` |
| crosscloud:gcp:archive_collected_data:default:run-9:y | default | 9 | payload_present | 6 | `dacdebd8917620846f215b61b174bce3918968ed35a131a1194a46788689ee1d` |

### 原始文件完整性

- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/README.md` — SHA-256 `b073b2e97aea4073fec2bf387e2c255d987dd8f3710e84f2df3cc59947e510f8`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/attack_scripts.zip` — SHA-256 `4599be3e224f3b9b43e76ab4ec1bfa8e3b209ebe529fb218ae4e65dd22417900`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/gcp_logs_redacted.zip` — SHA-256 `2765fedd91ce6a03c9a8d156a3d83e34dd493e7a366d0b38abd88a00ad10c5a4`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/log_analysis.zip` — SHA-256 `23b41863cc2ece4936277a1ee1fc6f64b4fea9f3c0f698cefbf5626eeca00fcf`

## 35. `crosscloud:gcp:automated_collection`

- 描述：DOI-published paired payload/no-payload GCP telemetry for automated_collection.
- 发布者：Dhooghe et al.
- 发布日期：2026-04-30
- 环境：controlled cloud subscription
- ATT&CK：
- 原始文件数：4
- 规范化观测数：0
- 上游 episode 数：40

### 准入判断（人工填写）

- [ ] 有外部或低权限入口
- [ ] 存在多步关系，而非单点事件
- [ ] 终点为数据库、存储、备份、secret 或其他数据资产
- [ ] 关键边均有原始证据
- [ ] 不是近重复案例
- 决定：`<accept | needs_execution | reject>`
- 理由：`<人工填写>`

### 观测索引

| observation_id | timestamp | actor_type | service | operation | status | raw record |
|---|---:|---|---|---|---|---|

### 上游配对 episode

| episode_id | profile | run | source condition | observations | member SHA-256 |
|---|---|---:|---|---:|---|
| crosscloud:gcp:automated_collection:additional:run-0:n | additional | 0 | payload_absent | 41 | `2abf7dd83b38e35bae79722aab97f855497a2cff995b4c98480ff8bb3256cfc2` |
| crosscloud:gcp:automated_collection:additional:run-0:y | additional | 0 | payload_present | 45 | `45f239d1e5fb62dd24c5b52b9bfc526423086bc3d43e3b471707022c93b62a13` |
| crosscloud:gcp:automated_collection:additional:run-1:n | additional | 1 | payload_absent | 43 | `16df4ddf4e076272521a625c9f1edd5cbf976eae19b5919c4af4553d1cc68df2` |
| crosscloud:gcp:automated_collection:additional:run-1:y | additional | 1 | payload_present | 45 | `2be5b83158ca7b38b88549c054ac173db65d0e6acdc1d40f85b11d3c55ac9ccc` |
| crosscloud:gcp:automated_collection:additional:run-2:n | additional | 2 | payload_absent | 45 | `ccdfed60889106e9e862cf11fc455c71d0da44b35aa0c2a5d93d323042debdde` |
| crosscloud:gcp:automated_collection:additional:run-2:y | additional | 2 | payload_present | 43 | `49b27217d8fb6c06d2cd47db4d584538b003e0b715824adf02fd99052e751af7` |
| crosscloud:gcp:automated_collection:additional:run-3:n | additional | 3 | payload_absent | 43 | `c6619c70efb162a0a577405610a133f7dbf58c81ea08d7b1da0ff38f07606afc` |
| crosscloud:gcp:automated_collection:additional:run-3:y | additional | 3 | payload_present | 43 | `1597875bd4323155018a765c8d13e8eca6f35c32275a7341bcf35b16f6d0dfc3` |
| crosscloud:gcp:automated_collection:additional:run-4:n | additional | 4 | payload_absent | 45 | `a18efc6149980c847794060f88a5e43ecbfcec1dd8a246ec900b6d09adf7e249` |
| crosscloud:gcp:automated_collection:additional:run-4:y | additional | 4 | payload_present | 45 | `9e89c23cb2b074afca3143896963b9bf761a98cca406b410d6af013b27098d6a` |
| crosscloud:gcp:automated_collection:additional:run-5:n | additional | 5 | payload_absent | 43 | `55f816c5a3473aa1cb51da1275a798c3300c8ab118f2ebf64e04d0a424e01ad3` |
| crosscloud:gcp:automated_collection:additional:run-5:y | additional | 5 | payload_present | 43 | `c1e9c5b9234534839bc9e2178ccc43622c77944cff0b45e45d269069227ffbe9` |
| crosscloud:gcp:automated_collection:additional:run-6:n | additional | 6 | payload_absent | 43 | `1a0b64cbf53df589f976842c49b01d83e072be55332ddfa247c51e414759810d` |
| crosscloud:gcp:automated_collection:additional:run-6:y | additional | 6 | payload_present | 43 | `abb9526976f0362cdf59bbec5d104418396c8baa769eb4968f52a37d1531052f` |
| crosscloud:gcp:automated_collection:additional:run-7:n | additional | 7 | payload_absent | 43 | `f9c3190f2981f52dd49bb7b35146354caa4af034c1b1a15fc24ae3ab292ef5c3` |
| crosscloud:gcp:automated_collection:additional:run-7:y | additional | 7 | payload_present | 45 | `52bbfd150496d49531486f918b3d81ca6f6a57fb725149246967e6d8de3747ef` |
| crosscloud:gcp:automated_collection:additional:run-8:n | additional | 8 | payload_absent | 45 | `1c2d36d036860c84649e82a57229d0809adc2db7f77f187fcc2eeb97bed3a1d5` |
| crosscloud:gcp:automated_collection:additional:run-8:y | additional | 8 | payload_present | 45 | `e6b046d77b9cc3a1e22932094f20cd61432d3685290f8dbfa4dcc2fdb9abbac0` |
| crosscloud:gcp:automated_collection:additional:run-9:n | additional | 9 | payload_absent | 43 | `fca1ea4ed5fc503a48c996f7f9f1f44bbb12d5f7565da3deca39cab8eea3e8e1` |
| crosscloud:gcp:automated_collection:additional:run-9:y | additional | 9 | payload_present | 43 | `5c610960a128ab17d39e0c1d636b89daa2865a370a2d3337f0f574519d4ec7bd` |
| crosscloud:gcp:automated_collection:default:run-0:n | default | 0 | payload_absent | 7 | `1dd170372d32262ab9c6ad900ec828fca8cd8bf1a64dc893793993a7ddf28673` |
| crosscloud:gcp:automated_collection:default:run-0:y | default | 0 | payload_present | 7 | `96fb5b8498f3d85075c702e47389abe32aca2860364d1221a45e143d57423693` |
| crosscloud:gcp:automated_collection:default:run-1:n | default | 1 | payload_absent | 7 | `766dd9f3461c464a11845e5341beaccc9b17e8a4ade7d40929f5e17a1217127a` |
| crosscloud:gcp:automated_collection:default:run-1:y | default | 1 | payload_present | 7 | `65490a49d2743c442479a439b0764ae0112480cb6a751ac4c49802c490bdfa5a` |
| crosscloud:gcp:automated_collection:default:run-2:n | default | 2 | payload_absent | 7 | `f6ad77f0107a9090d4ebcda3e07060ee5ba049a3b6bff864d1f63088d403f459` |
| crosscloud:gcp:automated_collection:default:run-2:y | default | 2 | payload_present | 7 | `6025d81b231f9e458fa07f7b53b31c8aa981d4463a22e3befb3ead168c26d836` |
| crosscloud:gcp:automated_collection:default:run-3:n | default | 3 | payload_absent | 7 | `981379157a069b140f8218f3c7db07b7f3ba973184acbc793567b4559cca5215` |
| crosscloud:gcp:automated_collection:default:run-3:y | default | 3 | payload_present | 7 | `a321ba779b603db4f7b360afea813dbcaa32a824ea99e0be7ebc2d633c7a02a5` |
| crosscloud:gcp:automated_collection:default:run-4:n | default | 4 | payload_absent | 7 | `1c3c0a3e9edc02f9f481995a07c14279986ebfad75ba39cbb6e6785b55b966a7` |
| crosscloud:gcp:automated_collection:default:run-4:y | default | 4 | payload_present | 7 | `ed12d559f67c3b1f8b020221dbc7337ca399fabd2e547ca57e3eba20c7bff1fa` |
| crosscloud:gcp:automated_collection:default:run-5:n | default | 5 | payload_absent | 7 | `3741b7de07634f7d41046b0b04d9938dc1c4ab93924f2609a3de0c12c355d20f` |
| crosscloud:gcp:automated_collection:default:run-5:y | default | 5 | payload_present | 7 | `7b194b71ef11735e89c1bcfe5794d444938663ab1c908f83c28cf2170108c00d` |
| crosscloud:gcp:automated_collection:default:run-6:n | default | 6 | payload_absent | 7 | `9cd4e90533549259c1a09d0c656101a6427954a20f203d8bf852dca650c47d26` |
| crosscloud:gcp:automated_collection:default:run-6:y | default | 6 | payload_present | 7 | `47d637ab7ea04943806f5903bf390bd5cc70896946538874c63ba8a0b50046ef` |
| crosscloud:gcp:automated_collection:default:run-7:n | default | 7 | payload_absent | 7 | `854f59e45d470dc1995c122dc88823f7fc342b3ad1ac8fab93411d53e06cfdb7` |
| crosscloud:gcp:automated_collection:default:run-7:y | default | 7 | payload_present | 7 | `df4c615753c52c1692f2020ba7e1ab1df366b83b8763e060551d202950ea1c81` |
| crosscloud:gcp:automated_collection:default:run-8:n | default | 8 | payload_absent | 7 | `eb0a519894ab4f3584ce5b0ec6861689a034a66fa992aee2f78467bc3fd45091` |
| crosscloud:gcp:automated_collection:default:run-8:y | default | 8 | payload_present | 7 | `b39f5bd76e43ca6cd11beeb8fb53f04e0b4216438d7ee6411b96fe99a55cdbb0` |
| crosscloud:gcp:automated_collection:default:run-9:n | default | 9 | payload_absent | 7 | `e269c9787752dcc89286bb556f91bf2c579212253b27a277cebc41832be62c08` |
| crosscloud:gcp:automated_collection:default:run-9:y | default | 9 | payload_present | 7 | `91184755f1f7e2058250c4adc9f147a7ea7cde220d542eb02cd69112fad4c690` |

### 原始文件完整性

- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/README.md` — SHA-256 `b073b2e97aea4073fec2bf387e2c255d987dd8f3710e84f2df3cc59947e510f8`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/attack_scripts.zip` — SHA-256 `4599be3e224f3b9b43e76ab4ec1bfa8e3b209ebe529fb218ae4e65dd22417900`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/gcp_logs_redacted.zip` — SHA-256 `2765fedd91ce6a03c9a8d156a3d83e34dd493e7a366d0b38abd88a00ad10c5a4`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/log_analysis.zip` — SHA-256 `23b41863cc2ece4936277a1ee1fc6f64b4fea9f3c0f698cefbf5626eeca00fcf`

## 36. `crosscloud:gcp:automated_exfiltration`

- 描述：DOI-published paired payload/no-payload GCP telemetry for automated_exfiltration.
- 发布者：Dhooghe et al.
- 发布日期：2026-04-30
- 环境：controlled cloud subscription
- ATT&CK：
- 原始文件数：4
- 规范化观测数：0
- 上游 episode 数：40

### 准入判断（人工填写）

- [ ] 有外部或低权限入口
- [ ] 存在多步关系，而非单点事件
- [ ] 终点为数据库、存储、备份、secret 或其他数据资产
- [ ] 关键边均有原始证据
- [ ] 不是近重复案例
- 决定：`<accept | needs_execution | reject>`
- 理由：`<人工填写>`

### 观测索引

| observation_id | timestamp | actor_type | service | operation | status | raw record |
|---|---:|---|---|---|---|---|

### 上游配对 episode

| episode_id | profile | run | source condition | observations | member SHA-256 |
|---|---|---:|---|---:|---|
| crosscloud:gcp:automated_exfiltration:additional:run-0:n | additional | 0 | payload_absent | 102 | `8896de932791944444f035d1f0850b9c45942aaae366f1f4863b80b2c34c5f59` |
| crosscloud:gcp:automated_exfiltration:additional:run-0:y | additional | 0 | payload_present | 875 | `f5115f6c32f11dbc9cb8cc74e75432d8b0ac1e681d5c6404846fccb6e8fde5ae` |
| crosscloud:gcp:automated_exfiltration:additional:run-1:n | additional | 1 | payload_absent | 95 | `41a9500e137a7ed13606e8a60e13b713a3fff0c576d1270c5d8a8b106bb0c90f` |
| crosscloud:gcp:automated_exfiltration:additional:run-1:y | additional | 1 | payload_present | 834 | `aaf681fe7df2b7526a52afbc0b4187a2c5e4468aa79ebd0cefd1cf4f83461795` |
| crosscloud:gcp:automated_exfiltration:additional:run-2:n | additional | 2 | payload_absent | 109 | `c671914bbfe0c63c16edcc98297474f038fc227e679f8a06da25e5eb7c8ac948` |
| crosscloud:gcp:automated_exfiltration:additional:run-2:y | additional | 2 | payload_present | 836 | `dc5e4ddd1a2fab5ed70f86d7545c3efcfd2612361c2ba535ecff0183ea222dab` |
| crosscloud:gcp:automated_exfiltration:additional:run-3:n | additional | 3 | payload_absent | 97 | `dfff081df2eae5cbec103c476d806936566a4c29d8177708e1f71aa51982b303` |
| crosscloud:gcp:automated_exfiltration:additional:run-3:y | additional | 3 | payload_present | 865 | `34d4ea3eaeac3c273851ffcb60f7d193c5dc688819a7135fc01906de84445121` |
| crosscloud:gcp:automated_exfiltration:additional:run-4:n | additional | 4 | payload_absent | 106 | `88507ad87dbd3361c5fd78ac9eb419f56c098a1d4c16ddd237ab1bb10ddc310c` |
| crosscloud:gcp:automated_exfiltration:additional:run-4:y | additional | 4 | payload_present | 858 | `fde4302e5c610adb1b183a22bc6a4602aa32664607c49f9a4838efd5094560f8` |
| crosscloud:gcp:automated_exfiltration:additional:run-5:n | additional | 5 | payload_absent | 107 | `27221078f8700a0f8ea55c996c7c60aceb7c9b0af6009b435a9bf24137cb9545` |
| crosscloud:gcp:automated_exfiltration:additional:run-5:y | additional | 5 | payload_present | 861 | `8bf09e0b5f6a6f151ab8f21e8cdb3cc7e8da879d1008fc77669a2cfef435d42c` |
| crosscloud:gcp:automated_exfiltration:additional:run-6:n | additional | 6 | payload_absent | 97 | `2b1ef6d6a029b5f634892a87eea129c96ffdc27841e56d0697b3988e339c2ea9` |
| crosscloud:gcp:automated_exfiltration:additional:run-6:y | additional | 6 | payload_present | 839 | `f88e2413193a5abc289c94fbe31dc8722e618b7504057a970b3a102aa2542fbb` |
| crosscloud:gcp:automated_exfiltration:additional:run-7:n | additional | 7 | payload_absent | 92 | `230df400755158ad9d63f58130a9fab84824cac1d69cd4a10905c9fb3ba79caa` |
| crosscloud:gcp:automated_exfiltration:additional:run-7:y | additional | 7 | payload_present | 835 | `15f89bb98386d52085f9b532d7ec567aa50b20786616182fb7a366c72c1aa28c` |
| crosscloud:gcp:automated_exfiltration:additional:run-8:n | additional | 8 | payload_absent | 93 | `4a56cb52c8b5da2501983e1cab643ba92148af8f4d6a50c2cbd682a80250b9aa` |
| crosscloud:gcp:automated_exfiltration:additional:run-8:y | additional | 8 | payload_present | 892 | `a5447a56bec1273dc795f7bd5e03c60c178d68e821873c8e2f74f0f48b93491e` |
| crosscloud:gcp:automated_exfiltration:additional:run-9:n | additional | 9 | payload_absent | 96 | `2e452bfaf9b8a8dbb426ccb57d1605978e6a48c5790a634e4983941905f6d9f3` |
| crosscloud:gcp:automated_exfiltration:additional:run-9:y | additional | 9 | payload_present | 851 | `c255a42c0f3bd8485aa5df74a3fcd13bc82fa60d636b723aa32063d2637d0c02` |
| crosscloud:gcp:automated_exfiltration:default:run-0:n | default | 0 | payload_absent | 10 | `b43fa85a9dbc846ce95dda024284f5a10fc2e81af336ba239ffc9f4ce697befd` |
| crosscloud:gcp:automated_exfiltration:default:run-0:y | default | 0 | payload_present | 543 | `7af7823fe99875e53f0e7e99a9eaa2349dfcc8d7448385b7ea1c3aec62be9e52` |
| crosscloud:gcp:automated_exfiltration:default:run-1:n | default | 1 | payload_absent | 10 | `823b4a911c5385a65437737f4e1120206d662bfe7f6d604baa3bdc9db4580fb9` |
| crosscloud:gcp:automated_exfiltration:default:run-1:y | default | 1 | payload_present | 556 | `d164946ac8d6851690e78a49ec30d1a8ed2c7089320fe0466ed444cd1ba88a60` |
| crosscloud:gcp:automated_exfiltration:default:run-2:n | default | 2 | payload_absent | 10 | `5954e3cb02853c8d2b01799dd4b9223c2cbc597efa63206c84c798b013ba8e05` |
| crosscloud:gcp:automated_exfiltration:default:run-2:y | default | 2 | payload_present | 553 | `b215feeffe902e9a150ad3deb2ef7047fbbe5076516082ae229406d674e32e0b` |
| crosscloud:gcp:automated_exfiltration:default:run-3:n | default | 3 | payload_absent | 10 | `f31f83493a7abb18c4762aea26ff697066e8338d186bce15697a191d316d7db8` |
| crosscloud:gcp:automated_exfiltration:default:run-3:y | default | 3 | payload_present | 548 | `932d0c2cf39be64efe9b6ee2810e22049dbb287f53b12d90958ac081e7d7da58` |
| crosscloud:gcp:automated_exfiltration:default:run-4:n | default | 4 | payload_absent | 10 | `1b03dd70997f171e4764ffbe1a04e5b7c5b70bd955d26a2e66ac75cc5f87b43a` |
| crosscloud:gcp:automated_exfiltration:default:run-4:y | default | 4 | payload_present | 550 | `3b22f77e3589473648454561bb58678a46f6ef72b237518b870e82c04c62203a` |
| crosscloud:gcp:automated_exfiltration:default:run-5:n | default | 5 | payload_absent | 10 | `c1ebe1d7cd138e4c1e048c23af6d74828bde822d7c76e01647fa13208fc469d2` |
| crosscloud:gcp:automated_exfiltration:default:run-5:y | default | 5 | payload_present | 558 | `7fa879bb9176ab7c53be7deb69a4ed40cf5e63078eea8c8144cb8d4d5beb8779` |
| crosscloud:gcp:automated_exfiltration:default:run-6:n | default | 6 | payload_absent | 10 | `9eb888019c1c04d74765a55524ad43432e334fc3b245523acffc414b5c1480be` |
| crosscloud:gcp:automated_exfiltration:default:run-6:y | default | 6 | payload_present | 551 | `ba40e503fb9347f60ad9f085b4e63a7f0ed2e453a697a85f2e58aa34e7c009e4` |
| crosscloud:gcp:automated_exfiltration:default:run-7:n | default | 7 | payload_absent | 10 | `a34d7160686c4327226b14024643a5ca6e80ca00096cc9ea216d48e818956d60` |
| crosscloud:gcp:automated_exfiltration:default:run-7:y | default | 7 | payload_present | 550 | `935b8563ad5d8e108dbaa844ac5a542def4755a59070c1143b4da6bd2ebc8d73` |
| crosscloud:gcp:automated_exfiltration:default:run-8:n | default | 8 | payload_absent | 10 | `1b6562b5d548ab19a044363158d05041a4e5f02f6c63be595c99909caf4b1119` |
| crosscloud:gcp:automated_exfiltration:default:run-8:y | default | 8 | payload_present | 551 | `a52863dd6dfbf40204ceb267b8872a4b3ed8ef04fb82cc5b79d35a9159760c46` |
| crosscloud:gcp:automated_exfiltration:default:run-9:n | default | 9 | payload_absent | 10 | `9fd9bef437e0f35f2ac814ba7d5f7d1d69be22b49e3abf86b8f4d4904180bc2b` |
| crosscloud:gcp:automated_exfiltration:default:run-9:y | default | 9 | payload_present | 550 | `cea95a3b6261d1bdc923efc5b28eb11f93f6628526d7485ff89643dc6058f7b2` |

### 原始文件完整性

- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/README.md` — SHA-256 `b073b2e97aea4073fec2bf387e2c255d987dd8f3710e84f2df3cc59947e510f8`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/attack_scripts.zip` — SHA-256 `4599be3e224f3b9b43e76ab4ec1bfa8e3b209ebe529fb218ae4e65dd22417900`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/gcp_logs_redacted.zip` — SHA-256 `2765fedd91ce6a03c9a8d156a3d83e34dd493e7a366d0b38abd88a00ad10c5a4`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/log_analysis.zip` — SHA-256 `23b41863cc2ece4936277a1ee1fc6f64b4fea9f3c0f698cefbf5626eeca00fcf`

## 37. `crosscloud:gcp:credentials_from_password_stores`

- 描述：DOI-published paired payload/no-payload GCP telemetry for credentials_from_password_stores.
- 发布者：Dhooghe et al.
- 发布日期：2026-04-30
- 环境：controlled cloud subscription
- ATT&CK：
- 原始文件数：4
- 规范化观测数：0
- 上游 episode 数：40

### 准入判断（人工填写）

- [ ] 有外部或低权限入口
- [ ] 存在多步关系，而非单点事件
- [ ] 终点为数据库、存储、备份、secret 或其他数据资产
- [ ] 关键边均有原始证据
- [ ] 不是近重复案例
- 决定：`<accept | needs_execution | reject>`
- 理由：`<人工填写>`

### 观测索引

| observation_id | timestamp | actor_type | service | operation | status | raw record |
|---|---:|---|---|---|---|---|

### 上游配对 episode

| episode_id | profile | run | source condition | observations | member SHA-256 |
|---|---|---:|---|---:|---|
| crosscloud:gcp:credentials_from_password_stores:additional:run-0:n | additional | 0 | payload_absent | 18 | `04ccd8fe70875117c2ef878f4f6dfe19c79810ff81c6d199652e061b40c363a4` |
| crosscloud:gcp:credentials_from_password_stores:additional:run-0:y | additional | 0 | payload_present | 27 | `141b0d3968e57f715613c40640445fffdc2adda1ef798dffbbe9de2f50e62dbc` |
| crosscloud:gcp:credentials_from_password_stores:additional:run-1:n | additional | 1 | payload_absent | 18 | `5ba613172fc0646c55c1ba72e8fc88633674299cf4c84ef50b10f679afe53091` |
| crosscloud:gcp:credentials_from_password_stores:additional:run-1:y | additional | 1 | payload_present | 27 | `8b84a3042a10bda9f74ebeb9ad3fda33cb437a7c890719719a7e7321aa445af8` |
| crosscloud:gcp:credentials_from_password_stores:additional:run-2:n | additional | 2 | payload_absent | 18 | `7c029f4854261fd0a21de1b989d79570ed2e5f63f4c5535877303d806cfa020e` |
| crosscloud:gcp:credentials_from_password_stores:additional:run-2:y | additional | 2 | payload_present | 27 | `07cb85c7ba22c08da348ae8eaafbb4fe88a64da88bfc5ee6344cf42c1ca40d5b` |
| crosscloud:gcp:credentials_from_password_stores:additional:run-3:n | additional | 3 | payload_absent | 18 | `bd4c5e23cd95b494b57669a418e48bf5edef11ba9723fb9b3f988207442ca8ff` |
| crosscloud:gcp:credentials_from_password_stores:additional:run-3:y | additional | 3 | payload_present | 27 | `b655476383d05782c2fc47c69b8ef3f101e6171b0bf2bd259c4895baba90da35` |
| crosscloud:gcp:credentials_from_password_stores:additional:run-4:n | additional | 4 | payload_absent | 18 | `39d5cf96771800f9c4b8c45714d5cfd073b8121ec833adad997cc86d9878df71` |
| crosscloud:gcp:credentials_from_password_stores:additional:run-4:y | additional | 4 | payload_present | 27 | `9a943941f039b2e00b07ed04420419ed1a4c02b9155b5961146695be4a8e7dc3` |
| crosscloud:gcp:credentials_from_password_stores:additional:run-5:n | additional | 5 | payload_absent | 18 | `35714cf93d91c5557989e392afe6c5d5ed53c317b1911e6b4ed648d4ef2f13f3` |
| crosscloud:gcp:credentials_from_password_stores:additional:run-5:y | additional | 5 | payload_present | 27 | `ebc93624c015f6df132e78aa7c3267da06566f638e35942bf06b0843623cbcf0` |
| crosscloud:gcp:credentials_from_password_stores:additional:run-6:n | additional | 6 | payload_absent | 18 | `6d43ff66d93666f5e7273e3d44bda4fdb9a981b699204d8609fe94f52fb52373` |
| crosscloud:gcp:credentials_from_password_stores:additional:run-6:y | additional | 6 | payload_present | 27 | `8ce6d9bf1d639812f1c37d7793c5340a0d6b8c4ef7feedf177ed900d18ebc3db` |
| crosscloud:gcp:credentials_from_password_stores:additional:run-7:n | additional | 7 | payload_absent | 18 | `44c367ddea315b93d39635de9773745b0b089f44c23d358f3570af3cfccfceda` |
| crosscloud:gcp:credentials_from_password_stores:additional:run-7:y | additional | 7 | payload_present | 27 | `afc3aa55293bdb7afd91993cc23538806452ca39a3a4a5f178f21c27fac6e76d` |
| crosscloud:gcp:credentials_from_password_stores:additional:run-8:n | additional | 8 | payload_absent | 18 | `ddbc7a1abf232f628709de9b55bd9c141fc82afcfb6bb1af6414058d692bdb38` |
| crosscloud:gcp:credentials_from_password_stores:additional:run-8:y | additional | 8 | payload_present | 27 | `6b929a2c272b92f645381b7eda303596a3db59c7be03efc5137c985dd92b2771` |
| crosscloud:gcp:credentials_from_password_stores:additional:run-9:n | additional | 9 | payload_absent | 18 | `65244fe5a865f2e4940afd38d34324828fe350d6f485861d66e61f5d41b48a48` |
| crosscloud:gcp:credentials_from_password_stores:additional:run-9:y | additional | 9 | payload_present | 27 | `e361ce295f3006b7bc1a6315d89ff36d315259f7e4d7878a35ac851f3c551966` |
| crosscloud:gcp:credentials_from_password_stores:default:run-0:n | default | 0 | payload_absent | 7 | `c7ffe4d5e3d9818c9938f2822438343717772904c8d775bda0090932679b2939` |
| crosscloud:gcp:credentials_from_password_stores:default:run-0:y | default | 0 | payload_present | 10 | `3fa4b494c70c78231ebc6caf4072b023f24d1ff62bd2285252d9ebeeefe52a60` |
| crosscloud:gcp:credentials_from_password_stores:default:run-1:n | default | 1 | payload_absent | 7 | `3123372609bbd1cab94edd52dd0879dd7525278474989016a55dd887810bd2f1` |
| crosscloud:gcp:credentials_from_password_stores:default:run-1:y | default | 1 | payload_present | 10 | `d5fbaefc9c2f1b346cbaad51c67bc1c3d9180dea7928c874a709651cc1d86a15` |
| crosscloud:gcp:credentials_from_password_stores:default:run-2:n | default | 2 | payload_absent | 7 | `efc2fabd1f666c0298cf029f0b3330dc33e4855352da927bcba80f7e6d0d3cbc` |
| crosscloud:gcp:credentials_from_password_stores:default:run-2:y | default | 2 | payload_present | 10 | `b05d8863afb17a73956e2437f0efbfd932019c76c3127f0bc401fd6b95c44443` |
| crosscloud:gcp:credentials_from_password_stores:default:run-3:n | default | 3 | payload_absent | 7 | `dc04b81ed33a69edb63ac4ad99cddadb224ff78e7241760ccef77528a503a5fb` |
| crosscloud:gcp:credentials_from_password_stores:default:run-3:y | default | 3 | payload_present | 10 | `e7097a30ff9230e6716581663bfd86228fb1a1bc50f6f6efb5e745c17bbee90d` |
| crosscloud:gcp:credentials_from_password_stores:default:run-4:n | default | 4 | payload_absent | 7 | `4ad8e4664509dd625206d26627de4c9cb910e750a0fc69dfb4117e360d9ab0a0` |
| crosscloud:gcp:credentials_from_password_stores:default:run-4:y | default | 4 | payload_present | 10 | `bfe5e64251f9ffe71e2c9cb8900bf148d0ec456e5c93dd6043d8a4d8f6b81c13` |
| crosscloud:gcp:credentials_from_password_stores:default:run-5:n | default | 5 | payload_absent | 7 | `04436e532c235c9d20fcc92d4361bfb0ec5609cd41e60abdf6c3eb7e1374a0d5` |
| crosscloud:gcp:credentials_from_password_stores:default:run-5:y | default | 5 | payload_present | 10 | `f639cc9521f8c54a0193880e01f5c3578a82f0468266f029738a56260576a4f6` |
| crosscloud:gcp:credentials_from_password_stores:default:run-6:n | default | 6 | payload_absent | 7 | `1183347a6a7a27d691f16acfaeaaa9224766820d2720bb9a8512b9ec15561390` |
| crosscloud:gcp:credentials_from_password_stores:default:run-6:y | default | 6 | payload_present | 10 | `74259adef33eb43efbcf8e886d43461331b755bbb295dfca35d26cfd3f876883` |
| crosscloud:gcp:credentials_from_password_stores:default:run-7:n | default | 7 | payload_absent | 7 | `1d2af8bac6334169afc91026539e7377490129c5ec6ba278335c0698fc0373cc` |
| crosscloud:gcp:credentials_from_password_stores:default:run-7:y | default | 7 | payload_present | 10 | `254a48b9cef6d0021a7368cb51818dc6839f49c78145fbbf5645ceedf93e4a55` |
| crosscloud:gcp:credentials_from_password_stores:default:run-8:n | default | 8 | payload_absent | 7 | `0c662ee7768bce853fd5da6a52b7043f92fa88a858ebc4e9c9404b5336da7f27` |
| crosscloud:gcp:credentials_from_password_stores:default:run-8:y | default | 8 | payload_present | 10 | `e6d86ede94100995d582e6cb6c0b76ab100665c2dd00a1a4996ba7ef2d665303` |
| crosscloud:gcp:credentials_from_password_stores:default:run-9:n | default | 9 | payload_absent | 7 | `8640ede9525bcd794a700154d2d13c0cf8f4ed0c27d6e9e1c72a8aa54eefbd34` |
| crosscloud:gcp:credentials_from_password_stores:default:run-9:y | default | 9 | payload_present | 10 | `66c7f835a852bcdb411fff654127537ff4d3a17dda31ba35a9ef5cd708b0bd8d` |

### 原始文件完整性

- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/README.md` — SHA-256 `b073b2e97aea4073fec2bf387e2c255d987dd8f3710e84f2df3cc59947e510f8`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/attack_scripts.zip` — SHA-256 `4599be3e224f3b9b43e76ab4ec1bfa8e3b209ebe529fb218ae4e65dd22417900`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/gcp_logs_redacted.zip` — SHA-256 `2765fedd91ce6a03c9a8d156a3d83e34dd493e7a366d0b38abd88a00ad10c5a4`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/log_analysis.zip` — SHA-256 `23b41863cc2ece4936277a1ee1fc6f64b4fea9f3c0f698cefbf5626eeca00fcf`

## 38. `crosscloud:gcp:data_destruction`

- 描述：DOI-published paired payload/no-payload GCP telemetry for data_destruction.
- 发布者：Dhooghe et al.
- 发布日期：2026-04-30
- 环境：controlled cloud subscription
- ATT&CK：
- 原始文件数：4
- 规范化观测数：0
- 上游 episode 数：40

### 准入判断（人工填写）

- [ ] 有外部或低权限入口
- [ ] 存在多步关系，而非单点事件
- [ ] 终点为数据库、存储、备份、secret 或其他数据资产
- [ ] 关键边均有原始证据
- [ ] 不是近重复案例
- 决定：`<accept | needs_execution | reject>`
- 理由：`<人工填写>`

### 观测索引

| observation_id | timestamp | actor_type | service | operation | status | raw record |
|---|---:|---|---|---|---|---|

### 上游配对 episode

| episode_id | profile | run | source condition | observations | member SHA-256 |
|---|---|---:|---|---:|---|
| crosscloud:gcp:data_destruction:additional:run-0:n | additional | 0 | payload_absent | 51 | `374bf8453d3160ed74d5fd3fac6552fb678c853235d1b9dd13e74f85503b5ffe` |
| crosscloud:gcp:data_destruction:additional:run-0:y | additional | 0 | payload_present | 154 | `c5e5f3a4314c77366e26ffa0a7346847e232465ac9bc749dbb139fd34566e0c8` |
| crosscloud:gcp:data_destruction:additional:run-1:n | additional | 1 | payload_absent | 51 | `7bf37f90d0046bd13b1357d318e1117454b63f0592c59a0d4c4c29bbb193645f` |
| crosscloud:gcp:data_destruction:additional:run-1:y | additional | 1 | payload_present | 154 | `a7c7c4b661d8668e1e372f0fec98be8dd7e14092b8060f8caf398d06e8f6825d` |
| crosscloud:gcp:data_destruction:additional:run-2:n | additional | 2 | payload_absent | 51 | `d0d160984f20a6aa35045eda2a05001fe3e499aca257fb006bc8884c875f00c5` |
| crosscloud:gcp:data_destruction:additional:run-2:y | additional | 2 | payload_present | 154 | `a1dc0b6dcc21417cba2422d151f55eabdef5740459825db49147af2a3b26139a` |
| crosscloud:gcp:data_destruction:additional:run-3:n | additional | 3 | payload_absent | 51 | `3a0913c06cdf3f551022e6cd3848f40c941906f00045229cb82c35e0574b5db9` |
| crosscloud:gcp:data_destruction:additional:run-3:y | additional | 3 | payload_present | 154 | `5efafcba2ef8b6345f4c6910b3005aaf8176ddf60ceab08b426216aa7b2ab984` |
| crosscloud:gcp:data_destruction:additional:run-4:n | additional | 4 | payload_absent | 51 | `81563279dea66b424470ede4f754e04a157509ce378ce0ab4b96929422f93c92` |
| crosscloud:gcp:data_destruction:additional:run-4:y | additional | 4 | payload_present | 154 | `63c7d23e977c051bd3e7b991ff226090a68154a873778ad85ef68d5a25fa7727` |
| crosscloud:gcp:data_destruction:additional:run-5:n | additional | 5 | payload_absent | 51 | `f1414f41976f3da0e872f151bcd607362ccf23f0b773a28021bfa6d97c0367e7` |
| crosscloud:gcp:data_destruction:additional:run-5:y | additional | 5 | payload_present | 154 | `c819bf741dbab2b90bef4de48d9ebe958c24ebd6e0405872e737a57fddcd2c12` |
| crosscloud:gcp:data_destruction:additional:run-6:n | additional | 6 | payload_absent | 51 | `eff1be59fc579d371225191351daaa785237502d831a6f46d826175813ddc908` |
| crosscloud:gcp:data_destruction:additional:run-6:y | additional | 6 | payload_present | 154 | `73e72082f7e1ee8854e72a4b483e61254d412808a3ef096a08c144b898bffd49` |
| crosscloud:gcp:data_destruction:additional:run-7:n | additional | 7 | payload_absent | 51 | `009601de832a1222dc60a7c25f54b19a30ff0222834baa1b442333620ca2f889` |
| crosscloud:gcp:data_destruction:additional:run-7:y | additional | 7 | payload_present | 154 | `658cde7f0dcf02789a4d1aa854294680691d0ea972e9965839dfbec5d880f6a3` |
| crosscloud:gcp:data_destruction:additional:run-8:n | additional | 8 | payload_absent | 51 | `3fbd9842811b521bf43dc820cb47c09f1b421e32c07c96e664150292fde61080` |
| crosscloud:gcp:data_destruction:additional:run-8:y | additional | 8 | payload_present | 154 | `ae9302107939859df64dbd925cedfb07f0072966234cf5879487cdd55d9bbb5f` |
| crosscloud:gcp:data_destruction:additional:run-9:n | additional | 9 | payload_absent | 51 | `81053f4238d6f57e49ff2007fee4a14ca101ae12dca19f8a5fd2debf3bc5ca39` |
| crosscloud:gcp:data_destruction:additional:run-9:y | additional | 9 | payload_present | 154 | `28e70fa52728d6e34c3b4b7f5cfaca6b1cfa88e61156bbe90ebf1b0c441e88a1` |
| crosscloud:gcp:data_destruction:default:run-0:n | default | 0 | payload_absent | 1 | `e9bfd6b00d48f6b9e7f1cb4146e4ada186e5fde3ebe9f360152ebb235f333dd6` |
| crosscloud:gcp:data_destruction:default:run-0:y | default | 0 | payload_present | 2 | `1174a39622beef7c6e73c20e77e8b6ed6f61987bfa04b7c910d2bf1941a3bc6c` |
| crosscloud:gcp:data_destruction:default:run-1:n | default | 1 | payload_absent | 1 | `0e066134da738b814ce7211abd627749ae09951965cb9130f84410c5a4316d24` |
| crosscloud:gcp:data_destruction:default:run-1:y | default | 1 | payload_present | 2 | `013fd2e0dbd2a3bba0953eafcccab940cc18c67adbe24a21848e8fc1bd872909` |
| crosscloud:gcp:data_destruction:default:run-2:n | default | 2 | payload_absent | 1 | `07efa3296662c02d9ce2c00a7e39d645ac0eac9fca58d40d559809e97370cff9` |
| crosscloud:gcp:data_destruction:default:run-2:y | default | 2 | payload_present | 2 | `4df797b8b7e60144a6d33935b567024747252a67056f8ed0d092ef6fe2dc5a3c` |
| crosscloud:gcp:data_destruction:default:run-3:n | default | 3 | payload_absent | 1 | `c6d7691f5f5c9b356d2c797df4972ec2027853dc3177692459fa4599fc86c2bc` |
| crosscloud:gcp:data_destruction:default:run-3:y | default | 3 | payload_present | 2 | `08f414fb520c31dfa5e83bba38c222d3cf8f408e5080a73586ac5a0709d4d444` |
| crosscloud:gcp:data_destruction:default:run-4:n | default | 4 | payload_absent | 1 | `dbe6d90d3aa729783e2dd60b166c82ec1e96d897a0430a3d3a443cb3d63513ff` |
| crosscloud:gcp:data_destruction:default:run-4:y | default | 4 | payload_present | 2 | `fb0911a97b10a1e3ae3f1d8e4d594a3025c6d6dd0affb950aea1e98b825a7b76` |
| crosscloud:gcp:data_destruction:default:run-5:n | default | 5 | payload_absent | 1 | `4769b8b15d5a5854e4f5cc6a4bb1c92b98955155c3667730e64537dabbf23589` |
| crosscloud:gcp:data_destruction:default:run-5:y | default | 5 | payload_present | 2 | `766a8396b021efe8cd60ce7605b103d72b5a5f521054a62389bd92f286c34841` |
| crosscloud:gcp:data_destruction:default:run-6:n | default | 6 | payload_absent | 1 | `c1ef81ff734a4a2c46fa52cf65e666467b506bd0674c59561b8b0b04fbb50791` |
| crosscloud:gcp:data_destruction:default:run-6:y | default | 6 | payload_present | 2 | `5561bda2ad2ec4b3ec52366a4ae6bddeb8cd77fb8d0bcf5945e214204fcf2e2d` |
| crosscloud:gcp:data_destruction:default:run-7:n | default | 7 | payload_absent | 1 | `bf98e09a3796381f80657829679045e1c93cd79efd6f88d0a28e32bc31af33c5` |
| crosscloud:gcp:data_destruction:default:run-7:y | default | 7 | payload_present | 2 | `c695f29f1eabe785369e1eeb77be18a830d8573bda5c59e116bd06a35bb2b93d` |
| crosscloud:gcp:data_destruction:default:run-8:n | default | 8 | payload_absent | 1 | `d14110a6a9ced3f01ea7c3a209700cef3db3ceb376cc3ee451d192fa7d29a75d` |
| crosscloud:gcp:data_destruction:default:run-8:y | default | 8 | payload_present | 2 | `ba87e5766a9dbf552d330379052a0ac0316e45c88d1456ccc1b034dd8c2de002` |
| crosscloud:gcp:data_destruction:default:run-9:n | default | 9 | payload_absent | 1 | `e038d5eeb1cccd9b21126a6ba7d1720214651922b15deec839b2400704fbdb40` |
| crosscloud:gcp:data_destruction:default:run-9:y | default | 9 | payload_present | 2 | `4b0d69685bd95f580a9383308131e974c4d34e9af10b29dc870a557a1b44ccb6` |

### 原始文件完整性

- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/README.md` — SHA-256 `b073b2e97aea4073fec2bf387e2c255d987dd8f3710e84f2df3cc59947e510f8`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/attack_scripts.zip` — SHA-256 `4599be3e224f3b9b43e76ab4ec1bfa8e3b209ebe529fb218ae4e65dd22417900`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/gcp_logs_redacted.zip` — SHA-256 `2765fedd91ce6a03c9a8d156a3d83e34dd493e7a366d0b38abd88a00ad10c5a4`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/log_analysis.zip` — SHA-256 `23b41863cc2ece4936277a1ee1fc6f64b4fea9f3c0f698cefbf5626eeca00fcf`

## 39. `crosscloud:gcp:data_encrypted_for_impact`

- 描述：DOI-published paired payload/no-payload GCP telemetry for data_encrypted_for_impact.
- 发布者：Dhooghe et al.
- 发布日期：2026-04-30
- 环境：controlled cloud subscription
- ATT&CK：
- 原始文件数：4
- 规范化观测数：0
- 上游 episode 数：40

### 准入判断（人工填写）

- [ ] 有外部或低权限入口
- [ ] 存在多步关系，而非单点事件
- [ ] 终点为数据库、存储、备份、secret 或其他数据资产
- [ ] 关键边均有原始证据
- [ ] 不是近重复案例
- 决定：`<accept | needs_execution | reject>`
- 理由：`<人工填写>`

### 观测索引

| observation_id | timestamp | actor_type | service | operation | status | raw record |
|---|---:|---|---|---|---|---|

### 上游配对 episode

| episode_id | profile | run | source condition | observations | member SHA-256 |
|---|---|---:|---|---:|---|
| crosscloud:gcp:data_encrypted_for_impact:additional:run-0:n | additional | 0 | payload_absent | 16 | `f07f728344e1f2b11dce4a578871b4a7a0cd0de732b19a84062f12513ac7f31b` |
| crosscloud:gcp:data_encrypted_for_impact:additional:run-0:y | additional | 0 | payload_present | 20 | `6106db0cbf00b588b85bee47b7e44fda3b6908bbd9736ea4ea2bafcff528b783` |
| crosscloud:gcp:data_encrypted_for_impact:additional:run-1:n | additional | 1 | payload_absent | 16 | `2bf458380540484bf840d5a80df32519e892ac150487aebd7ab0aca45df68c52` |
| crosscloud:gcp:data_encrypted_for_impact:additional:run-1:y | additional | 1 | payload_present | 20 | `732b84e2e2a0396602bb9a1b403a373a4d43060205853695fdddbbf3609d8623` |
| crosscloud:gcp:data_encrypted_for_impact:additional:run-2:n | additional | 2 | payload_absent | 16 | `db4e280177c49737ad3d8491186f846b026c9e389119cad93c93adfbdfce9e4e` |
| crosscloud:gcp:data_encrypted_for_impact:additional:run-2:y | additional | 2 | payload_present | 20 | `2030b2bc623f375a154656de9633fa087522bb488213313c22d06a859dd4df33` |
| crosscloud:gcp:data_encrypted_for_impact:additional:run-3:n | additional | 3 | payload_absent | 16 | `18fb05149d484089debc7b0569eae3675a2dc368eae4001946498e48a37c8502` |
| crosscloud:gcp:data_encrypted_for_impact:additional:run-3:y | additional | 3 | payload_present | 20 | `840e2d56c207c83f7623148a2f9c36ad08b4dc18315e2aae19ce93fabc0a3e1e` |
| crosscloud:gcp:data_encrypted_for_impact:additional:run-4:n | additional | 4 | payload_absent | 16 | `f6f9b660b97ff54b605b4e3de5130ec0e94c4906dd8db95b07a778ed74d47fbd` |
| crosscloud:gcp:data_encrypted_for_impact:additional:run-4:y | additional | 4 | payload_present | 20 | `a1ee4d2b7a6f2cba118a567cc60044c738f39887310296d13d548e040495bf84` |
| crosscloud:gcp:data_encrypted_for_impact:additional:run-5:n | additional | 5 | payload_absent | 16 | `2376e776951566b942f7101733043b015a8c71b7ac7a0936d1d78d992b6925fe` |
| crosscloud:gcp:data_encrypted_for_impact:additional:run-5:y | additional | 5 | payload_present | 20 | `3e652b107a5d37855b82099766246ab1c6ac8a34f3fc9b21b68e4a40eab478bc` |
| crosscloud:gcp:data_encrypted_for_impact:additional:run-6:n | additional | 6 | payload_absent | 16 | `715f489323ee6abdb8c232adb7138d25738ef1160e65c578615717ae594a3641` |
| crosscloud:gcp:data_encrypted_for_impact:additional:run-6:y | additional | 6 | payload_present | 20 | `af68b96acbb5b0d79760a21663dbc6b7d681ca6da2bddd293c3ee01b1a4ffb34` |
| crosscloud:gcp:data_encrypted_for_impact:additional:run-7:n | additional | 7 | payload_absent | 16 | `2b458ecb52f0a261b9eff81e60d8e417b066a6b5aed2d7c6dd77b2fb436305d6` |
| crosscloud:gcp:data_encrypted_for_impact:additional:run-7:y | additional | 7 | payload_present | 20 | `ef82dbc274449e566e3cd2277545393e013ba937344d89aa67ff5d0cf20b0b16` |
| crosscloud:gcp:data_encrypted_for_impact:additional:run-8:n | additional | 8 | payload_absent | 16 | `f7a3f0f041b2f756d4a9a9e5e61d38a46314f2d0fb51ac4e443862091fc72bf3` |
| crosscloud:gcp:data_encrypted_for_impact:additional:run-8:y | additional | 8 | payload_present | 20 | `c8de7377032a37123c1535f95c19f3576d21d4f95ed4107c4948d82df207f798` |
| crosscloud:gcp:data_encrypted_for_impact:additional:run-9:n | additional | 9 | payload_absent | 16 | `a9ccc026eb0852b954d766fd0a382bf3f1697174ba1747c94a4566cefe9f9c23` |
| crosscloud:gcp:data_encrypted_for_impact:additional:run-9:y | additional | 9 | payload_present | 20 | `64883295a9616d377d93bcd3a0c416850a0292e94aa7880bcecd50551fdf439f` |
| crosscloud:gcp:data_encrypted_for_impact:default:run-0:n | default | 0 | payload_absent | 4 | `1ecf8ae8790e019bb54eea0f730d228c8ade294126aeacbf8e9c4c5e0096a586` |
| crosscloud:gcp:data_encrypted_for_impact:default:run-0:y | default | 0 | payload_present | 5 | `d6996c450e33020f8c7c0e5d45ef0e7bb28d34f9ee211e1ff5393d67d9ac8bc3` |
| crosscloud:gcp:data_encrypted_for_impact:default:run-1:n | default | 1 | payload_absent | 4 | `a1a3a572f56e07ebf6d41dfbc8e7595c5de5705d0d539c57ec627d17ab3eb153` |
| crosscloud:gcp:data_encrypted_for_impact:default:run-1:y | default | 1 | payload_present | 5 | `772d8cee1ad5620a5b3b25f31adfcd5c90fe374d70002253fd5530906f7603f4` |
| crosscloud:gcp:data_encrypted_for_impact:default:run-2:n | default | 2 | payload_absent | 4 | `086c12945768cb2bedc9138aee6e4bd6fb8ed37a8d688f986ec8be487862d88d` |
| crosscloud:gcp:data_encrypted_for_impact:default:run-2:y | default | 2 | payload_present | 5 | `22480cc0c82708f768daf83dbe8c21da8ff4d73b509860cf3af35d140c48c474` |
| crosscloud:gcp:data_encrypted_for_impact:default:run-3:n | default | 3 | payload_absent | 4 | `9840a0f07e882489da52c94ae25a0471e2e52911b9dc99dd70453c1ea6edeabc` |
| crosscloud:gcp:data_encrypted_for_impact:default:run-3:y | default | 3 | payload_present | 5 | `098d512f49d60ba0a87deefb39aeb42f0e1841b90bcf5da2a316cff19399511a` |
| crosscloud:gcp:data_encrypted_for_impact:default:run-4:n | default | 4 | payload_absent | 4 | `2810fae1cc0cb37ee6db3b43bebb61cc87c611c067273cc1b97d56dc153fecad` |
| crosscloud:gcp:data_encrypted_for_impact:default:run-4:y | default | 4 | payload_present | 5 | `c10d820cc5b208b5574e195f739fe97a601832d546fc3b0616eea257c941e561` |
| crosscloud:gcp:data_encrypted_for_impact:default:run-5:n | default | 5 | payload_absent | 4 | `def3fca3efdd0596777f8b43b8e637dc5901f0b2e8258792c4ba8261a6a1fcbf` |
| crosscloud:gcp:data_encrypted_for_impact:default:run-5:y | default | 5 | payload_present | 5 | `ea3a5fa237f0880b9bbe6482380303c9fdbf6aa45c9343b6c3477f88c6abbd8c` |
| crosscloud:gcp:data_encrypted_for_impact:default:run-6:n | default | 6 | payload_absent | 4 | `300a7cfc0bd6ee65d59a12b9af7b4cec7077f2011ade06c603e3477f76a5cbe0` |
| crosscloud:gcp:data_encrypted_for_impact:default:run-6:y | default | 6 | payload_present | 5 | `64ade1c0e7e64f29679b0dea5d6179788a605fbcfa70e520835db55646c0e69f` |
| crosscloud:gcp:data_encrypted_for_impact:default:run-7:n | default | 7 | payload_absent | 4 | `65450a8d0b6b8aaeaa5558fa8d130ec9ed22799319de2f4d71e771be0462ff08` |
| crosscloud:gcp:data_encrypted_for_impact:default:run-7:y | default | 7 | payload_present | 5 | `8857fba354a809a10d3e2bd950eee55630489a8cd895bf53e23ed8bfb53430bf` |
| crosscloud:gcp:data_encrypted_for_impact:default:run-8:n | default | 8 | payload_absent | 4 | `a9fecaed07304c827df84c59aae2785232f2bd3c3344bb9353c0832ca8ffb771` |
| crosscloud:gcp:data_encrypted_for_impact:default:run-8:y | default | 8 | payload_present | 5 | `ef656188e0a19d4aac2fea9b906de4c0cd8635fcaed208cf51cd55408855f576` |
| crosscloud:gcp:data_encrypted_for_impact:default:run-9:n | default | 9 | payload_absent | 4 | `d45fff0654d94554164d34c350fe5258e3a02b3730606fd9aed0c04650afca02` |
| crosscloud:gcp:data_encrypted_for_impact:default:run-9:y | default | 9 | payload_present | 5 | `8ba94c16568be016b735450591e21ea6b6ea19ecd46c867b60761d3229dfbd1c` |

### 原始文件完整性

- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/README.md` — SHA-256 `b073b2e97aea4073fec2bf387e2c255d987dd8f3710e84f2df3cc59947e510f8`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/attack_scripts.zip` — SHA-256 `4599be3e224f3b9b43e76ab4ec1bfa8e3b209ebe529fb218ae4e65dd22417900`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/gcp_logs_redacted.zip` — SHA-256 `2765fedd91ce6a03c9a8d156a3d83e34dd493e7a366d0b38abd88a00ad10c5a4`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/log_analysis.zip` — SHA-256 `23b41863cc2ece4936277a1ee1fc6f64b4fea9f3c0f698cefbf5626eeca00fcf`

## 40. `crosscloud:gcp:data_manipulation`

- 描述：DOI-published paired payload/no-payload GCP telemetry for data_manipulation.
- 发布者：Dhooghe et al.
- 发布日期：2026-04-30
- 环境：controlled cloud subscription
- ATT&CK：
- 原始文件数：4
- 规范化观测数：0
- 上游 episode 数：40

### 准入判断（人工填写）

- [ ] 有外部或低权限入口
- [ ] 存在多步关系，而非单点事件
- [ ] 终点为数据库、存储、备份、secret 或其他数据资产
- [ ] 关键边均有原始证据
- [ ] 不是近重复案例
- 决定：`<accept | needs_execution | reject>`
- 理由：`<人工填写>`

### 观测索引

| observation_id | timestamp | actor_type | service | operation | status | raw record |
|---|---:|---|---|---|---|---|

### 上游配对 episode

| episode_id | profile | run | source condition | observations | member SHA-256 |
|---|---|---:|---|---:|---|
| crosscloud:gcp:data_manipulation:additional:run-0:n | additional | 0 | payload_absent | 23 | `f4dbd1036b8ddf084a946b9fcd725c69fa79fe12a571158285d04efd949d13f8` |
| crosscloud:gcp:data_manipulation:additional:run-0:y | additional | 0 | payload_present | 65 | `6cfdbcbc56e90651ee0a479fdb45b70b2d40f22cca3acc648e2f12a387d8756f` |
| crosscloud:gcp:data_manipulation:additional:run-1:n | additional | 1 | payload_absent | 23 | `3ceabc3582743ac49fce5a7ad857648072fa168eed70e9cdbf9889a30c0dcec5` |
| crosscloud:gcp:data_manipulation:additional:run-1:y | additional | 1 | payload_present | 65 | `ad8ccea214146813e958649d36deccb794ac114d0942f6c58677e2fb836e338a` |
| crosscloud:gcp:data_manipulation:additional:run-2:n | additional | 2 | payload_absent | 23 | `5619c3697b72b06556ad30b372265b57351ad3f5fa45b48aa12cd77cd1f6c2d5` |
| crosscloud:gcp:data_manipulation:additional:run-2:y | additional | 2 | payload_present | 65 | `6cbb00784cd3116c047803b85bafd44c7b5df4b076075dfb400013ed689a0fd2` |
| crosscloud:gcp:data_manipulation:additional:run-3:n | additional | 3 | payload_absent | 23 | `d40f7b6c350d5316a18ff5ac62429a3fe93bb90dd843247d28b93f3cb536b937` |
| crosscloud:gcp:data_manipulation:additional:run-3:y | additional | 3 | payload_present | 65 | `ebf7036aa5d25bfbe33437181beb7b2e8f38db7263c5c2f4c1d86b0c9d301faf` |
| crosscloud:gcp:data_manipulation:additional:run-4:n | additional | 4 | payload_absent | 23 | `a3586ea07e59d7cfbc6e9acbc4e822806e99fd09754b757fddf6b3e8b2dcc167` |
| crosscloud:gcp:data_manipulation:additional:run-4:y | additional | 4 | payload_present | 65 | `990a02d6ffade1b6071fd21369435c5abfd0dc41c09623adf94b35e235a92b00` |
| crosscloud:gcp:data_manipulation:additional:run-5:n | additional | 5 | payload_absent | 23 | `a2257485182f954938169e233343c7dd50ab0ffc04e9b6a09b42a98ecde2559a` |
| crosscloud:gcp:data_manipulation:additional:run-5:y | additional | 5 | payload_present | 65 | `d0a0762471e4f23c0a9ea2d34a9d01f87ebae6e98d7b53f27fb901f12824afea` |
| crosscloud:gcp:data_manipulation:additional:run-6:n | additional | 6 | payload_absent | 23 | `d2c667497a6c40aeefd29e2ea633b6a76734552724c83cae8730620855165645` |
| crosscloud:gcp:data_manipulation:additional:run-6:y | additional | 6 | payload_present | 65 | `6b67daf6490841c134ea64c6ee8634ec474deb23af562c0311e2e2b069bc78b8` |
| crosscloud:gcp:data_manipulation:additional:run-7:n | additional | 7 | payload_absent | 23 | `04e477d365a86394bc42dc3ef91062141d571f6e4788fecf3a9ed1b4f8b6e086` |
| crosscloud:gcp:data_manipulation:additional:run-7:y | additional | 7 | payload_present | 65 | `bed1b15756417daf7e3de41a6dad4354fc81ba56e2ee7fc57a172a7fbb8a8be7` |
| crosscloud:gcp:data_manipulation:additional:run-8:n | additional | 8 | payload_absent | 23 | `9db5c413083487829ae5adfaa3d7d1dc9a2217089718bdd1792af12f60099027` |
| crosscloud:gcp:data_manipulation:additional:run-8:y | additional | 8 | payload_present | 65 | `315af789d6178da3b0682156f9dd58ca8ac042a16513d5e8ee166907b5a88484` |
| crosscloud:gcp:data_manipulation:additional:run-9:n | additional | 9 | payload_absent | 23 | `dd2f4d6613df97c6e4f613b5feba19f8b3e17230a9e8d95ac27e9d51b3760bc8` |
| crosscloud:gcp:data_manipulation:additional:run-9:y | additional | 9 | payload_present | 65 | `a408a8a0345922826cf254ef5b4e060336c385f377a1ffc43c26c1b5d4510b3a` |
| crosscloud:gcp:data_manipulation:default:run-0:n | default | 0 | payload_absent | 3 | `aea120928b257ba4e5e64d4310b68de4f4e28a400f23912e69c72ceec73a2497` |
| crosscloud:gcp:data_manipulation:default:run-0:y | default | 0 | payload_present | 3 | `f1fe8f51b05fd29b653653dd21a69c86bbc983c01fffffd78ca2a3860557fefa` |
| crosscloud:gcp:data_manipulation:default:run-1:n | default | 1 | payload_absent | 3 | `b90d1436bd7db1c5b85ec25c4d3798077ac9077b224cb5dff039ee29848cf707` |
| crosscloud:gcp:data_manipulation:default:run-1:y | default | 1 | payload_present | 3 | `6f9842c4e4b3b4595b5cd23e778bc810f8a6ea8338bbafd929837227783f7573` |
| crosscloud:gcp:data_manipulation:default:run-2:n | default | 2 | payload_absent | 3 | `d1a8359e74e459fc4eaa97841d29d769ed70af09c9c4f3e7581009be80f8dc11` |
| crosscloud:gcp:data_manipulation:default:run-2:y | default | 2 | payload_present | 3 | `1029a829ba19ec146574b08ddf86401e6d1010861663a48c9a0d4b6a5df2041e` |
| crosscloud:gcp:data_manipulation:default:run-3:n | default | 3 | payload_absent | 3 | `fce2c9ac23ce77a1ca29faddc72d50c30d2bdea2aa91523c113a0f0bc59c3a02` |
| crosscloud:gcp:data_manipulation:default:run-3:y | default | 3 | payload_present | 3 | `2bc5313ac9636a33a8bd229bf59e397a90fe5dc29bd8c7ed96b6c6e086c18864` |
| crosscloud:gcp:data_manipulation:default:run-4:n | default | 4 | payload_absent | 3 | `124a680e5b3406bd688c5847d3c1ecfe1cbf0940583af0d1402003b20874f1ee` |
| crosscloud:gcp:data_manipulation:default:run-4:y | default | 4 | payload_present | 3 | `f97f5c8277bb343a1d11e1dea635f46edaa70fb89f67635966aaf72608b4d511` |
| crosscloud:gcp:data_manipulation:default:run-5:n | default | 5 | payload_absent | 3 | `1cea8e985e5996c38a3bc8a3086f99883370777cee9e2fd0f75d0f17e2579ac8` |
| crosscloud:gcp:data_manipulation:default:run-5:y | default | 5 | payload_present | 3 | `bebc905bec8ae3488a5c05b623348362741e405712009b61ddae1c8d1e68e74f` |
| crosscloud:gcp:data_manipulation:default:run-6:n | default | 6 | payload_absent | 3 | `ee75ab6e5502634aca21192a4a98194579b2a5238ee43d09a91e42ebdb3a0952` |
| crosscloud:gcp:data_manipulation:default:run-6:y | default | 6 | payload_present | 3 | `222036f91fdafe046f35df6cf2028abaddcf1c2afba89cdcd8d5a117ee5642b4` |
| crosscloud:gcp:data_manipulation:default:run-7:n | default | 7 | payload_absent | 3 | `a350b3766c171f1c293653b47249ecce8c7f24f9568f7b89816a30af810c3fba` |
| crosscloud:gcp:data_manipulation:default:run-7:y | default | 7 | payload_present | 3 | `379c6ea5302383b714dfd91317bbd98c701f07c03bbcd94a696d9b5f7e548a40` |
| crosscloud:gcp:data_manipulation:default:run-8:n | default | 8 | payload_absent | 3 | `bf995b14540f459228215da95d8a1874d596d04af31e5516777d55468c883971` |
| crosscloud:gcp:data_manipulation:default:run-8:y | default | 8 | payload_present | 3 | `17400ce8e7d6a7b05f0235a91cff022241b099b3a8f5fa1d91e8177285ffd7f4` |
| crosscloud:gcp:data_manipulation:default:run-9:n | default | 9 | payload_absent | 3 | `c8805ba977aca7a6757ef4dacce74b70e82ac093e16397c547e774d6d57a2228` |
| crosscloud:gcp:data_manipulation:default:run-9:y | default | 9 | payload_present | 3 | `15055b31bc0c8d819b0391f23c4fd831533b42f086ebec22bed7aeb0dedf1423` |

### 原始文件完整性

- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/README.md` — SHA-256 `b073b2e97aea4073fec2bf387e2c255d987dd8f3710e84f2df3cc59947e510f8`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/attack_scripts.zip` — SHA-256 `4599be3e224f3b9b43e76ab4ec1bfa8e3b209ebe529fb218ae4e65dd22417900`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/gcp_logs_redacted.zip` — SHA-256 `2765fedd91ce6a03c9a8d156a3d83e34dd493e7a366d0b38abd88a00ad10c5a4`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/log_analysis.zip` — SHA-256 `23b41863cc2ece4936277a1ee1fc6f64b4fea9f3c0f698cefbf5626eeca00fcf`

## 41. `crosscloud:gcp:data_staged`

- 描述：DOI-published paired payload/no-payload GCP telemetry for data_staged.
- 发布者：Dhooghe et al.
- 发布日期：2026-04-30
- 环境：controlled cloud subscription
- ATT&CK：
- 原始文件数：4
- 规范化观测数：0
- 上游 episode 数：40

### 准入判断（人工填写）

- [ ] 有外部或低权限入口
- [ ] 存在多步关系，而非单点事件
- [ ] 终点为数据库、存储、备份、secret 或其他数据资产
- [ ] 关键边均有原始证据
- [ ] 不是近重复案例
- 决定：`<accept | needs_execution | reject>`
- 理由：`<人工填写>`

### 观测索引

| observation_id | timestamp | actor_type | service | operation | status | raw record |
|---|---:|---|---|---|---|---|

### 上游配对 episode

| episode_id | profile | run | source condition | observations | member SHA-256 |
|---|---|---:|---|---:|---|
| crosscloud:gcp:data_staged:additional:run-0:n | additional | 0 | payload_absent | 23 | `4647a35ef62c0c8cce5e68fb112a89981256447ca9677f4d4f1214e3a47f4b50` |
| crosscloud:gcp:data_staged:additional:run-0:y | additional | 0 | payload_present | 108 | `d99f395da0e5ccd1800d57b6d3554463ea9fd58e56d651506c5853c2057f7a74` |
| crosscloud:gcp:data_staged:additional:run-1:n | additional | 1 | payload_absent | 23 | `92a79e2da01b7c69785211c78bbb486775ea60c2364a7c3bb90aeac60638feb5` |
| crosscloud:gcp:data_staged:additional:run-1:y | additional | 1 | payload_present | 108 | `f129397b053f25853af36fad6f70b7fcff6efe458ec9893d1df68ae30cf543f6` |
| crosscloud:gcp:data_staged:additional:run-2:n | additional | 2 | payload_absent | 23 | `43d2dcbdd4c32d0c35c6de26c5be2c59a6ce1c6e7d0b52cdceb022587c0e4e3c` |
| crosscloud:gcp:data_staged:additional:run-2:y | additional | 2 | payload_present | 108 | `00eb48828453dc4817162778d6f0937cc778f431bc8f99c34c8c13b0fb476915` |
| crosscloud:gcp:data_staged:additional:run-3:n | additional | 3 | payload_absent | 23 | `587ad8ca16bb44b887e421bb1fa052ab074ebe5f5f0495309a83972f0da51143` |
| crosscloud:gcp:data_staged:additional:run-3:y | additional | 3 | payload_present | 108 | `294ce4e48dfb9bdb78e4a186bc24663d90cdb8267bfa03b8131174fd3f238126` |
| crosscloud:gcp:data_staged:additional:run-4:n | additional | 4 | payload_absent | 23 | `4a5af625deba4fd59b601db7c29f93b4121a216198f722200c41d386b18b24cd` |
| crosscloud:gcp:data_staged:additional:run-4:y | additional | 4 | payload_present | 108 | `862510113cacc89b6080bbc8bf79a2b6a8fe8ba270cc3d5109553bef2e6d9887` |
| crosscloud:gcp:data_staged:additional:run-5:n | additional | 5 | payload_absent | 23 | `37ad33bd3a3d63b52115aaf12837d5431d531c18acb6630cdb675726b8783b8c` |
| crosscloud:gcp:data_staged:additional:run-5:y | additional | 5 | payload_present | 108 | `936beb0ac0cc18cde1f5df3855d15726b0f7e429aecb08b5eeff597211f8ea8a` |
| crosscloud:gcp:data_staged:additional:run-6:n | additional | 6 | payload_absent | 23 | `760dfaf0fe7a2cff8dbb4883826a48bbbb034b47cb93d3cf62e6f7f2fd46f6ec` |
| crosscloud:gcp:data_staged:additional:run-6:y | additional | 6 | payload_present | 108 | `dada9e4c9961b9fe56152ae941950ed7e014f09b943fda9f4f9c0ab8d6d27ed5` |
| crosscloud:gcp:data_staged:additional:run-7:n | additional | 7 | payload_absent | 23 | `d02b418d3719a8c2e46455f71802cbf6918528439c4867a33ddf01e9e5de118f` |
| crosscloud:gcp:data_staged:additional:run-7:y | additional | 7 | payload_present | 108 | `968d1fb33e1f111fda07ac3e5f1d19c1097318cb59d90082211f3b41fc32ecec` |
| crosscloud:gcp:data_staged:additional:run-8:n | additional | 8 | payload_absent | 23 | `61ae475d2b0e7a3a6811699136ab07aa551d8ae5a7774bb0a0e1932e236317be` |
| crosscloud:gcp:data_staged:additional:run-8:y | additional | 8 | payload_present | 108 | `085f3786c138aefd9fc966536c090a2ed36bc888343f1fc1b8c98bbfcf76cee1` |
| crosscloud:gcp:data_staged:additional:run-9:n | additional | 9 | payload_absent | 23 | `1c0e941bae974c32c2fc710cbcbf023c9e1bdd929423cccf9d6bdc95cc96348c` |
| crosscloud:gcp:data_staged:additional:run-9:y | additional | 9 | payload_present | 108 | `cb999eb6d437306362005d589520dbf73a762b5277609f94a29e07cd8fa474ec` |
| crosscloud:gcp:data_staged:default:run-0:n | default | 0 | payload_absent | 3 | `a4c0526b8e3139dc4dd5000c51a287c7b0e55b066056bc6101d7ff4ce84e6282` |
| crosscloud:gcp:data_staged:default:run-0:y | default | 0 | payload_present | 3 | `d00659dafd9f9dccfd3873bd183ddb484d67c086e0e1a58c5f82368b86640641` |
| crosscloud:gcp:data_staged:default:run-1:n | default | 1 | payload_absent | 3 | `2f2d761cd297c903d911f5ca03761af9a937dea3530329140bdc0c71d32791e8` |
| crosscloud:gcp:data_staged:default:run-1:y | default | 1 | payload_present | 3 | `21305cf64191eb709410612fc77ba6cc15df6637de08ef1ad7ffcd0462836141` |
| crosscloud:gcp:data_staged:default:run-2:n | default | 2 | payload_absent | 3 | `14d586c23d9edf417c4838dbeb189695b77bab7e1d497dfe5e60f542b325f002` |
| crosscloud:gcp:data_staged:default:run-2:y | default | 2 | payload_present | 3 | `7a6fb000aa0e8e422832170f75a0443d2d97a492cf89362c1fef56a41dec9ccd` |
| crosscloud:gcp:data_staged:default:run-3:n | default | 3 | payload_absent | 3 | `a36b7e3e0c7074cfc694bc2c36e361c595fd8dc681adcdafb27361f8fdae8570` |
| crosscloud:gcp:data_staged:default:run-3:y | default | 3 | payload_present | 3 | `eb62416e675d968d19366b32e1b81a21b7941acfb082698c32943b6b40301571` |
| crosscloud:gcp:data_staged:default:run-4:n | default | 4 | payload_absent | 3 | `e9f0aac3a3bcd0ca3cf79d61c74ff22ab7b00c19b6588da165776d7a4fe37642` |
| crosscloud:gcp:data_staged:default:run-4:y | default | 4 | payload_present | 3 | `2f56a0cb5258eba52ef3ea66112d1a6bf5a1c74a1927f64adb18c0ca1f436a56` |
| crosscloud:gcp:data_staged:default:run-5:n | default | 5 | payload_absent | 3 | `6bbab22152558e84baa6208825f09e350d911cff3d206aceb29dd4f98faa8ed4` |
| crosscloud:gcp:data_staged:default:run-5:y | default | 5 | payload_present | 3 | `cb310e7e71aa83024df4d9a820927083624bb748624149fc22905226d46c41ec` |
| crosscloud:gcp:data_staged:default:run-6:n | default | 6 | payload_absent | 3 | `ba5b30d3bd1276b1c5735ee35f0e2df06dacb6d7366d075ecb3a4871edee853c` |
| crosscloud:gcp:data_staged:default:run-6:y | default | 6 | payload_present | 3 | `c8c950551553c84e0e26114524006311bb2eee4fd5cf07999b73ea4f06752007` |
| crosscloud:gcp:data_staged:default:run-7:n | default | 7 | payload_absent | 3 | `9e2cbbcffdc67678e960811e2e8f014ae8acdfb346c9b8ef5f3e41bec6fe6d25` |
| crosscloud:gcp:data_staged:default:run-7:y | default | 7 | payload_present | 3 | `645ce83edbde25b52ac9046d07974b9c9da6568a6f8fa8f3a124b18eddfaa4a2` |
| crosscloud:gcp:data_staged:default:run-8:n | default | 8 | payload_absent | 3 | `70e36db502df2fb415640df495e6c9ff0e1a0e639edee0786c9c7e4593ccdd73` |
| crosscloud:gcp:data_staged:default:run-8:y | default | 8 | payload_present | 3 | `eab6e53200822226b73da08d0672c0c05e57f7aeb3828a8b4a94ca527e0df18a` |
| crosscloud:gcp:data_staged:default:run-9:n | default | 9 | payload_absent | 3 | `1ba4f6255977d10e4fedbecdd9ce28bcd405318598abf1a4456ced9ba35a180a` |
| crosscloud:gcp:data_staged:default:run-9:y | default | 9 | payload_present | 3 | `f30a6be7eff3528dbe9edb3f8e603bfad9d7cec3ab02dba09ce3b22859b782a1` |

### 原始文件完整性

- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/README.md` — SHA-256 `b073b2e97aea4073fec2bf387e2c255d987dd8f3710e84f2df3cc59947e510f8`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/attack_scripts.zip` — SHA-256 `4599be3e224f3b9b43e76ab4ec1bfa8e3b209ebe529fb218ae4e65dd22417900`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/gcp_logs_redacted.zip` — SHA-256 `2765fedd91ce6a03c9a8d156a3d83e34dd493e7a366d0b38abd88a00ad10c5a4`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/log_analysis.zip` — SHA-256 `23b41863cc2ece4936277a1ee1fc6f64b4fea9f3c0f698cefbf5626eeca00fcf`

## 42. `crosscloud:gcp:inhibit_system_recovery`

- 描述：DOI-published paired payload/no-payload GCP telemetry for inhibit_system_recovery.
- 发布者：Dhooghe et al.
- 发布日期：2026-04-30
- 环境：controlled cloud subscription
- ATT&CK：
- 原始文件数：4
- 规范化观测数：0
- 上游 episode 数：40

### 准入判断（人工填写）

- [ ] 有外部或低权限入口
- [ ] 存在多步关系，而非单点事件
- [ ] 终点为数据库、存储、备份、secret 或其他数据资产
- [ ] 关键边均有原始证据
- [ ] 不是近重复案例
- 决定：`<accept | needs_execution | reject>`
- 理由：`<人工填写>`

### 观测索引

| observation_id | timestamp | actor_type | service | operation | status | raw record |
|---|---:|---|---|---|---|---|

### 上游配对 episode

| episode_id | profile | run | source condition | observations | member SHA-256 |
|---|---|---:|---|---:|---|
| crosscloud:gcp:inhibit_system_recovery:additional:run-0:n | additional | 0 | payload_absent | 10 | `38bf609dc24ca47f1f8a3cd1d447af8b49da775679e51502f3adb0128a25bba0` |
| crosscloud:gcp:inhibit_system_recovery:additional:run-0:y | additional | 0 | payload_present | 12 | `862d30ab54f7766627be8d79778bdb54f250229414edb9e815ffe863a98a7e18` |
| crosscloud:gcp:inhibit_system_recovery:additional:run-1:n | additional | 1 | payload_absent | 10 | `bbe638fdd4d1e1d52b09fcecb5d8084f942600f683028cad7ce6202c0999a16a` |
| crosscloud:gcp:inhibit_system_recovery:additional:run-1:y | additional | 1 | payload_present | 12 | `5f4c93a9c49d9a2af22d90ac93c5e8250b3fd7e76b821049a44c8387c3d3971c` |
| crosscloud:gcp:inhibit_system_recovery:additional:run-2:n | additional | 2 | payload_absent | 10 | `4310f6f0b376ef1ee871ad96e6b346cf82c64bfec8028fa0152935fc68f33ca4` |
| crosscloud:gcp:inhibit_system_recovery:additional:run-2:y | additional | 2 | payload_present | 12 | `00c1c69d093531ec0e4f874dec5d89cbdabd6586fca48af1a1945ff3cb0440a7` |
| crosscloud:gcp:inhibit_system_recovery:additional:run-3:n | additional | 3 | payload_absent | 10 | `81808fc97d7267995d4c251245ea5b84d5eeb2c80b1aaab0d6cd24a4ca9645f6` |
| crosscloud:gcp:inhibit_system_recovery:additional:run-3:y | additional | 3 | payload_present | 12 | `38fe3ecdbacbcb35c4e61d8b4148a6c0dce88dc102545042dfe9ac0c1ba41faf` |
| crosscloud:gcp:inhibit_system_recovery:additional:run-4:n | additional | 4 | payload_absent | 10 | `269053d3de86368d6ea94bb7bee580fda652756dbdf0425d42439f111d100050` |
| crosscloud:gcp:inhibit_system_recovery:additional:run-4:y | additional | 4 | payload_present | 12 | `cb8b192349b70f7633766363314a3135ff7996d32b0d71be032144938c3223fb` |
| crosscloud:gcp:inhibit_system_recovery:additional:run-5:n | additional | 5 | payload_absent | 10 | `8518bd55364a31e2a89080e28a87ac2ba31ccfd3c68f79c56e4a9a3fe42c7c90` |
| crosscloud:gcp:inhibit_system_recovery:additional:run-5:y | additional | 5 | payload_present | 12 | `61ab056ed46bc4a7b9b08181a538aac570cddcfc0d5a0a1c1cc3331ceb040ff1` |
| crosscloud:gcp:inhibit_system_recovery:additional:run-6:n | additional | 6 | payload_absent | 10 | `fdf635dba99e1e2b0a64dbd23d4147f056b6a6c8b213f95769cb35d247ecc711` |
| crosscloud:gcp:inhibit_system_recovery:additional:run-6:y | additional | 6 | payload_present | 12 | `b7473e64f2817aaf4f3904f2953f45716422e1ef429f775fa5ebf557b3ff69a8` |
| crosscloud:gcp:inhibit_system_recovery:additional:run-7:n | additional | 7 | payload_absent | 10 | `3dd5c2b0dff958c14025ae7547572bd1304cc1fd4129a04c1d67531cbd110abb` |
| crosscloud:gcp:inhibit_system_recovery:additional:run-7:y | additional | 7 | payload_present | 12 | `75011a3f9dccd1d69b48b5bc7c43eed0fc838ca80592cc1350a1098e575fd2d0` |
| crosscloud:gcp:inhibit_system_recovery:additional:run-8:n | additional | 8 | payload_absent | 10 | `9809f4d9d4daaaa23abc88664c75e32122bdd1f7cebe2335ff8e0c80554e52c3` |
| crosscloud:gcp:inhibit_system_recovery:additional:run-8:y | additional | 8 | payload_present | 12 | `98bf5ca5847ffbd5b26475ea54bfcd8c434902add85a34263ab624eddd628572` |
| crosscloud:gcp:inhibit_system_recovery:additional:run-9:n | additional | 9 | payload_absent | 10 | `908553b4e6312c80dd38c885506e162c7b3d7157959ed53d231ab5c1d67da60d` |
| crosscloud:gcp:inhibit_system_recovery:additional:run-9:y | additional | 9 | payload_present | 12 | `654eb8d1549238a0e6e0860998d96af8d3be18594dffb2e2a44859c0cf1afd1b` |
| crosscloud:gcp:inhibit_system_recovery:default:run-0:n | default | 0 | payload_absent | 1 | `e6d45278fb767d1a875844db88d3fa070610815ecbeb8423cfd3fbe9fdb8776f` |
| crosscloud:gcp:inhibit_system_recovery:default:run-0:y | default | 0 | payload_present | 1 | `3658bc1b5985ee625910a783c66283a81c0e5098fd9b44029596f753bf935a74` |
| crosscloud:gcp:inhibit_system_recovery:default:run-1:n | default | 1 | payload_absent | 1 | `bbbd74c9302c957d8534075cb2bbcfa54b5129c86e0a867ae2c6c28878f13c01` |
| crosscloud:gcp:inhibit_system_recovery:default:run-1:y | default | 1 | payload_present | 1 | `ccc3bc74d2bb5016f2bde12d8eb505e7ee95df431a5c7728c4cd1a150058918b` |
| crosscloud:gcp:inhibit_system_recovery:default:run-2:n | default | 2 | payload_absent | 1 | `f719c715e1d90142f2bd43c9eca1e4c05e561834ff4c4c1fab2c70b8fe9a2240` |
| crosscloud:gcp:inhibit_system_recovery:default:run-2:y | default | 2 | payload_present | 1 | `94674ffe55c34b6751dfe999ced09f2b71bc5fb6e1ede36f05ce9479a2790d74` |
| crosscloud:gcp:inhibit_system_recovery:default:run-3:n | default | 3 | payload_absent | 1 | `944bc3395aba8db08123a7c871242b79d3b8b1fce07708047f6f23818eb042f2` |
| crosscloud:gcp:inhibit_system_recovery:default:run-3:y | default | 3 | payload_present | 1 | `eaf4d9eed326b9e50c2fbb044728459a10e91bc58707b74afa3862eeec2d82b9` |
| crosscloud:gcp:inhibit_system_recovery:default:run-4:n | default | 4 | payload_absent | 1 | `e1e398995d26042dd56387236f97ebc48a25cbfd55c0ea9c08eca3741d7324eb` |
| crosscloud:gcp:inhibit_system_recovery:default:run-4:y | default | 4 | payload_present | 1 | `6f9856b6af0492d5b0e34e031c35fe4888d716e3dcfb7de97bd6d8f572f4bd79` |
| crosscloud:gcp:inhibit_system_recovery:default:run-5:n | default | 5 | payload_absent | 1 | `f61ce9ddb05b7751c622d1f419ddf256bd8fb2ba76278770e633d217a8e30c38` |
| crosscloud:gcp:inhibit_system_recovery:default:run-5:y | default | 5 | payload_present | 1 | `ac8c8c08a966167344599424870cbbfe50d8e03af2cba8b9a3f7bc8ccda9c5d6` |
| crosscloud:gcp:inhibit_system_recovery:default:run-6:n | default | 6 | payload_absent | 1 | `c2a48e24b706125249d32af012c9954cfde7c500a5f350d5386f08fedbe613c1` |
| crosscloud:gcp:inhibit_system_recovery:default:run-6:y | default | 6 | payload_present | 1 | `ece78c4953d0ba76096460c8aaa728016cf7f914cf76fd51a3de3baa4bc6958c` |
| crosscloud:gcp:inhibit_system_recovery:default:run-7:n | default | 7 | payload_absent | 1 | `11cf17d06db255bfc7eed5db4c738ec818e2ed9010eafda97987dec12339629f` |
| crosscloud:gcp:inhibit_system_recovery:default:run-7:y | default | 7 | payload_present | 1 | `b293531312f54e37597ccde0a7e0dbeb179ab95ffcc913930183c85ae75ade9c` |
| crosscloud:gcp:inhibit_system_recovery:default:run-8:n | default | 8 | payload_absent | 1 | `aca5c2508924d8a8b2822ce5774129595ba1e78112eaba407b5a667561cfa2ea` |
| crosscloud:gcp:inhibit_system_recovery:default:run-8:y | default | 8 | payload_present | 1 | `d2ba10967c778037e2d83296b0a77044e0cd45f0cb07cc4cc8644f2e738fe247` |
| crosscloud:gcp:inhibit_system_recovery:default:run-9:n | default | 9 | payload_absent | 1 | `d741b14c92010af0699546eedfb14e4169154e23206fff325089f364bb526c93` |
| crosscloud:gcp:inhibit_system_recovery:default:run-9:y | default | 9 | payload_present | 1 | `0c7bc94a839c4e3c11fe37035669181a3fb0724b3248fb1b436351c8ccf7b62d` |

### 原始文件完整性

- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/README.md` — SHA-256 `b073b2e97aea4073fec2bf387e2c255d987dd8f3710e84f2df3cc59947e510f8`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/attack_scripts.zip` — SHA-256 `4599be3e224f3b9b43e76ab4ec1bfa8e3b209ebe529fb218ae4e65dd22417900`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/gcp_logs_redacted.zip` — SHA-256 `2765fedd91ce6a03c9a8d156a3d83e34dd493e7a366d0b38abd88a00ad10c5a4`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/log_analysis.zip` — SHA-256 `23b41863cc2ece4936277a1ee1fc6f64b4fea9f3c0f698cefbf5626eeca00fcf`

## 43. `crosscloud:gcp:scheduled_transfer`

- 描述：DOI-published paired payload/no-payload GCP telemetry for scheduled_transfer.
- 发布者：Dhooghe et al.
- 发布日期：2026-04-30
- 环境：controlled cloud subscription
- ATT&CK：
- 原始文件数：4
- 规范化观测数：0
- 上游 episode 数：40

### 准入判断（人工填写）

- [ ] 有外部或低权限入口
- [ ] 存在多步关系，而非单点事件
- [ ] 终点为数据库、存储、备份、secret 或其他数据资产
- [ ] 关键边均有原始证据
- [ ] 不是近重复案例
- 决定：`<accept | needs_execution | reject>`
- 理由：`<人工填写>`

### 观测索引

| observation_id | timestamp | actor_type | service | operation | status | raw record |
|---|---:|---|---|---|---|---|

### 上游配对 episode

| episode_id | profile | run | source condition | observations | member SHA-256 |
|---|---|---:|---|---:|---|
| crosscloud:gcp:scheduled_transfer:additional:run-0:n | additional | 0 | payload_absent | 93 | `868521f2c7c04e9807ae4a5d234ae7e0a14a8aa53d369094f093d83db7014d04` |
| crosscloud:gcp:scheduled_transfer:additional:run-0:y | additional | 0 | payload_present | 805 | `a9c86a96df498e05832fa47375407990294dbff04b6c662e784bf899990059d8` |
| crosscloud:gcp:scheduled_transfer:additional:run-1:n | additional | 1 | payload_absent | 92 | `4e3b9ecbad331c69c6632fec12cb1c6d18b6126da99ebd0f61f67b394b9d4a6c` |
| crosscloud:gcp:scheduled_transfer:additional:run-1:y | additional | 1 | payload_present | 765 | `0b3b6693bc17a0ba35635ad5c19414dfeffa73ecc8b315eb016fe51af6af1c75` |
| crosscloud:gcp:scheduled_transfer:additional:run-2:n | additional | 2 | payload_absent | 87 | `01f1f3a18fd164f6c9e838d84955f539ca4a90686c482a8b3e532e4bb008159f` |
| crosscloud:gcp:scheduled_transfer:additional:run-2:y | additional | 2 | payload_present | 756 | `67a0747eda36a8ee380c4c0301293174e6b91752fb1d183c2da7b2e8f41318fd` |
| crosscloud:gcp:scheduled_transfer:additional:run-3:n | additional | 3 | payload_absent | 75 | `f4fbe558ce87b11b3cea52b504e356e7f657b8e0820a66f93c7b4cd27ceafe88` |
| crosscloud:gcp:scheduled_transfer:additional:run-3:y | additional | 3 | payload_present | 747 | `9181ccf4f7005647f1f40aa87f5ec49e964aee6d5ed79b308931748a0cfd9c58` |
| crosscloud:gcp:scheduled_transfer:additional:run-4:n | additional | 4 | payload_absent | 94 | `328467d0622edd3ac5b1d68bb525a0aa2bc2e36d93c336a9698f397b687160b1` |
| crosscloud:gcp:scheduled_transfer:additional:run-4:y | additional | 4 | payload_present | 752 | `ce03aeacfd7cc165ebc0fedc756352ddf74d81133787464a7632d076f76ab91a` |
| crosscloud:gcp:scheduled_transfer:additional:run-5:n | additional | 5 | payload_absent | 92 | `b615fb2340e3842e9cb6fb90f8027190f677272cf1c208932b44a68b01799b60` |
| crosscloud:gcp:scheduled_transfer:additional:run-5:y | additional | 5 | payload_present | 797 | `483790a2d80bab56e143c32de83c570318420c3635fb64ea4f25268ae7418b5d` |
| crosscloud:gcp:scheduled_transfer:additional:run-6:n | additional | 6 | payload_absent | 102 | `8b88c0f090094efb940a9813a4519071371b2ed8ca5a221db7055d0b6e674e1d` |
| crosscloud:gcp:scheduled_transfer:additional:run-6:y | additional | 6 | payload_present | 771 | `599cf6af03b148b1bd65db0d1f81079b77f1887ef971d91738ba9d2b56626c66` |
| crosscloud:gcp:scheduled_transfer:additional:run-7:n | additional | 7 | payload_absent | 96 | `ede4070c874b122b6526e32cda1aaf30826e3501485e544da5fd12407d2bd330` |
| crosscloud:gcp:scheduled_transfer:additional:run-7:y | additional | 7 | payload_present | 757 | `dd0672493146aa94485808d4cfe437f734a01d04ea8d11eebb04c007c81deae9` |
| crosscloud:gcp:scheduled_transfer:additional:run-8:n | additional | 8 | payload_absent | 85 | `cd3f5127f1d9934b025ffb519669e8cf49d4ca7e95f23bade6de2593790d2acb` |
| crosscloud:gcp:scheduled_transfer:additional:run-8:y | additional | 8 | payload_present | 765 | `2d946efeea4e7a3e88ec7d9b71cec981d498ea1ae1e0c54b597e2da17d0192f2` |
| crosscloud:gcp:scheduled_transfer:additional:run-9:n | additional | 9 | payload_absent | 99 | `4ba7d1bf3c53eb662d585681a17738e34681b764070c6fced3c4b5d9b3134403` |
| crosscloud:gcp:scheduled_transfer:additional:run-9:y | additional | 9 | payload_present | 751 | `06f99ed751f8ad4ee6d48fe3053f5914986db84906bdcc39602f004647bee8eb` |
| crosscloud:gcp:scheduled_transfer:default:run-0:n | default | 0 | payload_absent | 7 | `5bc866643f0feecfc3a7c0bbe0ef3a0012e08dc9b1cca4e05a3df0399605ac36` |
| crosscloud:gcp:scheduled_transfer:default:run-0:y | default | 0 | payload_present | 507 | `aa8b5da975fd11e252e5a43dcd010904919d1f55bf468933028c78751487c862` |
| crosscloud:gcp:scheduled_transfer:default:run-1:n | default | 1 | payload_absent | 7 | `afe6851690efe9b3e53a0072ec86288b3c6fd4b238f67c40465ca0df94c67c1b` |
| crosscloud:gcp:scheduled_transfer:default:run-1:y | default | 1 | payload_present | 497 | `2b3f82c85e8e8e9bb2e9ee4c375dbbce27f08d7d6a43573b6f6a477d8eab57a9` |
| crosscloud:gcp:scheduled_transfer:default:run-2:n | default | 2 | payload_absent | 7 | `945a7923d8d44b46b356165e9ebf1bc49086de26570826b74c72b7e07ca5d3e5` |
| crosscloud:gcp:scheduled_transfer:default:run-2:y | default | 2 | payload_present | 498 | `2e567b68c41e57d10c218cd5f368444224cbc92283ebfa59a6969a355b15acb4` |
| crosscloud:gcp:scheduled_transfer:default:run-3:n | default | 3 | payload_absent | 7 | `19f474cd7213d4f790ac0a1e55e93f14bf7d2b08823ca78b5bf411249a771229` |
| crosscloud:gcp:scheduled_transfer:default:run-3:y | default | 3 | payload_present | 500 | `18a5f9df2bd9dbd7b3b254fd8145865e86a286fb4ca469dfd403e73e451dcc27` |
| crosscloud:gcp:scheduled_transfer:default:run-4:n | default | 4 | payload_absent | 7 | `f254d8606ee70c7201d122065b2ae2dea9fc76cf0305cc1279695ca7a0764ebe` |
| crosscloud:gcp:scheduled_transfer:default:run-4:y | default | 4 | payload_present | 500 | `774065a9489bcba41c1386ac93bb93c5b5ca5b867df97786426f69d9e8ebb93a` |
| crosscloud:gcp:scheduled_transfer:default:run-5:n | default | 5 | payload_absent | 7 | `42335d172a9b7c4fb21da8eab457ea86e1f854619090364b8e9150fad46fd47a` |
| crosscloud:gcp:scheduled_transfer:default:run-5:y | default | 5 | payload_present | 498 | `5d562ddf646e66aa6b6c1aa5eb47854537c26ee7960c27952a4f4e2f1dd71466` |
| crosscloud:gcp:scheduled_transfer:default:run-6:n | default | 6 | payload_absent | 7 | `243517a60c168d8d9ae13099554f13753a9b9e30df6d6409cb6ad4e6aedc2ff3` |
| crosscloud:gcp:scheduled_transfer:default:run-6:y | default | 6 | payload_present | 503 | `d88e107f77220a129caeef01f95e6d757342f5598f303c858a5859cc7fb19c01` |
| crosscloud:gcp:scheduled_transfer:default:run-7:n | default | 7 | payload_absent | 7 | `3ce0242bda5dcc007d5302577877c970248f03422a78a623178400f4d56973bc` |
| crosscloud:gcp:scheduled_transfer:default:run-7:y | default | 7 | payload_present | 499 | `190c94f830c2b37f2d98fdc3f8971a0043a3b69275da4ef47f370b97f94e7f33` |
| crosscloud:gcp:scheduled_transfer:default:run-8:n | default | 8 | payload_absent | 7 | `27b01c3bfc379b5f7ff1d659d0060911cc5cc1c3a045fd375481e95ed5a2626c` |
| crosscloud:gcp:scheduled_transfer:default:run-8:y | default | 8 | payload_present | 502 | `956cbcd9db9250c76c756012fe9bb5bd0a34ae4de985ff2c74d11bba7fe12d41` |
| crosscloud:gcp:scheduled_transfer:default:run-9:n | default | 9 | payload_absent | 7 | `7de9ed13768a8fefe1a5599395234d34d3bdf30b9bd7ee4e458db830ead24eeb` |
| crosscloud:gcp:scheduled_transfer:default:run-9:y | default | 9 | payload_present | 500 | `5fd111d84eefc2710d272f89bb47a7b0d033e7d87dd03a7dbf55f0b9dcd61772` |

### 原始文件完整性

- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/README.md` — SHA-256 `b073b2e97aea4073fec2bf387e2c255d987dd8f3710e84f2df3cc59947e510f8`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/attack_scripts.zip` — SHA-256 `4599be3e224f3b9b43e76ab4ec1bfa8e3b209ebe529fb218ae4e65dd22417900`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/gcp_logs_redacted.zip` — SHA-256 `2765fedd91ce6a03c9a8d156a3d83e34dd493e7a366d0b38abd88a00ad10c5a4`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/log_analysis.zip` — SHA-256 `23b41863cc2ece4936277a1ee1fc6f64b4fea9f3c0f698cefbf5626eeca00fcf`

## 44. `crosscloud:gcp:steal_application_access_token`

- 描述：DOI-published paired payload/no-payload GCP telemetry for steal_application_access_token.
- 发布者：Dhooghe et al.
- 发布日期：2026-04-30
- 环境：controlled cloud subscription
- ATT&CK：
- 原始文件数：4
- 规范化观测数：0
- 上游 episode 数：40

### 准入判断（人工填写）

- [ ] 有外部或低权限入口
- [ ] 存在多步关系，而非单点事件
- [ ] 终点为数据库、存储、备份、secret 或其他数据资产
- [ ] 关键边均有原始证据
- [ ] 不是近重复案例
- 决定：`<accept | needs_execution | reject>`
- 理由：`<人工填写>`

### 观测索引

| observation_id | timestamp | actor_type | service | operation | status | raw record |
|---|---:|---|---|---|---|---|

### 上游配对 episode

| episode_id | profile | run | source condition | observations | member SHA-256 |
|---|---|---:|---|---:|---|
| crosscloud:gcp:steal_application_access_token:additional:run-0:n | additional | 0 | payload_absent | 26 | `448686444f3f786368922c8e507153ccac3dd48682cac4a3db7f47f713477e06` |
| crosscloud:gcp:steal_application_access_token:additional:run-0:y | additional | 0 | payload_present | 27 | `26e4323180e3822e81a4ffa2b37171b602bca2a2edccd2e50f6a64df44b9a00f` |
| crosscloud:gcp:steal_application_access_token:additional:run-1:n | additional | 1 | payload_absent | 26 | `200ce8ba95c8837c7979dbb37b05c3c721085a536918a74dc63c774b94bea416` |
| crosscloud:gcp:steal_application_access_token:additional:run-1:y | additional | 1 | payload_present | 27 | `a1b441f89aedd802bd5b71aaff15361b26014707807ae45613e91edcbad12ea4` |
| crosscloud:gcp:steal_application_access_token:additional:run-2:n | additional | 2 | payload_absent | 26 | `d8adb1fcc6ad31138b0afb12742c64c83433c12de61ba58766b5df50b7df16fe` |
| crosscloud:gcp:steal_application_access_token:additional:run-2:y | additional | 2 | payload_present | 27 | `df1c68c2fd11ddc5419043579e1868e993a688a39d76f9616addeb8cd50eaa34` |
| crosscloud:gcp:steal_application_access_token:additional:run-3:n | additional | 3 | payload_absent | 26 | `55c08492abdd51de40a3c75622c44f01ef0a43b338d42bd6661647bc23c74b5d` |
| crosscloud:gcp:steal_application_access_token:additional:run-3:y | additional | 3 | payload_present | 27 | `697dcf169d5b5f3b08d3b5315f53247c24a27a4047e34fbf0de7498f5c84c91b` |
| crosscloud:gcp:steal_application_access_token:additional:run-4:n | additional | 4 | payload_absent | 26 | `791c062473125e618fba39d6c3c27532c83a80665b0f8988ebbdac91c2602ffc` |
| crosscloud:gcp:steal_application_access_token:additional:run-4:y | additional | 4 | payload_present | 27 | `085bcc1929cd33f38551deb267702da3aed3e416d9468b68ba56aa118680e1fb` |
| crosscloud:gcp:steal_application_access_token:additional:run-5:n | additional | 5 | payload_absent | 26 | `895d90640370170cce3ba576e80b037d5f43fb2fb9fc4202deada7e14e78982b` |
| crosscloud:gcp:steal_application_access_token:additional:run-5:y | additional | 5 | payload_present | 27 | `8374d6a19ae5295e47d43a3cc5f4fae73d2bb63537ebbcd44c58c807e767bc1a` |
| crosscloud:gcp:steal_application_access_token:additional:run-6:n | additional | 6 | payload_absent | 26 | `c1462ad4bacbba3b5ccb3c0c39d28b8672e0febabba56e9768257dd52e31e662` |
| crosscloud:gcp:steal_application_access_token:additional:run-6:y | additional | 6 | payload_present | 27 | `5b62a6c35aabadd1da37164b097d3f906de6c2f31a6734afd47d4de951b42ba7` |
| crosscloud:gcp:steal_application_access_token:additional:run-7:n | additional | 7 | payload_absent | 26 | `67445243cd8a7a7d9023dddae942b10ad9a89232a7efd7e28831b57ae1341dda` |
| crosscloud:gcp:steal_application_access_token:additional:run-7:y | additional | 7 | payload_present | 27 | `3bc0acd44cdd1ed6259063543ea29b625d51f33cbcef2224931f5c9472aeff06` |
| crosscloud:gcp:steal_application_access_token:additional:run-8:n | additional | 8 | payload_absent | 26 | `eb06e8aa05058c2403b142d08ff66475ddd35cbd9af28dde8fe1adf9c7386958` |
| crosscloud:gcp:steal_application_access_token:additional:run-8:y | additional | 8 | payload_present | 27 | `54c3a6c003b8bfa2314bed631362f28771d6b0995c0760f8c69eeb7096f9dbd1` |
| crosscloud:gcp:steal_application_access_token:additional:run-9:n | additional | 9 | payload_absent | 26 | `8fc3e06801490765b7a13d78b8ba9e96319955e6d32887f8236a9489362e6df0` |
| crosscloud:gcp:steal_application_access_token:additional:run-9:y | additional | 9 | payload_present | 27 | `4d6ee4b861792b81f170f44721f331a67295ff722cbdc9e384027ec74d40f895` |
| crosscloud:gcp:steal_application_access_token:default:run-0:n | default | 0 | payload_absent | 9 | `121d57cee6a1b46eb1ad860ad220df69e755fb1859e321674b1b64daa75fc10e` |
| crosscloud:gcp:steal_application_access_token:default:run-0:y | default | 0 | payload_present | 9 | `abaa605af0171f56f53544d31b145b8c188455a7839c34ceabe16596d90831ef` |
| crosscloud:gcp:steal_application_access_token:default:run-1:n | default | 1 | payload_absent | 9 | `00dcd750644a396d517ababa171275e8c1e935847ade4d895fd3154deaab0c3c` |
| crosscloud:gcp:steal_application_access_token:default:run-1:y | default | 1 | payload_present | 9 | `85d342bdcaa529d4d1b3038961427496f769f95dfd8a7b377e9124874f019f12` |
| crosscloud:gcp:steal_application_access_token:default:run-2:n | default | 2 | payload_absent | 9 | `8d147077b7fead74acb4fb29134ceaf817b5d7496738529a8845b0ba09e72abb` |
| crosscloud:gcp:steal_application_access_token:default:run-2:y | default | 2 | payload_present | 9 | `711a3bd8fdd75aa2084776dd28dcfdd5c22586d0c77b979f17925dfb95423146` |
| crosscloud:gcp:steal_application_access_token:default:run-3:n | default | 3 | payload_absent | 9 | `ecb4a1a7569fb594a681cb573583b46a46a04e2cc288324ba74e3538e2b5c7f8` |
| crosscloud:gcp:steal_application_access_token:default:run-3:y | default | 3 | payload_present | 9 | `46d1706a68c8eda77689f3bb8fae60911402f46a41f4fff950b2905b4688c7d2` |
| crosscloud:gcp:steal_application_access_token:default:run-4:n | default | 4 | payload_absent | 8 | `9f8f11913dfc9fff6109c4160c25cac0f75038072f8d8b7dd4525ff4d12d2980` |
| crosscloud:gcp:steal_application_access_token:default:run-4:y | default | 4 | payload_present | 9 | `c9b7985e0c47c2c39292106dd4d3514885c09215145a08ca1b817a47900360a2` |
| crosscloud:gcp:steal_application_access_token:default:run-5:n | default | 5 | payload_absent | 9 | `40e7e6df5d852580bd153b850182e166dabb48a6bcf12c2bba76c1e186fe6928` |
| crosscloud:gcp:steal_application_access_token:default:run-5:y | default | 5 | payload_present | 9 | `b5575c67a7281f979725cfb6bc882ba55f2028b6e10c081922d90674bd207849` |
| crosscloud:gcp:steal_application_access_token:default:run-6:n | default | 6 | payload_absent | 9 | `917069eabfd2b4af0bfeb0d52a4059b20abe66ffb623ea9b06456ef96aa3239d` |
| crosscloud:gcp:steal_application_access_token:default:run-6:y | default | 6 | payload_present | 9 | `8b72a9aefacef66b9ad0fa519f084a3050e5fa6ca2966b23d865125e16d5c5c5` |
| crosscloud:gcp:steal_application_access_token:default:run-7:n | default | 7 | payload_absent | 9 | `e5d3f1e470b331532197fba3b03ca17d17cec802ad1153ffd603dd6f2a9b6050` |
| crosscloud:gcp:steal_application_access_token:default:run-7:y | default | 7 | payload_present | 9 | `3d1de6235077698495bc5b3f04bc5e7bce6d43f79ebaaf55fd0d014709a1c6a8` |
| crosscloud:gcp:steal_application_access_token:default:run-8:n | default | 8 | payload_absent | 9 | `67ab08c396ce8c5e7b1057f04c59eb976f21ba4201daf4fc9600758980a7ed7e` |
| crosscloud:gcp:steal_application_access_token:default:run-8:y | default | 8 | payload_present | 9 | `93a7a125eb4b4a92dfc82c810ced53f0ec397998d903d937b045fe376c643921` |
| crosscloud:gcp:steal_application_access_token:default:run-9:n | default | 9 | payload_absent | 9 | `f035bfd08b81d4c59678187d1cef1630b38b047edd2ce0ebb84a3de62fb9a110` |
| crosscloud:gcp:steal_application_access_token:default:run-9:y | default | 9 | payload_present | 9 | `569bc798dfe75c4cc11b5e51c5d0d62b3ae6f1dea787096ec4d538b8985eabb8` |

### 原始文件完整性

- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/README.md` — SHA-256 `b073b2e97aea4073fec2bf387e2c255d987dd8f3710e84f2df3cc59947e510f8`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/attack_scripts.zip` — SHA-256 `4599be3e224f3b9b43e76ab4ec1bfa8e3b209ebe529fb218ae4e65dd22417900`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/gcp_logs_redacted.zip` — SHA-256 `2765fedd91ce6a03c9a8d156a3d83e34dd493e7a366d0b38abd88a00ad10c5a4`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/log_analysis.zip` — SHA-256 `23b41863cc2ece4936277a1ee1fc6f64b4fea9f3c0f698cefbf5626eeca00fcf`

## 45. `crosscloud:gcp:unsecured_credentials`

- 描述：DOI-published paired payload/no-payload GCP telemetry for unsecured_credentials.
- 发布者：Dhooghe et al.
- 发布日期：2026-04-30
- 环境：controlled cloud subscription
- ATT&CK：
- 原始文件数：4
- 规范化观测数：0
- 上游 episode 数：40

### 准入判断（人工填写）

- [ ] 有外部或低权限入口
- [ ] 存在多步关系，而非单点事件
- [ ] 终点为数据库、存储、备份、secret 或其他数据资产
- [ ] 关键边均有原始证据
- [ ] 不是近重复案例
- 决定：`<accept | needs_execution | reject>`
- 理由：`<人工填写>`

### 观测索引

| observation_id | timestamp | actor_type | service | operation | status | raw record |
|---|---:|---|---|---|---|---|

### 上游配对 episode

| episode_id | profile | run | source condition | observations | member SHA-256 |
|---|---|---:|---|---:|---|
| crosscloud:gcp:unsecured_credentials:additional:run-0:n | additional | 0 | payload_absent | 12 | `b990156831b36bf6c220721f44637d5193d9ee38e2099c1c37e59407fea688f0` |
| crosscloud:gcp:unsecured_credentials:additional:run-0:y | additional | 0 | payload_present | 10 | `09025c920f9395c71e99853774bdc813cfe3c591e8b298bddf94d081526784af` |
| crosscloud:gcp:unsecured_credentials:additional:run-1:n | additional | 1 | payload_absent | 12 | `71148bdf1d68f0e1a32892d6ba07f60b9d3169cc3847f82249daf32c68faefb4` |
| crosscloud:gcp:unsecured_credentials:additional:run-1:y | additional | 1 | payload_present | 10 | `fd5f4358e5de894aa0d8bd13f751a9b781cc5e0c32743b9d0b4a524f3f691650` |
| crosscloud:gcp:unsecured_credentials:additional:run-2:n | additional | 2 | payload_absent | 12 | `59568fe59f22651a8b7eb7257e1f5f11253e4a6d9878ebadd9e0225aad646686` |
| crosscloud:gcp:unsecured_credentials:additional:run-2:y | additional | 2 | payload_present | 10 | `f75b2970c09a02be46d3f6d444679f8378c14558ae060462116070c78fb1124a` |
| crosscloud:gcp:unsecured_credentials:additional:run-3:n | additional | 3 | payload_absent | 12 | `72f3f8fb1aa1c6a0d956f7ce51aa0863809ee9d143a877b5b0a864020a9af492` |
| crosscloud:gcp:unsecured_credentials:additional:run-3:y | additional | 3 | payload_present | 10 | `3de5f1a4cf194576da71bf9ae1f589181329cb1601fdb0f94d7d3381bed99b74` |
| crosscloud:gcp:unsecured_credentials:additional:run-4:n | additional | 4 | payload_absent | 12 | `69b324d3e3422c34e284ef2b4157a9a0bde2c8e1271ea77239053a3751cc3b65` |
| crosscloud:gcp:unsecured_credentials:additional:run-4:y | additional | 4 | payload_present | 10 | `e0381380720e2e0edba89e014a20e1d5e3d67af0cfd704fba0c17395f7f4bad8` |
| crosscloud:gcp:unsecured_credentials:additional:run-5:n | additional | 5 | payload_absent | 12 | `ace9ba333f1d68455c4e084f68fea3a02ef821d2a42bac8472cf661b09ad3933` |
| crosscloud:gcp:unsecured_credentials:additional:run-5:y | additional | 5 | payload_present | 10 | `91765dfbd7aa9d673b71bf73756d7c0ee8f00831fc9a487eab66c42f123f45c7` |
| crosscloud:gcp:unsecured_credentials:additional:run-6:n | additional | 6 | payload_absent | 12 | `a5883d47cae2862c231cdb19ed1037a13e88b04f26564b7d93007c44cbd41cc2` |
| crosscloud:gcp:unsecured_credentials:additional:run-6:y | additional | 6 | payload_present | 10 | `f24108e58aae88a4273f0cd56ca6ce7501c9eb63bda950dc983d04dbd334478f` |
| crosscloud:gcp:unsecured_credentials:additional:run-7:n | additional | 7 | payload_absent | 12 | `5096e53b1b03354c75bb3f5de4b2a4050ed1d3943025bdea2df8af429e1cb1e8` |
| crosscloud:gcp:unsecured_credentials:additional:run-7:y | additional | 7 | payload_present | 10 | `45bac858f149e8931db802e9b01cf3ed3bf0e5c88ae04a5b8e3f887b59b1f428` |
| crosscloud:gcp:unsecured_credentials:additional:run-8:n | additional | 8 | payload_absent | 12 | `de14f85690949883ae20a4835ac00253dd6c8e5331c176f0f9a8cad5eae4a846` |
| crosscloud:gcp:unsecured_credentials:additional:run-8:y | additional | 8 | payload_present | 10 | `56a1117d2276b2ab4b0efb57c12470b85de850b19d210c711ff53c870ada417b` |
| crosscloud:gcp:unsecured_credentials:additional:run-9:n | additional | 9 | payload_absent | 12 | `3b13a77712e19bd90db66d3f114eb0f1697b9426f69d9297b63e33a82ad5800f` |
| crosscloud:gcp:unsecured_credentials:additional:run-9:y | additional | 9 | payload_present | 10 | `6a61b0fedba668342500039a018aab549ac41c8db10e308f83b81e3c3a2de2e5` |
| crosscloud:gcp:unsecured_credentials:default:run-0:n | default | 0 | payload_absent | 5 | `9be70b799ce68ef649c97426ca4dfd92c335f55719905277c01d18c6992e76fc` |
| crosscloud:gcp:unsecured_credentials:default:run-0:y | default | 0 | payload_present | 6 | `8241d3364a6f432a11af0aaa6db0fd0ff5922cdd43fbb3a7f215ca48c58d6b60` |
| crosscloud:gcp:unsecured_credentials:default:run-1:n | default | 1 | payload_absent | 5 | `bf621c544883c98753a7d3744f740da33dd64b44f6a77a5b6e5a8ca056b8804b` |
| crosscloud:gcp:unsecured_credentials:default:run-1:y | default | 1 | payload_present | 6 | `18f3c21d72edc3a9a525c182fa10e5ffc952d91fed54edc89730f6ba0c8561c5` |
| crosscloud:gcp:unsecured_credentials:default:run-2:n | default | 2 | payload_absent | 5 | `402f453820e50c4f5e8a4d353516df25b605fea4fbc7b7e29231f16d63ac1869` |
| crosscloud:gcp:unsecured_credentials:default:run-2:y | default | 2 | payload_present | 6 | `17705dd713d6afdf4760da0bf91edd6ea5bc8a754ee5058ad578afa240a7f8ec` |
| crosscloud:gcp:unsecured_credentials:default:run-3:n | default | 3 | payload_absent | 5 | `4c236ec484b0d6182e77c4b782ea347cd4b4d3faeda46b1bbc8972addf3a1644` |
| crosscloud:gcp:unsecured_credentials:default:run-3:y | default | 3 | payload_present | 6 | `36db7755a4fb92ba22685234b04f7bcf802e58f29d7f35c6b4fbcccfbf04970e` |
| crosscloud:gcp:unsecured_credentials:default:run-4:n | default | 4 | payload_absent | 5 | `7a82d262fca2f225bcd29018d96ef97d84407d6426cd4c3372e4eb26dfe23d73` |
| crosscloud:gcp:unsecured_credentials:default:run-4:y | default | 4 | payload_present | 6 | `c136a00d91bd491147bebef9ed4604bfc9062603ceb26be25b90d4e7899cbee0` |
| crosscloud:gcp:unsecured_credentials:default:run-5:n | default | 5 | payload_absent | 5 | `d6f45e040efec270964864870cd41d7ec7953d037ef91d73a707ba4f2dbe3849` |
| crosscloud:gcp:unsecured_credentials:default:run-5:y | default | 5 | payload_present | 6 | `f0d660eec1ec402193f25f7358248e42b9a60fe1f4420635c473b82c7efa2f42` |
| crosscloud:gcp:unsecured_credentials:default:run-6:n | default | 6 | payload_absent | 5 | `faf724439361bfd7454ffe50f9c3fe2cdd203c52c12c7c153da2df4570d33494` |
| crosscloud:gcp:unsecured_credentials:default:run-6:y | default | 6 | payload_present | 6 | `220a4aa32cbdd7012fd5ca3041e41e4fb8ed3c49e4921c5211e18c59a32624d8` |
| crosscloud:gcp:unsecured_credentials:default:run-7:n | default | 7 | payload_absent | 5 | `16446b694a2061ad680897d076977174e8c6b82fa011ebdc554bfa4a6efdc24c` |
| crosscloud:gcp:unsecured_credentials:default:run-7:y | default | 7 | payload_present | 6 | `b76ee874d0f9dc6b84f026f84aba7c5f410f891986c63ed41437781550c71bec` |
| crosscloud:gcp:unsecured_credentials:default:run-8:n | default | 8 | payload_absent | 5 | `be29159d41d09df9ecc442ec5ea292741a13cfb16b527b49522a22d127468e14` |
| crosscloud:gcp:unsecured_credentials:default:run-8:y | default | 8 | payload_present | 6 | `1229504d965855df98127d3222318b099a0f232599876963fae0eddae6ed9f61` |
| crosscloud:gcp:unsecured_credentials:default:run-9:n | default | 9 | payload_absent | 5 | `cace53e53751d637c41b40e9eb33a9751f460330b53768495bd576cd93fc610c` |
| crosscloud:gcp:unsecured_credentials:default:run-9:y | default | 9 | payload_present | 6 | `a367fbca2f0288172f5fdc1cf7d50d337ebd1a4edb6199747173a592710f12d8` |

### 原始文件完整性

- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/README.md` — SHA-256 `b073b2e97aea4073fec2bf387e2c255d987dd8f3710e84f2df3cc59947e510f8`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/attack_scripts.zip` — SHA-256 `4599be3e224f3b9b43e76ab4ec1bfa8e3b209ebe529fb218ae4e65dd22417900`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/gcp_logs_redacted.zip` — SHA-256 `2765fedd91ce6a03c9a8d156a3d83e34dd493e7a366d0b38abd88a00ad10c5a4`
- `data/real_sources/raw/cross_cloud_observability_2026/record-19933893-v2/log_analysis.zip` — SHA-256 `23b41863cc2ece4936277a1ee1fc6f64b4fea9f3c0f698cefbf5626eeca00fcf`

