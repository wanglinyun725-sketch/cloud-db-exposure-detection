# RealPathBench-CD v2 首轮人工标注包

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
- 待人工筛选案例数：11
- 自动生成标签数：0

## 1. `splunk:datasets/attack_techniques/T1110.002/aws_rds_password_reset`

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

## 2. `splunk:datasets/attack_techniques/T1486/s3_file_encryption`

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

## 3. `splunk:datasets/attack_techniques/T1490/aws_bucket_version`

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

## 4. `splunk:datasets/attack_techniques/T1530/aws_s3_public_bucket`

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

## 5. `splunk:datasets/attack_techniques/T1537/aws_snapshot_exfil`

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

## 6. `crosscloud:aws:automated_exfiltration`

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

## 7. `crosscloud:aws:credentials_from_password_stores`

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

## 8. `crosscloud:azure:automated_exfiltration`

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

## 9. `crosscloud:azure:credentials_from_password_stores`

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

## 10. `crosscloud:gcp:automated_exfiltration`

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

## 11. `crosscloud:gcp:credentials_from_password_stores`

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

