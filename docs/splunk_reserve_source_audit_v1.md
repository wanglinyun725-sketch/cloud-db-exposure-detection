# Splunk 后备真实路径来源审计 v1

目的：为首批 30 个确认性谱系准备真实后备候选，但不通过重复事件、
单步动作或元数据描述虚增独立路径数。

## 固定来源

- 上游：`splunk/attack_data`
- 固定 commit：`3821bdb77c66c95b4e529f62a9d00b168446d1a8`
- 获取脚本：`scripts/data/acquire_real_sources.py`
- 完整哈希清单：`data/real_sources/acquisition_manifest.json`
- 机器审计：`output/research_design/splunk_reserve_source_audit_v1.json`

获取过程只下载上游元数据与原始遥测并计算 SHA-256，不生成事件、
攻击标签或人工准入结论。获取清单已移除运行时间字段，连续两次获取
产生相同字节。

为避免只挑选“看起来有利”的目录，另在较新的固定 commit
`67fe973a954cc35688ad9b4906ed6e85af5892e9` 上按预先固定的云数据关键词
扫描完整 Git tree。15 个命中数据集中，8 个已在冻结主包，1 个是 KMS
候补，2 个已经结构排除，4 个属于端点、DNS 或 Kubernetes 范围；未分类
项目为 0。完整逐项处置见
`output/research_design/splunk_cloud_data_catalog_coverage_v1.json`。

## 结构审计结论

| 上游数据集 | 原始记录结构 | 后备人工路径筛选 |
|---|---|---|
| `T1486/aws_kms_key` | 111 条与同一 KMS key 精确关联的 CloudTrail 记录；覆盖创建、别名、策略修改、禁用、删除调度、恢复及 S3 `GenerateDataKey` | 可进入后备双人筛选，但当前仍是 0 gold |
| `T1537/aws_ami_shared_public` | 2 条 `ModifyImageAttribute` | 排除：重复同类操作不是多步路径 |
| `T1562.008/put_bucketlifecycle` | 5 条 `PutBucketLifecycle` | 排除：重复同类操作不是多步路径 |
| `T1485/aws_delete_knowledge_base` | 1 条 `DeleteKnowledgeBase` | 排除：单步动作 |
| `T1485/decommissioned_buckets` | 1 条 CloudFront HTTP 访问记录 | 排除：单条访问不能独立证明多步路径 |
| `T1078/gcploit_exploitation_framework` | 1 条 GCP Cloud Functions 创建结果 | 排除：没有关联的数据访问或暴露状态变化 |
| `T1526/aws_security_scanner` | 1,071 条、53 种只读 `Describe*` 操作，其中 979 条显式失败 | 排除：属于发现扫描，没有修改、数据读取或暴露状态变化 |
| `T1204.003/aws_ecr_container_upload` | 2 条 `PutImage` | 排除：重复同类操作，且 ECR 镜像上传本身不是多步云数据暴露路径 |

KMS/S3 候选的标签空白制品位于
`data/real_sources/splunk_kms_s3_reserve_candidate_v1.json`。它保留每条
观测在原始文件中的记录序号、原始文件 SHA-256 和上游 URL，并明确：

- `candidate_is_not_gold = true`
- `human_admission_required = true`
- `external_or_low_privilege_entry = "unknown"`
- `publication_use_before_double_human_review = false`

因此该扩展当前只增加 1 个真实后备候选，不改变已发布候选门槛，也不把
Splunk 的数据集描述当成攻击意图或端到端可达性证明。

## 候补充足性门禁

冻结主包恰好只有 30 个 `independence_group`。为避免任意一次人工不准入就
使 30 谱系目标失效，预注册的操作性供给门禁要求至少 5 个结构合格候补，
相当于为目标样本量保留 16.7% 的剔除缓冲。该门禁不改变论文发布条件，也
不把候补当作 gold。

可复算结果位于
`output/research_design/confirmatory_reserve_adequacy_v1.json`：

- 主包独立谱系：30；
- 结构合格候补：1；
- 当前最多容忍主包剔除：1；
- 距 5 个候补门槛仍缺：4；
- `robust_annotation_supply_ready = false`；
- 新增 human gold：0。

复算命令：

```powershell
D:\anaconda\python.exe scripts/data/audit_splunk_reserve_sources_v1.py
D:\anaconda\python.exe scripts/data/audit_splunk_cloud_data_catalog_v1.py
D:\anaconda\python.exe scripts/data/audit_reserve_adequacy_v1.py
```
