# OTRF CloudGoat S3 外传运行时证据说明

## 核验结论

OTRF Security-Datasets 固定 commit
`d9d40ef123d2c87d5d3df28c96bcab4f0faccc87` 发布了
`SDAWS-200914011940` 数据。上游元数据说明：攻击者利用错误配置的 EC2 反向
代理取得实例角色凭据，随后列举并外传 S3 文件；其 simulation environment
明确链接到 CloudGoat `cloud-breach-s3`。

固定压缩包包含一份 106,600 字节的 CloudTrail JSONL，计 103 条事件、26 种
operation、6 个 AWS service；其中包括 `ListBuckets`、`ListObjects`、
`GetObject`、`AssumeRole`，也保留同一执行窗口内的上下文事件。

机器可读索引：

```text
data/real_sources/otrf_cloud_breach_s3_runtime_index.json
```

- 索引 SHA-256：
  `464c8ed66723c76c169f7dc79f177a4b3a212bf6e501e581a2a205e6fe62dfe3`
- 归档 SHA-256：
  `83cc349afa5672ae46fc38a824946b470f2f3fa39f22889b59dce9fda43fe74d`
- 日志 member SHA-256：
  `9cfc6675f59b666cee6e6f0bcb72b1034ea4bbcdaf19c0f02b3092317128289b`
- 生成事件：0；
- 生成路径/证据标签：0。

## 独立性边界

OTRF 是独立的遥测发布者，但不是独立攻击场景。该数据必须关联到现有
`cloudgoat:aws:cloud_breach_s3`，并继续使用
`cloudgoat-scenario:cloud_breach_s3` independence group；不能另起 group
扩大样本量。

为保持刚冻结的人工 pilot v2 不变，pilot 继续引用 92 实例的 v0.2 母包。主候选
包另升为 `expanded_full_pool_v0_3_unlabeled.json`，将完整 103 条事件作为
CloudGoat 案例的第 93 个 B 级运行实例接入，同时不增加案例数或 independence
group。它仍没有进入任何人工 gold 或方法效果统计。

后续全源工具契约审计发现两个与 OTRF 无关的 Cross-Cloud 实例为零观测，故正式
主候选包升级为 `expanded_full_pool_v0_4_unlabeled.json`。OTRF 的 103 条观测
原样保留；v0.4 共 91 个非空实例，案例数与 independence group 仍不变。

随后 v0.5 只补回同一固定 Cross-Cloud 原始归档中的无标签详情字段；OTRF
实例、事件、哈希和 lineage 均未改变。正式主候选路径现为
`expanded_full_pool_v0_5_unlabeled.json`。
