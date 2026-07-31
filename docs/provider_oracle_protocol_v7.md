# Provider-Oracle Protocol v7

## 定位

v7 是真实 provider 证据驱动的协议级 pilot，不是论文主效果实验。它用于验证三态判定、正负证书、工具预算、public/gold 隔离和独立组统计是否一致。`research_effectiveness_result` 固定为 `false`。

## 数据组成

- 21 个案例、33 条观测；
- 16 个 provider-oracle gold 案例，5 个配置证据不足的 Unknown 控制；
- 案例状态为 6 Reachable、10 NotReachable、5 Unknown；
- 统计单元为 13 个独立组：5 Reachable、4 NotReachable、4 Unknown；
- 冻结的 pilot split 按来源完全隔离：development 为 6 个独立组，
  `source_held_out_test` 为 7 个独立组；
- 所有原始事件来自固定版本的公开上游制品，生成样本数和生成标签数均为 0。

v7 在 v6 上新增 Splunk Attack Data 的
`T1580/aws_iam_accessdenied_discovery_events`。固定提交为
`67fe973a954cc35688ad9b4906ed6e85af5892e9`，原始 CloudTrail 文件
SHA256 为
`4f52389f17745abf5fa1cf30c055d4f9d34022fcfb8e5c2544c70177da228433`。
该文件有 1,150 条真实记录。协议只选取 us-east-1 下同一 IAM 用户的五条明确
`AccessDenied`：SSM parameter catalogue、Secrets Manager catalogue、
Redshift cluster catalogue、RDS instance catalogue 和 DynamoDB table
catalogue。

这五条记录属于同一次上游 discovery sweep，因此无论案例数还是重复运行数如何，
统计时只计一个独立组。该制品没有同主体或异主体的成功控制，证书中明确写入
`target_existence_control = not_available`。

## 语义边界

对主体 \(p\)、操作 \(a\)、目录范围 \(r\) 和事件时刻 \(t\)，v7 的负判定是：

\[
\operatorname{Denied}(p,a,r,t)
\Rightarrow
\operatorname{NotReachable}(p,a,r,t)
\]

它不蕴含：

\[
\forall a',r',t'\;
\operatorname{NotReachable}(p,a',r',t')
\]

也就是说，`ListSecrets` 被拒绝只能证明该目录操作在当时不可达，不能证明主体无法
用另一个 API 读取某个已知 Secret。`DescribeDBInstances` 被拒绝也不能证明数据面
查询永远失败。

## 协议级结果

运行命令：

```powershell
& 'D:\anaconda\python.exe' scripts\experiments\run_provider_oracle_protocol_v7.py
```

共执行 504 个 case-run。重复随机种子和同一 lineage 的多个案例不作为额外独立
样本。

预算为 4 时：

| 方法 | provider 状态准确率 | 正确拒绝率 | Unknown 拒答率 | false-Reachable | 平均成本 | edge F1 |
|---|---:|---:|---:|---:|---:|---:|
| provider-aware CP-Cert 参考 | 1.000 | 1.000 | 1.000 | 0.000 | 2.0 | 0.667 |
| fixed-order | 0.556 | 0.000 | 1.000 | 0.077 | 3.0 | 0.000 |
| full-query | 0.556 | 0.000 | 1.000 | 0.077 | 2.0 | 0.000 |
| random-tool | 0.556 | 0.000 | 1.000 | 0.077 | 3.0 | 0.000 |

provider-aware 参考在 9 个 provider 独立组上的准确率 Wilson 95% CI 为
`[0.701, 1.000]`；在 4 个拒绝组上的正确拒绝率 CI 为
`[0.510, 1.000]`。区间仍宽，因此不能作总体性能结论。该参考策略显式编码
provider 语义，也不能写成“LLM Agent 达到 100%”。

source-held-out 划分中，一个 `source_id` 只能出现在一个 split，避免同一发布源的
lineage 泄漏。不过测试集只有 7 个独立组，因此它只是执行协议的冻结 pilot，
不能替代至少 30 个较均衡独立组的论文主测试。

## 冻结哈希

| 制品 | SHA256 |
|---|---|
| label-free discovery index | `b3fa97f0ab80c8efdcb88e2a9dd92f940927c21e8f8fa0c3843915c38a6b9ac0` |
| public packet | `536c9970e093f75d31cb84ed9d9a37ba86ef76d9b8300166e67c84d4cf407984` |
| evaluator gold | `188d517b526d6a8a063e3ec441482409ca5eccba0d04b51604ca2e8bd8410236` |
| split manifest | `5b7ea258667a7a9443b8694485228dedc6ea7352e9edc8bf14b62d4f87589cc4` |
| result report | `6cf34245b12f957c55c73631e1e9294418ccd69a73c682d26d96d05296110d22` |

## 尚未通过的门槛

- finalized human gold 仍为 0；
- 只有 13 个独立组，未达到预注册的 30 组；
- NotReachable 独立组只有 4 个；
- 已冻结 source-disjoint pilot，但正式主测试仍因样本不足而未通过；
- 尚无合格的真实 LLM EC-ReAct 对照和消融结论。
