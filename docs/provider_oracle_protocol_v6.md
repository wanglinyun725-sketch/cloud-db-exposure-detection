# Provider-Oracle Protocol v6：真实拒绝、同范围对照与保守统计

## 结论

Protocol v6 是一个可复现的研究协议 pilot，不是最终主实验。它包含 16
个案例、28 条公开观测和 12 个保守独立组：

| 状态 | 案例数 | 独立组数 | 证据性质 |
|---|---:|---:|---|
| `Reachable` | 6 | 5 | provider-native 成功事件 |
| `NotReachable` | 5 | 3 | provider-native 明确拒绝及同目标/同范围对照 |
| `Unknown` | 5 | 4 | 只有冻结配置，未运行完整权限分析或运行时探针 |
| 合计 | 16 | 12 | 8 个 provider-gold 组、4 个 epistemic control 组 |

同一数据文件、攻击家族或重试产生的多个案例不会被当作独立样本。新增的
三个 AWS 目录枚举案例虽然覆盖 S3、Secrets Manager 和 Elasticsearch，
但都来自同一个 Splunk attack-range episode，因此只计为一个独立组。

## 1. 新增真实来源

新增来源固定在 Splunk Attack Data 提交：

`67fe973a954cc35688ad9b4906ed6e85af5892e9`

原始 CloudTrail 制品包含 4,196 条记录，大小为 5,038,501 字节，SHA-256
为：

`d0e597bf34919e87ff53d757766a71431847d8788ca80ffe78d8ac23bb498f35`

原始日志是上游 attack-range 记录，不是本项目脚本或 AI 生成的事件。上游
`data.yml` 由其仓库脚本自动归类，但它只作为目录元数据；gold 证据来自原始
CloudTrail 的 provider outcome。

标签无关的标准化索引由
`scripts/data/build_splunk_denial_expansion.py` 生成。它只选择和规范化事件，
不产生攻击路径或标签：

- 原始样本生成数：0；
- 自动标签数：0；
- 候选案例：3；
- 规范化观测：6；
- 独立 lineage：1。

索引文件：

`data/real_sources/splunk_denial_expansion_v1.json`

SHA-256：

`133c4e619cf87f80cee85bceb776aad5e989b3b59c019ad8966db00249dbcda4`

## 2. 三类拒绝证书

每个案例包含一条被拒绝主体的事件，以及同一账户、区域、服务和操作范围内
由另一 IAM 用户产生的成功对照：

| 服务 | 拒绝操作 | 精确范围 | 拒绝主体 | 对照主体 |
|---|---|---|---|---|
| Amazon S3 | `ListBuckets` | 账户级 bucket catalog | `cloudsploit` | `cloudmapper` |
| AWS Secrets Manager | `ListSecrets` | `us-east-1` secret catalog | `cloudsploit` | `cloudmapper` |
| Amazon Elasticsearch Service | `ListDomainNames` | `arn:aws:es:us-east-1:760111141337:domain/*` | `cloudsploit` | `cloudmapper` |

对每个操作范围 \(q\)，负证书要求：

\[
C^-(q)=
\mathbb 1[
p=p_d
\land a=a_q
\land r=r_q
\land d=\mathrm{AccessDenied}
\land \mathrm{CompleteScope}(q)
\land \mathrm{SuccessControl}(q)
].
\]

其中成功对照只证明目标操作范围存在且服务可用，不把对照主体的权限转移给
被拒绝主体。

## 3. 语义边界

目录枚举被拒绝的严格结论是：

> 指定 IAM 用户在指定时间不能对指定账户/区域目录执行该枚举操作。

它不等价于：

- 账户内不存在 bucket、secret 或 domain；
- 该主体不能通过另一个 API 读取某个已知对象；
- 以后状态仍然被拒绝；
- 整个云账户“安全”。

这类操作级负证书进入 `NotReachable`，是因为评估命题本身就是精确的
catalogue-enumeration edge，而不是泛化的“所有数据访问均不可达”。

另一个 v5 延续案例使用更强的同请求对照：同一 IAM 用户对同一 S3 bucket、
源对象、目标对象和 KMS key 发起完全相同的 `CopyObject`。第一次因
`KMS.KMSInvalidStateException` 被拒绝，错误明确指出 key 处于
`pending deletion`；37 秒后的相同请求成功。该结论只限定在第一次事件的
provider state。

## 4. 防泄漏与独立性

Agent 只加载：

`data/real_sources/provider_oracle_protocol_v6_public.json`

状态、证据极性和标准路径仅存在于 evaluator-only 文件：

`data/real_sources/provider_oracle_protocol_v6_gold.json`

案例进入环境后继续使用散列 opaque handle，真实 case ID 不在 Agent
上下文中。主二元指标按独立组严格聚合：

\[
Y_g=\mathbb 1\left[\bigwedge_{i\in g} y_i=1\right],
\qquad
\hat p=\frac{1}{G}\sum_{g=1}^{G}Y_g.
\]

因此新增 lineage 内三个案例必须全部正确，该 lineage 才计为一次成功。
随机种子、重试和同源变体不增加 \(G\)。

## 5. v6 协议验证结果

配置：

`configs/provider_oracle_protocol_v6.json`

结果：

`output/provider_oracle_protocol_v6_results.json`

共执行 384 个 case-run。它们是工程运行次数，不是 384 个统计样本。预算
4 下：

| 方法 | 有效 provider 组 | 状态准确率 | 95% Wilson CI | 有效负组 | 正确拒绝率 | 95% Wilson CI | Unknown 拒答率 | false-Reachable | 成本 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| provider-aware CP-Cert 透明参考 | 8 | 1.000 | [0.676, 1.000] | 3 | 1.000 | [0.439, 1.000] | 1.000 | 0.000 | 2.00 |
| fixed-order | 8 | 0.625 | [0.306, 0.863] | 3 | 0.000 | [0.000, 0.561] | 0.000 | 0.583 | 3.00 |
| full-query | 8 | 0.625 | [0.306, 0.863] | 3 | 0.000 | [0.000, 0.561] | 0.000 | 0.583 | 2.00 |
| random-tool | 8 | 0.625 | [0.306, 0.863] | 3 | 0.000 | [0.000, 0.561] | 0.000 | 0.583 | 3.00 |

透明参考是按 provider outcome 编码的协议验证策略，不是 LLM 效果。因此
它的 100% 只能说明 tri-state、证据极性、评分与环境在这些已知案例上对齐。
3 个负独立组对应的拒绝率区间仍然很宽，不能声称稳定泛化。

完整路径 edge F1 仍为 0.667，说明参考策略只提交决定状态的关键边，并未
解决完整多步路径重建。这正是 LLM EC-ReAct 后续实验需要证明的部分。

## 6. 冻结哈希

| 制品 | SHA-256 |
|---|---|
| `provider_oracle_protocol_v6_public.json` | `c8401c882568f29a82e2539ce104e526288663cecdd46627b86329f832d30ce5` |
| `provider_oracle_protocol_v6_gold.json` | `745d69a88bc2eefe0d608635b5d1e187412aa62e1fb20d1e1cf179123be2e1ec` |
| `provider_oracle_protocol_v6_splits.json` | `7a12886b4dcac625a60f1a8e50df19f16993a376d66c2737ed8836955bf935c0` |
| `provider_oracle_protocol_v6_results.json` | `35e12084ab86597504ba7490c8c3929854b5a0520431a7396ddabd23686386dd` |

## 7. 当前允许与禁止的论文表述

可以表述：

- 建立了真实、版本固定、哈希可复核的三态 provider-oracle pilot；
- 能区分成功、显式拒绝、其他 provider error 和证据不足；
- 能生成对象级、请求级或操作范围级的时态负证书；
- 统计按 lineage 聚合并报告小样本置信区间。

不能表述：

- EC-ReAct 已优于 Vanilla ReAct；
- 透明参考的 100% 是 LLM 准确率；
- 三个负独立组足以证明泛化；
- catalogue denial 证明所有对象均不可访问；
- finalized human gold 已经完成。

