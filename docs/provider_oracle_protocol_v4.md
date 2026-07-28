# Provider-Oracle Protocol v4：跨来源真实证据与独立组统计

## 结论先行

Protocol v4 把 v3 的 6 个案例扩展为 12 个案例、10 个保守独立组，并引入 OTRF、Cross-Cloud、Stratus、Splunk、AWSGoat、AzureGoat、GCPGoat 七类来源。所有运行时正负状态均来自 provider-native 审计结果；五个配置案例只标为 epistemic `Unknown`，不把上游 walkthrough 当作 gold。

它已经足以验证数据契约、三态判定、正负 CP-Cert、泄漏隔离和独立组统计是否正常工作，但仍然只是 protocol-scale pilot，不是 EC-ReAct 的主效果实验。

## 1. 本轮修正的两个数据问题

### 1.1 非拒绝不等于成功

旧候选扫描器使用“没有显式权限拒绝”作为成功条件，因此 GCP `code=5 (NotFound)` 虽然不是权限拒绝，却可能被误收为成功。v4 前置审计改为：

\[
\mathrm{Success}(o)=
\begin{cases}
1,&\text{AWS 且 errorCode/errorMessage 均为空},\\
1,&\text{GCP 且 status.code}\in\{\varnothing,0\}\text{ 且无 granted=false},\\
0,&\text{其他情况}.
\end{cases}
\]

重扫结果中有 514 条 GCP provider error 被排除出正证据。候选操作组数量仍为 58，是因为这些组内同时存在其他真正成功事件；但各组的成功 occurrence 数已被纠正。

### 1.2 执行背景变体不等于独立攻击

上游 `-with-webapp` 表示同一攻击运行时叠加良性 Web 流量，不是新的攻击设计。因此：

\[
\mathrm{lineage}(s)=
\begin{cases}
s\setminus\texttt{-with-webapp},&s\text{ 具有该后缀},\\
s,&\text{其他}.
\end{cases}
\]

原报告的 28 个 scenario variant 被保守折叠为 17 个攻击家族 lineage。进一步按同一主体、同一目标和可形成的数据访问结构连接后，得到 20 个路径候选组、14 个保守 lineage：

| 候选类型 | 组数 | 含义 |
|---|---:|---|
| `list_then_object_read` | 10 | 同一主体、同一目标下至少有枚举与读取两类成功操作 |
| 直接 secret/object read | 10 | 有决定性的真实读取边，但上游前驱仍需语义审核 |
| 合计 | 20 | 均为候选，不是 gold |

其中 17/20 个代表案例的主体不是 Root。每个候选都保留 archive SHA-256、member SHA-256、JSON pointer、主体、操作和资源。

## 2. v4 数据组成

| 状态/角色 | 案例数 | 保守独立组 | 来源 |
|---|---:|---:|---|
| provider-runtime `Reachable` | 6 | 5 | OTRF、Cross-Cloud、Stratus、Splunk |
| provider-runtime `NotReachable` | 1 | 1 | Cross-Cloud GCP code-7 denial |
| epistemic `Unknown` control | 5 | 4 | AWSGoat、AzureGoat、GCPGoat |
| 合计 | 12 | 10 | 7 类来源 |

两个新增的 runtime gold 为：

1. Stratus Red Team：同一 IAM user 先 `ListSecrets`，随后对精确 secret ARN 成功执行 `GetSecretValue`；
2. Splunk Attack Data：精确 IAM user、bucket 和 key 的成功 `GetObject`。

配置控制例只证明固定 Terraform 片段存在。由于 provider-native analyzer 和授权 runtime probe 均未运行，其状态严格保持为 `Unknown`。

公开证据与 evaluator-only gold 分别位于：

- `data/real_sources/provider_oracle_protocol_v4_public.json`
- `data/real_sources/provider_oracle_protocol_v4_gold.json`
- `data/real_sources/provider_oracle_protocol_v4_splits.json`

Agent 只加载 public 文件，真实 case ID 在环境中继续被盲化。

## 3. 人工复核工作量已被压缩

`provider_semantic_review_round1_unlabeled.json` 包含 20 个 label-empty 案例。人工不需要重新判断 CloudTrail/GCP Audit Log 已经给出的 success/deny；两名独立审核者只判断：

1. 精确主体能否作为路径入口；
2. 目标是否属于云数据资产；
3. 操作是否形成因果/可达路径，而非无关并列行为；
4. 是否缺少关键前驱；
5. lineage 去重后是否仍独立。

节点、边、路径状态和准入决定均为空，脚本没有生成任何 human label。现有 blind assignment、双人一致性和第三人裁决流程已通过自动测试。

## 4. 独立组统计

同一 lineage 内的不同平台案例、重复运行和随机种子不能作为独立样本。v4 的主二元指标采用严格聚类规则：

\[
Y_g=\mathbb{1}
\left[
\bigwedge_{i\in g} y_i=1
\right].
\]

即同一独立组内的所有案例和重复都正确，该组才计为成功。报告比例为：

\[
\hat p=\frac{1}{G}\sum_{g=1}^{G}Y_g.
\]

95% 区间使用 Wilson score interval：

\[
\mathrm{CI}_{95\%}=
\frac{
\hat p+\frac{z^2}{2G}
\pm z\sqrt{\frac{\hat p(1-\hat p)}{G}+\frac{z^2}{4G^2}}
}{
1+\frac{z^2}{G}
},\qquad z=1.96.
\]

案例/随机种子级均值仅保留在 `diagnostic_case_run_metrics`，不能作为论文主显著性结果。

## 5. v4 协议实验结果

配置：`configs/provider_oracle_protocol_v4.json`  
结果：`output/provider_oracle_protocol_v4_results.json`

共运行 288 个 case-run，但有效统计单位始终只有 10 个独立组。在预算 4 下：

| 方法 | provider gold 状态准确率 | 95% CI | 显式阻断识别率 | Unknown 拒答率 | false-Reachable | 平均查询成本 |
|---|---:|---:|---:|---:|---:|---:|
| provider-aware CP-Cert 透明参考 | 1.000 | [0.610, 1.000] | 1.000 | 1.000 | 0.000 | 2.00 |
| fixed-order | 0.833 | [0.436, 0.970] | 0.000 | 0.000 | 0.500 | 3.00 |
| full-query | 0.833 | [0.436, 0.970] | 0.000 | 0.000 | 0.500 | 2.00 |
| random-tool | 0.833 | [0.436, 0.970] | 0.000 | 0.000 | 0.500 | 3.00 |

透明参考策略的阻断识别只有 1 个有效负组，其 95% CI 为 `[0.207, 1.000]`；Unknown 也只有 4 个有效组，其 95% CI 为 `[0.510, 1.000]`。这些宽区间明确说明 100% 只是协议功能验证，不能声称稳定泛化。

透明参考的完整路径 edge F1 仍为 0.667：它能找到决定状态的关键边，但没有自动补齐全部前驱。这正是后续 LLM EC-ReAct 主实验需要解决的部分。

## 6. 当前能主张与不能主张

可以主张：

- 数据筛选已区分 success、denial、NotFound 和 Unknown；
- 路径候选按攻击家族保守去重，重复运行不增加独立样本数；
- public/gold 物理分离，Agent 不读取 evaluator gold；
- 正负 CP-Cert 和 Unknown 拒答在真实 provider evidence 上可运行；
- 主统计按 independence group 聚合，并报告小样本置信区间。

不能主张：

- EC-ReAct 已经显著优于 vanilla ReAct 或强基线；
- 透明规则策略的 100% 是 LLM 或 Agent 泛化准确率；
- 当前 1 个负组足以证明稳定的 NotReachable 识别；
- 20 个候选已成为 20 个 gold；
- 五个配置案例已经证明暴露或不暴露。

## 7. 下一阶段硬任务

1. 完成 20 个候选的双人语义审核，优先处理 10 个多操作链；
2. 从独立来源补充至少 9 个 NotReachable 组，避免用同一 GCP 场景的十次重试冒充十个样本；
3. 将 provider/human gold 扩展到至少 30 个平衡独立组；
4. 冻结 source-held-out 划分后，再运行真正的 LLM EC-ReAct、vanilla ReAct、full-query、fixed-order 和组件消融；
5. 只在独立组层面进行置信区间、配对检验和效应量报告。
