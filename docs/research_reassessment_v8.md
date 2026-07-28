# Cloud DB PathBench v8 客观再评估

评估日期：2026-07-28
结论性质：阶段性、证据约束，不是答辩成绩预测

## 结论先行

当前项目已经从“展示型 Agent 原型”升级为一个**工程完整、数据可追溯、实验边界较诚实的研究原型**。它可以支撑一篇合格偏强、具备冲击“良好”质量的研究生毕业设计，但现有证据仍不足以客观认定为“优秀毕业设计已完成”。

核心原因不是代码量不够，而是外部效度仍弱：

- v8 只有 25 个案例、16 个独立来源组；
- 16 个独立组中 AWS 占 12 个，GCP 3 个，Azure 1 个；
- 18 个案例是 provider-runtime gold，7 个是 Unknown 覆盖控制；
- 独立真人 gold 为 0；
- 本地 Qwen 子实验只有 3 个独立 lineage；
- 完整 EC-ReAct 相对 Vanilla ReAct 只有 1 胜、0 负、2 平，精确检验
  \(p=1.0\)，不能声称显著优越；
- 本地 Qwen 的 exact gold-path edge F1 仍为 0，说明“状态判定正确”尚未转化为“细粒度攻击路径恢复正确”。

因此，论文当前最稳妥的定位是：

> 面向真实云审计证据的范围感知、成本约束攻击路径发现协议与可审计 Agent 原型。

不应写成：

> 已证明优于现有 Agent、能够在真实企业环境中准确恢复完整攻击链。

## 数据证据审计

| 项目 | 当前证据 | 判断 |
|---|---:|---|
| 案例数 | 25 | 仅协议规模 |
| 独立 lineage | 16 | 可以做精确配对试验，但统计功效有限 |
| 可追溯上游 source ID | 8 | 来源多样性尚可 |
| 云平台 | AWS/GCP/Azure | 跨云成立，但极不均衡 |
| provider-runtime gold | 18 | 强于 AI/脚本自标注 |
| epistemic Unknown controls | 7 | 能测“不过度声称” |
| 真人双标 gold | 0 | 优秀毕设的主要缺口 |
| AI 生成云事件 | 0 | 满足“不用 AI 生成实验数据”的要求 |
| 冻结 public/gold/split | 已完成 | 泄漏边界清楚 |

数据文件：

- `data/real_sources/provider_oracle_protocol_v8_public.json`
- `data/real_sources/provider_oracle_protocol_v8_gold.json`
- `data/real_sources/provider_oracle_protocol_v8_splits.json`

构建入口：

- `scripts/data/build_provider_oracle_protocol_v8.py`

## 方法结果

### 非 LLM、16 独立组协议试验

范围感知 provider-aware CP-Cert 参考策略在预算 2/4/8 下均达到
16/16 组协议正确且 unsafe false-Reachable 为 0。该结果首先是“冻结协议能被正确消费”的 sanity check，不能单独证明真实世界泛化。

预算 2 时：

| 方法 | 组正确率 | unsafe false-Reachable | 平均组成本 |
|---|---:|---:|---:|
| Provider-aware CP-Cert | 1.000 | 0.000 | 1.875 |
| Full query | 0.625 | 0.188 | 1.875 |
| Fixed order | 0.375 | 0.000 | 1.000 |
| Random tool | 0.375 | 0.000 | 1.000 |

以 16 个独立组做配对精确检验并对 9 次比较进行 Holm 校正：

- 相对 Fixed order：10 胜、0 负、6 平，Holm \(p=0.0176\)；
- 相对 Random tool：10 胜、0 负、6 平，Holm \(p=0.0176\)；
- 相对 Full query：6 胜、0 负、10 平，原始 \(p=0.0313\)，但
  Holm \(p=0.1094\)，不显著；
- 预算 4/8 的比较经 Holm 校正后均为 \(p=0.1094\)。

可支持的结论：

> 在这个冻结的 16-lineage provider-oracle 协议上，范围感知参考策略在低预算条件下优于固定顺序和随机工具基线。

不能支持的结论：

> EC-ReAct 全面显著优于所有基线。

### 本地 Qwen2.5-7B 真实 Tool-Use 试验

清洁 v8.1 网格包含：

- 同一模型 digest；
- 4 个新增真实遥测案例；
- 3 个种子；
- EC-ReAct linear、EC-ReAct LangGraph、Vanilla ReAct；
- 共 36 个唯一运行；
- 重复记录 0，语义冲突 0，调度完整。

组级结果：

| 方法 | 修复前正确率 | 修复后正确率 | 修复前 false-Reachable | 修复后 false-Reachable |
|---|---:|---:|---:|---:|
| EC-ReAct LangGraph | 0.667 | 1.000 | 0.333 | 0.000 |
| EC-ReAct Linear | 0.667 | 1.000 | 0.333 | 0.000 |
| Vanilla ReAct | 0.333 | 0.667 | 0.667 | 0.000 |

范围语义修复后：

- RDS password reset：三种方法均为 3/3 `Unknown`；
- S3 ACL change：三种方法均为 3/3 `Unknown`；
- snapshot external share：三种方法均为 3/3 `Reachable`；
- snapshot invalid grantee：完整方法为 6/6 `NotReachable`，Vanilla 为
  1/3 `NotReachable`、2/3 `Unknown`。

完整方法相对 Vanilla 的独立组比较为 1 胜、0 负、2 平，
\(p=1.0\)。这说明方向有价值，但样本不足以形成显著性主张。

线性与 LangGraph 在 12 个同 case/seed 配对运行上：

- predicted-state mismatch = 0；
- semantic-score mismatch = 0；
- runner-decision mismatch = 0。

因此 LangGraph 是可替换的工程编排后端，不是准确率创新点。

## 三个候选创新点的证据矩阵

| 候选创新 | 与其他点的独立性 | 当前代码/数据证据 | 当前实验支撑 | 能否作为最终创新点 |
|---|---|---|---|---|
| C1 真实来源、provider-outcome 与 Unknown control 分离的跨云协议 | 数据与评测贡献 | v8 public/gold/split、8 个 source ID、0 生成事件 | 可复现构建、泄漏测试、16 组统计 | **可以，但需补真人 gold 才更强** |
| C2 范围感知的证据约束 EC-ReAct：渐进 Tool Use、Pareto 预算、provider scope gate | 搜索与决策方法 | `ec_react.py`、工具环境、范围规则、双后端 | 低预算相对 fixed/random 显著；真实 Qwen 复现并消除控制面误报 | **可以** |
| C3 CP-Cert 四值路径证书：结构、可见引用、可执行断言、最小证据覆盖 | 验证与解释方法 | `path_proposal.py`、`cp_cert.py`、证书审计测试 | 参考策略 mean edge F1=0.7；但本地 Qwen exact edge F1=0 | **方法成立，效果创新尚未充分支撑** |

最终论文建议保留 C1、C2 为主创新，C3 作为第三个候选创新或安全机制。只有当主实验能证明 C3 提升 exact edge F1、降低 unsupported-path false positive，才把它写成独立的效果创新。

## 当前阶段评分

以下评分只衡量“优秀研究型毕业设计所需证据”，不是学校正式评分：

| 维度 | 满分 | 当前 | 理由 |
|---|---:|---:|---|
| 数据真实性与可复现性 | 20 | 18 | 来源真实、hash/lineage 冻结，但规模与均衡性不足 |
| 方法工作量与完整性 | 20 | 18 | ReAct、Tool Use、Pareto、LangGraph、证书守卫均落地 |
| 实验设计严谨性 | 20 | 15 | 组级统计、精确检验、Holm、失败保留较好；样本仍小 |
| 创新点的独立证据 | 20 | 13 | C1/C2 较强，C3 的 LLM 路径效果尚弱 |
| 外部效度与论文可答辩性 | 20 | 10 | 真人 gold=0，跨云不均衡，主 LLM 试验仅 3 lineage |
| **合计** | **100** | **74** | **良好研究原型，尚未客观达到“优秀已完成”** |

## 达到“优秀”前必须完成的门槛

1. **真人 gold**：至少形成一个双人独立标注子集；报告原始一致率、
   Cohen's \(\kappa\) 或 Krippendorff's \(\alpha\)、仲裁规则和分歧案例。
2. **扩大独立组**：目标至少 30–50 个独立 lineage，并减少 AWS/Splunk
   单源占比；新增数据仍必须来自公开原始遥测或可执行真实靶场。
3. **冻结主实验**：在停止方法调参后生成新的配置 hash、实现 bundle
   hash、模型 digest 和 schedule manifest；诊断试验不能冒充主试验。
4. **路径级指标过关**：不仅判三状态，还要在真人或独立 gold 上报告
   exact node/edge precision、recall、F1，以及 unsupported-path rate。
5. **至少一个强模型复核**：本地 7B 模型保留作为可复现基线，再增加一个
   能力更强、版本固定的模型；报告模型交互而不是只报总体均值。
6. **统计功效与置信区间**：以 lineage 为样本单位预先估算最小可检测差异，
   主要比较不把事件数、案例派生数或随机种子当作独立样本。

在上述门槛完成前，项目可以继续答辩准备，但论文中应使用“协议规模”“诊断性”“参考策略”等限定词，避免把工程正确性误写成总体有效性。
