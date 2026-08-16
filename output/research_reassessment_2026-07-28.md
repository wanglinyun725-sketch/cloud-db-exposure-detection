# Cloud DB PathBench 阶段性客观复评（2026-07-28）

## 结论

项目已经从“方法框架可运行的小型原型”推进为“数据准入更严格、跨来源 provider-oracle pilot 更完整、统计口径更可信的研究原型”。当前最明显的进步不是把数字做大，而是主动纠正了两个会污染论文结论的问题：把 GCP `NotFound` 从成功证据中剔除，以及把 `-with-webapp` 背景变体从独立样本中合并。

按优秀研究生毕业设计的严格标准，当前仍不能客观认定为“优秀成品”。更合理的定位是：良好偏强、方法与工程基础扎实、已经具备冲击优秀的清晰路径。若必须量化，可暂评约 **7.8/10**；这个分数不是实验指标，只是项目成熟度判断。

## 本轮可核验进展

| 维度 | 新结果 | 客观含义 |
|---|---|---|
| 成功证据准入 | 从候选正证据中排除 514 条 GCP code 5/7 provider error | “不是权限拒绝”不再被错误等同于“成功” |
| 独立性 | 28 个 scenario variant 保守折叠为 17 个攻击家族 lineage | 修正重复计数，避免夸大有效样本量 |
| 路径候选 | 20 个路径候选组、14 个保守 lineage；10 个为 list→read 多操作链 | 候选更接近路径，而不只是单个 API 名称 |
| 人工审核入口 | 20 个 label-empty 双人复核任务已冻结并通过 blind workflow 测试 | 人只审核语义/准入，不重判 provider success/deny |
| v4 协议集 | 12 案例、10 独立组、7 类来源；7 个 runtime gold、5 个 Unknown 控制 | 来源和 Unknown 覆盖优于 v3，但负例仍严重不足 |
| 实验 | 288 个 case-run，主指标改为严格 independence-group 聚合 | 重复种子和同 lineage 案例不再伪装成独立样本 |
| 不确定性 | 所有关键二元指标增加 Wilson 95% CI | 小样本的宽不确定性被如实展示 |
| 测试 | 新增成功筛选、候选构建、v4 泄漏隔离、人工包和组统计测试 | 研究协议的关键约束有代码防回退 |

## v4 结果的正确解释

透明 provider-aware CP-Cert 参考策略在 6 个 provider-gold 独立组上的状态准确率为 1.000，95% CI 为 `[0.610, 1.000]`；对 4 个 Unknown 控制组的拒答率为 1.000，95% CI 为 `[0.510, 1.000]`；false-Reachable 为 0，但上界仍为 0.278。

这不是 LLM Agent 的效果结果。它是一个按 provider 语义硬编码的透明参考，用于证明三态协议、证据极性和评分器没有明显逻辑错误。

fixed-order、full-query 和 random-tool 在 provider gold 上的独立组准确率为 0.833，但它们对唯一负组的识别为 0、对 Unknown 的拒答也为 0，并在 10 个总体独立组中的 5 个组产生 false-Reachable。较高准确率主要来自正类占多数，不能说明它们具备可靠路径判断能力。

完整路径 edge F1 仍为 0.667，说明当前透明策略只是找到了决定状态的关键边，还没有解决 Agent 主动重建完整多步路径的问题。

## 三个创新点的当前强度

### 1. ConfigTruth / Provider-Oracle PathBench

状态：**小型跨来源 pilot 已成立，足量 benchmark 尚未成立。**

已有真实来源、哈希、许可、public/gold 分离、Reachable/NotReachable/Unknown 三态、保守 lineage 去重和人类语义审核入口。主要缺口是只有 6 个 provider-gold 独立组，其中 NotReachable 仅 1 组。

### 2. EC-ReAct 渐进证据发现

状态：**代码和实验契约已成立，LLM 主效果尚未成立。**

ReAct、Tool Use、预算、Pareto 动作约束、四值记忆和 LangGraph/linear 后端均已实现。真正要证明的不是“用了 LangGraph”，而是 Agent 是否能在相同证据预算下，比 vanilla ReAct 和全量查询更完整、更少误报地发现路径。当前尚无合格的 LLM 主实验结果。

### 3. CP-Cert 冲突保留的正/负最小证书

状态：**目前最强的创新点。**

正证书用加权 set cover，负证书用加权 hitting set，Unknown/Conflict 不被强行折叠。本轮又通过真实 success、明确 denial 和配置 Unknown 验证了状态接口，并把独立组统计接入实验。它仍需更多负组和消融才能成为强实证贡献。

## 优秀硬门槛

| 硬门槛 | 当前状态 |
|---|---|
| 至少 30 个可审计、平衡、独立的 gold 组 | 未通过：v4 总计 10 个独立组，provider gold 6 组 |
| 至少 10 Reachable / 10 NotReachable / 10 Unknown 或 Conflict | 未通过：负组只有 1 |
| 真人完成语义准入与争议审核 | 未通过：工作包已生成，finalized human gold 仍为 0 |
| source-held-out 冻结测试 | 未通过 |
| 真实 LLM EC-ReAct 对强基线稳定占优 | 未证明 |
| Pareto、四值记忆、规则先验、budget stop 独立贡献 | 未证明 |
| 代码、数据哈希、实验配置、统计口径可复现 | 基本通过，仍需最终发行清单 |

## 下一步优先级

1. 先完成 10 个 P1 多操作候选的双人审核，再处理 10 个直接读取边；
2. 继续搜集独立 provider-native 明确拒绝，目标不是更多重试，而是更多场景 lineage；
3. 达到至少 30 个平衡独立组后冻结 source-held-out；
4. 再运行真实 LLM 的 EC-ReAct、vanilla ReAct、full-query、fixed-order 和消融；
5. 最后才把合格结果写入论文和 PPT，不能把 v4 透明参考的 100% 写成 Agent 准确率。
