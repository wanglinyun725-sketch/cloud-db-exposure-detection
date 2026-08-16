# Cloud DB PathBench 阶段性客观复评（2026-07-27）

## 结论

项目现在已经从“有 Agent 外形但证据链较虚”推进到“存在真实来源、确定性状态语义、正负证书和可运行 pilot”的研究原型。它的研究问题、工程实现和方法结构已经具备较强的硕士毕设潜力。

但按“优秀研究生毕业设计”的严格标准，当前仍不能客观认定为优秀。最大短板仍是主效果实验没有独立、足量的 gold：真人 finalized gold 仍为 0；新增 provider-native runtime gold 为 5 个案例（保守聚类后为 4 个 gold independence group），另有 1 个 Unknown 协议控制。它们解决了方法能否处理真实成功、明确拒绝和证据不足的问题，却不足以证明 Agent 的泛化效果。

当前建议评价：**7.5/10，良好偏上、具备冲击优秀的清晰路径，但优秀硬门槛未通过。**

## 本轮新增的确定性事实

| 维度 | 本轮结果 | 客观含义 |
|---|---|---|
| 真实来源 | 新接入并固定 AWSGoat、AzureGoat、GCPGoat、IAM Vulnerable、TerraGoat 等公开制品 | 数据候选不再依赖 AI 或脚本生成攻击样本 |
| 配置验证 | 4/4 Terraform 模块通过离线语义验证；2/4 通过格式检查 | 证明配置可解析，不等于证明暴露路径成立 |
| 明确负路径 | GCP scheduled-transfer 的 10 次独立运行均出现同一关键权限拒绝，共 44 次 code-7 拒绝 | 重试属于一个 lineage case，不能计作 10 个独立 gold |
| provider gold | 4 个 Reachable、1 个 GCP NotReachable | 可用于协议验证；类别仍不平衡且样本量很小 |
| provider success 候选池 | 58 个场景—操作组、28 个保守 lineage group，其中 30 组含非 Root 主体 | 是下一轮审计队列，不是 58 个 gold |
| Unknown 控制 | 1 个 AWSGoat 配置存在但 analyzer/probe 未运行的案例 | 验证系统不会把“没查到”当“明确安全” |
| 方法 | CP-Cert 已同时支持最小正证书与最小负证书 | 修复了旧方法只能证明正路径的核心缺口 |
| 实验 | v3 运行 144 次、5 个保守聚类独立组、0 gold 泄漏；全部明确标记为非主效果结果 | 可复现的工程与协议证据，不是总体准确率 |

## 三个创新点的当前成立程度

### 创新点 1：ConfigTruth / Provider-Oracle PathBench

当前状态：**已有可运行 pilot，尚未形成足量 benchmark。**

独立价值在于将配置语义、provider-native analyzer 和授权 runtime probe 分层，禁止用 walkthrough、缺失 finding 或凭证获取替代真实数据访问结论。公开证据与 evaluator gold 分离，能够构造 Reachable、NotReachable、Unknown 三类状态。

要成为论文创新点，还需扩展到至少 30 个独立路径组，并进行分层人工语义审计和 source-held-out 测试。

### 创新点 2：EC-ReAct 渐进证据发现

当前状态：**代码与编排框架完整，尚无合格主效果结果。**

Agent 已具备 ReAct、Tool Use、硬预算、Pareto 动作约束、外部规则先验、四值记忆和线性/LangGraph 双后端。LangGraph 是工程选择，不单独算创新；创新应表述为“预算约束下的渐进证据分辨策略”。

要成为论文创新点，必须在冻结 gold 上证明相对于 vanilla ReAct、full-query、fixed-order 和随机工具策略的准确率—成本优势，并通过消融证明 Pareto、外部先验、四值记忆和 budget stop 的独立贡献。

### 创新点 3：CP-Cert 冲突保留的正/负最小证书

当前状态：**方法闭环已明显增强，已有真实 provider 证据的功能验证。**

它不再把明确拒绝降格为“没有正证书”，而是通过加权 hitting set 给出负证书；同时保留 Unknown 和 Conflict。该点已经有公式、代码、原始引用、自动测试和 pilot 结果，是目前最接近成立的独立创新点。

要成为强创新点，还需在足量 gold 上比较：无证书、仅正证书、正负证书、无冲突保留四种版本的错误可达率、拒答能力、证书大小与查询成本。

## v3 结果应该如何解释

透明 provider-aware 参考策略在五个 provider gold 上状态准确率为 1.00，对明确阻断的识别率为 1.00，对 Unknown 控制的正确拒答率为 1.00，平均查询成本为 2。

这个 100% 不能写成模型准确率，原因有三：

1. 只有五个 provider gold，且 4:1 偏向 Reachable；
2. 透明策略直接依据 provider 结果的确定性语义，是协议参考实现；
3. 完整路径 edge F1 均值仅 0.667，说明它只找到了决定状态的关键边，没有完整重建两步路径。

相反，fixed-order、full-query 和 random-tool 在预算 4/8 时 provider gold 状态准确率为 0.80，但明确阻断识别率仍为 0，并把全部 6 个样本中的 2 个（NotReachable 与 Unknown）错误报告为可达。较高的 0.80 主要来自 4:1 的类别不平衡，不能掩盖其拒绝语义和 Unknown 处理失败。

## 优秀硬门槛

| 硬门槛 | 当前 |
|---|---|
| 至少 30 个独立、可审计的 provider/human gold 路径组 | 未通过（当前 5 个 provider gold 案例、保守聚类后 4 组） |
| 至少 10 个 Reachable、10 个 NotReachable、10 个 Unknown/Conflict | 未通过 |
| 真人完成语义准入和争议审计 | 未通过 |
| 冻结 source-held-out 测试集 | 未通过 |
| EC-ReAct 对强基线具有稳定优势 | 未证明 |
| 关键组件消融具有独立贡献 | 未证明 |
| 全套代码、来源哈希、实验配置与测试可复现 | 基本通过 |

## 接下来最值钱的工作

不是继续美化 PPT，也不是增加更多同源重试，而是按以下优先级推进：

1. 从已固定的 Goat/Terraform 来源中批量构造候选，但只把 provider-native 完整 allow/deny 或授权 probe 结果升级为 gold。
2. 优先形成平衡的 30 组小而硬 benchmark，而不是追求 100+ 个语义不清案例。
3. 将人工工作压缩为“准入与语义审计”，不要求人工重新判断云厂商已经明确给出的 allow/deny。
4. 冻结划分后再跑 LLM Agent 主实验；当前本地 14B 模型冷启动超时，不应拿未完成输出填结果。
5. 最终论文只保留得到真实数据和实验支撑的三个创新点，不把 LangGraph、SFT/DPO 接口或未运行模块写成贡献。
