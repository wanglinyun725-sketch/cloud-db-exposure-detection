# Cloud DB PathBench 阶段性客观复评（v3，2026-07-28）

## 结论

项目目前已从“协议和工程可运行”推进到“真实 LLM 方法在小型三状态
source-held-out pilot 上可重复运行”。客观成熟度由上一版 **8.1/10**
调整为 **8.4/10**。

它现在是一个有明显研究价值、具备优秀毕设潜力的项目，但仍不能客观宣布为
“已经达到优秀研究生毕业设计”。提升的 0.3 分来自真实模型、公平基线、固定
seeds、实现哈希、动态证据约束和 18-run 清洁试验；没有更高，是因为独立样本和
真人 gold 两个核心证据缺口仍未解决。

## 本轮新增的硬事实

| 项目 | 当前事实 | 解释 |
|---|---:|---|
| provider-oracle v7 案例 | 21 | 16 provider gold + 5 epistemic controls |
| 原始观测 | 33 | 来自固定上游版本，不是 AI/脚本生成样本 |
| 独立组 | 13 | 5 Reachable / 4 NotReachable / 4 Unknown |
| 确定性协议运行 | 504 | 重复不增加独立样本量 |
| 本地 LLM 清洁 pilot | 18 runs | 3 独立组 × 2 方法 × 3 seeds |
| full run-level 正确 | 9/9 | 三状态各 3/3 |
| Vanilla run-level 正确 | 6/9 | KMS NotReachable 为 0/3 |
| human finalized gold | 0 | 仍是最主要短板 |
| 全量测试 | 244 passed | 当前实现回归通过 |

确定性 v7 在预算 4 下：

- provider-aware CP-Cert：9 个 provider 独立组准确率 1.000，
  Wilson 95% CI `[0.701, 1.000]`；
- 4 个负例组正确拒绝率 1.000，CI `[0.510, 1.000]`；
- 4 个 Unknown 组拒答率 1.000，CI `[0.510, 1.000]`；
- 查询成本 2.0，provider edge F1 0.667。

这是透明参考策略，不是 LLM 效果。它证明协议和评分器自洽。

本地 Qwen2.5-7B 清洁 pilot：

- EC-ReAct：provider 独立组准确率 1.000，CI `[0.342, 1.000]`；
- Vanilla：0.500，CI `[0.095, 0.905]`；
- full 正确拒绝率 1.000，Vanilla 0；
- 两者 Unknown 拒答率均为 1.000，false-Reachable 均为 0；
- full 平均耗时 33.91 秒，Vanilla 30.17 秒。

只有 2 个 provider 独立组、1 个负例组；精确 McNemar \(p=1.0\)，不能声称
统计显著。

## 三个创新点的当前成立程度

### 创新点 1：真实来源、三状态、来源级独立统计的 Provider-Oracle PathBench

**成立程度：较强。**

数据来自固定 commit/版本的 Splunk Attack Data、Stratus Red Team、
AzureGoat、GCPGoat 等真实公开制品，保留 URL、原始记录索引、内容哈希和
public/gold 隔离。Reachable、NotReachable 与 Unknown 不再由“配置看起来危险”
直接推断，而由运行时 allow/deny 与控制证据定义。

短板是规模：13 个独立组仍是 pilot，跨云负例不足。

### 创新点 2：Evidence-Constrained ReAct 的动态可执行证据解码

**成立程度：中等，已有真实模型重复结果。**

Agent 仍通过 ReAct 和 Tool Use 自主选择探查步骤并构造路径；方法将工具返回的
provider polarity、observation/call 可见性和真实字段值编译成下一步 JSON
schema。它防止“引用对了 observation ID，却把另一个事件的值写进测试”。

KMS 诊断中，full 三个 seeds 均生成带反证证书的 NotReachable；公平 Vanilla
三个 seeds 均退为 Unknown。当前证据只覆盖一个独立负例组，不能外推。

### 创新点 3：四值路径语义与 CP-Cert 正/负最小证书

**成立程度：较强的方法实现，外部语义验证仍不足。**

正证书是加权 set cover，负证书是加权 hitting set；Unknown/Conflict 不被
强行折叠。证书检查图结构、citation visibility、executable tests、原始
raw refs、充分性、不可约性与成本一致性。

CP-Cert 证明“候选与可见证据在协议内一致”，不能替代真人对攻击语义的判断。

### 不应单列为已证明创新的部分

Pareto 动作前沿和四值记忆已经实现，但 v5 的 3-group 消融没有提供稳定的独立
收益证据；其中 w/o four-value memory 甚至在单个 KMS run 上成功而 full 失败。
因此它们目前只能作为待验证组件，不能写成“实验已证明的创新点”。

## 分项评分

| 维度 | 分数 / 10 | 客观依据 |
|---|---:|---|
| 数据真实性与可追溯性 | 9.0 | 固定上游版本、记录级 raw refs、哈希、无生成样本 |
| 方法工作量与完整性 | 8.8 | ReAct、工具环境、动态 schema、四值语义、CP-Cert |
| 实验设计与公平性 | 8.2 | public/gold 隔离、公平预算、固定 seeds、实现 bundle；样本仍小 |
| 创新性 | 8.5 | 三态真实基准、证据约束 Agent、正负证书三条线相互独立 |
| 工程与复现性 | 9.1 | resumable JSONL、配置/模型/代码哈希、244 tests、服务可运行 |
| 论文证据完备性 | 6.9 | human gold 0、正式主测试与跨模型结果尚缺 |
| 综合成熟度 | **8.4** | 有优秀潜力，尚未达到可无保留答辩的优秀档 |

## 尚未通过的优秀档硬门槛

| 门槛 | 状态 |
|---|---|
| 至少 10 Reachable / 10 NotReachable / 10 Unknown 独立组 | 未通过：5 / 4 / 4 |
| 双人独立标注、分歧裁决、一致性报告 | 未通过：finalized human gold = 0 |
| 足量 source-held-out 主测试 | 未通过：pilot held-out 仅 7 组 |
| LLM 主实验覆盖多个模型和足够独立组 | 未通过：当前 7B pilot 只覆盖 3 组 |
| Pareto、四值记忆等组件的可靠消融 | 未通过 |
| 冻结论文表格、统计检验和发布包 | 部分通过 |

## 最终判断

如果现在答辩，项目可被评价为“选题和工程较强、方法有实质内容、实验诚实，
但样本规模与人工语义验证不足”，更接近良好到优秀边缘，而不是稳妥优秀。

下一阶段不应继续调单个 KMS 提示词，而应优先：

1. 完成双人 gold；
2. 把 5/4/4 扩展到至少 10/10/10 独立组；
3. 冻结 source-held-out 主测试；
4. 在相同实现 bundle 下跑两个模型、完整基线和消融；
5. 再做独立组级置信区间、McNemar/置换检验和误差分析。

完成这些门槛后，项目才有充分证据进入稳定的优秀档。
