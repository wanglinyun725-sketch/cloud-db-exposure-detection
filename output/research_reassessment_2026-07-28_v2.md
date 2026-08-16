# Cloud DB PathBench 阶段性客观复评（v7，2026-07-28）

## 结论

项目目前可以客观定位为“研究问题明确、工程和协议较扎实、具备冲击优秀的条件”，但还不能作为已经完成的优秀研究生毕业设计。暂定成熟度为 **8.1/10**。这个分数是项目成熟度判断，不是实验指标。

和 v4 相比，v7 的实质进步是：真实 provider-oracle 案例从 12 增至 21，观测从 20 增至 33，独立组从 10 增至 13；NotReachable 独立组从 1 增至 4。新增证据来自固定 Git commit 下的两个独立 CloudTrail 数据目录，并保留记录索引、上游 URL 和 SHA256，没有生成样本或生成标签。

仍不能评为优秀的三个直接原因是：

1. `finalized human gold = 0`，双人语义准入包虽已准备好，但尚未完成人工独立标注与分歧裁决；
2. 13 个独立组仍是小型 pilot，尤其只有 4 个 NotReachable 独立组，Wilson 区间很宽；
3. 已冻结来源完全隔离的 pilot split，但 held-out 只有 7 个独立组；真实 LLM 的 EC-ReAct、vanilla ReAct 和消融实验也尚未形成合格的冻结主结果。

## v7 数据与实验事实

| 项目 | v6 事实 | 正确解读 |
|---|---:|---|
| 案例 / 观测 | 21 / 33 | 规模仍小，但所有进入协议的证据可回溯 |
| 状态案例 | 6 Reachable / 10 NotReachable / 5 Unknown | 案例数较均衡，但独立组仍不均衡 |
| 独立组 | 5 Reachable / 4 NotReachable / 4 Unknown | 同一 discovery sweep 的五条拒绝只计一个上游独立组 |
| provider gold | 16 案例、9 独立组 | Unknown 是认知控制，不伪装成 provider gold |
| 全部运行 | 504 case-runs | 重复运行不是额外独立样本 |
| human gold | 0 | 不能声称已完成人类金标准 |

预算为 4 时，透明 `provider_aware_cp_cert` 参考策略在 9 个 provider 独立组上的状态准确率为 1.000，Wilson 95% CI 为 `[0.701, 1.000]`；4 个拒绝组的正确拒绝率为 1.000，CI 为 `[0.510, 1.000]`；4 个 Unknown 组的拒答率为 1.000，CI 为 `[0.510, 1.000]`；平均查询成本为 2，路径 edge F1 为 0.667。

这些数字只证明协议、工具接口、极性逻辑和评分器能够一致工作。它不是 LLM Agent 的效果结果，因为该参考策略显式编码了 provider 语义。

同预算下，`fixed_order`、`full_query` 和 `random_tool` 的独立组状态准确率均为 0.556，CI 为 `[0.267, 0.811]`；正确拒绝率和 Unknown 拒答率均为 0，false-Reachable 为 0.615。该结果显示仅查到成功事件会系统性地把拒绝和证据不足误判为可达，也说明总准确率在类别不均衡下会掩盖严重错误。

## 三个创新点的当前成立程度

### 1. ConfigTruth / Provider-Oracle PathBench

**已形成可审计的小型原型，尚未形成足量 benchmark。**

已具备真实来源、固定版本与哈希、public/gold 隔离、Reachable/NotReachable/Unknown 三态、保守 lineage 去重、原始记录定位和双人语义准入入口。当前瓶颈是独立组数量和真人 gold。

### 2. EC-ReAct 渐进式证据发现

**方法和执行框架已实现，真实 LLM 效果尚待实验确认。**

方法由 ReAct、工具调用、Pareto 动作约束、四值证据记忆、预算停止和 finish guard 组成。研究价值不在于使用某个编排库，而在于验证这些约束能否在相同查询预算下提高路径完整度、正确拒绝率和 Unknown 校准，并降低查询成本。

### 3. CP-Cert 冲突保留的正/负最小证书

**目前最成熟的独立创新点。**

正证书采用加权 set cover，负证书采用加权 hitting set，Unknown/Conflict 不被强行折叠。v7 已覆盖真实成功、明确 provider denial、配置 Unknown，并按独立组统计；仍需要更多独立负例和正式消融来证明普适收益。

## 优秀毕业设计的剩余硬门槛

| 硬门槛 | 当前状态 |
|---|---|
| 至少 30 个经审计且较均衡的独立 gold 组 | 未通过：13 组 |
| 至少 10 Reachable / 10 NotReachable / 10 Unknown 或 Conflict | 未通过：5 / 4 / 4 |
| 双人独立语义标注、分歧裁决和一致性报告 | 未通过：finalized human gold 为 0 |
| 冻结的 source-held-out 测试 | pilot 已通过来源隔离；正式主测试未通过：held-out 仅 7 组 |
| 真实 LLM EC-ReAct 相对 vanilla / full-query 的稳定收益 | 未证明 |
| Pareto、四值记忆、规则先验、budget stop 的独立贡献 | 未证明 |
| 代码、来源、哈希、配置、统计脚本可复现 | 基本通过，仍需最终发布清单 |

## 当前研究边界

- `AccessDenied` 只证明特定主体、特定操作、特定资源范围在该次请求中被拒绝，不能外推为整个账户或对象“绝对安全”。
- `ListBuckets`、`ListSecrets`、`ListDomainNames` 只建模 catalogue enumeration，不能声称已经读取了桶对象、Secret 内容或数据库记录。
- 同一上游实验、同一攻击 lineage 和重复随机种子必须聚合为一个统计单元。
- 在冻结 human gold、source-held-out split 和模型配置前，任何本地 LLM 运行都只能称为 execution/behavior pilot。

因此，下一阶段的判定标准不是“再堆几个漂亮数字”，而是依次补齐真人 gold、独立负例、冻结测试和真实 LLM 对照/消融。完成这些硬门槛后，项目才有充分依据从 8.1/10 提升到优秀档。
