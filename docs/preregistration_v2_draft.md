# EC-ReAct 主实验预注册 v2（冻结前草案）

状态：`DRAFT_NOT_FROZEN`  
日期：2026-07-29  
适用目标：Cloud DB PathBench Graduate Goal v2

本文件在数据人工标注、模型版本和最终配置尚未齐备时建立。它不是已经完成的预注册，也不是实验结果。冻结后将生成只读配置、数据/代码哈希和变更记录；冻结测试集不得用于调参。

## 1. 研究问题与可证伪主张

在相同模型、工具集合、工具结果、最大步数和查询预算下，EC-ReAct 是否比 vanilla ReAct 更准确地恢复人工确认的细粒度云数据攻击/暴露路径？

### 确认性主假设 H1

分析单位为独立攻击/配置谱系 \(g\)。在预算 \(B=20\) 下，定义：

\[
D_g =
F^{cert-edge@5}_{1,g}(\text{EC-ReAct})
-
F^{cert-edge@5}_{1,g}(\text{Vanilla ReAct}).
\]

- 零假设：EC-ReAct 与 vanilla ReAct 的谱系级配对差分布关于 0 对称；
- 备择假设：两者存在差异，且预期方向为 EC-ReAct 更高；
- 检验：双侧 group-level 配对 sign-flip 随机化检验，\(\alpha=0.05\)；
- 区间：对独立谱系做 cluster bootstrap，报告均值差的 95% CI；
- 效应量：报告配对标准化效应 \(d_z\) 及未标准化百分点差；
- 确认成功必须同时满足：
  1. 双侧 \(p<0.05\)；
  2. 平均 fine-grained exact edge F1 提升至少 0.10；
  3. EC-ReAct 测试集平均 fine-grained exact edge F1 不低于 0.60；
  4. unsafe false-Reachable 不高于 vanilla ReAct。

任何一个条件未满足，论文不得写成“主假设得到完整支持”。

### 关键次要假设 H2：效率

在预算 \(B\in\{10,20,30\}\) 下比较 accuracy-cost Pareto 曲线。只有当：

- edge F1 相对 full-query 的差不低于预设非劣界 \(-0.05\)；且
- 平均标准化查询成本至少降低 20%，其 cluster-bootstrap 95% CI 支持正向节省，

才声称“在准确性基本不下降的情况下提高效率”。

非劣检验及成本检验的具体统计实现必须在冻结前写入分析器测试，不能观察测试结果后选择。

### 关键次要假设 H3：安全与 Unknown

分别报告：

- unsafe false-Reachable rate；
- Unknown/abstention 的 precision、recall 与 coverage；
- unsupported-path rate；
- 有效证书但语义路径错误的比例。

零事件不解释为风险等于零；使用精确二项区间报告其 95% 上界。

### 条件性创新假设 H4：CP-Cert

比较 EC-ReAct 与 `ablate_evidence_cert`：

- edge precision；
- edge F1；
- unsupported-path rate；
- valid-path recall；
- abstention rate。

只有证书机制显著或实质性降低 unsupported-path rate，并且 edge F1 不劣于消融方法超过 0.05 时，CP-Cert 才作为独立第三创新点；否则只作为工程安全机制。

## 2. 数据与独立性

### 当前供给，不是 gold

截至本草案：

- 候选案例 150；
- 候选独立谱系 113；
- 上游场景来源 6；
- 具有运行时观测的案例 57、运行时实例 91；
- 运行时平台实例：AWS 42、Azure 25、GCP 24；
- human-finalized gold：0。

候选数量不得冒充正式样本量。

### 正式准入目标

- 至少 80 个通过准入且双人独立复核的独立谱系；
- 至少 67 个谱系保留给确认性配对评估；
- AWS、Azure、GCP 均有覆盖，任一平台不超过 60%；
- 至少 6 个独立上游来源，任一来源不超过 40%；
- 同一上游攻击技术、模板、日志变体和近重复资源拓扑不得跨 split；
- 原始材料必须有 URL/DOI/commit、许可证、SHA-256 和精确证据定位；
- AI/LLM 可辅助界面和一致性检查，但不得生成原始事件或充当人工标注者。

### 人工标注

- 两位标注人先独立盲标，再仲裁；
- 不向标注者展示 Agent 输出或方法名称；
- 至少报告原始一致率和 Cohen's kappa；多类别/缺失条件不适用时报告 Krippendorff's alpha；
- 不删除争议难例以提高一致性；
- 测试 gold 只允许评估器读取，Agent、提示词、动作排序和停止规则均不可见。

## 3. 划分与冻结

按 `independence_group` 和来源约束生成 split：

- development：仅用于 schema、提示词和工具契约调试；
- validation：仅用于冻结前阈值和方差估计；
- test：不少于 67 个独立谱系，用于 H1；
- external_test / leave-one-source-out：用于来源外推；
- external_negative_control：用于正确拒绝和错误 Reachable 风险；
- excluded：证据不足、许可不明、近重复或未通过双标的材料。

若总计 80 个接受谱系无法同时容纳 67 个 test 和足够的 development/validation，则继续扩充，而不是把测试集用于开发。

冻结包必须记录：

- source packet、gold、split、ontology、Sigma prior 的 SHA-256；
- Git commit；
- 依赖锁与操作系统；
- 模型 ID、服务版本或本地模型 digest、量化方式；
- system prompt、tool schema、预算、种子和 schedule manifest；
- 预注册文档哈希。

## 4. 方法、基线与公平性

确认性方法：

- `ec_react_full`
- `vanilla_react`

次要基线：

- `fixed_order`
- `random_tool`
- `full_query`

消融：

- `ablate_pareto`
- `ablate_provider_scope_gate`（已进入 v2 草案方法矩阵，冻结前须保持仅改变该组件）
- `ablate_external_rule_prior`
- `ablate_four_value_memory`
- `ablate_budget_stop`
- `ablate_evidence_cert`

所有 LLM 方法共享：

- 同一模型版本、温度和重复种子；
- 同一可见事件、工具 schema 和工具原始结果；
- 同一最大步数、路径候选数和查询预算；
- 同一输出 ontology。

LangGraph 是主工程编排后端；线性后端只用于一致性复核，不作为准确率创新点。

模型层级：

- 本地 Qwen2.5-7B：可复现资源基线；
- 一个冻结版本的更强模型：用于检验方法结论是否依赖弱模型。

不同模型分别报告结果和交互效应，不把更强模型带来的收益计入 EC-ReAct 方法贡献。

## 5. 指标与多重比较

唯一确认性主指标：

- `certified_fine_edge_f1_at_5` at \(B=20\)，先在实例内汇总重复，再在独立谱系内汇总。

该指标把所有通过 CP-Cert 的 Top-5 路径转换为
`(source canonical node type, canonical edge type, target canonical node type)`
多重集，再与所有 Valid gold 路径的对应多重集计算 micro precision、recall 和 F1。额外候选会进入 precision 分母，ontology 非法边作为未匹配预测计入，不能通过大量猜测提高召回而不付代价。无 Valid gold 的负例返回 `null`，不能通过空集匹配抬高路径 F1。

scorer 与统计分析器已经实现并测试 fine-grained
`certified_fine_edge_precision_at_5`、`certified_fine_edge_recall_at_5`
和 `certified_fine_edge_f1_at_5`；当前 `ec_react_main_v1.yaml`
仍只把 coarse 指标列为次要指标，因此冻结前必须由 v2 配置显式采用上述唯一主指标。

次要指标族：

- exact path match、valid path recall@5；
- edge precision、edge recall；
- query cost、latency；
- correct rejection、correct abstention；
- hallucinated/unsupported path rate；
- ontology-invalid path rate；
- 分平台、分来源和 leave-one-source-out 结果。

除唯一主检验外，同一指标族内的推断性比较采用 Holm 校正。预算 10 和 30 不参与主假设，不能因其结果更好而替代预算 20。

## 6. 重复、失败与缺失

- LLM 条件每个实例运行 5 个冻结种子，用于估计稳定性；
- 先在实例内汇总重复，再在谱系内汇总；推断 N 始终是谱系数；
- 失败、超时、无合法 JSON、拒答和预算耗尽全部保留；
- 不进行“只重跑失败条件”的选择性补跑；
- 允许基础设施故障整批重跑，但必须保留原记录并给出事先定义的故障判据；
- 缺失处理规则在冻结前进入代码与测试。

## 7. 功效与样本量决策

`docs/power_analysis_v1.md` 给出不依赖虚假 pilot 方差的敏感性分析：

- 连续配对效应 \(d_z=0.45\) 时，约 39 个谱系达到 80% 功效；
- 较小效应 \(d_z=0.35\) 时，约需 65 个谱系；
- 若 50% 谱系产生非平局、非平局中 EC-ReAct 胜率为 75%，精确 sign test 约需 67 个总谱系；
- 因此 40 只是数据治理硬下限，操作目标采用至少 80 个接受谱系、至少 67 个确认性谱系。

冻结前只允许使用 development/validation 估计配对方差并最终确认 N。若实际可用 test 少于计划，保留原分析并将欠功效列为限制，不降低门槛或更换主指标。

## 8. 结论规则

- H1 全部门槛通过：允许写“EC-ReAct 在冻结基准上显著且实质性提高细粒度路径恢复”；
- 只有 p 值通过、效应不足 0.10：写“差异可检出但实际收益有限”；
- 只有效应通过、p 值未通过：写“观察到有意义趋势但证据不足”；
- edge F1 低于 0.60：不得宣称已可靠恢复完整攻击路径；
- unsafe false-Reachable 增加：即使平均 F1 提升，也不得给出总体方法成功结论；
- 跨来源异质性显著：结论限定到成立的平台或来源；
- H4 未通过：论文保留两个主创新点，将 CP-Cert 降级为安全机制。

## 9. 冻结前阻断项

1. human gold、negative-control gold 和仲裁结果仍为 0；
2. `configs/ec_react_main_v2_draft.yaml` 已加入 scope-gate 单组件消融和唯一 fine-edge-F1 主指标，但仍是草案，不能作为冻结配置；
3. 更强模型的确切版本尚未冻结；
4. 80 个接受谱系及 67 个确认性谱系尚未形成；
5. 非劣界、成本 CI、unsafe 不增门槛与零事件精确上界已进入自动统计代码，但尚待冻结数据上的正式运行；
6. 配置、gold、split、代码和 schedule 的最终哈希尚未冻结。

阻断项全部关闭前，任何运行只能标记为 pilot、diagnostic 或 engineering validation，不得进入论文主结果表。
