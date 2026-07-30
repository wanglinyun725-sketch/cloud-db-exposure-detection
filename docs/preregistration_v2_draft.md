# EC-ReAct 主实验预注册 v2（冻结前草案）

状态：`DRAFT_BLOCKED_ON_HUMAN_GOLD_AND_OPENAI_ACCESS`

日期：2026-07-30

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

截至本草案，`executable_lineage_inventory_v1.json` 给出 42 个原始可执行组；
扣除审计发现的 2 个碰撞组后，保守计数为 40 个独立组，覆盖 AWS、Azure、
GCP 和 9 个直接来源。当前确认性盲标包
`runtime_confirmatory_30_unlabeled.json` 包含：

- 52 个候选案例；
- 恰好 30 个完整、互不跨组的 `independence_group`；
- 79 个运行时实例和 2,548 条原始观测；
- 4 个运行时证据来源，AWS、Azure、GCP 均有覆盖；
- human-finalized gold：0。

候选数量不得冒充正式样本量。

### 正式准入目标

- 30 个确认性谱系的全部 52 个案例均须完成两位不同真人的独立盲标和仲裁；
- 冻结实验最低需要 30 个准入案例、20 个准入独立谱系，其中至少
  30 个案例具有非空运行时证据；
- test 至少包含 15 个运行时准入案例；此门槛只保证主实验可执行，
  不等于对中小效应有充分统计功效；
- 外部负对照至少 20 个，并完成独立双标和仲裁；
- AWS、Azure、GCP 均有覆盖，任一平台不超过 60%；
- 完整基准库存至少 6 个独立上游来源（当前保守库存为 9）；
- 冻结运行时确认实验当前只覆盖 4 个证据来源，任一来源不超过 40%；
  因此跨来源推断只能限定到这 4 个来源，不能写成“已验证 9 来源泛化”；
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
- test：至少 15 个运行时准入案例，按完整 `independence_group` 划分，用于 H1；
- external_test / leave-one-source-out：用于来源外推；
- external_negative_control：用于正确拒绝和错误 Reachable 风险；
- excluded：证据不足、许可不明、近重复或未通过双标的材料。

30 个谱系是本轮人工标注和最小可执行主实验的承诺，不是充分功效的替代物。
如果仲裁后不足 20 个准入独立谱系、30 个运行时准入案例或 15 个冻结 test
案例，则继续补充和双标，而不是把测试集用于开发或降低门槛。

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

- 本地 Qwen2.5-7B：Ollama `qwen2.5:7b`，冻结运行时 digest
  `845dbda0ea48ed749caafd9e6037047aa19acfcfd82e704d7ca97d631a0b697e`，
  使用原生 chat 接口、`think=false`、`num_ctx=4096`、`num_predict=512`；
- 更强模型：OpenAI `gpt-5.4-2026-03-05` 日期快照，`reasoning_effort=medium`。
  选择日期快照而非随时间移动的别名，以便复现；确切快照来自
  [OpenAI GPT-5.4 官方模型页](https://developers.openai.com/api/docs/models/gpt-5.4)。

不同模型分别报告结果和交互效应，不把更强模型带来的收益计入 EC-ReAct 方法贡献。

### 预注册实验臂与成本约束

不运行“方法 × 模型 × 预算”的无差别笛卡尔积。冻结调度由配置中的
`schedule_arms` 显式列出，禁止运行后增删实验臂：

| 实验臂 | 方法 | 模型 | 预算 | 重复 |
|---|---|---|---:|---:|
| 确认性主比较 | EC-ReAct、vanilla ReAct | Qwen、GPT-5.4 snapshot | 20 | 5 |
| 组件消融 | 6 个单组件消融 | Qwen | 20 | 5 |
| 预算敏感性 | EC-ReAct、vanilla ReAct | Qwen | 10、30 | 5 |
| 随机基线 | random-tool | 非 LLM | 20 | 5 |
| 确定性基线 | fixed-order、full-query | 非 LLM | 20 | 1 |

每个运行时实例共 77 个冻结条件；以最低 30 个正例运行时实例和 20 个
负对照实例估算为 3,850 次 Agent 运行，而旧笛卡尔积会产生 13,050 次。
强模型只用于预算 20 的 EC-ReAct/vanilla 主比较，既保留跨模型验证，也避免
把消融和预算探索的 API 成本伪装成科研工作量。最终 gold 形成后，按实际
运行时实例数生成完整 schedule，写入 manifest 并冻结哈希。

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
- 因此 40 只是数据治理硬下限，而当前 30 个双标谱系的最小主实验低于
  \(d_z=0.45\) 所需约 39 个谱系，也远低于小效应所需样本量。30 谱系结果
  必须同时报告置信区间、效应量和实际功效限制；不能仅凭 \(p<0.05\) 宣称
  证据充分，也不能把未显著结果包装为等效。

冻结前只允许使用 development/validation 估计配对方差并最终确认 N。若实际可用 test 少于计划，保留原分析并将欠功效列为限制，不降低门槛或更换主指标。

## 8. 结论规则

- 对每个冻结模型，必须同时满足：EC-ReAct 的绝对
  `certified_fine_edge_f1_at_5 >= 0.60`；相对 vanilla ReAct 的平均增益
  `>= 0.10` **或** Holm 校正后 `p < 0.05`；external negative control 上
  unsafe false-Reachable 不增加；
- 两个模型都通过时，机器决策器才允许总体主张；任一模型缺失时记为
  `insufficient_evidence`，任一门槛失败时记为 `fail`；
- 只有 p 值通过、效应不足 0.10：只写“差异可检出但实际收益有限”，
  不写“实质性提高”；
- 只有效应通过、p 值未通过：可写“达到预注册的实质增益阈值”，但必须同时
  写明统计不确定性，不能写“显著提高”；
- edge F1 低于 0.60：不得宣称已可靠恢复完整攻击路径；
- unsafe false-Reachable 增加：即使平均 F1 提升，也不得给出总体方法成功结论；
- 跨来源异质性显著：结论限定到成立的平台或来源；
- H4 未通过：论文保留两个主创新点，将 CP-Cert 降级为安全机制。

## 9. 冻结前阻断项

1. 30 个确认性谱系的 primary/reviewer human gold、仲裁结果仍为 0；
2. external negative-control 的双人筛选和仲裁仍为 0；
3. `runtime_confirmatory_30_reviewed.json` 与冻结 split manifest 尚未形成；
4. 本地 Qwen digest 已由运行中 Ollama 实例核验，但
   `gpt-5.4-2026-03-05` 所需 `OPENAI_API_KEY` 当前不可用；
5. `configs/ec_react_main_v2_draft.yaml` 已加入 scope-gate 单组件消融、
   唯一 fine-edge-F1 主指标和精确模型版本，但仍是草案；
6. 非劣界、成本 CI、unsafe 不增门槛与零事件精确上界已进入自动统计代码，
   但尚待冻结数据上的正式运行；
7. 配置、gold、split、代码和 schedule 的最终哈希尚未冻结。

阻断项全部关闭前，任何运行只能标记为 pilot、diagnostic 或 engineering validation，不得进入论文主结果表。

## 10. 一键状态、计划与执行

统一入口按 fail-closed 顺序串联双人 gold 冻结、负对照冻结、主预检、调度、
运行、统计分析与结论决策：

```powershell
# 只审计当前阻断项，不调用模型
D:\anaconda\python.exe scripts/experiments/run_research_pipeline_v2.py

# 人工 gold 完成后冻结完整 schedule；不要求 API key、不调用模型
D:\anaconda\python.exe scripts/experiments/run_research_pipeline_v2.py --mode plan

# gold、split 与研究代码提交后，生成哈希绑定的只读协议
D:\anaconda\python.exe scripts/experiments/freeze_ec_react_protocol_v2.py

# 只有 freeze_status=FROZEN 且全部预检通过时才允许正式模型调用
D:\anaconda\python.exe scripts/experiments/run_research_pipeline_v2.py `
  --mode execute `
  --config configs/ec_react_main_v2_frozen.yaml
```

`status` 和 `plan` 均不会调用模型。`execute` 拒绝草案配置；即使运行结束，
最终论文主张仍由 `confirmatory_decision.json` 的机器门槛决定。
