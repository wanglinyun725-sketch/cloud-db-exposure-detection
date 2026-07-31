# 论文 v2 主张—证据矩阵

| 主张 | 权威证据 | 当前状态 | 最终允许措辞 |
|---|---|---|---|
| 候选库存覆盖三云、9 来源、40 个保守谱系 | `output/research_design/executable_lineage_inventory_v1.json` | 支持 | “候选库存达到数据治理数量门槛” |
| 已形成 30 个谱系人工 gold | confirmatory reviewed gold + freeze readiness | **不支持：0** | 不得声称 |
| 负对照足以评估错误 Reachable | negative reviewed release | **不支持：0** | 只能写“协议已建立” |
| EC-ReAct 组件已实现 | `src/agent/ec_react.py`、配置与测试 | 支持工程主张 | “实现并通过工程验证” |
| LangGraph 是创新点 | 无 | 否定 | 只写“编排后端” |
| EC-ReAct 优于 vanilla ReAct | frozen analysis + decision | **缺失** | 实验完成前不得声称 |
| exact edge F1 ≥ 0.60 | frozen analysis + decision | **缺失** | 实验完成前不得声称 |
| 查询效率优于 full-query | efficiency gate | **缺失** | 实验完成前不得声称 |
| 错误 Reachable 不增加 | external negative safety gate | **缺失** | 实验完成前不得声称 |
| CP-Cert 算法实现正确 | oracle、不可约性和审计测试 | 支持工程主张 | “算法与实现已验证” |
| CP-Cert 是独立第三创新 | `ablate_evidence_cert` 冻结结果 | **缺失** | 当前称“条件性创新” |
| 论文与结果可复现 | artifact chain + reproduction bundle | 部分支持 | 主实验后需干净环境复跑 |
| 最终达到 Goal v2 | `goal_acceptance_v2.json` 八门禁 | **3/8** | 不得声称完成 |

## 明确撤回的旧表述

以下旧稿数字没有当前合格仓库证据，不进入 v2：

- “500–800 个参数化合成样本”；
- “Mitigation Validity 93.5%”；
- “幻觉率从 18.4% 降至 5.3%”；
- “端到端耗时下降一个数量级”；
- “GV-FA/SFT+DPO 已完成并构成创新点”；
- smoke policy 的 candidate-found 比例作为准确率；
- 把多个 episode 或重复运行当作独立样本。

最终写作工具或人工编辑不得重新引入这些主张，除非新增权威实验文件并更新本表。
