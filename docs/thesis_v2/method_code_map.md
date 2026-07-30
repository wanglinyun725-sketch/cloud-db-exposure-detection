# 方法公式—代码—实验映射

| 论文对象 | 公式/约束 | 权威实现 | 直接测试或消融 |
|---|---|---|---|
| ReAct 状态循环 | \(a_t\sim\pi(O(s_t)), s_{t+1}=T(s_t,a_t,o_{t+1})\) | `ECReactRunner.run`，`src/agent/ec_react.py` | 线性/LangGraph 协议一致性 |
| 可见动作集 | \(\mathcal A_t^{vis}\) 只由 ledger 生成 | `pareto_action_candidates`、`_visible_event_map` | hidden-label、case-scope、action-space audit |
| Pareto 支配 | 四维效用的偏序支配 | `_dominates` | `ablate_pareto` |
| 硬预算 | \(\widehat c(a)\le b_t\)，实际成本扣减 | `ECReactRunner._guard_action`、工具环境 budget | `ablate_budget_stop`、B=10/20/30 |
| 四值融合 | \((s,r)\sqcup(s',r')\) | `FourValue.join`、`fuse_claims`，`src/verification/cp_cert.py` | `ablate_four_value_memory` |
| 路径保守判定 | Valid/Conflict/Invalid/Insufficient | `verify_path_claims` | 四态单元测试、人工 gold |
| 作用域决定性 | complete scope + exact-time | `_provider_scope_is_decisive`，`src/agent/ec_react.py` | `ablate_provider_scope_gate` |
| 引用约束 | 引用集合必须是可见 observation 子集 | `_finish`、结构化路径提交验证 | `ablate_evidence_cert` |
| 正证书 | 加权 set cover | `build_positive_certificate`、`_exact_weighted_cover` | exact oracle、充分性、不可约性 |
| 否定证书 | 加权 hitting-set | `build_negative_certificate` | Unknown 禁止否定、共享反证测试 |
| 证书审计 | 覆盖、成本、raw ref、删除检验 | `verify_certificate`、`_remove_redundancy` | 独立证书审计 |
| 显式实验调度 | 77 条件/运行实例 | `build_run_schedule`、`schedule_design_errors` | 调度重复与预算验证 |
| 聚类统计 | 先 repeat、再 instance、再 lineage | `_collapse_repeats_then_groups`，`src/experiments/statistics.py` | cluster bootstrap、sign-flip、Holm |
| 主张门禁 | absolute F1、relative gain/p、unsafe | `evaluate_confirmatory_decision` | `tests/test_confirmatory_decision.py` |
| 复现哈希链 | config→manifest→runs→analysis→decision | `src/experiments/artifact_chain_v2.py` | drift/incomplete schedule tests |

该表只映射方法定义与实现，不把“有代码”推断为“有效果”。效果证据只能来自冻结
分析和 `confirmatory_decision.json`。
