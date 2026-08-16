# Cloud DB PathBench 当前研究就绪度复评

## 结论

当前不能客观认定为优秀研究生毕业设计；研究设计与工程具有优秀潜力，但人工 gold、真实负对照和主实验效果证据尚未完成。

当前加权分为 **6.97/10**。该分数反映仓库当前已完成证据，不是对未来结果的预测；同时设置优秀硬门槛，因此不能靠工程分高来抵消主实验尚未完成。

## 已经成立的事实

- 真实来源候选 150 例，113 个独立组，6 个正向来源；
- 运行时案例 57 例、运行实例 91 个，平台分布 {'AWS': 42, 'AZURE': 25, 'GCP': 24}；
- 正式 pilot 为 23 例、35 个实例、14 个完整独立组、389 条观测；
- 方法矩阵包含 10 个方法，线性/LangGraph 后端不一致 0，策略隐藏标签泄漏 0；
- v0.5 的 91 个可执行真实运行实例已完成四来源共同工具契约审计：契约失败 0、后端不一致 0、策略泄漏 0；该结果仍不是效果实验；
- 在全部 91 个运行实例上，已完成 1911/1911 次无标签主条件干跑：执行失败 0、预算违规 0、线性/LangGraph 不一致 0；它只证明执行契约成立，未计算任何正确率或召回率；
- Pareto 动作空间在详情阶段平均裁剪 46.84%；这只是效率侧工程证据。

## 尚未成立的事实

- 人工 finalized gold：0；
- 人工 finalized 负对照：0；
- EC-ReAct 路径发现准确率/召回率优于基线：尚无合格主实验；
- 三项创新均已实现代码骨架，但目前没有一项完成真实人工 gold 上的独立效果闭环；
- Sigma 外部规则先验的唯一 operation 覆盖率仅 19.05%，必须保留独立消融，不能把零命中解释为良性。

## 优秀硬门槛

| 门槛 | 当前 |
|---|---:|
| pilot_human_release_and_gate | 未通过 |
| minimum_80_accepted_independence_groups | 未通过 |
| minimum_30_runtime_backed_accepted_cases | 未通过 |
| minimum_20_reviewed_external_negatives | 未通过 |
| frozen_group_safe_split | 未通过 |
| main_experiment_preflight_ready | 未通过 |
| all_source_runtime_contract_valid | 通过 |
| non_llm_main_execution_contract_valid | 通过 |
| human_gold_effectiveness_results_exist | 未通过 |

## 分项评分

| 维度 | 权重 | 当前分 | 依据 |
|---|---:|---:|---|
| research_problem_value | 10% | 8.5 | 云数据攻击/暴露路径的可验证主动发现具有明确研究价值 |
| engineering_reliability | 15% | 9.0 | 线性/LangGraph 双后端、硬预算、引用守卫和完整自动测试 |
| real_data_and_provenance | 20% | 7.0 | 真实固定来源丰富，但当前人工 gold 与负对照 release 均为 0 |
| method_contribution | 20% | 7.5 | 三项代码贡献已形成，但尚无主实验支持独立效果 |
| experiment_design | 15% | 8.0 | 盲法、预注册门槛、group-safe split、消融与统计协议已冻结 |
| completed_empirical_evidence | 15% | 1.5 | 当前只有工程审计；research_effectiveness_result 仍为 false |
| reproducibility | 5% | 9.0 | 来源哈希、配置、协议输出和 preflight 可机器复核 |

## 当前阻断项

- human annotation pilot release is missing: C:\Users\王凌云\Desktop\毕业设计\cloud_db_pathbench\cloud_db_pathbench\data\real_sources\annotation\reviewed\runtime_pilot_round2_reviewed.json
- human gold release is missing: C:\Users\王凌云\Desktop\毕业设计\cloud_db_pathbench\cloud_db_pathbench\data\real_sources\annotation\reviewed\expanded_full_pool_v0_5_reviewed.json
- human-screened negative-control release is missing: C:\Users\王凌云\Desktop\毕业设计\cloud_db_pathbench\cloud_db_pathbench\data\real_sources\annotation\reviewed\negative_control_round1_reviewed.json
- model openai_external has no frozen model name
- model openai_external is missing OPENAI_API_KEY
- model qwen_primary is missing DASHSCOPE_API_KEY
- split manifest is missing: C:\Users\王凌云\Desktop\毕业设计\cloud_db_pathbench\cloud_db_pathbench\data\real_sources\annotation\reviewed\expanded_full_pool_v0_5_splits.json

LangGraph 在本项目中是可替换的工程编排后端，不单独算创新点；线性后端语义等价测试用于证明方法不依赖框架。真正可主张的贡献仍应是真实数据基准、EC-ReAct 的渐进证据发现机制和 CP-Cert 证书方法，且必须由后续人工 gold 主实验决定能否作为独立创新点成立。
