# RefuteAwareBeamSearch 消融实验报告

## 实验口径

本实验在 308 个语义样本上运行，检索指标只对至少含一条 `Valid`
路径标签的样本计算。该结果属于 all-corpus 开发实验，参数选择应在
validation split 上完成，不能代替 test/hard_test 主实验。

## 当前代码复算结果

| Variant | R@1 | R@3 | R@5 | MRR | Avg Expanded |
|---|---:|---:|---:|---:|---:|
| full (beam=4) | 0.2353 | 0.6853 | 0.7176 | 0.5025 | 24.103 |
| beam=2 | 0.2353 | 0.5265 | 0.5265 | 0.4338 | 16.559 |
| beam=8 | 0.2353 | 0.6471 | 0.6794 | 0.4877 | 28.926 |
| beam=16 | 0.2353 | 0.6471 | 0.6882 | **0.5054** | 30.338 |
| no temporal | 0.2353 | 0.6853 | 0.7176 | 0.5025 | 24.103 |
| no query cost | 0.2353 | **0.6882** | **0.7324** | **0.5233** | 23.985 |
| no refute scoring | 0.2353 | 0.6853 | 0.7176 | 0.5025 | 24.103 |
| no temporal + no query cost | 0.2353 | **0.6882** | **0.7324** | **0.5233** | 23.985 |

完整机器相关耗时保存在 `ablation_study_results.json`，不作为算法质量结论。

## 可以支持的结论

1. `beam_width=2` 探索不足，R@3 和 R@5 明显下降。
2. `beam_width=4` 相比 beam=8/16 获得更高 R@3/R@5，并减少边扩展量。
3. `beam_width=16` 的 MRR 略高，但扩展量最大，收益有限。
4. 移除 temporal 或 refute scoring 后指标相同；移除 query cost 后
   R@3、R@5、MRR 反而略有提高。

## 不能支持的结论

- 不能声称 refute scoring 已被消融证明有效；当前 `no_refute_scoring`
  与完整版本指标相同。
- 不能声称 query cost 提升检索质量；当前实验显示它略微降低质量指标，
  若保留应以成本—质量权衡而非准确率增益来论证。
- 不能根据单次运行耗时宣称稳定的速度提升。
- 不能把 all-corpus 消融结果作为 held-out 泛化证据。

完整结果：`output/semantic_corpus/ablation_study_results.json`
