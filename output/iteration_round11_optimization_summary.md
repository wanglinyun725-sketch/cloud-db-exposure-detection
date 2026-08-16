# 第十一轮迭代报告：参数优化复核

## 状态说明

本报告原版本引用了早期实验结果，其中“移除 refute scoring 后 R@1
从 0.0805 提升到 0.3017”等数字已无法由当前代码复现。旧结论已撤回，
当前参数判断以最新 `ablation_study_results.json` 为准。

## 当前配置

- 默认 `beam_width=4`
- temporal conflict 惩罚：`-2.0`
- Contradicted 惩罚：`-1.5 - (1-strength)`
- Unknown 惩罚：`-0.3`
- query cost 权重：`0.15`

## 当前复算结果

| 变体 | R@1 | R@3 | R@5 | MRR | Avg Expanded |
|---|---:|---:|---:|---:|---:|
| beam=8 | 0.2353 | 0.6471 | 0.6794 | 0.4877 | 28.926 |
| beam=2 | 0.2353 | 0.5265 | 0.5265 | 0.4338 | 16.559 |
| beam=4 | 0.2353 | **0.6853** | **0.7176** | 0.5025 | 24.103 |
| beam=16 | 0.2353 | 0.6471 | 0.6882 | **0.5054** | 30.338 |
| no temporal | 0.2353 | 0.6471 | 0.6794 | 0.4877 | 28.926 |
| no query cost | 0.2353 | 0.6471 | 0.6794 | 0.4880 | 28.735 |
| no refute scoring | 0.2353 | 0.6471 | 0.6794 | 0.4877 | 28.926 |

## 复核结论

1. beam=4 在当前 all-corpus 开发实验中获得最高 R@3/R@5，并减少边扩展。
2. beam=16 的 MRR 略高，但搜索开销更大。
3. 当前 `no_refute_scoring`、`no_temporal` 与完整版本指标相同，不能声称
   这些组件已通过独立消融验证。
4. 参数选择应在 validation split 完成；all-corpus 结果只能作为开发记录。

详见：`output/semantic_corpus/ablation_study_report.md`
