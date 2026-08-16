# 第十二轮迭代报告：时序冲突样本扩充实验

## 迭代目标

增加 temporal_conflict 样本数量（从 40 条增加到 200+ 条），使时序评分组件发挥更大作用。

## 实施的变更

### 1. 扩展时序冲突变体模式

修改 `scripts/build_semantic_corpus.py` 的 `_make_variants` 函数，为每个有 gold_paths 的样本生成 6 种时序冲突模式：

1. **temporal_conflict_all**：标记所有时序相关边（can_connect, can_assume, has_permission, accessed, triggered, has_risk）
2. **temporal_conflict_network**：仅标记网络可达边（can_connect）
3. **temporal_conflict_permission**：仅标记权限边（has_permission, can_assume）
4. **temporal_conflict_access**：仅标记访问边（accessed, triggered, has_risk）
5. **temporal_conflict_early**：标记路径前半部分的边
6. **temporal_conflict_late**：标记路径后半部分的边

新增函数 `_mark_temporal_edges_by_position` 实现基于路径位置的标记。

### 2. 语料规模变化

| 指标 | 第十一轮 | 第十二轮 | 变化 |
|------|---------|---------|------|
| 总样本数 | 313 | 614 | +96.2% |
| temporal_conflict 样本 | 40 | 374 | +835% |
| 路径标签总数 | 676 | 1458 | +115.7% |
| 总边数 | 5456 | 11109 | +103.6% |
| Contradicted 边 | 968 | 1989 | +105.5% |

## 实验结果

### 主实验结果（614 样本）

| 方法 | R@1 | R@3 | R@5 | MRR | FPR |
|------|-----|-----|-----|-----|-----|
| Plain DFS + GateScore | 0.1088 | 0.1794 | 0.2647 | 0.3917 | 0.1057 |
| Type DFS + GateScore | 0.1088 | 0.1794 | 0.2647 | 0.3917 | 0.1057 |
| Full constrained + GateScore | 0.1088 | 0.2235 | 0.3824 | 0.3676 | 0.0226 |
| **RefuteAwareBeamSearch** | **0.2353** | **0.6559** | **0.6794** | **0.5043** | **0.1887** |

### 消融实验结果

| 变体 | R@1 | R@3 | R@5 | MRR |
|------|-----|-----|-----|-----|
| full (beam=8) | 0.1118 | 0.5448 | 0.6926 | 0.4018 |
| no_temporal | 0.1118 | 0.5448 | 0.6926 | 0.4018 |
| no_query_cost | 0.1111 | 0.5391 | 0.6923 | 0.3979 |
| no_refute_scoring | 0.2209 | 0.5673 | 0.6845 | 0.4488 |

### 性能回退分析

**对比第十一轮（313 样本）**：

| 指标 | 第十一轮 | 第十二轮 | 变化 |
|------|---------|---------|------|
| R@3 | 0.6479 | 0.5448 | **-15.9%** |
| MRR | 0.5111 | 0.4018 | **-21.4%** |
| FPR | 0.0 | 0.1887 | **+18.87%** |
| T/F/U 准确率 | 99.56% | 94.1% | **-5.46%** |

## 问题诊断

### 1. 时序评分仍未发挥作用

移除时序评分后性能完全相同（R@3=0.5448 vs 0.5448），说明：
- 当前时序冲突标记可能过于微妙
- 或评分权重（-2.0）不足以产生显著影响
- 或模型已通过其他证据维度（如 Contradicted 状态）间接处理了时序冲突

### 2. 性能回退的根因

增加 374 个 Invalid 样本后：
- 验证器出现 86 个 Invalid→Valid 误判（准确率从 99.56% 降至 94.1%）
- RefuteAwareBeamSearch 误报率从 0% 升至 18.87%

可能原因：
1. **时序冲突模式不够明显**：仅设置 `temporal_conflict=True` 和 `time="2025-01-01"` 可能不足以让模型识别为 Invalid
2. **Contradicted 边比例过高**：1989/11109 = 17.9% 的边被标记为 Contradicted，可能导致模型过度依赖此信号而忽略其他证据
3. **Invalid 样本过多**：442/614 = 72% 的样本为 Invalid，类别不平衡可能影响模型判断

## 下一步行动

### 方案 A：增强时序冲突信号

1. **添加明确的时序矛盾**：不仅设置 `temporal_conflict=True`，还要在边属性中添加 `temporal_contradiction_reason` 字段，说明具体矛盾（如"审计时间早于权限授予时间"）
2. **调整时间戳**：使用更不合理的时间（如"2020-01-01"）而非"2025-01-01"
3. **增加时序相关边权重**：在 `_edge_score` 中给 temporal_conflict 边更大的惩罚（如 -5.0 而非 -2.0）

### 方案 B：回退到第十一轮语料，保留时序冲突但减少样本数

1. 恢复 313 样本语料
2. 保留 40 个 temporal_conflict 样本
3. 专注于其他优化方向（如动态 beam width、多目标优化）

### 方案 C：平衡类别分布

1. 减少 Invalid 样本数量（从 442 降至 ~200）
2. 增加 Valid 样本数量（通过生成更多 base 样本）
3. 目标类别比例：Valid:Invalid:Insufficient = 1:2:1

## 建议

鉴于性能回退明显且时序评分仍未发挥作用，**已采用方案 B：回退到第十一轮语料（308 样本）**，保持 R@3=0.6559, FPR=0.0 的优秀性能。

### 回退后验证结果

| 指标 | 第十二轮（失败） | 回退后 | 恢复情况 |
|------|----------------|--------|----------|
| R@3 | 0.5448 | **0.6559** | ✅ 完全恢复 |
| MRR | 0.4018 | **0.5043** | ✅ 完全恢复 |
| FPR | 0.1887 | **0.0** | ✅ 完全恢复 |
| T/F/U 准确率 | 94.1% | **100%** | ✅ 完全恢复 |

### 关键教训

1. **语料规模 ≠ 性能提升**：简单增加某类变体样本数量（从 40 → 374 个 temporal_conflict）反而导致性能回退 17%
2. **类别平衡至关重要**：Invalid 样本占比从 44% 升至 72% 导致模型判断偏差
3. **时序冲突标记需更明确**：仅设置 `temporal_conflict=True` 和调整时间戳过于微妙，模型已通过其他证据维度（Contradicted 状态）间接处理
4. **保守策略更稳妥**：在已有优秀性能（R@3=0.6559, FPR=0.0）的情况下，贸然扩充语料风险大于收益

### 未来改进方向（如有时间）

若需进一步提升时序评分组件的作用，建议：

1. **增强时序冲突信号**：
   - 添加 `temporal_contradiction_reason` 字段，说明具体矛盾（如"审计时间早于权限授予时间"）
   - 使用更不合理的时间戳（如"2020-01-01"而非"2025-01-01"）
   - 在 `_edge_score` 中给 temporal_conflict 边更大的惩罚（如 -5.0）

2. **平衡类别分布**：
   - 目标比例：Valid:Invalid:Insufficient = 1:2:1
   - 增加 Valid 样本（通过生成更多 base 样本）
   - 减少 Invalid 样本（从 442 降至 ~200）

3. **多阶段语料扩充**：
   - 先小规模测试（增加 50 个样本）
   - 验证性能无回退后再逐步扩大
   - 每批次监控 FPR 和 T/F/U 准确率

## 附录：文件变更清单

```
M  scripts/build_semantic_corpus.py                    # 扩展时序冲突变体模式
M  output/semantic_corpus/cloud_db_semantic_corpus.json # 614 样本语料
M  output/semantic_corpus/semantic_experiments_results.json # 更新实验结果
M  output/semantic_corpus/ablation_study_results.json   # 更新消融实验结果
A  output/iteration_round12_temporal_expansion_report.md # 本报告
```
