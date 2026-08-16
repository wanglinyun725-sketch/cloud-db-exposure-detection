# C1/C2 实验表格与论文可用结论（dataset_v1 口径）

> 当前主语料：`output/semantic_corpus/cloud_db_semantic_corpus.json`  
> dataset_v1：`output/dataset_v1/dataset_v1_corpus.json`  
> split 实验结果：`output/dataset_v1/semantic_experiments_by_split.json`  
> 注意：本文件已将旧 all-corpus 结果标记为 legacy，不再把其作为最终主实验结论。

---

## 表 1：当前语义语料规模统计

| 项目 | 数量 |
|---|---:|
| 样本总数 | 308 |
| 原始 base 样本 | 104 |
| 变体样本 | 204 |
| 路径级标签 | 672 |
| 边总数 | 5456 |

---

## 表 2：样本变体分布

| 变体类型 | 数量 | 说明 |
|---|---:|---|
| base | 104 | 原始生成、CloudGoat、samples_v2 样本语义化结果 |
| missing | 68 | 样本级硬证据 Unknown 变体 |
| refuted | 68 | 样本级硬证据 Contradicted 变体 |
| temporal_conflict | 68 | 样本级时序冲突变体 |

---

## 表 3：样本级标签分布

| sample_label | 数量 |
|---|---:|
| Valid | 83 |
| Invalid | 136 |
| Insufficient | 89 |

---

## 表 4：路径级标签分布

| path_label | 数量 |
|---|---:|
| Valid | 164 |
| Invalid | 328 |
| Insufficient | 180 |

---

## 表 5：证据语义字段覆盖率

| 字段 | 覆盖率 |
|---|---:|
| status | 100% |
| source | 100% |
| time | 100% |
| confidence | 100% |
| query_cost | 100% |
| raw_evidence | 100% |

---

## 表 6：证据状态分布

| status | 边数 |
|---|---:|
| Supported | 3897 |
| Contradicted | 968 |
| Unknown | 591 |

---

## 表 7：dataset_v1 group split 分布

| split | 样本数 | group 数 | retrieval samples | 用途 |
|---|---:|---:|---:|---|
| dev | 164 | 56 | 36 | 开发检查，不作为主结果 |
| validation | 46 | 19 | 9 | 参数选择/消融参考 |
| test | 58 | 19 | 13 | 主实验 |
| hard_test | 40 | 10 | 10 | 缺证/反证/时序冲突鲁棒性测试 |

> split 单位为 `group_id`，同一个 base 样本及其 `missing/refuted/temporal_conflict` 变体不会跨 split。`dataset_v1_manifest.json` 中 `groups_crossing_splits=0`。

---

## 表 8：T/F/U 语义一致性检查

| split | path labels | correct | accuracy |
|---|---:|---:|---:|
| dev | 343 | 343 | 1.0000 |
| validation | 91 | 91 | 1.0000 |
| test | 134 | 134 | 1.0000 |
| hard_test | 104 | 104 | 1.0000 |
| all | 672 | 672 | 1.0000 |

> 注意：该指标是“语义标签—验证器实现”的一致性检查，不应表述为真实云环境泛化准确率。

---

## 表 9：dataset_v1 test split 路径搜索对比实验

| 方法 | R@1 | R@3 | R@5 | MRR | P@3 | Avg Expanded Edges | Avg Generated Paths | Avg Completed Paths | Top Query Cost | Sample FPR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Plain DFS + GateScore | 0.1231 | 0.2000 | 0.2462 | 0.4306 | 0.2308 | 34.759 | 12.466 | 12.466 | 5.207 | 0.0000 |
| Type-constrained DFS + GateScore | 0.1231 | 0.2000 | 0.2462 | 0.4306 | 0.2308 | 31.897 | 9.879 | 9.879 | 5.155 | 0.0000 |
| Full-constrained DFS + GateScore | 0.1231 | 0.2000 | 0.4000 | 0.4038 | 0.2436 | - | 6.724 | 6.724 | 5.983 | 0.0000 |
| RefuteAwareBeamSearch | 0.2308 | 0.6923 | 0.7231 | 0.5495 | 0.3333 | 25.121 | 20.724 | 6.741 | 6.241 | 0.0000 |

---

## 表 10：dataset_v1 hard_test split 路径搜索对比实验

| 方法 | R@1 | R@3 | R@5 | MRR | P@3 | Avg Expanded Edges | Avg Generated Paths | Avg Completed Paths | Top Query Cost | Sample FPR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Plain DFS + GateScore | 0.1000 | 0.1600 | 0.2200 | 0.3100 | 0.1333 | 31.800 | 13.500 | 13.500 | 5.550 | 0.0000 |
| Type-constrained DFS + GateScore | 0.1600 | 0.2200 | 0.2200 | 0.4754 | 0.2333 | 28.400 | 9.900 | 9.900 | 5.250 | 0.0000 |
| Full-constrained DFS + GateScore | 0.1600 | 0.2200 | 0.3200 | 0.4393 | 0.2500 | - | 7.200 | 7.200 | 6.000 | 0.0000 |
| RefuteAwareBeamSearch | 0.2000 | 0.6600 | 0.7200 | 0.5125 | 0.3000 | 23.800 | 20.550 | 7.100 | 6.400 | 0.0000 |

---

## 表 11：legacy all-corpus 路径搜索结果（仅作开发记录）

| 方法 | R@1 | R@3 | R@5 | MRR | P@3 | Avg Expanded Edges | Avg Generated Paths | Avg Completed Paths | Top Query Cost | Sample FPR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Plain DFS + GateScore | 0.0735 | 0.1412 | 0.2529 | 0.2905 | 0.1372 | 31.909 | 11.435 | 11.435 | 5.260 | 0.0000 |
| Type-constrained DFS + GateScore | 0.1088 | 0.1765 | 0.2559 | 0.3877 | 0.1961 | 29.234 | 9.175 | 9.175 | 5.042 | 0.0000 |
| Full-constrained DFS + GateScore | 0.1088 | 0.2206 | 0.3735 | 0.3636 | 0.2304 | - | 5.831 | 5.831 | 5.899 | 0.0000 |
| RefuteAwareBeamSearch | 0.2353 | 0.6882 | 0.7235 | 0.5320 | 0.2843 | 23.607 | 19.958 | 6.711 | 6.062 | 0.0000 |

> 该表没有 group split，只能作为开发阶段 all-corpus 记录，不能作为最终泛化实验主表。

---

## 表 12：消融实验（Valid-only gold 口径，all-corpus 开发记录）

| 变体 | R@1 | R@3 | R@5 | MRR | Expanded |
|---|---:|---:|---:|---:|---:|
| full_refute_aware_beam | 0.2353 | 0.6853 | 0.7176 | 0.5025 | 24.103 |
| beam_width_2 | 0.2353 | 0.5265 | 0.5265 | 0.4338 | 16.559 |
| beam_width_8 | 0.2353 | 0.6471 | 0.6794 | 0.4877 | 28.926 |
| beam_width_16 | 0.2353 | 0.6471 | 0.6882 | 0.5054 | 30.338 |
| no_temporal | 0.2353 | 0.6853 | 0.7176 | 0.5025 | 24.103 |
| no_query_cost | 0.2353 | 0.6882 | 0.7324 | 0.5233 | 23.985 |
| no_refute_scoring | 0.2353 | 0.6853 | 0.7176 | 0.5025 | 24.103 |
| no_temporal_no_query_cost | 0.2353 | 0.6882 | 0.7324 | 0.5233 | 23.985 |

> 消融脚本已修正为只使用 `state == Valid` 的 path labels 作为检索 gold。该表仍是 all-corpus 开发记录，后续应迁移到 validation/test split。

---

## 表 13：held-out 样本级统计检验

`test + hard_test` 共 23 个配对检索样本。置信区间使用 10,000 次非参数
bootstrap；p 值来自 50,000 次双侧配对符号翻转检验，并在五项指标内做
Holm-Bonferroni 校正。

| 指标 | Full-constrained 均值 | RefuteAware 均值 | 95% CI（RefuteAware） | 均值差 | Cohen's dz | Holm p |
|---|---:|---:|---:|---:|---:|---:|
| R@1 | 0.1391 | 0.2174 | [0.0435, 0.3913] | +0.0783 | 0.2085 | 0.9351 |
| R@3 | 0.2087 | 0.6783 | [0.5043, 0.8435] | **+0.4696** | 0.8180 | **0.0068** |
| R@5 | 0.3652 | 0.7217 | [0.5652, 0.8696] | **+0.3565** | 0.6646 | **0.0154** |
| MRR | 0.4193 | 0.5334 | [0.4257, 0.6504] | +0.1141 | 0.2192 | 0.9351 |
| P@3 | 0.2464 | 0.3188 | [0.2608, 0.3768] | +0.0724 | 0.2313 | 0.9351 |

> Holm 校正后 R@3 与 R@5 达到 0.05 显著性阈值。其余指标只能描述样本均值，
> 不能宣称统计显著。

---

## 可写入论文的阶段性结论

### 结论 1：证据语义化保证了反证与缺证可计算

本文将路径边从普通图关系扩展为带有 `status/source/time/confidence/query_cost/raw_evidence` 的证据语义边。当前语义语料中六类关键字段覆盖率均达到 100%，并形成了 `Supported / Contradicted / Unknown` 三类证据状态，为后续三值验证与反证感知搜索提供了基础。

### 结论 2：T/F/U 验证器通过语义一致性检查

在当前构造语义语料上，T/F/U 验证器对 672 条路径级标签均给出一致判定。该实验验证的是 C1 证据语义化与三值验证器之间的实现一致性，而非真实环境泛化能力。

### 结论 3：group split 后 RefuteAwareBeamSearch 仍保持 Top-K 召回优势

在 dataset_v1 test split 上，RefuteAwareBeamSearch 的 R@3 为 0.6923，高于 Full-constrained DFS + GateScore 的 0.2000；在 hard_test split 上，R@3 为 0.6600，高于基线的 0.2200。合并 23 个 held-out 配对检索样本后，R@3 均值差为 +0.4696，Holm 校正后 p=0.0068；R@5 均值差为 +0.3565，Holm 校正后 p=0.0154。当前统计证据支持 Top-3/Top-5 召回优势，但不支持“所有指标全面显著提升”的表述。按来源分层后，方法在 `pathbench_60` 上明显占优，在 `samples_v2` 上反而弱于完整约束基线，因此聚合结论不能外推为跨来源泛化能力。

来源增益异质性置换检验进一步显示，五项指标在两个来源间的增益差均达到
Holm 校正后的显著水平（R@3/MRR p≈0.0001，R@5 p=0.0023，R@1 p=0.0182，
P@3 p=0.0004）。这说明当前聚合提升具有显著来源依赖，必须同时报告来源分层
结果。完整结果见 `output/source_robustness_report.md`。

### 结论 4：当前结果仍属于构造语料上的阶段性验证

当前 test/hard_test 结果比 all-corpus 自测更可信，但数据仍来自构造语料和受控变体。后续若要提升论文说服力，应扩展 held-out external source，并将 SDDP 真实脱敏切片作为 case study 或单独 external_test，而非直接混入主语料。

---

## 写作注意事项

1. 不要把 `semantic_consistency_check=1.0000` 写成真实云环境准确率。
2. 主实验应优先引用 dataset_v1 的 `test` 和 `hard_test` 表，而不是 legacy all-corpus 表。
3. `sample_false_positive_rate=0` 是当前构造语料上的记录，不能外推成真实云环境零误报。
4. SDDP 当前是数据切片/案例材料，不是已确认真实入侵轨迹 ground truth。
5. 消融实验已修正 gold 口径，但仍需进一步迁移到 validation/test split。
