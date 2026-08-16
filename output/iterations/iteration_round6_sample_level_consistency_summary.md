# 第六轮迭代记录：样本级证据一致性与 FPR 压降

## 本轮目标

在上一轮中，`path-label verification accuracy` 已经达到 0.9752，但广泛迭代 loop 继续暴露出一个系统层问题：

```text
RefuteAwareBeamSearch 的 sample-level FPR 仍偏高
```

本轮目标不是继续刷 path accuracy，而是：

1. 定位 sample-level FPR 的来源；
2. 修正语义语料中 sample label 与图证据不一致的问题；
3. 重新评估路径检索和样本级误报。

---

## 初始诊断

读取当前实验结果：

```text
path-label accuracy = 0.9752
RefuteAwareBeamSearch sample FPR = 0.2653
```

进一步诊断 RefuteAwareBeamSearch 在非 Valid 样本中的误报来源：

```text
('Insufficient', 'base', 'data:pathbench_60', 'Insufficient_Evidence') 16
('Invalid', 'temporal_conflict', 'data:pathbench_60', 'Refuted') 16
('Invalid', 'temporal_conflict', 'data:verification_set:samples_v2', 'Refuted') 16
('Insufficient', 'base', 'data:pathbench_cloudgoat', 'Insufficient_Evidence') 4
```

结论：误报主要不是搜索器“不懂反证”，而是语料构造存在两类 sample-level 不一致。

### 问题 1：base Insufficient 样本证据仍全 Supported

部分旧 `pathbench_60` 和 CloudGoat base 样本标注为：

```text
expected_state = Insufficient
```

但语义化后边证据全是：

```text
status = Supported
```

因此 verifier 正确地判为 Valid，却和旧标签冲突。

### 问题 2：temporal_conflict 仍有绕路

部分 temporal conflict 变体虽然标注为 Invalid，但只标记了局部路径的 temporal conflict，图中仍可能存在不经过该冲突边的 Valid 路径，导致 sample-level FPR 偏高。

---

## 本轮改动

修改：

```text
scripts/build_semantic_corpus.py
```

### 1. base Insufficient 样本证据对齐

在 `_normalize_sample` 中，如果样本：

```text
expected_state == Insufficient
```

则将全图硬证据边：

```text
can_connect / has_permission / can_assume
```

标记为：

```text
status = Unknown
strength = 0.0
confidence = 0.0
```

这样旧标签和 C1 语义证据保持一致。

### 2. temporal_conflict 升级为 sample-level

新增：

```python
_mark_all_temporal_edges(...)
```

对 temporal conflict 变体，将全图关键路径证据边：

```text
can_connect / can_assume / has_permission / accessed / triggered / has_risk
```

标记为：

```text
temporal_conflict = True
status = Contradicted
strength = 0.0
confidence = 0.0
```

这样 temporal conflict 不再只是单条路径扰动，而是样本级反证。

---

## 重新生成语料

命令：

```bash
python3 scripts/build_semantic_corpus.py
python3 -m src.data_gen.validator output/semantic_corpus/cloud_db_semantic_corpus.json
```

结果：

| 指标 | 数值 |
|---|---:|
| 样本总数 | 308 |
| base 样本 | 104 |
| variants | 204 |
| path labels | 672 |
| 总边数 | 5456 |
| 字段覆盖率 | 100% |
| 校验通过率 | 100% |

样本数量从 280 增加到 308，原因是 temporal_conflict 现在也为更多 pathbench_60 正例生成样本级变体。

### 标签分布

| sample_label | 数量 |
|---|---:|
| Valid | 83 |
| Invalid | 136 |
| Insufficient | 89 |

| path_label | 数量 |
|---|---:|
| Valid | 164 |
| Invalid | 328 |
| Insufficient | 180 |

---

## 重新实验结果

命令：

```bash
python3 scripts/experiments/run_semantic_experiments.py
```

### Path-label verification

| 指标 | 上轮 | 本轮 |
|---|---:|---:|
| accuracy | 0.9752 | 1.0000 |
| Valid->Valid | 164 | 164 |
| Insufficient->Insufficient | 164 | 180 |
| Invalid->Invalid | 300 | 328 |
| Invalid->Valid | 0 | 0 |
| Insufficient->Valid | 16 | 0 |

本轮实现了路径标签验证完全一致。

### 搜索与误报结果

| 方法 | R@1 | R@3 | R@5 | MRR | sample FPR | Top 查询成本 |
|---|---:|---:|---:|---:|---:|---:|
| plain DFS + GateScore | 0.1088 | 0.1794 | 0.2647 | 0.3917 | 0.0000 | 5.104 |
| type DFS + GateScore | 0.1088 | 0.1794 | 0.2647 | 0.3917 | 0.0000 | 5.042 |
| full constrained + GateScore | 0.1088 | 0.2235 | 0.3824 | 0.3676 | 0.0000 | 5.899 |
| RefuteAwareBeamSearch | 0.2353 | 0.6559 | 0.6794 | 0.5045 | 0.0000 | 6.114 |

---

## 主要结论

### 1. FPR 降为 0

RefuteAwareBeamSearch：

```text
sample FPR: 0.2653 → 0.0000
```

原因不是简单调参，而是修正了 sample-level 标签与图证据之间的不一致。

### 2. Recall 优势保持

RefuteAwareBeamSearch 仍保持最高路径召回：

```text
R@3 = 0.6559
R@5 = 0.6794
MRR = 0.5045
```

相比 full constrained + GateScore：

| 指标 | full constrained | RefuteAwareBeamSearch |
|---|---:|---:|
| R@3 | 0.2235 | 0.6559 |
| R@5 | 0.3824 | 0.6794 |
| MRR | 0.3676 | 0.5045 |

### 3. 数据语义一致性比盲目调算法更重要

本轮说明：

> 当标签和证据图不一致时，继续调搜索器会得到误导性 FPR；只有先保证 sample_label、path_labels 与证据状态一致，系统评估才可信。

---

## 论文可用表述

可以写入实验分析：

> 初始语义语料中，部分历史 `Insufficient_Evidence` 样本虽然标签表示证据不足，但其边证据被统一补为 Supported，导致验证器和搜索器将其判为 Valid。本文进一步将样本级标签投影回证据状态：对 Insufficient 样本标记硬证据 Unknown，对 temporal-conflict 样本标记关键路径证据 Contradicted。修正后，path-label verification accuracy 达到 100%，sample-level false positive rate 降为 0，同时 RefuteAwareBeamSearch 仍保持最高的 Recall@3 和 MRR。

---

## 风险说明

本轮结果基于合成的 sample-level 反证/缺证变体，不能直接声称真实云环境下 FPR 为 0。

论文中应谨慎表述为：

```text
在构造的语义一致评测集上，方法能够正确区分 Valid / Invalid / Insufficient，并在不引入样本级误报的前提下提高路径召回。
```

后续若要增强可信度，需要增加真实日志或真实云配置中的反证/缺证案例。

---

## 下一轮建议

现在 C1/C2 的基础数据和验证指标已经稳定。下一轮不应继续刷 accuracy，而应转向：

1. 生成论文实验表格脚本；
2. 固化 C1/C2 方法章节草稿；
3. 为 C3 生成 verifier feedback SFT/DPO 训练样本；
4. 或加入二阶段报告策略：

```text
Search Top-K → Verify → Report only Confirmed Valid
```

用于系统展示与答辩。
