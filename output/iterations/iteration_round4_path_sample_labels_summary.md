# 第四轮迭代记录：path_labels / sample_label 拆分与样本级扰动

## 本轮目标

第三轮发现一个严重评价问题：

```text
Refuted / Missing 变体是 path-level 扰动，
但实验却按 sample-level false positive 统计。
```

这会导致样本级误报指标不可信，因为即使某条 gold path 被扰动，图中仍可能存在其他未扰动路径。

本轮目标：

1. 在语义语料中显式区分 `path_labels` 和 `sample_label`；
2. 将 refuted/missing 变体从单路径扰动升级为样本级硬证据扰动；
3. 更新实验脚本，让路径检索、路径验证、样本误报分开统计。

---

## 本轮数据改造

更新：

```text
scripts/build_semantic_corpus.py
```

### 新增字段

每个样本新增：

```json
{
  "sample_label": "Valid | Invalid | Insufficient",
  "path_labels": [
    {
      "path": ["..."],
      "state": "Valid | Invalid | Insufficient",
      "expected_type": "...",
      "variant_type": "base | refuted | missing | temporal_conflict",
      "label_scope": "gold_path"
    }
  ]
}
```

### 变体构造策略变化

上一轮：

```text
只扰动第一条 gold path 的一条边
```

本轮：

```text
refuted: 将全图 can_connect / has_permission / can_assume 硬证据标记为 Contradicted
missing: 将全图 can_connect / has_permission / can_assume 硬证据标记为 Unknown
```

这样 refuted/missing 更接近 sample-level 变体，而不是单条 path 变体。

---

## 数据统计

重新生成：

```text
output/semantic_corpus/cloud_db_semantic_corpus.json
output/semantic_corpus/cloud_db_semantic_corpus_stats.json
```

核心统计：

| 指标 | 数值 |
|---|---:|
| 样本总数 | 280 |
| base 样本 | 104 |
| 变体样本 | 176 |
| 路径标签总数 | 644 |
| 总边数 | 5166 |
| `status/source/time/confidence/query_cost/raw_evidence` 覆盖率 | 100% |
| SHACL-style 校验通过率 | 100% |

### 样本级标签分布

| sample_label | 数量 |
|---|---:|
| Valid | 83 |
| Invalid | 108 |
| Insufficient | 89 |

### 路径级标签分布

| path_label | 数量 |
|---|---:|
| Valid | 164 |
| Invalid | 300 |
| Insufficient | 180 |

### 证据状态分布

| status | 边数 |
|---|---:|
| Supported | 4250 |
| Contradicted | 478 |
| Unknown | 438 |

相比上一轮，`Contradicted` 和 `Unknown` 边显著增加，说明样本级扰动已生效。

---

## 实验脚本改造

更新：

```text
scripts/experiments/run_semantic_experiments.py
```

### 指标拆分

实验不再混用一个 `false_positive_rate`，而是拆成：

1. **路径级验证**
   - 对所有 `path_labels` 运行 `verify_path`；
   - 输出 path-label accuracy 和 confusion。

2. **路径检索**
   - 只在含 `Valid` path_labels 的样本上计算 Recall@K / MRR / Precision@K；
   - 避免把 Invalid/Missing 路径也当作检索 gold。

3. **样本级误报**
   - 对 `sample_label != Valid` 的样本，若 top path 被验证为 Valid，则计为 sample false positive。

---

## 实验结果

输出：

```text
output/semantic_corpus/semantic_experiments_results.json
```

### 路径级验证结果

| 指标 | 数值 |
|---|---:|
| path_labels total | 644 |
| accuracy | 0.8168 |

混淆：

```text
Valid->Valid: 164
Insufficient->Insufficient: 164
Insufficient->Valid: 16
Invalid->Invalid: 198
Invalid->Valid: 102
```

解释：

- Valid 与 Insufficient 的识别基本可用；
- Invalid 仍有 102 条被识别成 Valid，主要来自 temporal_conflict，因为当前 verifier 尚未显式检查时序谓词。

---

## 方法对比结果

| 方法 | R@1 | R@3 | R@5 | MRR | P@3 | 样本级 FPR | 平均扩展边 | Top 查询成本 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| plain DFS + GateScore | 0.1088 | 0.1794 | 0.2647 | 0.3917 | 0.2010 | 0.3061 | 32.657 | 5.257 |
| type DFS + GateScore | 0.1088 | 0.1794 | 0.2647 | 0.3917 | 0.2010 | 0.3061 | 29.857 | 5.211 |
| full constrained + GateScore | 0.1088 | 0.2235 | 0.3824 | 0.3676 | 0.2353 | 0.2245 | N/A | 6.054 |
| RefuteAwareBeamSearch | 0.2353 | 0.6559 | 0.6794 | 0.5045 | 0.2304 | 0.3061 | 28.561 | 6.489 |

---

## 本轮结论

### 1. 数据评价口径被修正

现在语料中明确区分：

```text
path_labels: 路径级真值
sample_label: 样本级真值
```

这解决了上一轮“path-level 变体却算 sample-level FPR”的问题。

### 2. 样本级扰动降低了误报

上一轮 RefuteAwareBeamSearch 的 sample false positive rate：

```text
0.6769
```

本轮：

```text
0.3061
```

误报明显下降，说明全图硬证据扰动比单路径扰动更适合样本级评估。

### 3. RefuteAwareBeamSearch 仍然显著提升路径召回

相比 full constrained + GateScore：

| 指标 | full constrained | RefuteAwareBeamSearch |
|---|---:|---:|
| R@1 | 0.1088 | 0.2353 |
| R@3 | 0.2235 | 0.6559 |
| R@5 | 0.3824 | 0.6794 |
| MRR | 0.3676 | 0.5045 |

这说明 C2 方法在“把真实暴露路径推到前面”方面有明确收益。

### 4. 当前最大问题转为时序反证识别

`Invalid->Valid: 102` 说明当前 verifier 不识别 temporal conflict。

这不是搜索器问题，而是验证谓词缺失：

```text
当前 verify_path = entry + reach + perm + target + sense
缺少 temporal_consistency
```

---

## 下一轮任务

下一轮应补 C1/C2 之间最关键的时序谓词：

### 1. 在 verifier 中新增 temporal 维度

```text
temporal ∈ {T, F, U}
```

规则：

- 若路径上存在 `temporal_conflict=True` 的证据边，则 `temporal=F`；
- 若路径边均有时间且顺序一致，则 `temporal=T`；
- 若缺少必要时间，则 `temporal=U`。

### 2. 将 `ALL_DIMS` 从 5 维扩展为 6 维

```text
entry, reach, perm, target, sense, temporal
```

### 3. 重新跑 path-label verification

目标：

```text
Invalid->Valid 从 102 明显下降
path-label accuracy 从 0.8168 提升到 > 0.90
```

### 4. 再评估搜索器

确认 temporal verifier 是否降低 sample-level FPR，同时不显著牺牲 Recall@K。
