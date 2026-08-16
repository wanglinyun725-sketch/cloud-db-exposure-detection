# 第三轮迭代记录：RefuteAwareBeamSearch 与语义语料实验

## 本轮目标

基于第二轮构建的 280 条统一语义语料，不再继续在旧 60 条数据上刷指标，而是实现真正的 C2 搜索方法：

```text
RefuteAwareBeamSearch
```

目标是让反证、缺证和查询成本在路径扩展阶段就参与决策，而不是先由 DFS 全量枚举，再用 GateScore 事后排序。

## 本轮实现

### 1. 新增搜索器

新增：

```text
src/graph/refute_aware_search.py
```

核心方法：

```python
refute_aware_beam_search(...)
```

搜索过程：

1. 从入口节点出发；
2. 按路径语法扩展合法边；
3. 对每条边计算 evidence-aware score；
4. 对 `Contradicted` 边强惩罚；
5. 对 `Unknown` 边中等惩罚；
6. 对查询成本和路径长度加惩罚；
7. 每层只保留 top beam；
8. 到达高敏目标后，用完整路径评分排序。

完整路径评分包括：

```text
state bonus
+ edge evidence score
+ GateScore risk score
- missing penalty
- refuted penalty
- query cost penalty
```

这使 C2 从“排序增强”推进为“搜索过程中的反证/缺证感知”。

### 2. 新增语义语料实验脚本

新增：

```text
scripts/experiments/run_semantic_experiments.py
```

输入：

```text
output/semantic_corpus/cloud_db_semantic_corpus.json
```

输出：

```text
output/semantic_corpus/semantic_experiments_results.json
```

对比方法：

| 方法 | 含义 |
|---|---|
| `plain_dfs_gatescore` | 普通 DFS 枚举 + GateScore 排序 |
| `type_dfs_gatescore` | 类型约束 DFS + GateScore 排序 |
| `full_constrained_gatescore` | 原完整约束搜索 + GateScore 排序 |
| `refute_aware_beam` | 本轮新增反证感知 Beam Search |

指标：

- Recall@K；
- Precision@K；
- MRR；
- Exact Match；
- Target Recall@K；
- 平均扩展边数；
- 平均生成路径数；
- 平均完成路径数；
- Top 查询成本；
- Top 状态分布；
- 样本级 false positive rate。

### 3. 修正三值验证器

实验初跑时发现三值验证器准确率只有 45.77%。诊断发现两个问题：

1. 把低 `strength` 当成反证，导致很多弱证据路径被误判为 Invalid；
2. 对缺证链路，只要同一维度中存在另一条 Supported 边，就盖过 Unknown。

修正后：

- `strength` 只作为风险强度，不再直接表示反证；
- 只有 `status=Contradicted` 才表示反证；
- 同一维度优先级：

```text
Contradicted > Unknown > Supported
```

修正后 gold path 三值验证准确率：

| 指标 | 修正前 | 修正后 |
|---|---:|---:|
| Gold-state accuracy | 45.77% | 86.92% |

修正后混淆：

```text
Valid->Valid: 68
Insufficient->Insufficient: 68
Invalid->Invalid: 90
Insufficient->Valid: 16
Invalid->Valid: 18
```

仍有 34 条错误，说明数据扰动仍未完全覆盖所有候选路径。

## 实验结果

语义语料：

```text
samples_total = 280
samples_with_gold = 260
```

### 路径检索结果

| 方法 | R@1 | R@3 | R@5 | MRR | P@3 | Target R@1 | Avg Expanded Edges | Avg Top Query Cost |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| plain DFS + GateScore | 0.0562 | 0.1177 | 0.2769 | 0.3655 | 0.1603 | 0.5923 | 33.231 | 6.015 |
| type DFS + GateScore | 0.0654 | 0.1223 | 0.2769 | 0.3886 | 0.1680 | 0.5923 | 30.446 | 5.969 |
| full constrained + GateScore | 0.0654 | 0.2262 | 0.4138 | 0.3823 | 0.2244 | 0.5923 | N/A | 6.500 |
| RefuteAwareBeamSearch | 0.1846 | 0.3323 | 0.6354 | 0.3737 | 0.1231 | 0.7692 | 29.196 | 7.288 |

## 主要结论

### 正向结果

相比 `full_constrained_gatescore`：

| 指标 | full constrained | RefuteAwareBeamSearch | 变化 |
|---|---:|---:|---:|
| Recall@1 | 0.0654 | 0.1846 | +182% |
| Recall@3 | 0.2262 | 0.3323 | +47% |
| Recall@5 | 0.4138 | 0.6354 | +54% |
| Target Recall@1 | 0.5923 | 0.7692 | +30% |

这说明将反证、缺证和查询成本引入搜索阶段，确实能更早把 gold path 推到 Top-K 中。

### 代价与问题

1. Top 查询成本上升：

```text
6.500 → 7.288
```

2. Precision@3 下降：

```text
0.2244 → 0.1231
```

说明 beam search 更偏召回，排序还不够精细。

3. False positive rate 仍高：

```text
RefuteAwareBeamSearch: 0.6769
```

但这个指标目前不能直接当作方法缺陷，因为语义变体只扰动了 gold path 上的一条边，图中可能仍存在其他可达高敏路径。也就是说：

> 当前 Refuted/Missing 是 path-level 变体，不一定是 sample-level invalid。

这暴露的是数据构造问题：如果要评估样本级误报，下一轮需要对所有 gold paths 或所有候选高敏路径做一致扰动。

## 本轮是否符合“不是只写计划”

是。本轮产物包括：

- 新搜索算法：`src/graph/refute_aware_search.py`
- 新实验脚本：`scripts/experiments/run_semantic_experiments.py`
- 新实验结果：`output/semantic_corpus/semantic_experiments_results.json`
- 修正三值验证语义：`src/graph/gate_score.py`
- 本轮论文材料：本文件

## 下一轮必须做什么

下一轮不要急着继续调 beam 参数，应该先修正数据标注粒度：

### 1. 区分 path-level label 和 sample-level label

当前 `expected_state` 更像 gold path 的状态，不一定代表整个样本没有其他有效路径。

需要新增：

```text
path_labels: 每条 gold/candidate path 的状态
sample_label: 整个图是否仍存在任意 Valid exposure path
```

### 2. 生成 sample-level refuted/missing 变体

对所有 gold paths 或所有可枚举暴露路径进行扰动，而不是只扰动第一条 gold path。

目标：

```text
sample-level invalid / insufficient 变体中，不应仍存在明显 Valid 高敏路径。
```

### 3. 重新定义 false positive

建议拆成两个指标：

| 指标 | 含义 |
|---|---|
| path_false_confirm_rate | 对已标注无效路径是否误判 Valid |
| sample_false_positive_rate | 对整个样本是否错误报告风险 |

### 4. 再优化 Beam Search 排序

在数据标注修好后，再加入：

- diversity penalty；
- stronger query cost penalty；
- path pattern support；
- temporal consistency bonus/penalty。

## 下一轮验收指标

- 语义语料包含 `path_labels`；
- `sample_label` 与 `path_labels` 分离；
- sample-level refuted/missing 变体数量不少于 100；
- Gold-state verifier accuracy 维持 ≥ 85%；
- 新 false positive 指标不再混淆 path-level 与 sample-level。
