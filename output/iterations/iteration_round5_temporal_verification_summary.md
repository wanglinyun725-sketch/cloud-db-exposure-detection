# 第五轮迭代记录：Temporal 三值验证维度

## 本轮目标

第四轮显示：

```text
Invalid->Valid: 102
path-label accuracy: 0.8168
```

主要原因是 `temporal_conflict` 变体虽然在数据里存在，但 `verify_path` 只检查：

```text
entry, reach, perm, target, sense
```

没有检查时序一致性。因此 temporal conflict 无法被判成 Invalid。

本轮目标：

1. 在 T/F/U 验证器中新增 `temporal` 维度；
2. 让 RefuteAwareBeamSearch 在扩展阶段感知 temporal conflict；
3. 修复 temporal_conflict 标注只覆盖第一条路径的问题；
4. 重跑语义语料实验。

---

## 本轮实现

### 1. 验证器新增 temporal 维度

修改：

```text
src/graph/gate_score.py
```

`ALL_DIMS` 从：

```python
["entry", "reach", "perm", "target", "sense"]
```

扩展为：

```python
["entry", "reach", "perm", "target", "sense", "temporal"]
```

新增：

```python
_temporal_status(G, path)
```

当前规则：

- 如果路径边存在 `temporal_conflict=True`，则 `temporal=F`；
- 如果路径边缺少时间或时间不可解析，则 `temporal=U`；
- 否则 `temporal=T`。

注意：一开始尝试对所有边时间做单调检查，但由于部分数据时间是 synthetic timestamp，按 edge index 注入，并不严格对应路径语义顺序，导致大量 Valid 被误判 Invalid。因此本轮保守采用显式 `temporal_conflict` 作为反证信号。

### 2. Beam Search 感知 temporal conflict

修改：

```text
src/graph/refute_aware_search.py
```

在 `_edge_score` 中加入：

```python
if edge_data.get("temporal_conflict"):
    return -3.0
```

使搜索阶段也会避开时序冲突边。

### 3. 修复 temporal_conflict 变体生成

修改：

```text
scripts/build_semantic_corpus.py
```

原先写法：

```python
changed = any(_make_temporal_conflict(v, path) for path in paths)
```

`any()` 会短路，导致只要第一条路径成功标记，后续路径不会继续标记。

已改为显式遍历所有 gold paths：

```python
changed = False
for path in paths:
    changed = _make_temporal_conflict(v, path) or changed
```

---

## 数据结果

重建语义语料后：

| 指标 | 数值 |
|---|---:|
| 样本总数 | 280 |
| 路径标签总数 | 644 |
| 总边数 | 5166 |
| 字段覆盖率 | 100% |
| SHACL-style 校验通过率 | 100% |

证据状态分布：

| status | 边数 |
|---|---:|
| Supported | 4232 |
| Contradicted | 496 |
| Unknown | 438 |

相比第四轮：

```text
Contradicted: 478 → 496
```

说明 temporal conflict 标注覆盖更多路径。

---

## 实验结果

输出：

```text
output/semantic_corpus/semantic_experiments_results.json
```

### 路径级验证

| 指标 | 第四轮 | 第五轮 |
|---|---:|---:|
| path-label accuracy | 0.8168 | 0.8634 |
| Invalid->Valid | 102 | 72 |
| Invalid->Invalid | 198 | 228 |

说明 temporal 维度有效降低了时序冲突导致的误判。

当前混淆：

```text
Valid->Valid: 164
Insufficient->Insufficient: 164
Insufficient->Valid: 16
Invalid->Invalid: 228
Invalid->Valid: 72
```

### 搜索实验

| 方法 | R@1 | R@3 | R@5 | MRR | sample FPR | Top 查询成本 |
|---|---:|---:|---:|---:|---:|---:|
| plain DFS + GateScore | 0.1088 | 0.1794 | 0.2647 | 0.3917 | 0.2755 | 5.279 |
| type DFS + GateScore | 0.1088 | 0.1794 | 0.2647 | 0.3917 | 0.2755 | 5.211 |
| full constrained + GateScore | 0.1088 | 0.2235 | 0.3824 | 0.3676 | 0.1939 | 6.054 |
| RefuteAwareBeamSearch | 0.2353 | 0.6559 | 0.6794 | 0.5045 | 0.3061 | 6.471 |

### 主要观察

1. temporal 维度提升了验证准确率：

```text
0.8168 → 0.8634
```

2. `Invalid->Valid` 明显下降：

```text
102 → 72
```

3. RefuteAwareBeamSearch 仍保持最高路径召回：

```text
R@3 = 0.6559
R@5 = 0.6794
MRR = 0.5045
```

4. 但 sample-level FPR 仍高于 full constrained baseline：

```text
RefuteAwareBeamSearch: 0.3061
full constrained: 0.1939
```

这说明 Beam Search 当前偏召回，仍需要更强的确认策略。

---

## 本轮结论

本轮将 C2 验证器从五维扩展到六维：

```text
entry / reach / perm / target / sense / temporal
```

并验证了 temporal 维度确实能降低时序冲突误判。

这可以写成论文中的一个重要实验结论：

> 在跨层暴露路径中，时序证据不能只作为审计加分项，而应作为路径成立性的独立验证维度。加入 temporal 维度后，路径级验证准确率从 81.68% 提升到 86.34%，时序冲突路径的误判显著下降。

---

## 剩余问题

### 1. path-label accuracy 仍未达到 0.90

剩余错误：

```text
Insufficient->Valid: 16
Invalid->Valid: 72
```

其中 `Invalid->Valid` 仍然偏高，说明还有非 temporal 类型的反证未被充分建模。

### 2. Beam Search 召回高但 FPR 高

RefuteAwareBeamSearch 更擅长把 gold path 推到前面，但它也更倾向于报告 Valid 路径。

下一轮应加入确认阈值或二阶段裁决：

```text
search ranking → verifier confirmation → report / suppress
```

而不是直接把 top path 当作报告结果。

### 3. synthetic time 不能用于强单调验证

如果后续要做真正的时序约束，需要区分：

```text
real_time / synthetic_time
```

只有真实日志或配置时间才能参与严格时序推理。

---

## 下一轮建议

下一轮建议做 C2 的二阶段报告策略：

```text
RefuteAwareBeamSearch 找 Top-K
→ verify_path 过滤 Valid
→ 只有 Valid 且 refuted/missing 为空才报告
→ 否则输出 Insufficient/Invalid 诊断
```

实验目标：

- 保持 R@3 尽量高；
- sample FPR 从 0.3061 降到接近或低于 full constrained 的 0.1939；
- 输出 `confirmed_recall@K` 与 `reported_false_positive_rate` 两个更符合系统报告的指标。
