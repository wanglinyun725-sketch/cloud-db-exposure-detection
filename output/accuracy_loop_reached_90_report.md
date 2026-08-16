# Accuracy Loop 达标报告：Path-label Verification ≥ 90%

## 目标

本轮专项 loop 的单一目标是：

```text
将 path-label verification accuracy 提升到 ≥ 90%
```

要求每轮必须：

1. 读取当前 accuracy 与 confusion；
2. 定位最大错误来源；
3. 做最小改动；
4. 重建 semantic corpus；
5. 运行 validator；
6. 运行 `scripts/experiments/run_semantic_experiments.py`；
7. 若达到 90%，停止继续围绕 accuracy 做迭代。

---

## 初始状态

专项 loop 开始前的结果：

```text
path-label accuracy = 0.8634
```

混淆矩阵：

```text
Invalid->Invalid: 228
Valid->Valid: 164
Insufficient->Insufficient: 164
Invalid->Valid: 72
Insufficient->Valid: 16
```

最大错误来源：

```text
Invalid->Valid = 72
```

诊断后发现：

- 这 72 条错误全部来自 `samples_v2` 的 `temporal_conflict` 变体；
- 错误原因不是数据没有 temporal conflict，而是 `MultiDiGraph` 中同一对节点存在多条并行边；
- 例如 `rds_role -> tbl_payments` 同时存在：
  - `has_permission`
  - `accessed`
- 原先 `_temporal_status` 通过 `_get_edge` 只取第一条边，常常拿到 `has_permission`，因此漏掉带 `temporal_conflict=True` 的 `accessed` 边。

---

## 本轮最小改动

修改文件：

```text
src/graph/gate_score.py
```

改动点：

```python
_temporal_status(G, path)
```

从“只检查第一条边”改为：

```text
遍历 MultiDiGraph 中同一 source-target 节点对的所有并行边
```

只要任一并行边存在：

```text
temporal_conflict=True
```

则：

```text
temporal = F
```

这是一个语义修复，不是调参。

---

## 执行验证

执行命令：

```bash
python3 scripts/build_semantic_corpus.py
python3 -m src.data_gen.validator output/semantic_corpus/cloud_db_semantic_corpus.json
python3 scripts/experiments/run_semantic_experiments.py
```

语料构建结果：

| 指标 | 数值 |
|---|---:|
| 样本总数 | 280 |
| path labels | 644 |
| 总边数 | 5166 |
| `status/source/time/confidence/query_cost/raw_evidence` 覆盖率 | 100% |
| SHACL-style 校验通过率 | 100% |

---

## 达标结果

修复后：

```text
path-label accuracy = 0.9752
```

混淆矩阵：

```text
Valid->Valid: 164
Insufficient->Insufficient: 164
Insufficient->Valid: 16
Invalid->Invalid: 300
```

关键变化：

| 指标 | 修复前 | 修复后 |
|---|---:|---:|
| path-label accuracy | 0.8634 | 0.9752 |
| Invalid->Valid | 72 | 0 |
| Invalid->Invalid | 228 | 300 |

目标达成：

```text
0.9752 ≥ 0.90
```

因此已停止专项 accuracy loop。

---

## 对论文可用的结论

可以写入实验章节的结论：

> 在异构云证据图中，同一实体对之间常存在多条并行关系，例如权限授予边和审计访问边共享相同 source-target。若验证器只读取第一条边，会漏掉审计边上的时序冲突证据，导致 temporal-conflict 路径被误判为 Valid。本文将时序验证扩展为对 MultiDiGraph 并行边的全量检查，使 path-label verification accuracy 从 86.34% 提升至 97.52%，并将 Invalid→Valid 错误从 72 条降为 0 条。

这说明：

```text
C1 的异构证据语义化
必须和
C2 的验证器并行边语义处理
共同设计。
```

否则，异构图中的证据会被图结构实现细节吞掉。

---

## 当前剩余错误

修复后仅剩：

```text
Insufficient->Valid = 16
```

这些主要来自旧 `pathbench_60` base 样本中标注为 `Insufficient_Evidence` 的路径，但边证据在语义化后全部为 Supported。

这类问题更像是历史标签与当前语义 schema 不一致，而不是 verifier 规则错误。后续若继续优化，需要回到数据生成器，重建这些 base insufficient 样本的 Unknown 证据，而不是继续改 verifier。

---

## loop 状态

专项 accuracy loop 已在达标后取消：

```text
job_id = 20ed3cf0
status = cancelled
```

注意：此前更广泛的每小时毕设迭代 loop 如果仍存在，并未在本报告中取消。
