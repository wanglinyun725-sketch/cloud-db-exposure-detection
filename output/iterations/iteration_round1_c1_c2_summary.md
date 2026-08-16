# 第一轮迭代记录：C1 证据语义化与 C2 反证感知排序

## 本轮目标

将当前 CloudDB-PathBench 从“路径枚举 + GateScore 判定”推进到 C1/C2 的最小闭环：

- C1：为旧样本补齐统一证据语义字段，形成可校验的 evidence semantic layer；
- C2：将路径成立性从 GateScore 中拆出，新增 T/F/U 三值验证，并以反证、缺证、查询成本参与路径排序；
- 实验：新增路径级 IR 指标，比较 GateScore 排序与反证感知排序。

## 本轮实现

### C1：证据语义化

新增 `src/graph/evidence_semantics.py`，为每条边统一补齐：

| 字段 | 含义 |
|---|---|
| `status` | `Supported / Contradicted / Unknown` |
| `source` | 证据来源，如 `network / iam / db_schema / dlp / audit / policy` |
| `time` | 证据时间，兼容 `observed_at / t` |
| `confidence` | 证据置信度，默认继承 `strength` |
| `query_cost` | 查询或验证该证据的代价 |
| `raw_evidence` | 原始证据引用，默认继承 `evidence_ref` |

`src/graph/graph_builder.py` 已在加载图时自动补齐上述字段，保证旧 JSON 数据无需改动即可参与新实验。

新增 `scripts/semanticize_evidence.py`，可将旧数据集显式转换为语义化数据集。

本轮生成：

- `output/pathbench_60_semantic.json`
- `output/pathbench_60_semantic_stats.json`

语义化统计：

| 指标 | 数值 |
|---|---:|
| 总边数 | 590 |
| `status` 覆盖率 | 100% |
| `source` 覆盖率 | 100% |
| `confidence` 覆盖率 | 100% |
| `query_cost` 覆盖率 | 100% |
| `raw_evidence` 覆盖率 | 100% |
| `time` 覆盖率 | 0% |

`time` 覆盖率为 0%，说明生成数据缺少时序证据，是下一轮 C1 的重点问题。

### C1 校验

扩展 `src/data_gen/validator.py`，新增 R15 语义字段校验：

- `status` 枚举合法；
- `source` 枚举合法；
- `confidence ∈ [0,1]`；
- `query_cost ≥ 0`；
- `time` 若存在必须为 ISO-8601。

语义化后的 `pathbench_60_semantic.json` 校验结果：

| 样本数 | 通过 | 失败 | 通过率 |
|---:|---:|---:|---:|
| 60 | 60 | 0 | 100% |

## C2：三值验证与反证感知排序

在 `src/graph/gate_score.py` 中新增：

- `evidence_status(G, path, dim)`：输出 `T/F/U`；
- `verify_path(G, path)`：输出 `Valid / Invalid / Insufficient`；
- `missing`：缺证维度列表；
- `refuted`：反证维度列表。

新的职责划分：

```text
verify_path: 判断路径是否成立
GateScore: 在路径成立或候选路径中做风险严重度排序
```

这避免继续把“路径成立性”和“风险强度”混在一个 GateScore 公式里。

新增 `src/eval/metrics.py`，提供：

- Recall@K；
- Precision@K；
- MRR；
- Exact Match；
- Target Recall@K。

新增 Exp5：反证/缺证感知路径排序。

排序目标：

```text
score(P) = state_weight
         + GateScore(P)
         - missing_penalty
         - refuted_penalty
         - query_cost_penalty
         - path_length_penalty
```

## 实验结果

实验脚本：

```bash
python3 scripts/experiments/run_experiments.py
```

结果写入：

```text
output/experiments_results.json
```

### Exp5：路径级 IR 指标

| 方法 | Recall@1 | Recall@3 | MRR | Precision@3 | Target Recall@1 | Target Recall@3 | 平均候选路径 | Top 查询成本 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| GateScore 排序 | 0.0833 | 0.1167 | 0.2141 | 0.0389 | 0.6667 | 0.8333 | 7.533 | 5.983 |
| 反证感知排序 | 0.1333 | 0.2000 | 0.2903 | 0.0667 | 1.0000 | 1.0000 | 7.533 | 6.667 |

### 主要观察

1. 反证感知排序相比 GateScore 排序有明显提升：
   - Recall@1 从 0.0833 提升到 0.1333；
   - Recall@3 从 0.1167 提升到 0.2000；
   - MRR 从 0.2141 提升到 0.2903；
   - Target Recall@1 从 0.6667 提升到 1.0000。

2. 代价也上升：
   - Top 查询成本从 5.983 上升到 6.667。

3. 当前方法仍然只是“排序增强”，还不是完整的搜索算法：
   - 候选路径仍来自 plain DFS；
   - 反证/缺证只参与 ranking，没有参与 frontier expansion；
   - 需要下一轮推进到 evidence-aware beam search / A* search。

## 本轮结论

本轮已经形成第一版可写入论文的 C1/C2 最小闭环：

```text
旧图数据 → 证据语义化 → T/F/U 验证 → 反证感知排序 → 路径级 IR 指标
```

它证明了一个初步结论：

> 相比只用 GateScore 进行风险排序，引入反证、缺证和查询成本信息后，候选路径排序在 Recall@K、MRR 和高敏终点命中率上均有提升，但需要付出更高的查询成本。

## 下一轮问题

下一轮应重点解决三件事：

1. **C1 时序证据不足**
   - 当前 `time` 覆盖率为 0%；
   - 需要从 `samples_v2.json` 的 `observed_at` 和 AuditEvent 节点中传播时间；
   - 为生成数据注入合理时间戳，支持时序一致性实验。

2. **C2 还停留在排序，不是搜索**
   - 当前候选路径仍由 plain DFS 生成；
   - 下一轮应实现 `RefuteAwareBeamSearch`，在扩展阶段就惩罚反证、缺证成本和查询成本；
   - 与 plain DFS / constrained DFS / GateScore ranking 比较扩展节点数和 Recall@K。

3. **反证数据仍不够真实**
   - 现有反证主要来自低 strength 或扰动；
   - 下一轮应构造显式 `Contradicted` 边，如 deny 权限、私网不可达、敏感标签缺失、时间顺序冲突。

## 下一轮建议验收指标

- `time` 覆盖率从 0% 提升到至少 50%；
- 新增 `RefuteAwareBeamSearch`；
- 在 Recall@3 不低于当前 0.20 的前提下，平均候选路径或扩展边数下降；
- 输出 Invalid / Insufficient 的三分类准确率表。
