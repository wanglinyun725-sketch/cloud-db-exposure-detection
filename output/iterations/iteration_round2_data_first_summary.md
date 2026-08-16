# 第二轮迭代记录：数据优先的 C1 语义语料构建

## 为什么需要这一轮

上一轮先做了证据语义字段、T/F/U 验证和 Exp5 排序实验，但用户指出一个关键问题：

> 应该先把数据弄好，再做方法和实验。

这个批评成立。上一轮的 `pathbench_60_semantic.json` 只是把 60 条生成数据补字段，仍然存在三大不足：

1. 只覆盖单一生成数据源；
2. `time` 覆盖率为 0%；
3. 缺少系统化的 Refuted / Missing / Temporal Conflict 变体。

因此第二轮改为数据优先，目标是形成 C1 的最小可用语义语料。

## 本轮目标

构建一个统一语义语料：

```text
原始数据源
→ 统一 evidence semantic schema
→ base / refuted / missing / temporal_conflict 变体
→ 数据质量统计
→ SHACL-style 校验通过
```

## 输入数据

本轮合并三份已有数据：

| 数据源 | 原始用途 |
|---|---|
| `data/pathbench_60.json` | 参数化生成样本 |
| `data/pathbench_cloudgoat.json` | CloudGoat 真实靶场转化样本 |
| `data/verification_set/samples_v2.json` | 24 个代表验证案例，含 `observed_at` |

## 本轮实现

新增脚本：

```text
scripts/build_semantic_corpus.py
```

功能：

1. 合并三份数据源；
2. 为每条边补齐统一字段：
   - `status`
   - `source`
   - `time`
   - `confidence`
   - `query_cost`
   - `raw_evidence`
3. 对缺失时间的数据注入 synthetic timestamp；
4. 为有 gold path 的正例样本生成：
   - `refuted` 变体；
   - `missing` 变体；
   - `temporal_conflict` 变体；
5. 统计字段覆盖率、状态分布、来源分布和样本分布。

输出：

```text
output/semantic_corpus/cloud_db_semantic_corpus.json
output/semantic_corpus/cloud_db_semantic_corpus_stats.json
```

## 校验器调整

更新 `src/data_gen/validator.py`：

1. `scenario` 从只允许 S1-S6 改为只要求非空，支持 CB/DS/RCE/RDS/CG 等多来源场景；
2. `expected_type` 扩展支持：
   - `Refuted`
   - `Invalid_Path`
3. R11 从“必须有 gold_paths”调整为“必须有 gold_paths 或 expected_state”，允许 CloudGoat 这类外部样本以状态监督进入语料；
4. R15 校验证据语义字段合法性。

更新 `src/graph/evidence_semantics.py`：

- `source` 从封闭枚举改为非空 provenance 字符串，适配多源证据，如 `iam_policy / audit_log / route_table / cloudgoat_ref / variant_perm`。

## 数据结果

统一语义语料统计：

| 指标 | 数值 |
|---|---:|
| 总样本数 | 280 |
| base 样本 | 104 |
| 变体样本 | 176 |
| 总边数 | 5166 |
| `status` 覆盖率 | 100% |
| `source` 覆盖率 | 100% |
| `time` 覆盖率 | 100% |
| `confidence` 覆盖率 | 100% |
| `query_cost` 覆盖率 | 100% |
| `raw_evidence` 覆盖率 | 100% |

### 样本变体分布

| variant_type | 数量 |
|---|---:|
| base | 104 |
| missing | 68 |
| refuted | 68 |
| temporal_conflict | 40 |

### 期望状态分布

| expected_state | 数量 |
|---|---:|
| Valid | 83 |
| Invalid | 108 |
| Insufficient | 89 |

### 原始数据贡献

| raw_dataset | 数量 |
|---|---:|
| `data:pathbench_60` | 164 |
| `data:pathbench_cloudgoat` | 20 |
| `data:verification_set:samples_v2` | 96 |

### 证据状态分布

| status | 边数 |
|---|---:|
| Supported | 4990 |
| Contradicted | 108 |
| Unknown | 68 |

## 校验结果

命令：

```bash
python3 -m src.data_gen.validator output/semantic_corpus/cloud_db_semantic_corpus.json
```

结果：

| 样本数 | 通过 | 失败 | 通过率 |
|---:|---:|---:|---:|
| 280 | 280 | 0 | 100% |

## 当前数据是否已经“足够好”

还不够，但已经比上一轮更接近 C1。

现在已经解决：

- 多来源统一；
- 关键 evidence 字段 100% 覆盖；
- 反证/缺证/时序冲突变体；
- 统一校验闭环。

仍然不足：

1. CloudGoat 20 条仍然缺少人工 gold path；
2. synthetic timestamp 只是工程补齐，不是真实日志时间；
3. temporal_conflict 目前是规则生成，真实性不足；
4. Refuted/Missing 变体主要沿 gold path 单边扰动，复杂反证还不够；
5. 还没有基于该 280 条语料重新运行 C2 搜索实验。

## 这轮之后的正确顺序

下一轮不应再回到旧 `pathbench_60.json` 上做实验，而应：

1. 让 Exp5 支持读取 `semantic_corpus/cloud_db_semantic_corpus.json`；
2. 实现 `RefuteAwareBeamSearch`；
3. 在 280 条语义语料上评估：
   - Valid / Invalid / Insufficient 三分类；
   - Recall@K / MRR；
   - 查询成本；
   - 反证识别率；
   - 缺证识别率；
   - temporal conflict 识别率。

## loop 状态

`/loop` 已调度，当前任务 ID：

```text
9c3a0724
```

频率：每 60 分钟一次。

说明：用户最初输入 `45m`，但 cron 无法均匀表达 45 分钟间隔，否则会出现 45/15 分钟交替，因此已按最近干净间隔调度为每 60 分钟。

只要当前 Qoder 会话进程仍在，下一轮会自动触发；也可以手动继续下一轮。
