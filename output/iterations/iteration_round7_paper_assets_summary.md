# 第七轮迭代记录：C1/C2 论文表格与方法草稿固化

## 本轮目标

经过前几轮迭代，C1/C2 已经具备：

- 统一语义语料；
- T/F/U 三值验证器；
- RefuteAwareBeamSearch；
- 语义实验结果；
- accuracy 与 FPR 的稳定结果。

本轮不再继续刷指标，而是将已有结果固化为论文可直接使用的材料。

---

## 本轮输入

读取：

```text
output/semantic_corpus/cloud_db_semantic_corpus_stats.json
output/semantic_corpus/semantic_experiments_results.json
```

当前核心结果：

```text
samples_total = 308
path_labels_total = 672
path-label accuracy = 1.0000
RefuteAwareBeamSearch R@3 = 0.6559
RefuteAwareBeamSearch MRR = 0.5045
sample-level FPR = 0.0000
```

---

## 本轮产物 1：论文实验表格

新增：

```text
output/paper_experiment_tables_c1_c2.md
```

包含 9 组表格：

1. 语义语料规模统计；
2. 样本变体分布；
3. 样本级标签分布；
4. 路径级标签分布；
5. 证据语义字段覆盖率；
6. 证据状态分布；
7. T/F/U 路径验证结果；
8. 路径搜索对比实验；
9. 相对提升。

其中核心对比表：

| 方法 | R@1 | R@3 | R@5 | MRR | P@3 | Sample FPR |
|---|---:|---:|---:|---:|---:|---:|
| Plain DFS + GateScore | 0.1088 | 0.1794 | 0.2647 | 0.3917 | 0.2010 | 0.0000 |
| Type-constrained DFS + GateScore | 0.1088 | 0.1794 | 0.2647 | 0.3917 | 0.2010 | 0.0000 |
| Full-constrained DFS + GateScore | 0.1088 | 0.2235 | 0.3824 | 0.3676 | 0.2353 | 0.0000 |
| RefuteAwareBeamSearch | 0.2353 | 0.6559 | 0.6794 | 0.5045 | 0.2304 | 0.0000 |

相对 full-constrained baseline：

```text
R@3: +193.5%
R@5: +77.7%
MRR: +37.2%
Top query cost: +3.6%
```

---

## 本轮产物 2：C1/C2 方法章节草稿

新增：

```text
output/paper_method_draft_c1_c2.md
```

内容覆盖：

### C1：异构云证据语义化方法

包括：

- 问题背景；
- 证据语义图定义；
- 证据边形式化：

```text
e = (u, r, v, status, source, time, confidence, query_cost, raw_evidence)
```

- 三值证据状态：

```text
Supported / Contradicted / Unknown
```

- 节点与关系类型；
- 异构证据归一化；
- 反证、缺证与时序变体构造；
- 数据质量校验。

### C2：反证感知路径搜索方法

包括：

- 问题定义；
- 六维 T/F/U 验证器：

```text
entry / reach / perm / target / sense / temporal
```

- 路径状态定义：

```text
Invalid       if any dimension = F
Insufficient  if no F and any U
Valid         otherwise
```

- RefuteAwareBeamSearch 搜索过程；
- GateScore 与 verifier 的职责拆分；
- 实验摘要；
- 方法边界。

---

## 本轮关键写作提醒

### 1. 不要把 accuracy=1.0 作为真实泛化能力

应写成：

```text
语义一致性验证集上的实现一致性结果
```

不应写成：

```text
真实云环境路径验证准确率 100%
```

### 2. 主结果应强调搜索指标

论文主结果更应强调：

```text
R@K / MRR / Query Cost / FPR
```

而不是单独强调 accuracy。

### 3. FPR=0 也要谨慎表述

应写为：

```text
在构造的语义一致评测集上，样本级误报为 0。
```

不能写成真实云环境零误报。

---

## 下一轮建议

当前 C1/C2 已经有可写内容。下一轮建议三选一：

### 方向 A：生成答辩图表

生成：

- C1 证据语义图 schema 图；
- C2 RefuteAwareBeamSearch 流程图；
- 实验指标柱状图；
- 与 DFS/GateScore 对比图。

### 方向 B：接 SDDP real evidence slice

从 SDDP 知识文档出发，构造一个真实证据切片 schema：

```text
data_instance_source
sys_data_limit
dsc_identify_task_asset
DescribeDataObjects
SLS task_detect
```

输出到 C1 semantic graph 格式，用于 case study。

### 方向 C：为 C3 生成训练样本

基于当前 verifier 和 semantic corpus 生成：

```text
state → action → verifier feedback
```

为后续 SFT/DPO 做准备。

---

## 本轮结论

本轮将前几轮代码和实验结果转化为论文可用资产：

```text
实验表格 + 方法章节草稿
```

这标志着 C1/C2 已经从“代码实验”进入“论文组织”阶段。
