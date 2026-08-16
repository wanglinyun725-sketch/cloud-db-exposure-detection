# C1/C2 方法章节草稿

> 本文档用于后续论文正文改写。内容聚焦 C1“异构云证据语义化方法”和 C2“反证感知的部分可见暴露路径搜索与排序方法”。

---

# 第 3 章 面向高敏数据暴露的异构云证据语义化方法

## 3.1 问题背景

云数据库高敏数据暴露路径并不是单一层面的配置问题。一次可能的暴露链通常同时涉及：

- 网络入口是否可达；
- 身份或角色是否可用；
- 权限是否允许访问数据库对象；
- 数据库中是否存在高敏字段；
- 审计日志是否显示真实访问；
- 安全控制项是否存在反证；
- 不同证据是否在时间上自洽。

现有云安全工具通常偏向某一层：IAM 工具更擅长权限传播，资产图工具更擅长资源盘点，敏感数据识别系统更擅长发现字段级敏感标签，但缺少将这些证据统一表达为可验证暴露路径的中间语义。因此，本文首先提出异构云证据语义化方法，将来自配置、权限、网络、数据库对象、识别结果和审计事件的异构证据统一转化为证据语义图。

## 3.2 证据语义图定义

本文将云数据库暴露路径建模为证据语义图：

```text
G = (V, E)
```

其中，`V` 表示云环境中的实体节点，包括网络入口、身份主体、数据库实例、数据库对象、敏感标签、审计事件和控制项等；`E` 表示实体之间的证据关系。

不同于普通知识图谱中的三元组关系，本文将每条边扩展为证据语义边：

```text
 e = (u, r, v, status, source, time, confidence, query_cost, raw_evidence)
```

其中：

| 字段 | 含义 |
|---|---|
| `u` | 源节点 |
| `r` | 关系类型 |
| `v` | 目标节点 |
| `status` | 证据状态，取值为 `Supported / Contradicted / Unknown` |
| `source` | 证据来源，如 IAM 策略、网络规则、数据库 schema、审计日志等 |
| `time` | 证据时间 |
| `confidence` | 证据置信度 |
| `query_cost` | 获取或验证该证据的查询代价 |
| `raw_evidence` | 原始证据引用 |

本文使用三种证据状态：

```text
Supported: 当前证据支持该关系成立
Contradicted: 当前证据明确反驳该关系成立
Unknown: 当前缺少足够证据判断该关系
```

这一设计使得暴露路径不再只是“是否连通”的图搜索问题，而可以表达为“在部分可见证据下，路径是否被支持、被反驳或仍然缺证”的验证问题。

## 3.3 实体与关系类型

本文采用八类节点：

```text
Network, Identity, DBInstance, DBObject,
SensitiveTag, AuditEvent, RiskFinding, Control
```

以及十类基础关系：

```text
can_connect, can_assume, has_permission,
contains, classified_as, accessed, triggered,
has_risk, owns, protected_by
```

这些关系覆盖了云数据库暴露路径中的关键层次：

```text
网络入口 → 身份权限 → 数据库实例 → 数据库对象 → 高敏字段 → 审计/风险证据
```

## 3.4 异构证据归一化

不同来源的原始证据字段并不一致。例如，网络规则更关注端口和 CIDR，IAM 策略更关注主体、动作和资源，数据库识别结果更关注表、列和敏感规则，审计日志更关注访问时间和行为。为使这些证据可用于统一路径验证，本文设计了证据语义归一化过程。

对于每条原始边，归一化函数补齐证据语义字段：

```text
Normalize(e_raw) → e_semantic
```

若原始数据缺少某些字段，则采用规则化补全：

- `source` 由边类型推断，如 `can_connect → network`，`has_permission → iam`，`classified_as → dlp`；
- `confidence` 默认继承 `strength`；
- `raw_evidence` 默认继承 `evidence_ref`；
- `query_cost` 根据关系类型设置默认代价；
- `time` 若缺失，则在构造语料时注入可追踪的时间字段。

## 3.5 反证、缺证与时序变体构造

为了评估方法在部分可见条件下的鲁棒性，本文构造三类语义变体：

1. **缺证变体**：将关键硬证据边标记为 `Unknown`，模拟权限、连通性或身份链路不可见；
2. **反证变体**：将关键硬证据边标记为 `Contradicted`，模拟 deny 权限、网络不可达或前置条件不满足；
3. **时序冲突变体**：将关键路径边标记为 `temporal_conflict=True`，模拟审计行为或配置变更在时间上不自洽。

本文进一步区分路径级标签与样本级标签：

```text
path_labels: 描述某条路径是 Valid / Invalid / Insufficient
sample_label: 描述整个样本是否仍存在有效暴露路径
```

这一设计避免将“某条路径不成立”和“整个样本无风险”混淆。

## 3.6 数据质量校验

本文为语义证据图设计结构与语义校验规则，检查：

- 节点类型是否合法；
- 边类型是否合法；
- 边的 source/target 是否引用已定义节点；
- `strength / confidence` 是否位于 `[0,1]`；
- 是否存在入口节点和高敏目标节点；
- 证据语义字段是否合法；
- `time` 是否可解析；
- `status` 是否属于三值状态集合。

实验中，构造后的语义语料共包含 308 个样本、672 条路径级标签、5456 条证据边，六类关键证据字段覆盖率均达到 100%，并全部通过校验。

---

# 第 4 章 反证感知的部分可见暴露路径搜索与排序方法

## 4.1 问题定义

给定证据语义图 `G`、入口节点集合 `S` 和高敏目标节点集合 `T`，暴露路径搜索任务是在部分可见证据下发现从入口到高敏目标的 Top-K 候选路径。

与传统 DFS 或最短路搜索不同，本文关注的路径不仅需要结构连通，还需要在证据层面满足：

- 没有被明确反证；
- 关键证据缺失较少；
- 查询成本可控；
- 更可能到达高敏目标；
- 时间证据自洽。

因此，本文将路径搜索目标从“枚举所有结构合法路径”改为“优先扩展更可能被验证为有效暴露路径的候选”。

## 4.2 三值路径验证器

本文首先定义路径级三值验证器。对于路径 `P`，验证器从六个维度计算证据状态：

```text
entry, reach, perm, target, sense, temporal
```

每个维度取值：

```text
T / F / U
```

分别表示：

- `T`：该维度存在支持证据；
- `F`：该维度存在反证；
- `U`：该维度证据未知。

路径状态定义为：

```text
Invalid       if any dimension = F
Insufficient  if no dimension = F and any dimension = U
Valid         otherwise
```

其中，`temporal` 维度用于捕获时序冲突。当路径上的并行边中存在 `temporal_conflict=True` 时，`temporal=F`。

由于异构图中同一对节点可能存在多条并行边，例如同一主体到同一表同时存在权限边和审计访问边，本文的时序验证会遍历 MultiDiGraph 中同一 source-target 对的全部并行边，避免因只读取第一条边而漏掉反证证据。

## 4.3 反证感知 Beam Search

本文提出 RefuteAwareBeamSearch。该方法在路径扩展阶段就引入证据状态，而不是在 DFS 枚举结束后再用 GateScore 排序。

对于扩展边 `e`，定义边得分：

```text
score(e) =
  - large_penalty,  if status(e)=Contradicted or temporal_conflict(e)
  - medium_penalty, if status(e)=Unknown
  positive_score,  if status(e)=Supported
```

对于部分路径 `P`，扩展优先级综合考虑：

```text
Priority(P) = evidence_score(P)
            + target_bonus(P)
            - query_cost(P)
            - path_length_penalty(P)
```

搜索过程如下：

1. 从入口节点初始化 frontier；
2. 扩展符合类型转移约束的边；
3. 根据证据状态、查询成本和目标价值计算优先级；
4. 每层只保留前 `beam_width` 个候选；
5. 到达高敏目标后，使用完整路径验证器和风险分数进行最终排序。

## 4.4 与 GateScore 的关系

原 GateScore 用于融合 entry、reach、perm、target、sense 五维风险强度。但 GateScore 同时承担“路径是否成立”和“风险严重度排序”会导致语义混淆。

本文将两者拆分：

```text
T/F/U verifier: 判断路径 Valid / Invalid / Insufficient
GateScore: 对候选路径进行风险严重度辅助排序
```

即：路径成立性由证据状态决定，风险强度由连续分数辅助排序。

## 4.5 实验结果摘要

在语义语料上，RefuteAwareBeamSearch 与三类基线进行对比：

- Plain DFS + GateScore；
- Type-constrained DFS + GateScore；
- Full-constrained DFS + GateScore。

结果显示，RefuteAwareBeamSearch 在 Top-K 召回上明显优于基线：

| 方法 | R@1 | R@3 | R@5 | MRR |
|---|---:|---:|---:|---:|
| Full-constrained DFS + GateScore | 0.1088 | 0.2235 | 0.3824 | 0.3676 |
| RefuteAwareBeamSearch | 0.2353 | 0.6882 | 0.7235 | 0.5320 |

该 all-corpus 开发结果说明 Beam 搜索整体能够提高 Top-K 召回，但现有消融尚未
证明反证、时序和查询成本各自具有独立贡献。最终结论应以 group split 和来源
分层实验为准。

## 4.6 方法边界

当前语义语料中的反证、缺证和时序冲突仍主要由规则构造，不能直接等价于真实云环境中的入侵轨迹。本文实验结果应表述为：

> 在当前构造语料的 23 个 held-out 检索样本上，RefuteAwareBeamSearch 对
> Full-constrained 基线显著提高 R@3 与 R@5；该结果尚不能证明跨来源泛化。

后续可进一步接入 SDDP 真实证据切片，通过真实资产、真实连通性、真实识别结果和可控威胁注入增强外部有效性。
