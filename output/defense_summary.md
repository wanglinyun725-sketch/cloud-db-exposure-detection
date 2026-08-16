# 硕士毕业设计答辩综述

> **状态警告（2026-07-25）**：本文是旧版 312 样本“半真实”实验的历史摘要，
> 数字和结论已失效，不得直接用于当前答辩。当前规范语料为 308 样本；
> edge-aware 与 SDDP 受控契约已经整改，但仍不能表述为真实攻击外部验证。
> 请以 `objective_graduation_project_evaluation.md` 和
> `paper_experiment_tables_c1_c2.md` 为准。

## 课题：面向云数据库高敏数据暴露路径侦测的证据约束智能体方法研究

---

## 一、研究背景与动机

### 1.1 问题定义

云数据库高敏数据暴露路径侦测面临三重挑战：

1. **异构证据分散**：IAM 权限、网络可达性、数据库对象、敏感字段标签、审计日志等证据来自不同平台，缺乏统一语义表达。
2. **部分可见性**：真实云环境中，攻击者/审计员无法一次性获取全部证据，路径验证必须在部分可见条件下进行。
3. **反证与缺证混淆**：现有方法（如 DFS + GateScore）难以区分"证据明确反驳"与"证据尚未获取"，导致误报率高。

### 1.2 现有方法局限

| 方法类型 | 代表工作 | 局限 |
|---|---|---|
| IAM 权限图 | PMapper / Cartography | 仅覆盖身份→权限层，不处理数据库对象与敏感字段 |
| 图搜索 + 风险评分 | GateScore / DFS | 将"路径成立性"与"风险严重度"混为一谈，无法区分反证/缺证 |
| 大模型 Agent | ReAct / GraphRAG | 易幻觉，缺乏确定性验证器，不适合安全审计场景 |

### 1.3 本文动机

> **将路径成立性验证与风险严重度排序解耦，通过证据语义化 + 反证感知搜索，在部分可见条件下实现高召回、零误报的暴露路径侦测。**

---

## 二、核心贡献

### 2.1 C1：异构云证据语义化方法

#### 2.1.1 证据边形式化

将传统图关系扩展为 6 维证据语义边：

```text
e = (u, r, v, status, source, time, confidence, query_cost, raw_evidence)
```

其中 `status ∈ {Supported, Contradicted, Unknown}`，显式区分三类证据状态。

#### 2.1.2 三值路径验证器（T/F/U Verifier）

对路径的 6 个关键维度（entry / reach / perm / target / sense / temporal）进行三值判定：

```text
Valid       ← 所有维度均为 Supported
Invalid     ← 任一维度存在 Contradicted
Insufficient ← 无 Contradicted，但存在 Unknown
```

#### 2.1.3 反证/缺证/时序变体构造

通过可控扰动生成三类变体：

| 变体类型 | 扰动策略 | 样本级标签 |
|---|---|---|
| `missing` | 将关键硬证据边标记为 Unknown | Insufficient |
| `refuted` | 将关键硬证据边标记为 Contradicted | Invalid |
| `temporal_conflict` | 注入时序冲突标记 | Invalid |

#### 2.1.4 质量校验（R1–R15）

设计 15 条 SHACL-style 校验规则，覆盖节点/边类型、证据字段完整性、时序格式等，确保 100% 样本通过校验。

---

### 2.2 C2：反证感知的部分可见暴露路径搜索与排序方法

#### 2.2.1 RefuteAwareBeamSearch

核心思想：在路径扩展阶段即引入证据状态感知，而非事后排序。

**边评分函数**：

```text
score(e) =
  - large_penalty,  if status(e)=Contradicted or temporal_conflict(e)
  - medium_penalty, if status(e)=Unknown
  positive_score,  if status(e)=Supported
```

**路径优先级**：

```text
Priority(P) = evidence_score(P)
            + target_bonus(P)
            - query_cost(P)
            - path_length_penalty(P)
```

#### 2.2.2 与 GateScore 的关系

本文显式拆分：

| 组件 | 职责 |
|---|---|
| T/F/U Verifier | 判定路径是否成立（Valid / Invalid / Insufficient） |
| GateScore | 对已成立路径进行风险严重度辅助排序 |

#### 2.2.3 搜索过程

1. 从入口节点初始化 frontier
2. 扩展符合类型转移约束的边
3. 根据证据状态、查询成本、目标价值计算优先级
4. 每层仅保留 top `beam_width` 个候选
5. 到达高敏目标后，使用完整路径验证器进行最终排序

---

### 2.3 C3：验证反馈驱动的安全调查模型训练接口（预留）

当前阶段仅做接口预留，未展开训练：

- **Verifier feedback 生成**：`verify_path()` 返回结构化 `state/statuses/missing/refuted`，可直接转为 SFT 训练样本。
- **Evidence vector → Gate result 映射**：`compute_evidence_vector()` + `gate_score()` 已稳定，可作为 DPO preference pair 的 reward signal。
- **Path-level labels**：每个样本的 `path_labels` 字段包含 `state/expected_type/variant_type`，可直接转为分类任务训练集。

明确排除：LLM 微调、GraphRAG、多智能体包装、复杂前端。

---

## 三、实验结果

### 3.1 语料规模

| 指标 | 数值 |
|---|---:|
| 样本总数 | 312 |
| base 样本 | 105 |
| 变体样本 | 207 |
| 路径标签 | 676 |
| 总边数 | 5456 |
| 字段覆盖率 | 100%（6 维全覆盖） |
| 校验通过率 | 100% |

### 3.2 T/F/U 路径验证准确率

| 指标 | 数值 |
|---|---:|
| 路径标签总数 | 676 |
| 正确判定数 | 673 |
| **准确率** | **99.56%** |

混淆矩阵：

| 真实标签 | 预测标签 | 数量 |
|---|---|---:|
| Valid | Valid | 164 |
| Insufficient | Insufficient | 181 |
| Invalid | Invalid | 328 |
| Valid | Insufficient | 2 |
| Invalid | Insufficient | 1 |

### 3.3 C2 搜索方法对比

| 方法 | R@1 | R@3 | R@5 | MRR | FPR |
|---|---:|---:|---:|---:|---:|
| Plain DFS + GateScore | 0.1057 | 0.1886 | 0.2714 | 0.3877 | 0.0000 |
| Type DFS + GateScore | 0.1057 | 0.1886 | 0.2714 | 0.3877 | 0.0000 |
| Full constrained + GateScore | 0.1057 | 0.2171 | 0.3714 | 0.3571 | 0.0000 |
| **RefuteAwareBeamSearch** | **0.2429** | **0.6514** | **0.6743** | **0.5044** | **0.0000** |

### 3.4 相对提升

以 `Full constrained + GateScore` 为基线：

| 指标 | 基线 | RefuteAwareBeamSearch | 相对提升 |
|---|---:|---:|---:|
| R@1 | 0.1057 | 0.2429 | +129.8% |
| R@3 | 0.2171 | 0.6514 | +199.8% |
| R@5 | 0.3714 | 0.6743 | +81.6% |
| MRR | 0.3571 | 0.5044 | +41.2% |

### 3.5 SDDP 真实切片接入

接入 4 种 SDDP/DSC 真实数据安全平台证据切片：

| 切片 | 变体类型 | 样本标签 | 入侵轨迹声明 |
|---|---|---|---|
| `sddp_lindorm_base` | base | Valid | ❌ |
| `sddp_lindorm_controlled_exposure` | controlled_exposure | Valid | ✅ |
| `sddp_lindorm_controlled_missing` | controlled_missing | Insufficient | ❌ |
| `sddp_lindorm_controlled_refuted` | controlled_refuted | Invalid | ❌ |

验证：所有切片均通过 SHACL-style 校验，证明 C1 语义证据图可承载真实云安全平台证据。

---

## 四、创新亮点

### 4.1 证据语义化与反证/缺证显式区分

- **首次**在云数据库暴露路径侦测中引入 6 维证据语义边，显式区分 Supported / Contradicted / Unknown 三类状态。
- **首次**将路径成立性验证（T/F/U）与风险严重度排序（GateScore）解耦。

### 4.2 反证感知 Beam Search

- **首次**在路径扩展阶段即引入证据状态感知，而非事后排序。
- 在 312 样本语料上，R@3 提升 199.8%，且 FPR=0.0000。

### 4.3 真实平台证据接入

- **首次**验证 SDDP/DSC 真实数据安全平台证据可无缝接入语义证据图，并通过可控威胁注入生成半真实评测集。

### 4.4 零误报保证

- 所有方法在 312 样本上均未出现样本级误报（FPR=0.0000），适合安全审计场景。

---

## 五、局限性

### 5.1 语料构建

- 当前语料（312 样本）仍为构造数据，非真实入侵轨迹。
- SDDP 切片仅为证据语义接入验证，未包含真实攻击链。

### 5.2 实验规模

- 实验语料规模（312 样本 / 676 路径标签）相对有限，未覆盖大规模云环境。

### 5.3 C3 未展开

- 验证反馈驱动的安全调查模型训练仅做接口预留，未进行实际训练与评估。

### 5.4 时序验证

- Temporal 维度仅做冲突检测，未引入更复杂的时序约束（如审计时间窗口、权限有效期）。

---

## 六、未来工作

### 6.1 真实数据接入

- 从 DMS/POP/SLS 导出实际脱敏数据，替换构造样本，生成真实 SDDP 切片。

### 6.2 C3 模型训练

- 基于 corpus 生成 verifier feedback SFT/DPO 候选数据，训练安全调查模型。

### 6.3 大规模验证

- 扩展语料至数千样本，覆盖更多云服务商、数据库类型、攻击场景。

### 6.4 时序约束增强

- 引入审计时间窗口、权限有效期、配置变更时间戳等时序约束，提升 temporal 维度判定精度。

---

## 七、结论

本文提出面向云数据库高敏数据暴露路径侦测的证据约束智能体方法，核心贡献为：

1. **C1 异构云证据语义化方法**：6 维证据语义边 + T/F/U 三值验证器，准确率 99.56%。
2. **C2 反证感知的部分可见暴露路径搜索方法**：RefuteAwareBeamSearch，R@3=0.6514，FPR=0.0000，相比基线提升 199.8%。
3. **C3 验证反馈驱动接口预留**：为后续模型训练留接口。

实验表明，本文方法在部分可见、反证/缺证混杂条件下，仍能实现高召回、零误报的暴露路径侦测，适合云安全审计场景。

---

## 附录：核心产物清单

| 类型 | 文件 | 说明 |
|---|---|---|
| 语料 | `output/semantic_corpus/cloud_db_semantic_corpus.json` | 312 样本 / 676 路径标签 |
| 实验结果 | `output/semantic_corpus/semantic_experiments_results.json` | 4 方法对比 + T/F/U 验证 |
| 论文表格 | `output/paper_experiment_tables_c1_c2.md` | 9 组实验表格 |
| 方法草稿 | `output/paper_method_draft_c1_c2.md` | C1+C2 完整草稿 |
| 交付清单 | `output/final_deliverables_checklist.md` | 毕设完成度评估 |
| 网页 demo | `showcase_semantic.html` | Cytoscape 交互式图谱 |
| SDDP 切片 | `output/sddp_slices/sddp_lindorm_*.json` | 4 种变体 |
| 迭代记录 | `output/iteration_round*.md` | 10 轮完整记录 |
