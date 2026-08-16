# 最终交付清单与毕设完成度评估

## 项目总览

**课题**：面向云数据库高敏数据暴露路径侦测的证据约束智能体方法研究

**核心贡献**：
- **C1**：异构云证据语义化方法（6 维证据边 + T/F/U 三值验证器）
- **C2**：反证感知的部分可见暴露路径搜索与排序方法（RefuteAwareBeamSearch）
- **C3**：验证反馈驱动的安全调查模型训练接口（仅预留，未展开）

---

## C1/C2 完成度评估

### ✅ 已稳定交付

| 模块 | 产物 | 状态 |
|---|---|---|
| 证据语义 schema | `src/graph/evidence_semantics.py` | ✅ 100% 字段覆盖 |
| 语料构建脚本 | `scripts/build_semantic_corpus.py` | ✅ 308 样本 / 672 路径标签 |
| 数据质量校验 | `src/data_gen/validator.py` (R1–R15) | ✅ 100% 通过率 |
| 三值验证器 | `src/graph/gate_score.py` (6 维 T/F/U) | ✅ 672/672 语义一致性检查通过 |
| RefuteAwareBeamSearch | `src/graph/refute_aware_search.py` | ✅ test R@3=0.6923 / hard_test R@3=0.6600 |
| 消融实验 | `scripts/experiments/run_ablation_study.py` | ✅ beam_width=4 的开发集 R@3/R@5 最优 |
| 分组主实验 | `output/dataset_v1/semantic_experiments_by_split.json` | ✅ group split，无同源泄漏 |
| 消融报告 | `output/semantic_corpus/ablation_study_report.md` | ✅ 参数选择依据详细说明 |
| 迭代报告 | `output/iteration_round11_optimization_summary.md` | ✅ 优化前后对比 |
| 统计显著性检验 | `scripts/experiments/run_statistical_tests.py` | ✅ 样本级 bootstrap + 配对置换检验 + Holm 校正 |
| 统计检验结果 | `output/semantic_corpus/statistical_tests_results.json` | ✅ R@3/R@5 显著（Holm p=0.0068/0.0154），其余指标未显著 |
| 来源稳健性检验 | `output/semantic_corpus/source_robustness_results.json` | ⚠️ 五项增益均存在显著来源异质性 |
| 案例研究分析 | `scripts/experiments/run_case_study_analysis.py` | ✅ 308 样本分析，15 个典型案例，验证三个核心能力 |
| 案例分析结果 | `output/semantic_corpus/case_study_analysis.json` | ✅ 时序冲突、反证、缺证案例详细分析 |
| 案例研究报告 | `output/paper_case_study_analysis.md` | ✅ 论文可用的定性分析报告 |
| 网页 demo | `showcase_semantic.html` (Cytoscape) | ✅ 可缩放/拖拽/高亮 |
| SDDP 真实切片接入 | `scripts/build_sddp_evidence_slice.py` | ✅ 4 种变体生成 |
| 论文表格 | `output/paper_experiment_tables_c1_c2.md` | ✅ 含 split 主实验、消融与统计检验 |
| 方法章节草稿 | `output/paper_method_draft_c1_c2.md` | ✅ C1+C2 完整草稿 |

### 📊 核心实验指标

**T/F/U 路径验证**：
- 672 条路径标签
- 672 条一致判定
- 该指标是构造标签与验证器的实现一致性，不是真实云泛化准确率

**C2 搜索对比**（308 样本 all-corpus 开发记录）：
| 方法 | R@1 | R@3 | R@5 | MRR | FPR |
|---|---:|---:|---:|---:|---:|
| Plain DFS + GateScore | 0.0735 | 0.1412 | 0.2529 | 0.2905 | 0.0000 |
| Type DFS + GateScore | 0.1088 | 0.1765 | 0.2559 | 0.3877 | 0.0000 |
| Full constrained + GateScore | 0.1088 | 0.2206 | 0.3735 | 0.3636 | 0.0000 |
| **RefuteAwareBeamSearch** | **0.2353** | **0.6882** | **0.7235** | **0.5320** | **0.0000** |

**相对提升**：
- R@3: 0.2206 → 0.6882（+212.0%）
- R@5: 0.3735 → 0.7235（+93.7%）
- MRR: 0.3636 → 0.5320（+46.3%）

**消融实验关键发现**：
- beam_width=4 的开发集 R@3/R@5 最高，并减少边扩展
- 当前 `no_refute_scoring` 与完整版本指标相同，尚不能证明该组件独立贡献
- temporal 移除后不变；移除 query_cost 后质量指标略有提高

**语料扩充教训**（第十二轮）：
- 将语料从 308 扩展到 614 样本（增加 306 个时序冲突变体）导致性能回退（R@3 -17.0%, FPR +18.87%）
- 已回退到 308 样本，恢复最优性能
- 教训：语料扩充需关注类别平衡，简单增加某类变体不一定提升性能

---

## C3 接口预留情况

C3 定位为"验证反馈驱动的安全调查模型训练"，当前仅做接口预留：

### 已预留接口

1. **Verifier feedback 生成**
   - `verify_path()` 返回 `state/statuses/missing/refuted`
   - 可直接用于生成 SFT 训练样本：
     ```python
     {"state": ..., "statuses": ..., "evidence_vector": ..., "gate_result": ...}
     ```

2. **Evidence vector → Gate result 映射**
   - `compute_evidence_vector()` + `gate_score()` 已稳定
   - 可作为 DPO preference pair 的 reward signal

3. **Path-level labels**
   - 每个样本的 `path_labels` 字段包含 `state/expected_type/variant_type`
   - 可直接转为分类任务训练集

### 未展开内容（明确排除）

- ❌ LLM 微调（SFT/DPO）
- ❌ GraphRAG / 多智能体包装
- ❌ 复杂前端 / 交互设计
- ❌ 模型部署 / 服务化

---

## 论文可用产物清单

### 📄 方法章节草稿

| 文件 | 内容 | 状态 |
|---|---|---|
| `output/paper_method_draft_c1_c2.md` | C1 证据语义化 + C2 反证感知搜索完整草稿 | ✅ 可用 |

包含：
- C1：问题定义、证据边形式化、异构归一化、反证/缺证/时序变体构造、质量校验
- C2：问题定义、T/F/U 验证器、RefuteAwareBeamSearch、与 GateScore 关系、实验摘要、方法边界

### 📊 实验章节表格

| 文件 | 内容 | 状态 |
|---|---|---|
| `output/paper_experiment_tables_c1_c2.md` | 9 组实验表格 + 论文写作注意事项 | ✅ 可用 |

包含：
- 表 1：语料规模统计
- 表 2：样本变体分布
- 表 3：样本级标签分布
- 表 4：路径级标签分布
- 表 5：字段覆盖率
- 表 6：证据状态分布
- 表 7：T/F/U 路径验证
- 表 8：C2 搜索对比
- 表 9：相对提升

### 🎨 网页 demo

| 文件 | 内容 | 状态 |
|---|---|---|
| `showcase_semantic.html` | Cytoscape 交互式图谱 + C2 方法对比 + T/F/U 验证 | ✅ 可演示 |

支持：
- 滚轮缩放 / 画布拖拽 / 节点拖拽
- 样本过滤（按变体类型、标签状态）
- 路径高亮（点击路径标签）
- 边证据详情（点击边查看元数据）
- Fit/Reset 按钮
- SDDP 真实切片展示

### 📝 迭代记录

| 轮次 | 主题 | 状态 |
|---|---|---|
| Round 1 | C1 证据语义化 + C2 反证感知排序 | ✅ |
| Round 2 | 数据优先 + sample-level 扰动 | ✅ |
| Round 3 | RefuteAwareBeamSearch 实现与实验 | ✅ |
| Round 4 | path_labels vs sample_labels 拆分 | ✅ |
| Round 5 | Temporal 维度加入验证器 | ✅ |
| Round 6 | Sample-level 一致性修复（FPR=0） | ✅ |
| Round 7 | 论文表格 + 方法草稿固化 | ✅ |
| Round 8 | SDDP 真实切片接入 | ✅ |
| Round 9 | SDDP 半真实实验验证 | ✅ |

---

## 毕设完成度评估

### 对照成功标准

| 标准 | 当前状态 | 是否达标 |
|---|---|---|
| C1 有统一证据语义 schema | ✅ 6 维证据边（status/source/time/confidence/query_cost/raw_evidence），100% 覆盖 | ✅ |
| C1 有转换脚本 | ✅ `build_semantic_corpus.py` + `build_sddp_evidence_slice.py` | ✅ |
| C1 有质量校验 | ✅ `validator.py` (R1–R15)，100% 通过率 | ✅ |
| C1 有数据统计 | ✅ `cloud_db_semantic_corpus_stats.json`（308 样本 / 672 路径标签 / 5456 边） | ✅ |
| C2 有明确命名方法 | ✅ RefuteAwareBeamSearch | ✅ |
| C2 有可复现实验 | ✅ `run_semantic_experiments.py`，结果稳定可重现 | ✅ |
| C2 有对比 baseline | ✅ 4 方法完整对比（Plain DFS / Type DFS / Full constrained / RefuteAwareBeam） | ✅ |
| 实验支撑论文主张 | ⚠️ 内部 held-out 上 R@3/R@5 显著，但只有 23 个检索样本且存在来源反转 | 部分达标 |
| 产物可转化为论文材料 | ✅ 方法草稿 + 实验表格 + 网页 demo 均已就绪 | ✅ |

### 总体评估

**当前结论：工程型硕士毕业设计已形成完整原型，具备通过和争取“良好”的基础；
现有证据还不足以客观认定为“优秀”。**

主要依据：
1. **C1/C2 工程闭环完整**：证据语义化、数据构造、搜索、验证、实验和 demo 均可运行。
2. **内部实验有正向结果**：23 个 held-out 检索样本上 R@3/R@5 显著，但样本量较小。
3. **外部有效性不足**：66.23% 样本是受控衍生变体，CloudGoat 没有检索 gold。
4. **来源间结论显著反转**：五项增益异质性 Holm p 均小于 0.05，方法在
   `pathbench_60` 上占优，在 `samples_v2` 上弱于基线。
5. **SDDP 受控契约已闭环但不是外部 ground truth**：8 条受控 gold 的检索率和状态一致率均为 100%。
6. **并行边歧义已修复**：180 条基础路径标签全部带 `edge_ids/edge_types`，未决歧义为 0。

完整的客观复评与整改优先级见 `output/objective_graduation_project_evaluation.md`。

---

## 达到“优秀”前的必需工作

1. 建立独立人工标注的外部测试集，补齐 CloudGoat 或真实脱敏案例的 gold path。
2. 定位并修复 `samples_v2` 失败模式，再用新来源或 source-held-out 重验。
3. 冻结 validation 上的参数，重新建立未参与调参的 test。
4. 加入更强基线和有效消融；当前 query cost 还略微降低质量指标。
5. 收缩论文主张：未实现的 C3/SFT/DPO 不得作为已完成创新点。

---

## 结论

当前项目已完成 edge-aware C1/C2 原型和 SDDP 受控契约闭环，论文素材与 demo
基本齐全，但独立外部研究证据仍有明显缺口。建议完成外部测试并解决已确认的
来源依赖后，再进入最终答辩定稿。
