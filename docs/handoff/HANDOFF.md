# EIC-Agent 历史交接文档（已归档）

> 本文记录 2026-07-09 的旧 macOS 工作区，路径和运行建议均已失效。
> 当前 Windows 项目请以仓库根目录的 `README.md`、`tests/` 和
> `output/dataset_v1/` 为准。

## 0. 状态核对（接手第一件事：以环境为准，不盲信本文）

| 文件 | 状态（已验证） |
|---|---|
| `projects/cloud_db_pathbench/showcase.html` | 不存在，待生成 |
| `Desktop/云数据库高敏数据暴露路径侦测/build_showcase.py` | **0 字节，已实质丢失，需重写** |
| `projects/output/web_results_v2.json` | 存在，57397 字节，完好 |
| `projects/data/verification_set/samples_v2.json` | 存在，664997 字节，完好 |

> 结论：旧文档的"修 7 处 CSS 颜色 → 运行"方案作废（生成器已空）。当前唯一可行路径是**重写生成器**，数据源完好可直接用。

## 1. 两个关键目录

| 目录 | 路径 | 性质 |
|---|---|---|
| 论文工作区 | 历史 macOS 路径（已失效） | 仅作归档 |
| Demo 项目 | 当前仓库根目录 | 数据与代码均已迁入 |

## 2. 环境坑（务必牢记）

1. **中文路径（Desktop）必须用 Bash 读写**——Read/Edit 在中文路径匹配不可靠；Write 跨会话会丢（build_showcase.py 已 0 字节验证）。
2. **最终交付物必须放英文路径 `projects/` 下**——放中文路径会丢。
3. **不要用 Flask 服务 + 端口方案**——后台进程被回收、反复 ERR_CONNECTION_REFUSED。改用**自包含单文件 HTML + `open` 命令 file:// 打开**。
4. **不要用 CDN/JS 图库**（G6/Cytoscape 出现过"图挤左上角/加载失败"）——用 Python 预算好 x/y 坐标，纯 SVG 手绘 + 原生 JS 点击高亮。

## 3. 当前任务：重建自包含 showcase.html

**目标**：零依赖单文件展示台，`open` 双击即看。

**做法**：写生成器（建议放 `projects/scripts/build_showcase.py`，别放 Desktop）→ 读 projects 下真实数据 → Python 算 SVG 分层布局 → 输出自包含 `projects/cloud_db_pathbench/showcase.html`。

**当前验收**：运行 `python -m unittest discover -s tests -v`，并通过
`python web_app.py` 启动 Flask 看板；自包含页面位于 `showcase/`。

## 4. 展示台需求（已确认，砍掉叙事，三栏一屏）

- **左栏**：4 案例切换（CodeBuild/数据密钥/Web RCE/RDS）+ 环境信息（行业、初始信号）+ 多条暴露路径列表（按 Score 降序）
- **中栏**：CDB-RG 四层图谱（网络入口→身份权限→数据库→敏感目标）；点路径高亮整链，点空白复位
- **右栏**：选中路径的 EIC-Agent 7 环节推理链路（竖向时间线）：①初始信号(DIE-Discover) ②候选路径(约束DFS) ③证据采集(7工具) ④五维证据向量 ⑤Gate 硬门判定 ⑥Score 风险量化 ⑦LLM 归因与处置

## 5. 数据结构

### output/web_results_v2.json — 4 个真实 DeepSeek 案例

| case | scenario | 行业 | 路径数 | 节点/边 |
|---|---|---|---|---|
| case_001 | CB-01 | devops | 12 | 54/37 |
| case_007 | DS-07 | ecommerce | 4 | 50/27 |
| case_013 | RCE-13 | tech | 12 | 54/40 |
| case_019 | RDS-19 | finance | 4 | 52/31 |

- case 顶层字段：`scenario, scenario_name, industry, expected, elapsed, node_count, edge_count, node_types, entries, targets, results`
- result 字段：`path`(节点id列表), `evidence_vector`{entry,reach,perm,target,sense}, `gate_result`{gate,score,path_type,blocked_by,evidence_vector}, `attribution`(LLM归因), `remediation`(LLM处置)

### data/verification_set/samples_v2.json — 24 案例（664KB）

- sample 字段：`sample_id, scenario, scenario_name, industry, initial_signal`{type,entity}, `variant_dims, seed_source, nodes, edges, gold_paths, expected_type`
- node：`{id, type, attrs{name,...}}`；edge：`{source, target, type, attrs{...evidence_ref}}`
- node 类型（8种）：Network, Identity, DBInstance, DBObject, SensitiveTag, Control, AuditEvent, RiskFinding
- 种子→样本：`codebuild_secrets`=001-006、`data_secrets`=007-012、`rce_web_app`=013-018、`rds_snapshot`=019-024（4 代表取 001/007/013/019）

## 6. Demo 代码现状（projects/ 下，均可跑）

- `run_demo.py`（根，端到端演示入口）
- `web_app.py`（根，Flask 看板，已加 `_dedup_edges` + `highlightPathByIndex`）
- `scripts/generate_web_results.py`（在 4 代表案例上跑真实 DeepSeek，`REPRESENTATIVE` 变量）
- `scripts/demo_gate_score.py`、`scripts/convert_data.py`、`scripts/patch_table.py`（后两者依赖 Desktop 外部路径，一次性）
- `src/agent/agent_graph.py`（7 环节 LangGraph 状态机，`get_llm_client`/`call_llm`）
- `src/agent/tools.py`（7 类工具）
- `src/graph/gate_score.py`、`constrained_search.py`、`graph_builder.py`
- DeepSeek API key 有效（本会话测过）

## 7. 论文现状

- 纯 AI 初稿，7 章齐全，65 篇参考文献，PDF 94 页（`paper_rewriting_output/final_paper/main.pdf`，在 Desktop 工作区）
- 章节 md：绪论与相关工作 / CloudDB_PathBench / EIC_Agent方法 / 图验证反馈对齐 / 实验与总结
- 实验数据是自洽占位（编的），demo 暂无法复现论文量化结果（Invalid Path 0.193→0.058、NDCG@3 0.41→0.80、EIC Pass 0.81）
- demo 覆盖：第3章(数据集)+第5章(EIC-Agent方法)+第7章(原型系统)
- demo 未覆盖：第6章 GV-FA 训练对齐（无 SFT/DPO 代码）、所有评估实验（eval/baselines 目录空）

## 8. 论文核心方法/术语（右栏链路要用）

- 三位一体：CloudDB-PathBench 基准 + EIC-Agent 方法 + GV-FA 对齐
- EIC-Agent 核心：表达-判定分离，LLM 从"证据判定者"降级为"证据表达者"；判定交给确定性算子 **EIC(P)=Gate(P)·Score(P)**
- 五维证据向量：entry(入口可达)、reach(网络连通)、perm(权限授予)、target(命中高敏)、sense(暴露/无防护)
- 路径类型：Observed_Risk、Potential_Exposure、Insufficient_Evidence、Low_Risk
- DIE 三阶段：Discover-Investigate-Explain
- 7 类工具：T1 GraphPathSearch、T2 NetworkCheck、T3 PermissionCheck、T4 SensitiveDataQuery、T5 AuditLogQuery、T6 ControlStatusCheck、T7 EvidenceValidator
