# RealPathBench-CD 人工金标准执行手册

## 1. 适用范围

本手册把无标签候选包转换为可审计的人工 gold。正式运行时先导标注使用：

```text
data/real_sources/annotation/runtime_pilot_round2_unlabeled.json
```

该包在人工标签产生前冻结，包含 23 个案例、35 个真实运行实例、14 个完整
independence group 和 389 条观测；AWS/Azure/GCP 实例数为 18/9/8，覆盖
Cross-Cloud、Splunk、Stratus 三个独立发布的真实运行时来源。旧的
`runtime_pilot_round1_unlabeled.json` 因在人工工作开始前发现第三来源而被
v2 取代，保留用于溯源，不再用于正式 pilot。更早的
`pilot_round1_unlabeled.json` 仅保留为 11 案例工作流 smoke，不得用于 EC-ReAct
有效性 pilot。正式扩展候选包为：

```text
data/real_sources/annotation/expanded_full_pool_v0_5_unlabeled.json
```

扩展包包含 150 个真实来源候选、113 个 independence group 和 91 个非空无标签
运行实例。pilot v2 继续引用哈希冻结的 v0.2 母包；v0.3 曾包含 93 个实例，
全源工具审计发现其中 2 个 Cross-Cloud 上游 episode 为零观测。v0.4 只按
`observation_count > 0` 这一无标签准入规则排除这两个实例，候选案例、来源材料和
independence group 均不变，并保留 OTRF 发布、但与 CloudGoat 共用场景 lineage
的实例。v0.5 再从同一固定 Cross-Cloud 原始归档和同一盲化环境保存 schema、
source IP、request、response 与 resource 详情，不增加或生成任何事件。上述包
都仍是候选池，不是已发布 benchmark。

## 2. 不可违反的约束

- Primary、reviewer 必须是两位不同的人，分别从同一个无标签包开始；
- reviewer 不读取 primary 的 JSON、笔记或最终判断；
- LLM、脚本和规则不得填写准入决定、边状态或路径状态；
- 每位标注者完成后设置 `human_attestation=true` 和 ISO-8601
  `completed_at`；
- 任何不一致必须由第三位人类 adjudicator 裁决；
- 脚本只做分发、模式校验、完整性检查、一致性计算和审计哈希。

建议使用稳定匿名 ID（如 `annotator_01`），不要在数据中保存姓名。

## 3. 创建两份盲法任务

在项目根目录执行：

任务已拆分后，推荐使用
`docs/local_human_annotation_app.md` 中的本地人工界面逐例阅读、保存草稿和严格
完成；该界面不调用模型，也不会修改冻结来源。下面的命令仍是任务生成和审计的
权威入口。

```powershell
& 'D:\anaconda\python.exe' scripts\annotation\manage_annotations.py `
  create-assignment `
  --packet data\real_sources\annotation\runtime_pilot_round2_unlabeled.json `
  --role primary `
  --annotator-id annotator_01 `
  --output data\real_sources\annotation\work\runtime_pilot_v2_primary_blank.json

& 'D:\anaconda\python.exe' scripts\annotation\manage_annotations.py `
  create-assignment `
  --packet data\real_sources\annotation\runtime_pilot_round2_unlabeled.json `
  --role reviewer `
  --annotator-id annotator_02 `
  --output data\real_sources\annotation\work\runtime_pilot_v2_reviewer_blank.json
```

两份任务必须直接从原始无标签包生成，不能用 primary 的结果生成 reviewer
任务。生成器会记录相同的 packet SHA-256，并保证复制标签数为 0。候选元数据、
原始 observations、冻结的 runtime instances 与静态 source materials 会进入
两份任务，并由 `source_context_sha256` 冻结；任何标注过程中对源材料的改写
都会被拒绝。`episode_refs` 仅保留在 evaluator 侧原始包中，不进入人工任务，
因为其 episode ID 和 `source_condition` 会泄露上游 present/absent 条件。

为避免手工维护巨型 JSON，可把每份任务无损拆成 23 个逐案例文件：

```powershell
& 'D:\anaconda\python.exe' scripts\annotation\manage_annotations.py `
  split-assignment `
  --assignment data\real_sources\annotation\work\runtime_pilot_v2_primary_blank.json `
  --output-dir data\real_sources\annotation\work\runtime_pilot_v2_primary_tasks
```

reviewer 使用自己的独立目录。填写期间可随时合并并查看进度：

```powershell
& 'D:\anaconda\python.exe' scripts\annotation\manage_annotations.py `
  merge-assignment `
  --manifest data\real_sources\annotation\work\runtime_pilot_v2_primary_tasks\assignment_manifest.json `
  --input-dir data\real_sources\annotation\work\runtime_pilot_v2_primary_tasks `
  --output data\real_sources\annotation\work\runtime_pilot_v2_primary.json

& 'D:\anaconda\python.exe' scripts\annotation\manage_annotations.py `
  progress `
  --assignment data\real_sources\annotation\work\runtime_pilot_v2_primary.json `
  --output output\runtime_pilot_v2_primary_progress.json
```

合并器会拒绝缺失/多余案例、案例 ID 改写、任务头改写和 source context
哈希变化。`progress` 只报告 blank/in-progress/valid/invalid，不推断或填充标签。

## 4. 人工填写

逐个案例阅读 `source.raw_artifacts` 指向的固定原始材料，并按
`docs/realpathbench_annotation_protocol.md` 填写：

1. `admission_screen` 的五个布尔项、`decision` 和 `rationale`；
2. 接纳案例的 `nodes`、`edges`、`path_labels` 和 `tool_tasks`；
3. 每个 `runtime_instances` 成员对应一条 `instance_labels`：逐路径填写
   `path_states`、整体四值状态、原始引用和人工理由；
4. 每条边的原始引用、证据项、支持/反驳极性和四值状态；
5. 完成时设置人类声明和完成时间。

`nodes[].type` 与 `edges[].type` 必须来自
`configs/path_ontology_v1.json` 的 canonical ID。任务中保存本体版本和
SHA-256；自由文本类型、别名或过期本体会被校验器拒绝。

`accept` 案例的四个案例级标签区都不能为空；只要存在 runtime instance，
还必须对每个实例恰好标注一次，且覆盖该案例的全部 path。`reject` 或
`needs_execution`
可以保留空结构，但必须写明人工理由。空查询结果默认是 Unknown，不能自动当成
Contradicted。

## 5. 独立校验与一致性

两位标注者分别完成后先校验：

```powershell
& 'D:\anaconda\python.exe' scripts\annotation\manage_annotations.py `
  validate-submission `
  --submission data\real_sources\annotation\work\runtime_pilot_v2_primary.json

& 'D:\anaconda\python.exe' scripts\annotation\manage_annotations.py `
  validate-submission `
  --submission data\real_sources\annotation\work\runtime_pilot_v2_reviewer.json
```

再生成一致性报告：

```powershell
& 'D:\anaconda\python.exe' scripts\annotation\manage_annotations.py `
  agreement `
  --primary data\real_sources\annotation\work\runtime_pilot_v2_primary.json `
  --reviewer data\real_sources\annotation\work\runtime_pilot_v2_reviewer.json `
  --output data\real_sources\annotation\work\runtime_pilot_v2_agreement.json
```

报告以案例为独立统计单位，包含准入 exact agreement 与 Cohen's kappa、
edge identity F1、匹配边的证据状态 macro-F1、匹配路径的状态 kappa、
运行实例整体状态 kappa/macro-F1、完整 payload 一致率和待裁决案例清单。
不能把同一案例的边、成对 episode 或重复运行当成额外独立样本扩大样本量。

## 6. 第三人裁决

只有前两位均提交后才能生成裁决任务：

```powershell
& 'D:\anaconda\python.exe' scripts\annotation\manage_annotations.py `
  create-adjudication-assignment `
  --primary data\real_sources\annotation\work\runtime_pilot_v2_primary.json `
  --reviewer data\real_sources\annotation\work\runtime_pilot_v2_reviewer.json `
  --annotator-id annotator_03 `
  --output data\real_sources\annotation\work\runtime_pilot_v2_adjudicator.json
```

裁决任务仅包含有分歧的案例。第三位标注者可以看到双方独立 payload 和分歧报告，
但必须重新查看原始证据并填写自己的最终结构；不得只做多数表决。完成后同样运行
`validate-submission`。

## 7. 批量冻结

无分歧时省略 `--adjudicator`；有分歧时执行：

```powershell
& 'D:\anaconda\python.exe' scripts\annotation\manage_annotations.py `
  finalize-assignments `
  --primary data\real_sources\annotation\work\runtime_pilot_v2_primary.json `
  --reviewer data\real_sources\annotation\work\runtime_pilot_v2_reviewer.json `
  --adjudicator data\real_sources\annotation\work\runtime_pilot_v2_adjudicator.json `
  --output data\real_sources\annotation\reviewed\runtime_pilot_round2_reviewed.json
```

冻结器会拒绝缺失第三人裁决、同一人兼任、来源包不同、案例集合不同、引用断裂、
非法四值状态和模式不合法的提交。最终案例保留三份提交哈希、一致性报告和裁决
来源，便于论文审计。

## 8. Pilot 决策门槛

门槛已在任何 pilot 结果产生前冻结到
`configs/human_annotation_pilot_gate_v2.json`，不得根据结果事后放宽。至少要求：

- 23 个案例全部由两位不同人独立提交，全部分歧完成第三人裁决；
- 准入 exact agreement ≥ 0.80；Cohen's kappa 在可定义时 ≥ 0.60；
- mean edge identity F1 ≥ 0.70，且至少 15 个匹配边状态的 macro-F1 ≥ 0.70；
- 至少 15 个匹配路径，路径状态 kappa 在可定义时 ≥ 0.60；
- 至少 24 个匹配实例，实例状态 kappa ≥ 0.60、macro-F1 ≥ 0.70；
- 最终至少保留 15 个案例、24 个运行实例、3 个真实来源，并满足预注册的平台
  最低覆盖；不允许遗留 `needs_execution`。

kappa 因单一类别而不可定义时，仅在对应 observed agreement 为 1.0 时放行。执行：

```powershell
& 'D:\anaconda\python.exe' scripts\annotation\evaluate_pilot_gate.py `
  --release data\real_sources\annotation\reviewed\runtime_pilot_round2_reviewed.json `
  --output output\runtime_annotation_pilot_gate.json
```

命令退出码为 0 才表示通过；退出码 2 表示必须修订指南或数据来源并重做 pilot。
此外：

- 报告被 reject、needs_execution 和最终 accept 的数量，不隐去淘汰样本；
- 只有人工决定为 `accept`、复核完成且满足 split 证据等级的案例才能进入
  EC-ReAct 和 CP-Cert 主实验；`needs_execution` 会进入执行队列，绝不再伪装成
  `reviewed` gold；
- 23 案例运行时 pilot 只负责校准工作流，不能替代扩展后的主数据集。

### 8.1 v0.5 主候选池任务（通过 pilot 后启用）

主候选池 v0.5 的两份 150 案例空白任务和逐案例目录已预生成：

```text
data/real_sources/annotation/work/expanded_v0_5_primary_blank.json
data/real_sources/annotation/work/expanded_v0_5_reviewer_blank.json
data/real_sources/annotation/work/expanded_v0_5_primary_tasks/
data/real_sources/annotation/work/expanded_v0_5_reviewer_tasks/
```

两份任务都直接绑定 v0.5 的 canonical packet SHA-256
`302769ba038fda16713414a302646b482f6e0b9454a34a9344228f19b05401cc`；
原始文件 SHA-256 为
`b71129268f4053e23ed3bd2c67abe8dad48750d1238fc9bfad8949b71ffe642b`，
复制标签数为 0。旧 `expanded_v0_3_*` 和 `expanded_v0_4_*` 任务保留用于审计，
但不得再启用。v0.5 任务也只是预分发工件；只有 runtime pilot v2 通过预注册
gate 后才能开始主池
标注。pilot 失败时必须先修订指南并重做 pilot，不能继续主池任务。

## 9. 运行实例盲法

- Splunk 每个案例冻结一个全量真实 observation 实例；
- Cross-Cloud 每个 platform×attack 候选确定性选择一组完整上游配对，形成两个
  不透明实例；选择时可使用上游条件核对配对完整性，但条件不会写入实例；
- Stratus 每个入选案例冻结其官方发布的完整 Grimoire CloudTrail 爆破日志，
  不抽取单条“好看”事件，也不把 technique 文档本身当成人工 gold；
- 人工标注者和 Agent 只能看到不透明实例、规范化真实 observations 与哈希引用，
  不能看到 `episode_refs`、`source_condition` 或 `payload_present/absent`；
- `instance_labels` 是人工字段，导出器生成数量始终为 0；
- 主实验只运行 `human_reviewed`/`human_adjudicated` 且实例标签完整的案例。

## 10. 外部负对照的独立盲审

30 份真实生产可靠性报告的筛选包位于：

```text
data/real_sources/annotation/negative_control_round1_unlabeled.json
```

它们不是预先认定的负例。Primary 与 reviewer 必须分别从该包生成任务：

```powershell
& 'D:\anaconda\python.exe' scripts\annotation\manage_negative_controls.py `
  create-assignment --packet data\real_sources\annotation\negative_control_round1_unlabeled.json `
  --role primary --annotator-id annotator_01 `
  --output data\real_sources\annotation\work\negative_primary.json

& 'D:\anaconda\python.exe' scripts\annotation\manage_negative_controls.py `
  create-assignment --packet data\real_sources\annotation\negative_control_round1_unlabeled.json `
  --role reviewer --annotator-id annotator_02 `
  --output data\real_sources\annotation\work\negative_reviewer.json
```

逐例人工填写 `cloud_data_relevant`、`non_attack_confirmed`、
`usable_as_negative_control` 和引用原文的理由，并设置
`human_attestation=true` 与 ISO-8601 `completed_at`。先运行
`validate-submission` 和 `agreement`；有分歧时用第三位人类生成
`create-adjudication-assignment`，最后运行 `finalize`。只有三个布尔项均为
true 且状态为 `reviewed`/`adjudicated` 的报告进入
`external_negative_control`，配置要求至少 20 例。Agent 看不到筛选状态，
但使用与正例完全相同的工具、预算和 Top-K 输出合同。若多个服务报告显式引用
同一上游 incident URL/Tracking ID，它们共享一个 independence group；没有事件
ID 时使用来源记录 SHA-256，不能把同次故障的多服务记录当成独立统计样本。

30 例负对照同样支持 `split-assignment`、`merge-assignment` 和 `progress`：

```powershell
& 'D:\anaconda\python.exe' scripts\annotation\manage_negative_controls.py `
  split-assignment `
  --assignment data\real_sources\annotation\work\negative_primary_blank.json `
  --output-dir data\real_sources\annotation\work\negative_primary_tasks
```

合并器复用相同的任务头、文件集合和 source context 哈希检查；进度命令不会把
“生产事故”自动解释为非攻击负例。

## 11. 人工 gold 后冻结 split

人工 release 完成后运行：

```powershell
& 'D:\anaconda\python.exe' scripts\data\build_ec_react_splits.py
```

划分器不读取 nodes、edges、path 或 instance label，只依据人工准入状态、来源、
证据等级、独立组和案例数做确定性平衡。整个 independence group 只能进入一个
分析 split；C 级材料只允许 development/validation；拒绝项与待执行项分别进入
`excluded` 和 `execution_queue`。缺少人工 release 时命令会拒绝生成 manifest。
