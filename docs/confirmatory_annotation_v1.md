# 30 谱系双人盲标确认集 v1

该确认集在任何人工标签产生前冻结。它从运行时就绪队列的 32 个谱系中，排除全部 2 个带有序列指纹冲突警告的谱系，并完整保留其余 30 个谱系的所有案例。

- 案例数：52
- 独立谱系数：30
- 运行时实例数：79
- 原始观测数：2548
- 上游来源数：4
- 当前 human gold：0

排除的近重复待复核组：

- `crosscloud-family:data_manipulation`
- `crosscloud-family:data_staged`

## 人工判定原则

- `accept`：五项准入问题都能由当前冻结证据肯定回答，并完整标出节点、边、路径和工具任务。
- `needs_execution`：存在合理路径假设，但关键权限、网络或数据面边需要额外 provider-native oracle 或隔离主动探针。
- `reject`：入口、多步性、云数据目标、原始证据或独立性中的必要条件明确不成立。
- 不确定时不得猜测；选择 `needs_execution` 并说明缺少哪条决定性证据。
- 主标人与复核人必须独立作答，互不可见；分歧只交给第三位真人仲裁。

52 个案例是 30 个完整谱系的组内展开，统计单位始终是谱系，不能把同一谱系下的多云案例当作多个独立样本。

## 标注后的冻结命令

主标和复核任务完成后，只运行同一个 fail-closed 命令：

```powershell
D:\anaconda\python.exe scripts/annotation/freeze_confirmatory_v1.py
```

该命令先逐文件校验任务 manifest 和冻结来源哈希，再合并两份 assignment。
如果任一案例未完成，只更新 readiness 报告，不生成 gold；如果存在分歧，
状态变为 `awaiting_adjudication`，仍不生成 gold。只有全部分歧由第三位真人
完成后，才写出：

- `reviewed/runtime_confirmatory_30_reviewed.json`
- `reviewed/runtime_confirmatory_30_splits.json`
- `output/research_design/confirmatory_freeze_readiness_v1.json`

已存在但内容不同的 gold 或 split 不会被覆盖，防止重跑悄悄改变冻结结果。

如果 readiness 报告进入 `awaiting_adjudication`，由第三位真人建立仲裁任务：

```powershell
D:\anaconda\python.exe scripts/annotation/freeze_confirmatory_v1.py `
  --adjudicator-id annotator_03
D:\anaconda\python.exe scripts/annotation/run_local_review_app.py `
  --task-dir data/real_sources/annotation/work/confirmatory_v1_adjudicator_tasks `
  --port 8777
```

第三位真人完成后，再运行冻结命令并显式提供
`--adjudicator-task-dir`：

```powershell
D:\anaconda\python.exe scripts/annotation/freeze_confirmatory_v1.py `
  --adjudicator-task-dir data/real_sources/annotation/work/confirmatory_v1_adjudicator_tasks
```

主标人、复核人或模型身份均不能充当仲裁人。
