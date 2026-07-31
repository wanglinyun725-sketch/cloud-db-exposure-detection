# 本地人工标注界面

该界面只用于让真实标注者填写已经冻结的 primary、reviewer 或 adjudicator
任务。它不调用 LLM、不访问外部 API、不推荐标签，也不能修改来源材料。

## Goal v2 当前入口

当前确认性双盲任务已启动：

- primary：`http://127.0.0.1:8775/`
- reviewer：`http://127.0.0.1:8776/`
- primary 判定手册：`http://127.0.0.1:8775/guide`
- reviewer 判定手册：`http://127.0.0.1:8776/guide`

外部负对照：

- primary：`http://127.0.0.1:8778/`
- reviewer：`http://127.0.0.1:8779/`
- primary 筛选手册：`http://127.0.0.1:8778/guide`
- reviewer 筛选手册：`http://127.0.0.1:8779/guide`

负对照端口会自动识别独立的 `screening` 协议，不会把负对照误当成攻击路径任务。
当前任务含 30 个候选案例、29 个 `independence_group` 独立来源记录；列表同时
显示案例与独立记录进度，避免把同谱系候选重复计数。完成时还会强制检查：
`usable_as_negative_control=true` 只有在 `cloud_data_relevant=true` 且
`non_attack_confirmed=true` 时才合法。

primary 与 reviewer 必须由不同真人在互不可见的条件下完成，不应共用笔记或
查看对方端口。

## 新版证据导向流程

1. 先阅读 `/guide`，按操作化定义判断五项准入条件；
2. 每个实例先看操作频次、主体、时间范围和 raw-ref 覆盖，再展开逐条观测索引；
3. 中立摘要只重排原始字段，不计算或推荐标签；
4. 任务列表同时显示案例进度和 `independence_group` 独立谱系进度，论文统计以
   谱系而不是近重复案例数为准；
5. `Unknown` 表示证据不足，不能当作反证；
6. JSON 区域下方提供结构示例，所有 `REPLACE_` 值必须替换，完成校验会拒绝
   占位符；
7. “只做完整性预检”会执行与最终提交相同的 schema/ontology/引用校验，但不
   写入任务文件、也不设置真人完成声明；
8. 预检通过后再点击“严格校验并完成”，完成文件随即不可修改。

## 启动 pilot primary

```powershell
& 'D:\anaconda\python.exe' scripts\annotation\run_local_review_app.py `
  --task-dir data\real_sources\annotation\work\runtime_pilot_v2_primary_tasks `
  --port 8765
```

浏览器打开 `http://127.0.0.1:8765/`。服务只监听本机回环地址。reviewer 必须使用
自己的任务目录和不同端口，例如：

```powershell
& 'D:\anaconda\python.exe' scripts\annotation\run_local_review_app.py `
  --task-dir data\real_sources\annotation\work\runtime_pilot_v2_reviewer_tasks `
  --port 8766
```

不要让 reviewer 查看 primary 的页面、文件或笔记。

## 页面行为

- 显示固定来源、候选元数据、运行实例和所有原始引用；
- 展示冻结节点/边本体；
- 允许保存未完成草稿；
- 点击“严格校验并完成”时调用与命令行相同的完整协议校验；
- 校验失败不会写文件；
- 完成文件在界面中变为不可修改，后续分歧通过裁决工作流处理；
- 每次写入前后重新验证 `source_context_sha256`。

页面中的 nodes、edges、path labels、tool tasks 和 instance labels 使用 JSON
数组，字段结构遵循 `docs/realpathbench_annotation_protocol.md`。先完成 23 例
pilot，不要直接启用 150 例 v0.5 主池。

## 完成后的合并

两个标注者各自完成全部案例后，使用现有 `merge-assignment`、`progress`、
`validate-submission`、`agreement` 和必要的 adjudication 命令。界面不会替人
计算或补齐标签，也不会绕过预注册 pilot gate。
