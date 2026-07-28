# 本地人工标注界面

该界面只用于让真实标注者填写已经冻结的 primary、reviewer 或 adjudicator
任务。它不调用 LLM、不访问外部 API、不推荐标签，也不能修改来源材料。

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
