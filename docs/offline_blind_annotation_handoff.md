# 双人盲标离线交接

当第二位标注者不在项目电脑旁时，不应共享正在填写的 primary 目录，也不应让
reviewer 通过同一浏览器会话查看 primary 结果。仓库提供离线交接命令，只负责
分发、完整性验证和回收，不生成或建议任何标签。

## 1. 在项目电脑导出 reviewer 空白任务

```powershell
& 'D:\anaconda\python.exe' scripts\annotation\manage_offline_handoff.py export `
  --task-dir data\real_sources\annotation\work\confirmatory_v1_reviewer_tasks `
  --output output\handoffs\confirmatory_reviewer_outbound.zip `
  --receipt output\handoffs\confirmatory_reviewer_private_receipt.json
```

把 `confirmatory_reviewer_outbound.zip` 发给第二位真人。`private_receipt.json`
只保留在原项目电脑，不发送给 reviewer。导出器只接受完全空白的任务，因此不会
把 primary 判断或已有 reviewer 草稿泄露出去。

## 2. 第二位真人独立标注

reviewer 解压 ZIP，按 `README_REVIEWER.md` 指示检出其中冻结的 Git commit，
然后运行：

```powershell
python scripts\annotation\run_local_review_app.py `
  --task-dir <解压目录>\tasks `
  --port 8776
```

reviewer 不得取得 primary JSON、截图、笔记或一致性结果。全部案例完成并通过
本地校验后封存：

```powershell
python scripts\annotation\manage_offline_handoff.py seal `
  --workspace <解压目录> `
  --output reviewer_completed.zip
```

reviewer 正常发送 `reviewer_completed.zip`，并通过另一条可信通信通道单独发送
命令输出的 `submission_sha256`。例如，ZIP 使用网盘传输，摘要通过当面或已确认
身份的即时消息发送。仅把摘要和 ZIP 放在同一未认证渠道不能证明传输未被替换。

## 3. 在项目电脑验证并导入

```powershell
python scripts\annotation\manage_offline_handoff.py import `
  --submission reviewer_completed.zip `
  --receipt output\handoffs\confirmatory_reviewer_private_receipt.json `
  --expected-sha256 <第二位真人单独发送的SHA-256> `
  --output-dir data\real_sources\annotation\work\confirmatory_v1_reviewer_returned
```

导入器拒绝：

- ZIP 摘要与独立通道摘要不一致；
- 任务角色、annotator ID、packet 或 assignment ID 变化；
- 案例集合、案例 ID、冻结源材料或 `source_context_sha256` 变化；
- 缺失/额外文件、重复 ZIP 成员或路径穿越；
- 未完成人工声明、无效标签结构或未通过逐案例校验；
- 返回包与本机私有 receipt 不属于同一次交接。

导入使用新目录且拒绝覆盖已有文件。验证后可将该目录传给冻结命令：

```powershell
python scripts\annotation\freeze_confirmatory_v1.py `
  --reviewer-task-dir data\real_sources\annotation\work\confirmatory_v1_reviewer_returned
```

负对照 reviewer 目录使用相同的 `export`、`seal` 和 `import` 流程。
