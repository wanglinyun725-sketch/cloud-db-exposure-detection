# 最终交付与三轮审稿压力测试协议 v2

本协议把论文、答辩材料和审稿记录绑定到同一个冻结主实验决策，防止实验失败后更换指标、遗漏负结果或误用旧版材料。模板本身是 `draft/blocked`，不能作为已完成审稿的证据。

## 前置条件

只有 `output/ec_react_main_v2/confirmatory_decision.json` 同时满足下列条件，封存程序才会继续：

- `overall_status == "pass"`；
- `claim_allowed == true`；
- `posthoc_metric_substitution_allowed == false`。

这意味着两个冻结模型都已达到路径级 F1、相对改进和错误 Reachable 不增加的预注册门槛。失败或证据不足时，不生成“完成”清单。

## 三类独立压力测试

| 审稿类型 | 必检问题 | 最低要求 |
|---|---:|---|
| 方法 | 6 | ReAct 循环、Tool Use 作用域、四值记忆、预算策略、CP-Cert、基线公平性 |
| 统计 | 8 | 独立谱系、隔离划分、95% CI、效应量、功效、Holm、安全终点、缺失数据 |
| 云安全 | 6 | 原始证据、云厂商作用域、错误 Reachable、外部负对照、跨云覆盖、威胁模型 |

每份报告必须：

1. 披露 `reviewer_id` 和 `reviewer_kind`，不得把 AI 审稿伪装成人类审稿；
2. 与制品作者独立，三份报告使用不同 reviewer ID；
3. 精确绑定主实验决策 SHA256；
4. 所有预定义检查项均为 `pass`，且每项至少引用一个仓库内真实证据文件；
5. 所有 critical/major finding 均为 `resolved`。

模板位于：

- `docs/review_templates/method_review_v2.template.json`
- `docs/review_templates/statistics_review_v2.template.json`
- `docs/review_templates/cloud_security_review_v2.template.json`

## 封存顺序

先复制模板到输出目录并由三位独立审稿者填写。主实验通过后，运行：

```powershell
D:\anaconda\python.exe scripts/experiments/freeze_review_stress_tests_v2.py `
  --method-review output/reviews/method_review_v2.json `
  --statistics-review output/reviews/statistics_review_v2.json `
  --cloud-security-review output/reviews/cloud_security_review_v2.json
```

再把最终论文 PDF、答辩 PPTX 和复现压缩包绑定到同一决策：

```powershell
D:\anaconda\python.exe scripts/experiments/package_reproduction_v2.py

D:\anaconda\python.exe scripts/experiments/finalize_deliverables_v2.py `
  --thesis-pdf output/final/thesis.pdf `
  --defense-deck output/final/defense.pptx `
  --reproduction-bundle output/final/cloud_db_pathbench_reproduction_v2.zip
```

复现包不是普通源码压缩包。打包程序从冻结 manifest 指定的 Git commit
读取代码，加入冻结输入、完整运行 JSONL、分析和决策，并复验从 decision 到
analysis、runs、run manifest、frozen config 的 SHA256 链。ZIP 使用固定时间戳
和排序，因此相同输入必须产生完全相同的字节；API key 不进入压缩包。

成功后才会生成：

- `output/research_design/review_stress_tests_v2_manifest.json`
- `output/research_design/final_deliverables_v2_manifest.json`

两个文件均采用 write-once 策略；若同一路径已有不同内容，程序拒绝覆盖。Goal v2 客观审计只承认哈希仍匹配的最终清单。
