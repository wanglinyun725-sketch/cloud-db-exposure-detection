# 本地 LLM Provider-Oracle Pilot

## 目的

该 pilot 用来回答两个工程问题：

1. 真正的 LLM 能否通过本项目的 ReAct/Tool Use 协议逐步读取真实
   provider evidence，而不是执行预设脚本；
2. EC-ReAct 的 guard、Pareto action frontier 和四值记忆是否能在同模型、
   同工具、同预算下与 Vanilla ReAct 做公平对比。

它不是论文主效果实验。v7 已冻结来源完全隔离的 pilot split，但 held-out
只有 7 个独立组；主实验仍要求更大的平衡独立组、合格模型重复和人工语义审核。

## 固定配置

配置文件：

`configs/provider_oracle_llm_pilot_v2.json`

数据使用 provider-oracle v7 的 public/evaluator-only 隔离结构。模型端只
接触 public packet 和工具返回值，runner 在模型结束后才用 evaluator gold
评分。v1/v6 配置保留为历史调试记录。

首轮模型条件：

- 本地 Ollama；
- `qwen2.5:7b`；
- temperature 0；
- native JSON schema；
- `think=false`；
- context 4096；
- 最大输出 512 tokens；
- 查询预算 4；
- 最多 6 个 ReAct step；
- 最多 1 条通过确定性证书的候选路径（无效候选仍保留在 trace 中）。

选择 native Ollama 接口不是为了改变任务，而是因为 reasoning model 通过
OpenAI-compatible 接口可能把全部输出预算消耗在独立 reasoning 字段，导致
action content 为空。native `think=false` 使动作通道可控和可解析。

## 方法矩阵

| 方法 | Pareto | 外部规则先验 | 四值记忆 | budget stop | 严格证书 |
|---|---:|---:|---:|---:|---:|
| EC-ReAct full | ✓ | ✓ | ✓ | ✓ | ✓ |
| Vanilla ReAct | — | — | — | — | — |
| w/o Pareto | — | ✓ | ✓ | ✓ | ✓ |
| w/o four-value memory | ✓ | ✓ | — | ✓ | ✓ |

所有方法使用同一模型、temperature、public evidence、工具 schema、查询成本
和输出结构。

## 可恢复执行

运行器：

`scripts/experiments/run_provider_oracle_llm_pilot_v1.py`

每完成一个 run 就追加到 `runs.jsonl`，并通过稳定 `schedule_id` 跳过已完成
运行。模型名称、Ollama digest、配置哈希、public/gold 哈希和方法组件均写入
manifest；密钥不会写入任何制品。

调试命令：

```powershell
D:\anaconda\python.exe scripts\experiments\run_provider_oracle_llm_pilot_v1.py `
  --config configs\provider_oracle_llm_pilot_v2.json `
  --output-dir output\provider_oracle_llm_pilot_debug `
  --method ec_react_full `
  --case-id oracle-v5:splunk:s3-kms-pending-deletion `
  --limit 1
```

全 pilot：

```powershell
D:\anaconda\python.exe scripts\experiments\run_provider_oracle_llm_pilot_v1.py `
  --config configs\provider_oracle_llm_pilot_v2.json `
  --output-dir output\provider_oracle_llm_pilot_v2
```

## 失败记录与处理

`deepseek-r1:14b` 的初始调试不能作为结果：

- OpenAI-compatible 接口在较小输出预算下只产生 reasoning，action content
  为空；
- native 接口虽能关闭 thinking，但 8K context 下模型仅部分驻留 GPU；
- 第一次单例因三次缺少必填 `thought` 被确定性 guard 拒绝并输出
  `Unknown`；
- 强化协议后第二次单例在 5 分钟内仍未完成，运行被终止，`runs.jsonl`
  保持为空。

这些是模型/执行失败，不是方法效果数据。对应修正为：

- JSON schema 强制 `kind` 和非空 `thought`；
- 未见证据时明确要求先调用工具；
- 重复 ontology 定义压缩为 canonical ID 列表；
- context 从 8192 降为 4096；
- 最大输出从 900 降为 512；
- 改用更适合 JSON structured output 且可完整驻留显卡的 7B 模型。

只有完成且写入 frozen run record 的运行才进入汇总。
