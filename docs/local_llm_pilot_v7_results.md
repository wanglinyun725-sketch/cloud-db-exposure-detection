# 本地 LLM 三状态行为试验（v7）

## 结论边界

这是方法开发完成后的 **behavior pilot**，不是论文冻结主实验。它回答的是：

1. 真正的本地 LLM 能否通过 ReAct 与工具调用逐步读取 public evidence；
2. 在同一模型、数据、查询预算和随机种子下，证据约束方法能否比公平
   Vanilla ReAct 更稳定地处理 Reachable、NotReachable 与 Unknown；
3. 动态 observation/test 约束能否阻止模型把一个事件的字段值错误绑定到另一个
   observation。

它不能回答总体有效性，因为只有 3 个独立组，其中 provider-gold 只有 2 组，
NotReachable 只有 1 组。`research_effectiveness_result` 因此固定为 `false`。

## 冻结条件

| 项目 | 固定值 |
|---|---|
| 模型 | `qwen2.5:7b` |
| Ollama digest | `845dbda0ea48ed749caafd9e6037047aa19acfcfd82e704d7ca97d631a0b697e` |
| temperature | 0 |
| seeds | 1729、1730、1731 |
| 上下文 / 输出上限 | 4096 / 1024 tokens |
| 查询预算 | 4 |
| 最大 ReAct 步数 | 6 |
| 每次候选上限 | 1 |
| 统计单位 | independence group；同组全部重复均成功才计成功 |
| public packet | provider-oracle v7 public；Agent 不加载 evaluator gold |

三条 source-held-out 诊断案例分别是：

- AzureGoat 配置控制组：Unknown；
- Stratus Red Team Secrets Manager 运行时成功：Reachable；
- Splunk Attack Data S3/KMS 明确拒绝且稍后存在成功对照：NotReachable。

公平性约束：EC-ReAct 与 Vanilla 使用相同硬预算可行性过滤。Vanilla 只关闭
Pareto guard、external rule prior、四值记忆和严格 finish certificate，不能通过
看到超预算动作而被人为削弱。

## 方法中的可验证约束

工具暴露的决定性证据集合定义为

\[
\mathcal{E}^{*}_t =
\{(o,c,p,f,v)\mid o\text{ 在 call }c\text{ 中可见},
p\in\{\text{allow},\text{deny}\}, f(o)=v\}.
\]

EC-ReAct 将下一步 JSON schema 编译为：

\[
\text{allow}\Rightarrow
(\hat y=\text{Reachable},\,\pi=\text{support}),
\qquad
\text{deny}\Rightarrow
(\hat y=\text{NotReachable},\,\pi=\text{refute}).
\]

`observation_id`、`call_id`、polarity 以及可执行测试的
`(field, operator, value)` 必须共同来自 \(\mathcal{E}^{*}_t\)。模型仍负责选择工具、
构造节点/边和提交路径，但不能发明 observation–test 组合。

只有 `not_run` 或 control evidence 时：

\[
\mathcal{E}^{*}_t=\varnothing
\Rightarrow \hat y=\text{Unknown},
\]

模型只能走 `finish/no_verified_path` 或 `abstain`。若 Ollama 遗漏非决定性的
`hypothesis`，协议只把已有 `thought` 复制过去，并在 trace 中记录
`hypothesis_from_thought`；该归一化不改变状态、证据或证书。

## 清洁版结果

18 个 run = 3 案例 × 2 方法 × 3 seeds。

| 方法 | run 正确 | provider 独立组准确率 | 正确拒绝率 | Unknown 拒答率 | false-Reachable | 平均查询成本 | provider edge F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| EC-ReAct full | 9/9 | 1.000 | 1.000 | 1.000 | 0.000 | 3.0 | 0.583 |
| Vanilla ReAct | 6/9 | 0.500 | 0.000 | 1.000 | 0.000 | 3.0 | 0.333 |

Wilson 95% CI：

- full provider accuracy：`[0.342, 1.000]`（2 个独立组）；
- vanilla provider accuracy：`[0.095, 0.905]`；
- full correct rejection：`[0.207, 1.000]`（1 个负例组）；
- 两者 Unknown abstention：`[0.207, 1.000]`（1 个控制组）。

分状态重复：

| gold 状态 | EC-ReAct | Vanilla |
|---|---:|---:|
| Unknown | 3/3 | 3/3 |
| Reachable | 3/3 | 3/3 |
| NotReachable | 3/3 | 0/3（均退为 Unknown） |

平均 wall-clock 延迟为 full `33.91 s`、Vanilla `30.17 s`。full 更慢约
`3.73 s/run`，主要来自 KMS 负证书生成。full 共 1 次非法动作，Vanilla 共 3 次；
三次 Unknown finish 都留下了透明的 `hypothesis_from_thought` 归一化记录。

这里不能报告“显著优于”。按独立组做配对比较，provider 组只有一个
full-correct/vanilla-wrong 的 discordant pair，双侧精确 McNemar
\(p=1.0\)。重复 seeds 用于检查执行稳定性，不增加独立样本量。

## 开发诊断与非挑选原则

修正前记录全部保留：

- v5 的自由文本 test value 允许模型把稍后 Success 字段绑定到早先 deny
  observation，严格 verifier 因可执行测试失败而拒绝；
- v6 首次加入动态 executable-test schema，在 KMS 上 full 3/3、
  Vanilla 0/3、w/o external prior 0/3；
- v7 在新实现 bundle 下重新执行完整三状态公平对照，没有把 v4/v5 中较好或较差
  的单次结果拼入最终表。

因此，本试验支持的最窄结论是：**动态证据极性和可执行测试约束在这个真实
KMS 拒绝案例上可重复地把安全退避推进为有原始证据证书的 NotReachable。**
它尚不支持跨攻击族、跨云或总体分布上的效果外推。

## 可复现制品

| 制品 | SHA256 |
|---|---|
| 配置 `configs/provider_oracle_llm_pilot_v7.json` | `08ee8386c0df4c4381060454f9877800bf649e430b7b8349868f697b253f3cad` |
| run manifest | `6cbb5cb88aa1083cde4b0af9beb5e953f4727824df646bff63e0a4790e5c6e00` |
| runs JSONL | `7ec633a2e98f0a52010f9c8d5b5ca557d17ca352a4312c461847f1472950cbe5` |
| results JSON | `765dc579ce0d7d441672d43612ec7e9de628ddf61e1ec166c048ba7edd0584c4` |
| implementation bundle | `494e5b4c809faf3ec855f112f8f0bd647e15e190ff55a628e2d8f4d2eb4acf00` |

运行命令：

```powershell
D:\anaconda\python.exe scripts\experiments\run_provider_oracle_llm_pilot_v1.py `
  --config configs\provider_oracle_llm_pilot_v7.json `
  --output-dir output\provider_oracle_llm_pilot_v7_clean_three_state_repeated `
  --case-id oracle-v5:splunk:s3-kms-pending-deletion `
  --case-id oracle-v4:stratus:iam-user-secret-read `
  --case-id oracle-v4:config-only:azuregoat_prod_dev_blob_control_pair
```

运行器按 run 追加 JSONL，可以安全续跑；schedule ID 同时绑定配置 SHA、模型
digest、seed 和实现 bundle SHA。

## 下一次冻结主实验的门槛

1. 至少 30 个独立组，Reachable / NotReachable / Unknown 各不少于 10；
2. 至少两名标注者独立完成语义 gold，并报告一致性与裁决；
3. source-held-out 主测试中保留足够的独立负例，而不是只保留一个 KMS 组；
4. 至少两个合格模型、每个方法多个预注册 seeds；
5. full、Vanilla、w/o evidence constraint、w/o Pareto、w/o four-value memory
   全部在同一冻结实现和测试集上运行；
6. 只按独立组做置信区间和配对检验，不把重复 seed 当成新增样本。
