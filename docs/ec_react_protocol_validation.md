# EC-ReAct 真实遥测协议验证

## 结论

LangGraph 与框架无关线性后端已经能在真实三云遥测上产生完全一致的受控轨迹，
且当前检查未发现攻击名、payload 条件或 episode 标识泄漏给策略。但离线
`ProgressiveTelemetryPolicy` 几乎对所有 episode 都返回
`candidate_evidence_found`，因此它只能是工程 smoke policy，不能作为
EC-ReAct 有效性的实验结果。

## 验证数据

- 来源：固定版本的 DOI 跨云可观测性数据；
- 索引：`data/real_sources/cross_cloud_full_episode_index.json`；
- 索引 SHA-256：
  `595e86202ab0f4fe8fb2a93f84737b22a1d36cc695e2ae0eaddbced2063a58a0`；
- 选择：每个 platform×attack 选择一组完整上游有/无 payload 配对；
- 覆盖：12 个独立攻击家族、36 个 platform×attack 组、72 个真实 episode；
- 平台：AWS、Azure、GCP 各 24 个；
- 条件：payload absent/present 各 36 个；
- 单次查询预算：30。

选择器只使用上游已有 episode，不生成、补齐或修改任何日志与标签。

## 检查结果

| 检查 | 结果 |
|---|---:|
| 线性/LangGraph 完整结果不一致 | 0 / 72 |
| 策略可见轨迹中的隐藏标签泄漏 | 0 / 72 |
| 平均有效工具调用数 | 2.944 |
| 平均查询成本 | 4.986 |
| payload absent：candidate / abstain | 35 / 1 |
| payload present：candidate / abstain | 35 / 1 |

输出保存在 `output/ec_react_protocol_validation.json`。每个 episode 均保存两种
后端的完整动作、观察、成本、停止原因和原始引用。

## 客观解释

这项检查只回答两个工程问题：

1. 编排框架是否改变研究控制器的动作与结果；
2. 隐藏的评估元数据是否进入策略可见上下文。

它不回答“是否发现了正确攻击路径”。上游 payload condition 不是人工
edge-aware 路径 gold，`candidate_evidence_found` 也只表示查到了候选事件。
两种 condition 获得完全相同的 35/36 candidate 比例，反而证明当前确定性
policy 没有区分能力。论文不得把 70/72 写成准确率或召回率。

后续主实验必须在冻结的人类 gold 上比较 EC-ReAct、Vanilla ReAct、固定顺序、
随机、全量查询和非 Agent 图搜索，并同时报告路径正确性、误报、abstention、
调用成本与置信区间。

## 复现

```powershell
& 'D:\anaconda\python.exe' `
  scripts\experiments\run_ec_react_protocol_validation.py
```

该命令不需要模型密钥；输出显式带有
`research_effectiveness_result=false`，防止被误当成论文主结果。
