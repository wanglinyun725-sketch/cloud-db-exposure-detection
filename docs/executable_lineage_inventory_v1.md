# 可执行谱系清单 v1

当前候选池在保守去重口径下达到数据治理的最低数量门槛，但尚未达到 human
gold 门槛。

- 32 个具有真实运行时观测的候选谱系；
- 10 个具有固定配置事实、等待 provider-native 分析或主动探查的候选谱系；
- 原始合计 42 个不重名候选谱系；
- 既有准入审计标记 2 个运行时谱系存在相同序列指纹，二者都暂不计入最低门槛；
- 排除这 2 个待近重复复核项后，保守候选数为 40；
- 覆盖 AWS、Azure、GCP；
- 合计 9 个独立上游来源。

这里的“40”只证明保守候选数量、来源与平台覆盖达到目标，不证明 40 个谱系
已经准入。运行时队列尚待双人盲标，配置队列尚待完整作用域 oracle；因此当前：

- human gold 谱系：0；
- 双人盲标谱系：0；
- 仲裁完成谱系：0；
- 距离至少 30 个双人盲标谱系仍差 30。

机器可读审计同时输出：

- `combined_independence_groups=42`；
- `near_duplicate_review_pending_groups=2`；
- `conservative_independence_groups=40`；
- `minimum_candidate_gate.passes=true`；
- `human_gold_gate.passes=false`。

最低数量门槛使用保守值而非原始值，避免把近重复风险包装成独立样本。最终独立
性仍须在盲标与去重审核后确认。
