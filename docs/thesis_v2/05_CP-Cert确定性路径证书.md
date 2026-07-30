# 第五章 CP-Cert 冲突保持的确定性路径证书

## 5.1 研究动机与定位

自然语言解释无法证明一条攻击路径真的被日志支持。即使 LLM 引用了若干事件，
仍可能遗漏关键边、使用作用域不完整的证据，或在支持和反证并存时只选择有利
证据。CP-Cert 接收候选路径和 Agent 已观察证据，以确定性算法输出最小证书；
LLM 不能修改融合状态、覆盖集合或证书结论。

CP-Cert 是条件性第三创新。其算法正确性和工程测试已经成立，但只有冻结人工
gold 上的独立消融同时支持路径质量和可审计性收益时，才在最终摘要中作为独立
贡献；否则本章保留为 EC-ReAct 的安全实现层。

## 5.2 四值事实格与路径状态

对命题 \(q\) 保存支持位和反证位：

\[
b(q)=(s_q,r_q)\in\{0,1\}^2.
\]

新增证据用 join 合并：

\[
b_{t+1}(q)=b_t(q)\sqcup e_{t+1}
=(s_t\lor s_e,r_t\lor r_e).
\]

设路径 \(P\) 的硬前提集合为 \(R(P)\)，采用保守状态：

\[
\operatorname{state}(P)=
\begin{cases}
\text{Valid}, & \forall q\in R(P),\,b(q)=(1,0),\\
\text{Conflict}, & \exists q\in R(P),\,b(q)=(1,1),\\
\text{Invalid}, & \nexists q:b(q)=(1,1)\land
                    \exists q:b(q)=(0,1),\\
\text{Insufficient}, & \text{otherwise}.
\end{cases}
\]

Unknown 不等于反证，不能生成“不存在有效路径”的结论；Conflict 也不能被
Supported 覆盖。

## 5.3 最小成本正证书

支持证据 \(e\) 覆盖前提集合 \(Cov^+(e)\)，代价为 \(c(e)>0\)。对 Valid 路径：

\[
C^+(P)=
\arg\min_{C\subseteq E^+}\sum_{e\in C}c(e),
\quad
\text{s.t.}\quad
\bigcup_{e\in C}Cov^+(e)\supseteq R(P).
\]

该问题是加权 set cover。小规模实例使用分支定界精确求解，按总成本、证据数、
稳定 evidence ID 依次打破平局；大规模实例使用加权贪心，每轮最大化新覆盖数
与代价之比。Conflict、Invalid 和 Insufficient 路径不能生成正证书。

## 5.4 已枚举候选集的否定证书

对候选路径集合 \(\mathcal P\)，反证 \(e\) 覆盖：

\[
Cov^-(e)=
\{P\in\mathcal P:
Claims(e)\cap R(P)\neq\varnothing\}.
\]

否定证书为加权 hitting-set：

\[
C^-=
\arg\min_{C\subseteq E^-}\sum_{e\in C}c(e),
\quad
\text{s.t.}\quad
\bigcup_{e\in C}Cov^-(e)=\mathcal P.
\]

其语义严格限定为“当前已枚举候选中不存在无冲突的有效路径”，不外推到未枚举
路径。Unknown 不属于 \(E^-\)。

## 5.5 可审计性与删除检验

证书保存 evidence ID、raw ref、覆盖前提、总代价、求解模式和稳定 hash ID。
独立审计器不复用求解器内部状态，而是重新检查：

1. 每个证据均有原始引用；
2. 所有必需前提或候选路径被覆盖；
3. 保存成本等于证据成本之和；
4. 移除任一证据后证书不再充分；
5. 精确模式达到最优，贪心模式报告适用的近似上界。

删除检验形式化为：

\[
\forall e\in C,\quad
\operatorname{sufficient}(C\setminus\{e\})=0.
\]

该性质排除“把整段日志都附上”的伪证书，使结果可供第三方逐条复核。

## 5.6 复杂度与实现选择

set cover 与 hitting-set 均为 NP-hard，因此 CP-Cert 不声称对任意规模都多项式
精确求解。对证据数较小的单案例使用分支定界；规模超过冻结阈值时使用贪心。
若 universe 大小为 \(|\mathcal U|\)，经典贪心上界为：

\[
\operatorname{cost}(C_{\mathrm{greedy}})
\le (1+\ln|\mathcal U|)
\operatorname{cost}(C^*).
\]

论文必须分别报告精确和贪心模式、问题规模、耗时和在可精确求解子集上的最优
差距，不能只报告成功生成证书的比例。

## 5.7 工程验证与实验验收

现有测试已经验证四态互不混淆、冲突保持、Unknown 不生成否定证书、精确结果
与穷举 oracle 一致、共享证据复用、raw ref 必填以及独立删除审计。这些结果
只证明实现符合算法定义。

独立创新验收比较 `ec_react_full` 与 `ablate_evidence_cert`，至少报告：

- certified exact edge precision、recall、F1；
- unsupported-path rate；
- valid-path recall；
- abstention rate；
- 证书充分率、不可约率、冗余率和冲突识别率；
- 平均证书大小、标准化成本与求解时延。

只有 unsupported-path rate 显著或实质性下降，且 exact edge F1 相对消融的
退化不超过 0.05，CP-Cert 才作为第三创新点。否则结论写为：“CP-Cert 提供了
确定性审计机制，但本实验不足以证明其构成独立效果贡献。”

## 5.8 本章小结

CP-Cert 将“模型给出一段解释”转化为“可重放、可删除检验的最小证据集合”，
并显式保留冲突与未知。该设计解决了安全路径输出的审计问题，但其学术贡献仍由
冻结消融决定，而不是由算法名称或单元测试数量决定。
