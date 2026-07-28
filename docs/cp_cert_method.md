# CP-Cert：冲突保持的路径验证与最小证据证书

## 1. 研究定位

CP-Cert 是与 LLM 和 LangGraph 解耦的确定性验证层。Agent 只能提交候选路径及
已观察证据，不能修改融合状态、证书内容或最终判定。它解决两个问题：

1. 同一事实同时出现支持和反证时，不能用平均分把矛盾消掉；
2. 判定结果必须附带一组可重放、可删除检验的最小证据，而不是整段日志或
   LLM 自然语言解释。

当前实现位于 `src/verification/cp_cert.py`。

## 2. 四值证据融合

对命题 \(q\) 分别维护支持位和反证位：

\[
b(q)=(s_q,r_q)\in\{0,1\}^2.
\]

它们对应：

| 位 | 状态 | 含义 |
|---|---|---|
| (0,0) | Unknown | 尚无足够证据 |
| (1,0) | Supported | 仅有支持 |
| (0,1) | Contradicted | 仅有反证 |
| (1,1) | Conflict | 支持与反证并存 |

新增证据使用逐位析取：

\[
b_{t+1}(q)=b_t(q)\sqcup e_{t+1}
          =(s_t\lor s_e,\ r_t\lor r_e).
\]

因此信息只会增加；加入反证不会删除既有支持，加入支持也不会覆盖反证。

## 3. 路径判定

设候选路径 \(P\) 的硬前提集合为 \(R(P)\)。采用保守判定：

- `Valid`：所有前提均为 Supported；
- `Conflict`：至少一个前提为 Conflict；
- `Invalid`：不存在 Conflict，且至少一个前提为 Contradicted；
- `Insufficient`：没有 Conflict/Contradicted，但至少一个前提为 Unknown。

Unknown 不是反证。它只能触发继续探查或 abstain，不能生成“不存在有效路径”的
否定证书。

## 4. 正证书

每条支持证据 \(e\) 可覆盖一个或多个路径前提 \(Cov^+(e)\)，代价为 \(c(e)\)。
正证书求解：

\[
C^+(P)=\arg\min_{C\subseteq E^+}\sum_{e\in C}c(e),
\quad
\text{s.t.}\quad
\bigcup_{e\in C}Cov^+(e)\supseteq R(P).
\]

只有 `Valid` 路径可以生成正证书。Conflict、Invalid 和 Insufficient 路径均被
确定性接口拒绝。

## 5. 否定证书

给定已经枚举的候选路径集合 \(\mathcal P\)，反证 \(e\) 覆盖所有含有其所反驳
前提的路径：

\[
Cov^-(e)=\{P\in\mathcal P:
Claims(e)\cap R(P)\neq\varnothing\}.
\]

否定证书是加权 hitting-set：

\[
C^-=\arg\min_{C\subseteq E^-}\sum_{e\in C}c(e),
\quad
\text{s.t.}\quad
\bigcup_{e\in C}Cov^-(e)=\mathcal P.
\]

该证书严格表示“已枚举候选中不存在无冲突的有效路径”，不声称未枚举路径
不可能存在。Unknown 不进入 \(E^-\)。

## 6. 求解器与可审计属性

- 小规模：分支定界精确求解，按总成本、证据条数、稳定 ID 依次打破平局；
- 大规模：加权贪心，每轮最大化新增覆盖数/代价；
- 贪心证书报告 \(1+\ln |\mathcal U|\) 的经典 set-cover 上界；
- 每个证书保存 evidence ID、原始引用、总成本、覆盖对象和稳定哈希 ID；
- 删除检验：移除任一证据后必须失去充分性，否则该证据被判定为冗余；
- 独立审计器重新计算覆盖、成本、raw-ref 完整性和不可约性。

## 7. 已完成的工程验证

当前自动测试覆盖：

1. Unknown、Supported、Contradicted、Conflict 四态互不混淆；
2. 支持与反证的信息合并保持冲突；
3. Unknown 不会生成否定证书；
4. 精确求解结果与独立穷举 oracle 的最优成本一致；
5. 正证书可复用一条覆盖多个前提的共享证据；
6. 精确和贪心证书均通过充分性与删除检验；
7. 缺少原始引用的证据不能进入证书；
8. 旧 active investigator 已改为对 Unknown abstain，并使用 CP-Cert 生成
   共享反证最小证书。

这些是算法和协议验证，不是论文主实验结果。

## 8. 尚未达到的研究验收门槛

在宣称 CP-Cert 为独立创新前仍需：

- 由人类在真实来源 pilot 中标出 Supported、Contradicted、Unknown、Conflict；
- 冻结真实候选路径和证据极性；
- 比较“全部证据、简单逐路径首反证、贪心证书、精确证书”的大小与成本；
- 报告证书充分率、不可约率、冗余率、冲突识别率和 raw-ref 完整率；
- 按独立案例/攻击家族统计，不能把 240 次重复 episode 当成 240 个独立案例；
- 对精确求解记录规模和耗时，对贪心求解报告最优差距（可求精确解的子集）。

没有真实人工 gold 之前，只能称为“实现完成、真实实验待验收”，不能把测试夹具
包装为真实数据结果。
