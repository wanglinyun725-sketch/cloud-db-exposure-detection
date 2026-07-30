# 第四章 预算约束的作用域感知 EC-ReAct

## 4.1 问题定义

给定一个只可通过工具逐步观察的云安全案例，目标是在有限查询预算内恢复最多
\(K\) 条由原始证据支持的 canonical 攻击或暴露路径。路径
\(P=(v_0,e_1,v_1,\ldots,e_m,v_m)\) 必须满足 ontology 的有向连接约束，
且每条边 \(e_i\) 都绑定 Agent 实际观察到的 evidence ID。

与“把完整日志塞入提示词后一次生成答案”不同，本任务是部分可观测序贯决策：

\[
\mathcal M=
(\mathcal S,\mathcal A,T,\Omega,O,c,B,\mathcal Y).
\]

\(\mathcal S\) 是内部调查状态，\(\mathcal A\) 是工具调用、提交路径和终止动作，
\(T\) 是确定性状态更新，\(\Omega\) 是工具观测，\(O\) 控制策略可见视图，
\(c\) 是标准化查询成本，\(B\) 是硬预算，\(\mathcal Y\) 是路径输出空间。
研究问题是：在相同模型、工具、预算和输出 ontology 下，EC-ReAct 是否比
vanilla ReAct 更准确地恢复人工 gold，同时不增加错误 Reachable。

## 4.2 状态、动作与不变量

时刻 \(t\) 的状态写为：

\[
s_t=(L_t,M_t,H_t,C_t,b_t,\tau_t),
\]

其中 \(L_t\) 为可见 evidence ledger，\(M_t\) 为四值 claim memory，
\(H_t\) 为候选路径及未决前提，\(C_t\) 为已提交路径，\(b_t\) 为剩余预算，
\(\tau_t\) 为完整执行轨迹。

策略只能看到 \(O(s_t)\)，其中包含：

- 剩余预算和已执行动作；
- 当前非支配动作候选；
- 截断后的可见 evidence ledger；
- 已观察 observation ID；
- 当前四值命题状态与已提交路径反馈。

隐藏 gold、payload 标签、未返回的日志字段和未观察 observation ID 均不进入
\(O(s_t)\)。

动作集合为：

\[
\mathcal A_t=
\mathcal A_t^{tool}
\cup\{\operatorname{submit}(P),\operatorname{finish},\operatorname{abstain}\}.
\]

确定性控制器强制五个不变量：

1. 工具参数必须满足 schema 与 case scope；
2. 重复或预算不可行调用被拒绝；
3. 提交路径必须为 ontology 合法的有向链；
4. 引用只能来自 \(L_t\)；
5. `Reachable/NotReachable` 只能由作用域充分的 provider-native 证据支持。

因此，LLM 可以选择下一动作和提出候选，但不能修改预算、证据状态、证书或
最终确定性验证结果。

## 4.3 ReAct 与 Tool Use 循环

EC-ReAct 保留 ReAct 的 Thought–Action–Observation 结构，但将 Action 限制在
确定性生成的可行集合内。单轮更新为：

\[
\begin{aligned}
a_t &\sim \pi_\theta(O(s_t)),\\
o_{t+1} &= \operatorname{GuardedTool}(a_t;s_t),\\
s_{t+1} &= T(s_t,a_t,o_{t+1}).
\end{aligned}
\]

若 \(a_t\) 是工具调用，控制器先校验参数和预算，再执行固定遥测环境并写入
ledger；若为路径提交，控制器执行结构、引用、字段断言、作用域和 CP-Cert
验证；若为 finish，则输出至多 \(K=5\) 条已通过证书的路径及 abstention 状态。

正式实现采用 LangGraph 的
`plan → guard/tool/update → route` 节点编排，并保留线性运行器。同一策略在
两个后端上的路径、四值状态、成本、停止原因和证书必须相同。这个一致性测试
用于排除框架实现偏差，LangGraph 本身不构成研究创新。

## 4.4 只由可见事实生成的动作空间

在每个时刻，控制器从当前可见事实生成
\(\mathcal A_t^{vis}\)，包含摘要查询、operation/service 查询、已见
observation 详情、已见 actor 时间线、已见 status 查询，以及仅从已见
request/response 提取的 resource 查询。自由构造的账号、区域、资源或时间
参数不能进入候选集。

对动作 \(a\) 定义四维效用：

\[
u_t(a)=
\left(
g_{\mathrm{ext}}(a),
g_{\mathrm{cov}}(a),
g_{\mathrm{res}}(a),
-\widehat c_t(a)
\right).
\]

其中 \(g_{\mathrm{ext}}\) 是命中的不同 Sigma 云检测规则数，
\(g_{\mathrm{cov}}\) 是新增可见对象覆盖，
\(g_{\mathrm{res}}\) 是证据分辨率增益，
\(\widehat c_t\) 是保守成本估计。若

\[
\forall j,\;u_{t,j}(a)\ge u_{t,j}(b)
\quad\land\quad
\exists j,\;u_{t,j}(a)>u_{t,j}(b),
\]

则 \(a\) Pareto 支配 \(b\)。完整方法只向策略暴露非支配前沿：

\[
\mathcal F_t=
\{a\in\mathcal A_t^{vis}:
\nexists a'\in\mathcal A_t^{vis},a'\succ a\}.
\]

Sigma 规则来自固定归档，只使用正向 detection selection，不读取人工 gold，
也不作为路径判定器。未命中 Sigma 只表示没有此外部先验支持，不表示安全。
由于该先验存在平台覆盖偏差，正式实验必须执行
`ablate_external_rule_prior` 并报告分平台结果。

## 4.5 硬预算与渐进停止

查询成本由工具调用共享，而非按一条查询返回的每条事件重复收费。实际成本由
环境在工具执行后扣减；返回量未知的动作在规划阶段使用保守上界。动作仅在

\[
\widehat c_t(a)\le b_t
\]

时可被选择，实际执行后

\[
b_{t+1}=b_t-c(a_t,o_{t+1})\ge0.
\]

预算停止不是固定“entry→reach→permission”的手写脚本。Agent 根据当前证据
选择下一工具，但控制器在三种条件下结束：

1. 已得到足够的 Top-\(K\) 证书路径；
2. 剩余预算无法支付任何可行动作；
3. 当前可见动作集为空或策略选择 abstain。

预算 \(B\in\{10,20,30\}\)，确认性比较固定为 \(B=20\)。预算 10 和 30 只做
敏感性分析，不能观察结果后替代主预算。

## 4.6 四值证据记忆

二值记忆会把“没查到”和“查到反证”混为一谈，也会被后到证据覆盖先前冲突。
对每个命题 \(q\)，EC-ReAct 保存：

\[
M_t(q)=(s_t(q),r_t(q))\in\{0,1\}^2,
\]

分别表示是否观察到支持与反证。新增证据逐位析取：

\[
M_{t+1}(q)=M_t(q)\sqcup e_{t+1}
=(s_t\lor s_e,\;r_t\lor r_e).
\]

四个状态为 Unknown \((0,0)\)、Supported \((1,0)\)、
Contradicted \((0,1)\) 和 Conflict \((1,1)\)。该更新在信息序上单调：

\[
M_t(q)\preceq M_{t+1}(q).
\]

这里的单调性只表示信息不被删除，不表示随着更多日志到来，路径风险分数必然
单调上升。Conflict 被保留并交由证书层处理，不能用平均置信度抹平。

## 4.7 云厂商作用域守卫

同一 API 结果只有在查询对象、账号/项目、区域、时间窗和资源范围足以覆盖目标
命题时才具有决定性。令 provider 工具返回：

\[
o=(d,\sigma,t,r),
\]

其中 \(d\in\{\text{Reachable},\text{NotReachable},\text{Unknown}\}\)，
\(\sigma\) 为 scope completeness，\(t\) 为时间关系，\(r\) 为 raw ref。
只有满足：

\[
\operatorname{Decisive}(o,q)=
\mathbb 1[\sigma\in\{\text{complete},\text{complete-*}\}]
\cdot
\mathbb 1[t\text{ 与 }q\text{ 的目标时刻一致}]
\]

时，\(d\) 才可更新为支持或反证。控制面配置、宽泛时间窗或不完整作用域只能
更新 Unknown/context，不得支持错误 Reachable 或错误 NotReachable。

该守卫尤其用于区分三类情况：明确存在可达路径、明确不存在该路径、现有证据
不足。`ablate_provider_scope_gate` 只关闭这一组件，其余工具和预算保持不变。

## 4.8 路径提交与引用守卫

候选路径提交必须给出 canonical node/edge sequence、命题—证据分配和
observation IDs。控制器依次验证：

1. 节点与边类型属于冻结 ontology；
2. 相邻节点和有向边构成连续链；
3. 所有 observation ID 已被策略实际看到；
4. 字段断言能在可见工具结果上执行并为真；
5. provider scope 足以支撑所声明状态；
6. 所有硬前提能由 CP-Cert 形成证书。

没有引用的正路径、引用隐藏 observation、非法语义边或字段断言失败均被拒绝。
“证书通过”只表示内部证据约束成立，不等于路径语义与人工 gold 相同；两者不
匹配仍记为语义误报。

## 4.9 方法与基线的公平比较

正式方法矩阵使用同一工具、原始结果、最大步数、输出 schema 和预算：

| 方法 | 主动 Pareto | Scope gate | 四值记忆 | 预算停止 | 证书 |
|---|---:|---:|---:|---:|---:|
| EC-ReAct | 是 | 是 | 是 | 是 | 是 |
| vanilla ReAct | 否 | 否 | 否 | 否 | 否 |
| fixed-order | 否 | 否 | 否 | 否 | 否 |
| random-tool | 否 | 否 | 否 | 否 | 否 |
| full-query | 全量 | 否 | 否 | 否 | 否 |

此外执行六个单组件消融：Pareto、provider scope、外部规则先验、四值记忆、
预算停止和证据证书。消融开关连接到真实控制分支，而非只修改提示词描述。

## 4.10 工程验证与研究效果的边界

当前已有自动测试覆盖预算、越权参数、隐藏引用、结构化路径、四值冲突、
Pareto 前沿、线性/LangGraph 一致性和证书审计。全量 Tool Use 契约审计与
smoke 测试证明系统能够运行，但不证明 EC-ReAct 比基线准确。研究效果必须由
第六章的双人 gold 冻结主实验决定。

## 4.11 本章小结

EC-ReAct 的核心不是使用了某个 Agent 框架，而是把 LLM 的自由规划限制在
可见事实、作用域、预算、四值记忆和确定性证书共同定义的安全状态机内。其可
证伪主张是：这些约束在相同模型和预算下能否提高路径级 exact edge F1，并且
不增加错误 Reachable；若冻结实验未通过，该方法只能被评价为工程可行而非
研究有效。
