# Provider-Oracle Protocol v3：确定性路径状态与正/负证书

## 1. 研究问题

旧协议只允许 Agent 提交“可达路径”，CP-Cert 也只签发正证书。这样会产生一个结构性缺口：当云厂商日志已经明确返回权限拒绝时，系统只能说“正路径未验证”，却不能证明“给定候选路径的关键边被阻断”。

Protocol v3 将问题改为：在冻结配置、provider-native 审计日志和明确的证据覆盖范围内，Agent 应渐进调用工具，将候选路径判定为：

- `Reachable`：所有必要边均得到支持，且不存在反证；
- `NotReachable`：至少一条必要边存在明确反证；
- `Unknown`：既没有完整支持，也没有完整反证；
- `Conflict`：同一必要边同时存在支持和反证。该状态由验证器保留，不强行折叠成前三类。

## 2. 数据边界

当前 v3 只是协议 pilot，不是主效果实验。

| 项目 | 数量 | 独立性 |
|---|---:|---|
| Agent 可见案例 | 6 | 5 个保守聚类后的 independence group |
| Agent 可见原始证据投影 | 11 | 均来自固定上游制品 |
| provider-native runtime gold | 5 | 4 个 Reachable，1 个 NotReachable |
| epistemic Unknown control | 1 | 配置存在，但 native analysis 与 runtime probe 均未运行 |
| 真人 gold | 0 | 未冒充、未补写 |

六个案例分别为：

1. OTRF/CloudGoat 链接的 AWS CloudTrail：同一 assumed-role 对同一 S3 桶成功执行 `ListObjects` 与 `GetObject`，状态为 `Reachable`。
2. DOI `10.5281/zenodo.19933893` 的 GCP 受控实验：Cloud Function 使用指定服务账号，随后该账号对同一桶执行 `storage.objects.list`，四次得到 code 7；另一个身份对同一桶成功，状态为 `NotReachable`。
3. 同一 DOI 数据中的 AWS IAM 用户成功执行 `GetSecretValue`，状态为 `Reachable`。
4. 同一 DOI 数据中的 GCP 低优先级服务账号成功执行 `AccessSecretVersion`，状态为 `Reachable`。
5. 同一 DOI 数据中的 GCP 服务账号先列举归档桶、再成功读取精确对象，状态为 `Reachable`。
6. 固定 commit 的 AWSGoat Terraform：只证明 DynamoDB 资源声明存在，未运行完整 IAM 分析和授权探针，运行时状态为 `Unknown`。

公开证据与 evaluator gold 分别保存在：

- `data/real_sources/provider_oracle_protocol_v3_public.json`
- `data/real_sources/provider_oracle_protocol_v3_gold.json`

Agent 只加载前者。运行环境将真实 `case_id` 变换为不透明句柄；gold 状态、gold 路径和 gold 证据极性不进入策略上下文。

## 3. 核心公式

### 3.1 四值边证据

对路径边 \(e_i\)，记是否存在支持证据和反证为：

\[
b_i=(s_i,r_i),\qquad s_i,r_i\in\{0,1\}.
\]

则边状态为：

\[
V(e_i)=
\begin{cases}
\mathrm{Unknown}, & (s_i,r_i)=(0,0),\\
\mathrm{Supported}, & (s_i,r_i)=(1,0),\\
\mathrm{Contradicted}, & (s_i,r_i)=(0,1),\\
\mathrm{Conflict}, & (s_i,r_i)=(1,1).
\end{cases}
\]

空查询、未运行工具和不完整范围只能产生 `Unknown`，不能令 \(r_i=1\)。

### 3.2 路径状态聚合

对包含必要边集合 \(E(P)\) 的候选路径 \(P\)：

\[
V(P)=
\begin{cases}
\mathrm{Conflict}, & \exists e_i\in E(P):V(e_i)=\mathrm{Conflict},\\
\mathrm{NotReachable}, & \exists e_i\in E(P):V(e_i)=\mathrm{Contradicted},\\
\mathrm{Unknown}, & \exists e_i\in E(P):V(e_i)=\mathrm{Unknown},\\
\mathrm{Reachable}, & \forall e_i\in E(P):V(e_i)=\mathrm{Supported}.
\end{cases}
\]

这一聚合是保守的：路径中任一硬前提被拒绝即可否定该候选路径；任一硬前提缺证则不能宣称可达。

### 3.3 最小正证书

设支持证据 \(z_k\) 的查询成本为 \(c_k\)，能覆盖的必要边集合为 \(C_k^+\)。最小正证书是集合覆盖：

\[
Z^+(P)=
\arg\min_{Z}\sum_{z_k\in Z}c_k
\quad
\mathrm{s.t.}\quad
\bigcup_{z_k\in Z}C_k^+=E(P).
\]

### 3.4 最小负证书

设候选路径族为 \(\mathcal P=\{P_1,\ldots,P_m\}\)，反证 \(z_k\) 能击中的候选路径集合为 \(C_k^-\)。最小负证书是加权 hitting set：

\[
Z^-(\mathcal P)=
\arg\min_Z\sum_{z_k\in Z}c_k
\quad
\mathrm{s.t.}\quad
\forall P_j\in\mathcal P,\ 
\exists z_k\in Z:\ P_j\in C_k^-.
\]

该证书只能证明“已枚举的候选路径均被反证击中”，不能证明所有未枚举路径都不可能。

### 3.5 渐进工具选择

EC-ReAct 在第 \(t\) 步只允许从预算可行的 Pareto 前沿中选择动作：

\[
\mathcal A_t^\star=
\operatorname{Pareto}\left\{
a:\hat c(a)\le B_t
\right\},
\]

其中动作向量至少包含外部规则增益、证据覆盖增益、状态分辨增益和查询成本：

\[
g(a)=
\bigl(
g_{\mathrm{rule}},
g_{\mathrm{coverage}},
g_{\mathrm{resolution}},
-\hat c(a)
\bigr).
\]

LangGraph 仅作为可替换编排后端；创新主张是证据状态、动作约束和证书机制，而不是使用了某个框架。

## 4. Pilot 实验

配置：`configs/provider_oracle_protocol_v3.json`。  
结果：`output/provider_oracle_protocol_v3_results.json`。

实验共运行 144 次，但保守聚类后的独立统计单位始终只有 5 个 independence group。AWS/GCP 的同名实验设计按同一 family 聚类；随机种子重复和 GCP 日志中的多次重试均没有被扩充为独立样本。

在预算 4 和 8 下：

| 方法 | provider gold 状态准确率 | 明确阻断识别率 | Unknown 拒答率 | 非可达样本误报为可达 | 平均查询成本 |
|---|---:|---:|---:|---:|---:|
| provider-aware CP-Cert 透明参考策略 | 1.00 | 1.00 | 1.00 | 0.00 | 2.00 |
| fixed-order | 0.80 | 0.00 | 0.00 | 0.333 | 3.00 / 5.00 |
| full-query | 0.80 | 0.00 | 0.00 | 0.333 | 2.00 |
| random-tool | 0.80 | 0.00 | 0.00 | 0.333 | 3.00 / 5.00 |

透明参考策略的 gold-path edge F1 均值只有 \(0.667\)：它正确找到了决定状态的关键边，但没有重建完整的两边路径。这一结果说明“状态判对”和“完整路径发现”必须分开报告。

## 5. 可以主张与不可以主张

当前可以主张：

- v3 已能在同一 Agent 输出契约下签发正证书和负证书；
- 明确拒绝、真实成功和证据不足不会再被强制折叠为同一种“未验证”；
- gold 与 Agent 可见证据已分离，相关泄漏与可复现测试通过；
- 透明参考策略证明协议与评分器按预期工作。

当前不可以主张：

- EC-ReAct 已在真实数据上显著优于基线；
- 透明确定性策略的 100% 是泛化准确率；
- 六个 pilot 案例足以支持总体统计推断；
- provider-oracle gold 等同于真人语义审阅；
- AWSGoat 配置案例已经证实可达或不可达。

## 6. 后续候选池

`output/provider_success_candidate_inventory.json` 已对固定 DOI 日志中的 AWS/GCP payload-present 成员进行严格 allowlist 扫描：

- 扫描 AWS 52,004 条、GCP 25,594 条 provider 事件；
- 得到 58 个“场景 × 精确数据操作”候选组；
- 保守折叠为 28 个 lineage group；
- 其中 30 个候选组至少包含非 Root 的 IAM 用户、assumed role 或 workload identity。

这些结果只是成功边候选，不是 58 个 gold。只有在关键前驱关系、主体、资源、查询范围和同状态反证均完成审核后，才能升级为路径 gold。

## 7. 下一阶段

1. 将相同构造扩展到至少 30 个独立 provider-oracle 路径组，覆盖 AWS、Azure、GCP，且同时包含 Reachable、NotReachable、Unknown。
2. 对全部语义映射争议和分层样本进行人工审计；真人负责语义与准入，provider 保留 allow/deny 的事实权威。
3. 冻结 development/validation/test/source-held-out 划分后，再运行本地或 API LLM 的 EC-ReAct、vanilla ReAct、full-query、fixed-order 与消融。
4. 分别报告路径状态、完整路径匹配、错误可达率、正确拒答率、查询成本和证书大小。
