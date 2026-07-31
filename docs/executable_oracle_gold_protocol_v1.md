# 可执行 Oracle Gold 协议 v1

## 1. 研究问题

本协议用于回答一个范围受限、可复现的问题：在给定主体、动作、资源、网络来源和时间窗口时，是否存在一条能够到达云数据目标的证据路径。

协议不把 Terraform 字面量、靶场说明或攻击名称直接当作运行时真值，也不要求无法获得的“双云安全专家盲标”。Gold 必须由独立于 Agent 的隐藏评估器依据真实制品和执行证据产生。

## 2. 四值真值

| 状态 | 含义 | 可进入主实验 |
|---|---|---|
| `Reachable` | 冻结范围内，原生权限分析允许且授权探针成功，审计日志观察到该操作 | 是 |
| `NotReachableWithinScope` | 冻结范围内，原生权限分析拒绝且授权探针失败，审计日志观察到拒绝 | 是 |
| `Unknown` | 任一必要证据缺失、执行未完成或范围未冻结 | 否 |
| `Conflict` | 独立证据通道给出矛盾结论 | 否，进入调查队列 |

`NotReachableWithinScope` 不是“全世界绝对不可达”。论文必须同时报告冻结的主体、动作、资源、网络来源和时间窗口。

## 3. 四个必要证据通道

每个进入正式 Gold 的独立谱系必须同时具备：

1. `configuration`：固定上游版本中的确定性配置事实，含文件、定位器和 SHA-256；
2. `provider_native_analysis`：云厂商原生权限或策略分析结果；
3. `authorized_active_probe`：在隔离测试账户、仅针对测试数据执行的允许/拒绝探针；
4. `audit_telemetry`：CloudTrail、Azure Activity/Resource Log 或 GCP Audit Log 等云平台实际产生的记录。

每条关键路径边至少引用两个不同证据通道。四通道任一缺失时，验证器保持 `Unknown`，不能因为案例名称、README预期结果或LLM判断而晋级。

## 4. 防止循环论证

- Agent 只能看到脱敏、预算受限的发现视图；
- 原生分析完整输出、探针判据和 Gold 路径仅由评估器读取；
- Agent视图与评估器制品分别保存并绑定不同哈希；
- 同一工具输出不能同时作为 Agent 的输入证据和隐藏 Gold；
- Gold 在模型输出完成后才由评分器加载。

因此，Agent不能通过直接查询“答案工具”获得路径。

## 5. 数据来源分层

| 分层 | 允许表述 |
|---|---|
| 公开真实世界遥测 | 按原始数据集说明报告，不扩大来源主张 |
| 公开靶场的隔离云复现 | “云平台真实产生的受控攻击遥测” |
| 固定上游配置 | “可追溯配置事实”，不能单独称为运行时暴露 |
| 研究者修复版本 | “受控反事实”，不能计作新的独立真实来源 |

脚本可以自动部署固定公开靶场、调用授权探针并收集云平台返回结果，但不得生成虚构事件或标签。

## 6. 机器门禁

权威入口：

```powershell
D:\anaconda\python.exe scripts/oracle/build_executable_oracle_registry_v1.py
D:\anaconda\python.exe scripts/oracle/audit_executable_oracle_registry_v1.py
D:\anaconda\python.exe scripts/oracle/build_oracle_execution_queue_v1.py
D:\anaconda\python.exe scripts/oracle/audit_oracle_execution_capability_v1.py --check-auth
D:\anaconda\python.exe scripts/oracle/build_oracle_split_v1.py
```

当前候选注册表固定40个保守独立谱系、9个上游来源及AWS/Azure/GCP。首次迁移时40个案例全部为 `Unknown`，Gold计数为0。这是预期的 fail-closed 结果。

为防止同一谱系中的多个平台或实例形成伪重复，每个谱系在产生 Gold 前只冻结一个规范评测单元：先用 `SHA-256(independence_group)` 在该谱系已有平台中确定平台，再选择该平台内按 `case_id/runtime_instance_id` 字典序最小的单元。注册表保存选择摘要，校验器会重新计算并拒绝任何事后改选。独立谱系仍是统计分析单位。

执行队列因此包含40个谱系任务，每个任务只对应其冻结评测单元的一个平台（当前AWS 28、Azure 5、GCP 7），默认禁止执行。只有专用测试账户/订阅/项目、工具、费用上限、无敏感数据声明和清理方案全部满足后，执行器才能获得授权；队列本身不包含预期答案。

现有证据完成度被分层记录：10个配置谱系的 `configuration` 通道已通过上游归档和成员哈希验证；30个运行时谱系的 `audit_telemetry` 原始制品已验证存在。后者只记为 `artifact_verified`，在事件语义、原生权限分析和主动探针完成前不会升级为允许/拒绝结论。

完成门槛：

- 至少30个独立谱系为可用的 `Reachable` 或 `NotReachableWithinScope`；
- 至少10个独立谱系为范围受限负例或修复前后对照；
- 所有输入、Agent视图、评估器制品和关键边证据均通过哈希验证；
- `Conflict` 与 `Unknown` 不进入路径有效性主指标。

## 7. 云厂商语义依据

- AWS IAM Access Analyzer使用策略逻辑分析外部和内部访问；其结果不代表外部主体已经实际访问，因此仍需动态探针与审计日志：
  <https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-concepts.html>
- Azure Blob匿名访问同时受存储账户设置和容器访问级别约束：
  <https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-configure>
- GCP Cloud Storage公共读取要求相应公开主体授权，且可能被Public Access Prevention覆盖：
  <https://cloud.google.com/storage/docs/access-control/making-data-public>

这些文档只用于冻结权限语义；最终案例结论仍由案例自己的配置、原生分析、探针和审计制品共同决定。
