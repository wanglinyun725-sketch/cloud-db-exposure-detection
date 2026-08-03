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
D:\anaconda\python.exe scripts/oracle/build_oracle_evidence_bundle_templates_v1.py
D:\anaconda\python.exe scripts/oracle/build_oracle_scope_candidates_v1.py
D:\anaconda\python.exe scripts/oracle/build_oracle_probe_contracts_v1.py
D:\anaconda\python.exe scripts/oracle/audit_replay_supply_safety_v1.py
D:\anaconda\python.exe scripts/oracle/build_replay_supply_inventory_v1.py
D:\anaconda\python.exe scripts/oracle/audit_oracle_execution_capability_v1.py --check-auth
D:\anaconda\python.exe scripts/oracle/preflight_oracle_probe_v1.py --contract-id <id> --runtime-context <runtime.json> --authorization-context <authorization.json> --output <preflight-report.json>
D:\anaconda\python.exe scripts/oracle/apply_completed_oracle_evidence_v1.py --bundle <evaluator-bundle.json> --output <new-registry.json>
D:\anaconda\python.exe scripts/oracle/build_oracle_split_v1.py
```

当前候选注册表固定40个保守独立谱系、9个上游来源及AWS/Azure/GCP。首次迁移时40个案例全部为 `Unknown`，Gold计数为0。这是预期的 fail-closed 结果。

为防止同一谱系中的多个平台或实例形成伪重复，每个谱系在产生 Gold 前只冻结一个规范评测单元：先用 `SHA-256(independence_group)` 在该谱系已有平台中确定平台，再选择该平台内按 `case_id/runtime_instance_id` 字典序最小的单元。注册表保存选择摘要，校验器会重新计算并拒绝任何事后改选。独立谱系仍是统计分析单位。

执行队列因此包含40个谱系任务，每个任务只对应其冻结评测单元的一个平台（当前AWS 28、Azure 5、GCP 7），默认禁止执行。只有专用测试账户/订阅/项目、工具、费用上限、无敏感数据声明和清理方案全部满足后，执行器才能获得授权；队列本身不包含预期答案。

每个任务还有一份无标签、无预期结果的证据包模板。执行完成的证据包必须绑定队列、策略、冻结单元和范围哈希，记录四通道原始制品、确定性适配器版本、命令摘要、时间、成本及清理后库存；真值字段不允许由执行者填写，而由验证器根据四通道结果唯一推导。测试中的合成制品只验证门禁代码，不进入数据注册表、Gold计数或实验结果。

作用域候选清单只从冻结评测单元中复制可观察字段，不选择终点边、不补全缺失字段，也不产生标签。当前30个运行时谱系中22个含至少一条真实观测，8个所选谱系的上游实例为空；只有7个运行时谱系同时观察到了五类作用域字段，其中仅2个天然形成单一主体、动作、资源和网络来源的候选。解析器不会把筛选器的 `key/name` 参数误当作资源标识。10个配置谱系仍需部署后解析精确主体、资源、网络和时间。候选清单不能直接写入证据包的 `frozen` 范围。

首批探针契约只覆盖两个可无歧义映射的AWS权限变更：EBS快照共享和AMI启动权限共享。契约不会复用历史账号、资源ID或IP，而要求当前运行创建资源，并只允许把权限授予另一个隔离测试账号；禁止使用公共组 `all`。AWS CLI支持对这两个修改操作进行`--dry-run`权限检查，但本协议只把它作为安全预检，不把DryRun结果当作运行时可达Gold。实际探针、后置状态读取、CloudTrail精确事件查询和逆向清理均以argv数组预注册，默认不执行：

- <https://docs.aws.amazon.com/cli/latest/reference/ec2/modify-snapshot-attribute.html>
- <https://docs.aws.amazon.com/cli/latest/reference/ec2/modify-image-attribute.html>
- <https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events-cli.html>
- <https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonec2.html>

在固定版 Stratus 源码基础上，另有3个凭据读取谱系被收缩为低影响终点边契约：单个 Secrets Manager secret、显式列出的两个 secrets 批量读取，以及单个 SSM SecureString parameter。每个资源必须由当前运行创建，只能装入无真实凭据的 canary；禁止上游的账户范围枚举、高数量收集和秘密值打印。CLI `--query` 在输出层排除 `SecretString`、`SecretBinary` 与 parameter `Value`，评估器还会执行二次字段剥离并禁止持久化原始 stdout。该收缩只验证精确终点边，不声称复现上游的广域收集行为：

- <https://docs.aws.amazon.com/secretsmanager/latest/userguide/retrieving-secrets_cli.html>
- <https://docs.aws.amazon.com/cli/latest/reference/secretsmanager/batch-get-secret-value.html>
- <https://docs.aws.amazon.com/secretsmanager/latest/userguide/monitoring-cloudtrail.html>
- <https://docs.aws.amazon.com/cli/latest/reference/ssm/get-parameters.html>
- <https://docs.aws.amazon.com/cli/latest/reference/ssm/put-parameter.html>

运行时预检只在内存中解析argv，不执行命令。它要求授权哨兵、专用非生产账户、精确 `/32` 或 `/128` 出口、递增且不超过TTL的UTC时间窗、政策内成本、强制标签、本轮资源清单、隔离账户差异以及私密输入文件的路径/大小/SHA-256/访问控制证明全部成立。落盘报告不包含运行时值、完整argv或私密文件路径；任一检查失败时，已解析步骤会被清空。秘密值承载响应不得原样持久化，只有去敏stdout/stderr及其哈希可进入证据包。

云平台在创建资源后才返回的ARN、实例ID等值不得由操作者提前猜测或手填。分阶段运行协议首先仅预检不依赖这些值的 `setup` argv；setup返回值只在同一评估器进程内解析，且只能按合同冻结的步骤摘要、JSON Pointer和内置类型验证器提取非敏感字段。提取值必须同时匹配云厂商格式、授权账户、区域和本轮 `run_id`，随后加入本轮资源清单并触发完整二次预检；二次预检通过后才释放原生分析、主动探针、审计查询和清理步骤。setup原始stdout和提取明文均不进入报告或Agent视图，只保留步骤摘要、stdout摘要和绑定值摘要。步骤替换、跨账户ARN、敏感JSON Pointer、预先注入动态值、非零退出或超时都会得到零个后续步骤。

固定的跨云公开攻击脚本也不能直接等同于安全复现代码。静态供应审计先验证 acquisition manifest 中的 Zenodo 文件大小和 SHA-256，再在不解压到文件系统、不执行任何上游代码的条件下扫描归档成员。审计不保留原始行或可能的密钥值，只记录规则、成员路径、行号和行哈希。当前固定版 `attack_scripts.zip` 的164个归档成员中，133个文本成员被扫描，64个成员触发298项阻断发现，覆盖把凭据写入容器层、创建长期凭据、公共主体/ACL、广域管理员角色以及未证明资源属于本次运行的删除操作。因此该制品的结论是 `direct_execution_blocked_requires_sanitized_wrapper`，不能按上游 README 原样运行；这些数字是安全审计结果，不是攻击标签或 Gold。

复现供应清单进一步把40个冻结谱系逐一映射为三层：11个 `pinned_iac_lab`、8个 `published_telemetry_only`、21个 `upstream_native_cli`。其中10个跨云脚本谱系被上述供应审计阻断，8个Splunk谱系只保留为公开遥测，15个谱系仍等待来源专属安全审计，已有7个谱系注册了安全探针契约（AWS 5、GCP 1、Azure 1）。即使这些契约存在，授权和执行资格仍全部为 `false`；供应存在、静态扫描通过或契约存在都不能推出可达性，也不能自动授权云操作。

首个GCP契约绑定固定GCPGoat提交、归档和 `main.tf` 成员哈希，只复现一个随机、无真实数据、本轮创建桶上的窄化策略变更路径。Google官方说明Cloud Audit Logs不跟踪公共对象访问，因此协议禁止把匿名GET伪称为Cloud Audit证据。契约改用两步探针：独立低权限服务账号先通过仅含 `storage.buckets.get/getIamPolicy/setIamPolicy` 的临时自定义角色修改精确桶策略，再读取本轮canary对象元数据；前一步必须匹配Admin Activity，后一步必须在预先启用Data Access日志的隔离项目中匹配Data Access记录。缺少任一事件、探针身份与所有者项目未隔离、桶名不含至少128位随机后缀或清理库存不成立，均保持 `Unknown`。公开对象访问若后续作为独立案例，只能使用GCP官方建议的Usage Logs，并显式处理其小时级延迟与不保证及时/完整交付的限制。

首个Azure契约绑定固定AzureGoat提交、归档及 `main.tf` 成员哈希，但不执行包含虚拟机、函数、Cosmos DB和上游演示数据的完整靶场。它只在专用订阅的随机本轮存储账户中复现同源的 `blob`（匿名对象读、禁止匿名列举）与 `container`（匿名对象读和列举）访问级别，并上传无敏感信息的本轮canary。四个直接HTTPS探针显式禁用curl配置、代理、重定向和所有认证材料，以独立UUID作为 `x-ms-client-request-id`；正式正向证据必须在外部专用Log Analytics工作区的 `StorageBlobLogs` 中同时匹配匿名认证类型、请求UUID、操作、精确URI、出口IP、状态码和时间窗。Azure官方说明大多数失败的匿名请求不会写入资源日志，因此生产容器列举失败只保留为辅助客户端证据，严禁用日志缺失证明拒绝；若任一成功请求日志在20分钟有界轮询内仍未到达，案例保持 `Unknown`。

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
- Azure Blob资源日志只有在预先创建诊断设置后才会保存；成功匿名请求会记录，而大多数失败匿名请求不会记录：
  <https://learn.microsoft.com/en-us/azure/storage/blobs/monitor-blob-storage>
- `StorageBlobLogs` 提供认证类型、调用方IP、客户端请求ID、操作、状态码和URI等精确关联字段：
  <https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/storagebloblogs>
- GCP Cloud Storage公共读取要求相应公开主体授权，且可能被Public Access Prevention覆盖：
  <https://cloud.google.com/storage/docs/access-control/making-data-public>

这些文档只用于冻结权限语义；最终案例结论仍由案例自己的配置、原生分析、探针和审计制品共同决定。
