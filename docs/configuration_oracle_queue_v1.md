# 确定性配置 Oracle 队列 v1

该队列把 10 个来自 AWSGoat、AzureGoat、GCPGoat、TerraGoat 和
CloudFoxable 的真实、固定版本配置候选转换成可执行的验证任务，但不会把
Terraform 文本或上游挑战说明直接当作攻击路径 gold。

每个任务严格拆成三层：

1. `frozen_configuration`：只验证固定归档中的字面配置事实，并记录归档
   SHA-256、成员 SHA-256、片段 SHA-256 和精确行号；
2. `provider_native_analysis`：必须对精确 principal-action-resource 范围取得
   provider-native allow/deny；“没有发现”保持 `Unknown`；
3. `authorized_active_probe`：只允许在隔离、授权的实验账户中执行，并要求操作
   响应与云审计记录配对，才能升级为 runtime gold。

当前机器可审计结果：

- 10 个候选案例、10 个独立配置谱系；
- AWS、Azure、GCP 均覆盖；
- 5 个直接案例来源；
- 17 项配置字面断言已由固定源码验证；
- configuration gold、runtime gold、path gold 均为 0；
- 10 个案例全部保持 `needs_execution`。

CloudFoxable 的 `Double Tap` 与 `Search 1` 只贡献固定配置事实和待验证假设：
前者不能凭挑战目标推断 Secrets Manager 路径闭合；后者也不能凭
Elasticsearch 资源策略推断公网与数据面必然可达。两者仍须完整作用域的 AWS
权限分析、隔离部署和正/负主动探针。

因此，这批材料增加了真实配置来源和确定性验证工作量，但在 provider 分析、
主动探查与双人盲标完成前，不能计入正式 gold，也不能用于宣称路径
`Reachable` 或 `NotReachable`。
