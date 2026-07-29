# 确定性配置 Oracle 队列 v1

该队列把 5 个来自 AWSGoat、AzureGoat 和 GCPGoat 的真实、固定版本
Terraform 候选转换成可执行的配置验证任务，但不会把 Terraform 文本直接
当作攻击路径 gold。

每个任务严格拆成三层：

1. `frozen_configuration`：只验证固定归档中的字面配置事实，并记录归档
   SHA-256、成员 SHA-256、片段 SHA-256 和精确行号；
2. `provider_native_analysis`：必须对精确
   principal-action-resource 范围取得 provider-native allow/deny，
   “没有发现”保持 Unknown；
3. `authorized_active_probe`：只允许在隔离、授权的实验账号中执行，并要求
   操作响应与云审计记录配对，才能升级为 runtime gold。

当前结果：

- 5 个候选案例、5 个独立配置谱系；
- AWS、Azure、GCP 均覆盖；
- 3 个独立上游来源；
- 9 项 Terraform 字面断言已由固定源码验证；
- configuration gold、runtime gold、path gold 均为 0；
- 5 个案例全部保持 `needs_execution`。

因此，这批材料可以增加真实配置来源和确定性验证工作量，但在 provider
分析或主动探查完成前，不能计入正式 gold，也不能用于宣称路径 Reachable
或 NotReachable。
