# Provider-oracle protocol v8

## 目的

v8 不是把更多危险 API 名称直接标成“攻击成功”，而是检验系统能否区分：

1. provider 已确认的有效数据权限暴露；
2. provider 对精确目标的失败决定；
3. 控制面操作成功但数据面结论仍不完备的 `Unknown`。

原始事件来自固定版本的 Splunk Attack Data CloudTrail 制品。协议不生成云事件，不把上游说明文档直接作为 gold，也不把同一制品中的重复调用当作独立样本。

## 新增案例矩阵

| 上游制品 | 观测 | v8 状态 | 确定性依据 | 不能声称的内容 |
|---|---|---:|---|---|
| EBS snapshot exfil（2023 capture） | 未加密快照创建成功，随后向外部账号共享成功 | `Reachable` | 精确快照、外部账号、`encrypted=false`、`_return=true` | 外部账号已经复制或读取数据 |
| EBS snapshot exfil（2021 capture） | 同一快照权限 API 可用，但向无效账号共享被拒绝 | `NotReachable` | 精确快照与受让账号、provider 错误、同快照成功控制 | 其他账号或其他时间也不可共享 |
| RDS password reset | 主密码修改成功并返回 endpoint | `Unknown` | 缺少网络连通、数据库认证和 SQL 查询记录 | 已经读取数据库记录 |
| S3 public bucket | 9 次 ACL 修改成功 | `Unknown` | 缺少 Block Public Access 状态、最终 ACL 与匿名读取探测 | ACL API 成功即等于有效公开 |

快照正负案例属于同一个上游数据集 lineage，统计时只贡献一个 independence group。9 次 S3 ACL 事件也不会被计算为 9 个独立样本。

## 核心评测公式

令独立组集合为 \(\mathcal{G}\)，三状态真值为
\(y_g\in\{\mathrm{Reachable},\mathrm{NotReachable},\mathrm{Unknown}\}\)。
组级状态准确率为：

\[
\mathrm{Acc}_{group}
=
\frac{1}{|\mathcal{G}|}
\sum_{g\in\mathcal{G}}
\mathbf{1}[\hat y_g=y_g].
\]

非可达或证据不完备案例上的错误“可达”率为：

\[
\mathrm{FRR}
=
\frac{
\sum_g
\mathbf{1}[
y_g\neq\mathrm{Reachable}
\land
\hat y_g=\mathrm{Reachable}
]
}{
\sum_g \mathbf{1}[y_g\neq\mathrm{Reachable}]
}.
\]

`Unknown` 控制的正确弃权率为：

\[
\mathrm{CAR}
=
\frac{
\sum_g
\mathbf{1}[
y_g=\mathrm{Unknown}
\land
\hat y_g=\mathrm{Unknown}
]
}{
\sum_g \mathbf{1}[y_g=\mathrm{Unknown}]
}.
\]

工具成本仍按一次运行实际执行的有效查询数 \(q_i\) 计算：

\[
\overline C
=
\frac{1}{N}\sum_{i=1}^{N} q_i.
\]

重复随机种子只用于估计策略方差，不增加独立样本量。v8 仍是协议级 pilot，不能替代真人双标注主测试。
