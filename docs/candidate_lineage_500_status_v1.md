# 500 个真实谱系扩充状态 v1

本报告是来源与独立性硬门禁结果，不是攻击路径 Gold 评测结果。

## 当前硬结果

- 已声明候选：430。
- 通过全部机器门禁的独立候选谱系：430。
- 距 500 个还差：70。
- 已核验精确证据定位：454。
- Runtime/Oracle Gold：0（候选绝不计作 Gold）。

## 分层

| 层级 | 通过数 |
|---|---:|
| `cti_procedure` | 200 |
| `deterministic_configuration` | 31 |
| `executable_lab` | 187 |
| `published_runtime_telemetry` | 12 |

## 云平台覆盖

| 平台 | 通过数 |
|---|---:|
| AWS | 158 |
| AZURE | 91 |
| CROSS_CLOUD | 163 |
| GCP | 50 |

## 来源

| 来源 | 通过数 |
|---|---:|
| `atomic_red_team` | 64 |
| `cloudfoxable` | 8 |
| `cloudgoat` | 26 |
| `cross_cloud_observability_2026` | 12 |
| `iam_vulnerable` | 31 |
| `mitre_attack_stix` | 200 |
| `stratus_red_team` | 89 |

## 尚未完成

当前开发目录仅纳入 MITRE ATT&CK 和 Atomic Red Team 两个来源。其余已有固定来源与外部新来源必须逐一转换为同一证据合同，并完成跨来源近重复复核；达到 500 前，`target_passed` 必须保持 false。
