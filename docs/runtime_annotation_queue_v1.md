# 运行时谱系双人标注队列 v1

该队列在任何人工标签产生前冻结，选择过程只读取来源、哈希、运行时实例和独立谱系元数据，不读取或生成 gold。

## 规模

- 案例：58
- 独立谱系：32
- 运行时实例：91
- 原始观测：2635
- 独立运行时来源：4
- human gold：0

## 来源分布

| 来源 | 案例 | 独立谱系 |
|---|---:|---:|
| `cloudgoat` | 1 | 1 |
| `cross_cloud_observability_2026` | 36 | 12 |
| `splunk_attack_data` | 9 | 8 |
| `stratus_red_team` | 12 | 11 |

## 平台实例分布

| 平台 | 运行时实例 |
|---|---:|
| AWS | 42 |
| AZURE | 25 |
| GCP | 24 |

## 人工流程

1. 两位真实标注者必须从同一无标签队列分别创建 assignment，彼此不可见。
2. 每位标注者独立回答五项准入问题，并为接受案例标注 canonical 节点、边、路径和证据。
3. 系统计算原始一致率、Cohen's kappa/其他适用一致性指标。
4. 只对分歧案例创建第三人仲裁任务。
5. 标注提交必须包含 human attestation；LLM、AI assistant 或模型身份不能登记为标注者。

## 必须人工复核的近重复风险

- `crosscloud-family:data_manipulation`
- `crosscloud-family:data_staged`

运行序列指纹碰撞只触发复核，不自动判为重复，也不自动赋予任何标签。
