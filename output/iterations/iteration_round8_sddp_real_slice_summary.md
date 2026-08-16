# 第八轮迭代记录：SDDP 真实证据切片接入

## 本轮目标

在 C1/C2 已稳定的基础上，探索如何参考 SDDP/DSC 数据安全平台的真实链路，将真实资产、连通性、识别任务和敏感字段结果接入 CloudDB 语义证据图。

关键约束：

```text
SDDP 真实配置 ≠ 真实入侵轨迹
```

因此，本轮不把 SDDP 数据包装成攻击 ground truth，而是定位为：

```text
真实资产与敏感识别证据切片
```

用于增强 C1 的真实适配性和系统展示可信度。

---

## 本轮实现

新增脚本：

```text
scripts/build_sddp_evidence_slice.py
```

该脚本将本地导出的 SDDP/DSC JSON 转换为 CloudDB 语义证据图格式。

### 输入文件

脚本接受一个 input directory，支持以下文件：

| 文件 | 来源 | 用途 |
|---|---|---|
| `data_instance_source.json` | DMS / 控制面 | 资产实例 |
| `sys_data_limit.json` | DMS / 控制面 | 授权与连通性 |
| `dsc_identify_task_asset.json` | DMS / 控制面 | 识别任务绑定 |
| `data_objects.json` | POP `DescribeDataObjects` | 数据库 / 表 / 列 / 敏感规则 |
| `sls_results.json` | SLS `task_detect` 等 | 底层识别结果证据 |

脚本不直接访问生产 DMS/POP/SLS，不读取凭证，只处理本地导出的 JSON。

---

## 映射规则

### 1. 资产实例

`data_instance_source` 转为：

```text
DBInstance
```

字段映射：

```text
instance_id → DBInstance.name
engine → DBInstance.engine
region → DBInstance.region
resource_name → DBInstance.resource_name
```

### 2. 连通性

`sys_data_limit.check_status` 转为：

```text
identity_sddp_scanner --can_connect--> DBInstance
```

状态映射：

| check_status | status |
|---|---|
| 3 | Supported |
| 4 | Contradicted |
| -1 / 其他 | Unknown |

### 3. 数据对象与敏感字段

`DescribeDataObjects` 转为：

```text
DBInstance --contains--> Database
Database --contains--> Table
Table --contains--> Column
Column --classified_as--> SensitiveTag
```

`RuleList` / `rule_name` 转为 `SensitiveTag`。

### 4. 识别任务与 SLS 结果

识别任务绑定和 SLS 检测结果转为 `AuditEvent` 证据节点，用于表达：

```text
该敏感识别结果来自真实识别任务或 SLS 结果
```

---

## 输出格式

输出仍是 CloudDB semantic sample：

```json
{
  "sample_id": "sddp_lindorm_example_slice",
  "scenario": "SDDP-REAL-SLICE",
  "sample_label": "Valid",
  "has_attack_trace": false,
  "notes": "This slice uses real SDDP/DSC evidence semantics but does not claim a real intrusion trajectory.",
  "nodes": [],
  "edges": [],
  "path_labels": []
}
```

重点字段：

```text
has_attack_trace = false
```

用于防止论文中误表述为真实攻击路径。

---

## 脱敏示例验证

运行命令：

```bash
python3 scripts/build_sddp_evidence_slice.py \
  --input-dir output/sddp_slices/example_input \
  --output output/sddp_slices/sddp_lindorm_example_slice.json \
  --slice-id sddp_lindorm_example_slice \
  --write-example

python3 -m src.data_gen.validator \
  output/sddp_slices/sddp_lindorm_example_slice.json
```

结果：

| 指标 | 数值 |
|---|---:|
| 样本数 | 1 |
| 节点数 | 8 |
| 边数 | 7 |
| path_labels | 1 |
| 校验通过率 | 100% |
| has_attack_trace | false |

生成文件：

```text
output/sddp_slices/example_input/
output/sddp_slices/sddp_lindorm_example_slice.json
output/sddp_slices/sddp_lindorm_example_slice_stats.json
```

---

## 论文定位

这部分在论文中不应作为主 benchmark，而应作为：

```text
真实证据切片案例分析
```

推荐写法：

> 由于真实云环境中完整入侵轨迹通常不可获得，本文不将 SDDP 证据切片作为攻击 ground truth，而是将其作为真实资产、授权状态、连通性、识别任务和敏感字段结果的证据来源。本文验证 C1 证据语义图能够承载真实数据安全平台中的多源证据，并可在其上叠加可控威胁假设构造可验证暴露路径。

---

## 可以如何用于展示

后续可以将该 slice 加入 `showcase_semantic.html` 或单独生成：

```text
showcase_sddp_slice.html
```

展示内容：

```text
SDDP Scanner / Connector
→ can_connect
→ Lindorm DBInstance
→ contains
→ Database / Table / Column
→ classified_as
→ SensitiveTag
```

这是一条真实证据链，不是入侵链。

---

## 下一步建议

### 方向 A：接真实导出数据

从 DMS/POP/SLS 导出真实脱敏 JSON，替换 example_input：

```text
data_instance_source.json
sys_data_limit.json
data_objects.json
sls_results.json
```

然后运行转换器生成真实切片。

### 方向 B：生成可控威胁注入

在 SDDP real slice 上叠加：

```text
external principal
leaked credential
public endpoint
Unknown connectivity
Contradicted connectivity
```

构造：

```text
controlled_exposure
controlled_missing
controlled_refuted
```

用于半真实实验。

### 方向 C：加入网页展示

将 SDDP slice 作为单独分类加入 Cytoscape demo：

```text
filter: sddp_real_slice
```

用于答辩展示“系统可接入真实数据安全平台证据”。
