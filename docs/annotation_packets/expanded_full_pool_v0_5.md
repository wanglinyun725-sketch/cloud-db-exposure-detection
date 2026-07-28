# RealPathBench-CD 扩展无标签候选池

## 结论

- 候选案例：150；生成标签：0。
- 冻结的无标签真实运行实例：91；实例级人工标签：0。
- Cross-Cloud 成对实例在导出时移除上游 present/absent 条件，只保留真实规范化 observations 与哈希引用。
- 新增内容均复制自固定 commit/版本的上游仓库；脚本只做确定性路由、
  解包、哈希和格式转换。
- CloudGoat、CloudFoxable、MITRE 及无匹配爆破日志的 Stratus 静态材料
  保守记为 C 级；11 个带官方真实爆破日志的 Stratus 候选升级为 B 级。
- v0.3 将 OTRF 的完整 103 条 CloudTrail 接到既有 CloudGoat cloud_breach_s3 案例；发布者新增但独立组不增加。
- B 级运行时来源仍不等于 gold；人工未接纳前不得进入主测试集。

## 来源分布

| 来源 | 候选数 |
|---|---:|
| cloudfoxable | 8 |
| cloudgoat | 26 |
| cross_cloud_observability_2026 | 36 |
| mitre_attack_stix | 20 |
| splunk_attack_data | 9 |
| stratus_red_team | 51 |

## 溯源结构

每个新增案例保存归档 SHA-256、归档内成员路径、成员 SHA-256、
原始文本或原始 STIX 对象、独立分组和执行状态。所有人工字段为空。

## 研究边界

候选数大于 80 不等于已有 80 个 gold。`needs_execution`、reject 和
同源近重复不会计入 main included cases；最终样本量只能在盲法双人
标注与必要的隔离执行完成后报告。
