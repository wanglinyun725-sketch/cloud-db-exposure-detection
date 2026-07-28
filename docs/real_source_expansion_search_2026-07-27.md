# 真实数据源扩展检索与准入审计（2026-07-27）

## 检索规则

本轮按 `nature-academic-search` 的 T1→T2 路由执行：

1. 优先论文/DOI 数据记录、官方仓库、云厂商文档和作者数据仓库；
2. DOI 作为主去重键，无 DOI 时使用仓库身份和标题；
3. 必须确认原始文件、固定版本、许可和校验和；
4. “可执行靶场”“官方示例”“论文宣称有数据”不能自动等同于公开攻击遥测；
5. 新来源只能按其真实用途接入，不能为了样本量改变数据语义。

检索没有使用不稳定的 Google Scholar 抓取结果；T1 官方页面和作者仓库已足够
作出本轮准入决定。

## 准入结果

| 候选来源 | 一手核验 | 决定 | 原因 |
|---|---|---|---|
| Measuring Attack Observability in Cloud Telemetry Logs | https://zenodo.org/records/19933893 | 已接入并扩展 | DOI v2、CC-BY-4.0、攻击脚本和三云原始日志齐全；由原2个家族扩为12个数据相关家族 |
| Cloud Incident Reports (2016–2024) | https://zenodo.org/records/14010282 | 新接入，但仅作负对照候选 | DOI v1、CC-BY-4.0、3,087份生产可靠性事件；不是攻击遥测 |
| 作者代码仓库 | https://github.com/atlarge-research/llm-cloud-incident-extraction | 作为数据方法佐证 | CC0 工具仓库明确链接 Zenodo，并区分 raw/clean/sample/label 数据 |
| Splunk Cloud Attack Range | https://github.com/splunk/attack_range_cloud | 不新增独立数据源 | 是生成真实 CloudTrail 的执行平台；可用于未来隔离执行，但仓库本身不是新的固定日志语料 |
| Splunk AWS RDS Password Reset | https://research.splunk.com/attack_data/baa24d41-2a93-43c6-af77-ff9e97f75191/ | 已在现有 Splunk 来源中 | 明确为 attack_range CloudTrail 数据，不能重复计数 |
| Stratus Red Team detonation logs | https://stratus-red-team.cloud/attack-techniques/AWS/aws.defense-evasion.dns-delete-logs/ | 已核验并接入 | 固定归档含35份 Grimoire 真实测试云爆破日志、310条 CloudTrail；只把与云数据候选相交的11份/139条升级为 B 级 |
| OTRF Security-Datasets SDAWS-200914011940 | https://github.com/OTRF/Security-Datasets | 已固定并接入主候选包 v0.3 | MIT 许可、103条 CloudTrail；元数据明确派生自 CloudGoat `cloud-breach-s3`，故是独立发布遥测而不是新独立场景 |
| AWS RDS CloudTrail 文档 | https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/logging-using-cloudtrail.html | 仅作工具/字段语义依据 | 官方示例不是独立攻击事件数据集 |
| ACSE-Eval | https://arxiv.org/abs/2505.11565 | 暂不进入攻击遥测主集 | 是架构威胁建模数据，适合 C 级结构扩展，但不是运行时路径证据 |

## Cross-Cloud 完整候选池结果

- 12 个独立攻击家族；
- 36 个平台×攻击组；
- 1,424 个严格 payload/no-payload 配对 episode；
- 712 对 run；
- 65,041 条原始云审计观测；
- 5 个上游未完整配对 run key 被排除，未补造数据。

统计分析必须以12个攻击家族为独立 group，不能以1,424个 episode 作为独立样本。

## 真实生产事件负对照结果

- 3,087 份 AWS/Azure/GCP 生产可靠性事件报告；
- 996 份云数据关键词候选；
- 4 份命中安全相关词，必须优先人工排除；
- 首轮未标注筛选包按 AWS/Azure/GCP 各10份，共30份；
- 只有双人确认“云数据相关且非攻击”的案例才能进入
  `external_negative_control`；
- 这些报告不进入攻击路径训练集，也不增加正向攻击案例数。

## 对论文实验的影响

该扩展增加一个不能靠正样本召回来掩盖的研究问题：Agent 面对真实云数据库/
存储故障时，是否会臆造攻击路径。新增指标为 hallucinated-path rate、
unsupported-evidence rate 和 correct-abstention rate。

OTRF 的新增价值是为一个此前只有静态 walkthrough 的 CloudGoat 多步路径提供
103 条第三方采集 CloudTrail，但统计上必须继续归入同一个
`cloudgoat-scenario:cloud_breach_s3` 组。当前 v2 人工 pilot 已冻结且尚未产生
人工标签，因此本轮不改写其 v0.2 输入；另发布主候选包 v0.3，将 OTRF 作为
第 93 个运行实例接入，同时保持候选数 150、独立组数 113 不变。

全源契约审计随后在 v0.3 中识别出两个零观测 Cross-Cloud episode。正式主池
因此升级为 v0.4：只排除这两个不可执行实例，保留 OTRF 和全部候选谱系；主池
现含 91 个非空实例。v0.3 及其 93 实例审计继续保留作为版本化来源证据。

为避免 Cross-Cloud 紧凑投影使 `resource_search` 先天不可用，v0.5 又从同一固定
归档、同一哈希校验和同一确定性盲化环境复制详情字段。v0.5 没有新增事件或标签，
但 91 个非空实例现在均有可检索的 request/response/resource 详情。
