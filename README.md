# CloudDB-PathBench: 云数据库暴露路径侦测基准与EIC-Agent原型

## 项目简介

本项目是硕士论文《面向云数据库高敏数据暴露路径侦测的证据约束智能体方法研究》的中期实验实现。

核心思想：**表达—判定分离**
- LLM（侦探）：负责调度工具、收集证据、解读结果、生成归因解释与处置建议
- Gate·Score（法官）：负责确定性的路径判定，不经过LLM，确保可追溯、无幻觉

## 技术栈

- Python 3.10+
- LangGraph（Agent状态机框架）
- NetworkX（图引擎）
- DeepSeek API（LLM + Function Calling）

## 快速开始

```bash
# 1. 安装依赖
pip install -r requirements.txt

# 2. 配置API Key
cp .env.example .env
# 编辑 .env 填入 DEEPSEEK_API_KEY

# 3. 运行 EIC-Agent 端到端演示
python run_demo.py

# 4. 启动 Web 可视化看板（默认 http://localhost:5050）
python web_app.py
```

## 项目结构

```
cloud_db_pathbench/
├── run_demo.py        # 端到端演示入口
├── web_app.py         # Flask 可视化看板入口（:5050）
├── configs/           # Gate阈值 + LLM配置
├── data/
│   ├── schema_pool/   # 行业表定义
│   └── verification_set/  # 验证样本
├── src/
│   ├── graph/         # 图加载 + 约束DFS + 敏感性聚合
│   ├── agent/         # LangGraph EIC-Agent
│   ├── data_gen/      # 样本生成 + 校验
│   ├── eval/          # 评估指标（占位，待实现）
│   └── baselines/     # 对比方法（占位，待实现）
├── scripts/           # 辅助/一次性脚本
│   ├── generate_web_results.py  # 生成看板结果数据
│   ├── demo_gate_score.py       # Gate·Score 判定验证
│   ├── convert_data.py          # 旧格式数据转换（依赖外部路径）
│   └── patch_table.py           # 对照表补丁（依赖外部路径）
├── docs/              # 论文 PDF + 公式代码对照表
├── output/            # 生成的结果 JSON
└── experiments/       # 实验结果
```

## EIC-Agent Agent循环

1. **假设生成** → DFS枚举候选暴露路径
2. **证据采集** → 工具调用查询网络/权限/敏感数据/控制项/审计
3. **信念更新** → Gate-Score计算五维证据向量，确定性判定
4. **动作决策** → 剪枝/补证/确认/终止（POMDP信念状态驱动）
