# dataset_v1 说明

`dataset_v1` 是当前 C1/C2 语义语料的可信评估切分版本，用于解决同源样本混用和 all-corpus 自测问题。

## 数据来源

输入语料：`output/semantic_corpus/cloud_db_semantic_corpus.json`

该输入语料由 `scripts/build_semantic_corpus.py` 从以下来源生成：

- `data/pathbench_60.json`
- `data/pathbench_cloudgoat.json`
- `data/verification_set/samples_v2.json`

当前 SDDP 文件仍作为 case slice，不进入 `dataset_v1` 主实验。

## 当前规模

| 项目 | 数量 |
|---|---:|
| samples_total | 308 |
| groups_total | 104 |
| path_labels_total | 672 |

## split 分布

| split | samples | groups | retrieval samples |
|---|---:|---:|---:|
| dev | 164 | 56 | 36 |
| validation | 46 | 19 | 9 |
| test | 58 | 19 | 13 |
| hard_test | 40 | 10 | 10 |

## 为什么使用 group split

同一个 base 样本会派生 `missing/refuted/temporal_conflict` 等变体。如果把 base 放到开发集、变体放到测试集，就会出现同源结构泄漏。`dataset_v1` 按 `group_id` 切分，保证同一个 base 及其所有变体只出现在同一个 split。

## 指标边界

- `semantic_consistency_check` 只能说明语义标签和验证器实现是否一致。
- `test` 和 `hard_test` 可作为当前主实验结果来源。
- `dev` 和 `validation` 只用于开发检查和参数选择。
- SDDP 切片目前是案例材料，不是真实攻击 ground truth。
