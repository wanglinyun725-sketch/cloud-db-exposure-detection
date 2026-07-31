# Graduate Goal v2 机器验收

- objective_complete：`false`
- 通过门槛：2/8
- 口径：只读取仓库证据，不提供主观分数或学校成绩保证。

## 验收矩阵

| 门槛 | 状态 |
|---|---|
| `real_cross_cloud_benchmark` | PASS |
| `thirty_lineage_executable_oracle_gold` | BLOCKED |
| `ten_bounded_negative_or_paired_controls` | BLOCKED |
| `ec_react_and_baselines_implemented` | PASS |
| `hash_bound_protocol_frozen` | BLOCKED |
| `confirmatory_experiment_claim_passed` | BLOCKED |
| `final_deliverables_bound_to_results` | BLOCKED |
| `research_branch_synchronized_to_remote` | BLOCKED |

## 当前阻断项

- `thirty_lineage_executable_oracle_gold`：At least 30 independent lineages must pass the hidden, hash-bound executable Oracle protocol.
- `ten_bounded_negative_or_paired_controls`：At least 10 scope-bounded negative or paired counterfactual controls must pass the executable Oracle protocol.
- `hash_bound_protocol_frozen`：绑定gold、split、代码版本与哈希的FROZEN协议尚不存在
- `confirmatory_experiment_claim_passed`：冻结双模型实验尚未通过F1、相对增益与安全门槛
- `final_deliverables_bound_to_results`：论文、答辩材料、复现包和三轮审稿压力测试尚未绑定最终决策哈希
- `research_branch_synchronized_to_remote`：本地研究分支仍有未同步到上游的提交

## 关键证据

```json
{
  "dataset": {
    "conservative_independence_groups": 40,
    "source_count": 9,
    "platforms": [
      "AWS",
      "AZURE",
      "GCP"
    ]
  },
  "executable_oracle_gold": {
    "valid": true,
    "qualifying_independence_groups": 0,
    "bounded_negative_or_paired_control_groups": 0,
    "completion_gate": {
      "minimum_oracle_gold_groups": 30,
      "minimum_bounded_negative_or_paired_controls": 10,
      "oracle_gold_passes": false,
      "negative_control_passes": false,
      "passes": false
    }
  },
  "method": {
    "required_methods_present": [
      "ablate_budget_stop",
      "ablate_evidence_cert",
      "ablate_external_rule_prior",
      "ablate_four_value_memory",
      "ablate_pareto",
      "ablate_provider_scope_gate",
      "ec_react_full",
      "fixed_order",
      "full_query",
      "random_tool",
      "vanilla_react"
    ],
    "schedule_errors": [],
    "model_locks_pass": true
  },
  "frozen_protocol": {
    "config_present": false,
    "manifest_present": false
  },
  "confirmatory_decision": {
    "status": "missing"
  },
  "deliverables_manifest": {
    "path": "output\\research_design\\final_deliverables_v2_manifest.json",
    "present": false
  },
  "git": {
    "branch": "agent/research-upgrade",
    "behind_upstream": 0,
    "ahead_of_upstream": 1,
    "synchronized": false
  }
}
```
