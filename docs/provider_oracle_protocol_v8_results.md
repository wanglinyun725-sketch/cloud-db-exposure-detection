# Provider-oracle protocol v8 results

## Scope

The pilot contains 600 run records but only **16 independent groups**. Events, cases from the same lineage, and repeated random seeds are not treated as independent samples.

## Group-level results

| Method | Budget | Correct groups | 95% CI | Unsafe false-Reachable | Mean query cost |
|---|---:|---:|---:|---:|---:|
| `fixed_order` | 2 | 0.375 | [0.185, 0.614] | 0.000 | 1.000 |
| `fixed_order` | 4 | 0.562 | [0.332, 0.769] | 0.250 | 3.062 |
| `fixed_order` | 8 | 0.562 | [0.332, 0.769] | 0.250 | 3.750 |
| `full_query` | 2 | 0.625 | [0.386, 0.815] | 0.188 | 1.875 |
| `full_query` | 4 | 0.562 | [0.332, 0.769] | 0.250 | 2.062 |
| `full_query` | 8 | 0.562 | [0.332, 0.769] | 0.250 | 2.062 |
| `provider_aware_cp_cert` | 2 | 1.000 | [0.806, 1.000] | 0.000 | 1.875 |
| `provider_aware_cp_cert` | 4 | 1.000 | [0.806, 1.000] | 0.000 | 2.062 |
| `provider_aware_cp_cert` | 8 | 1.000 | [0.806, 1.000] | 0.000 | 2.062 |
| `random_tool` | 2 | 0.375 | [0.185, 0.614] | 0.000 | 1.000 |
| `random_tool` | 4 | 0.562 | [0.332, 0.769] | 0.250 | 3.062 |
| `random_tool` | 8 | 0.562 | [0.332, 0.769] | 0.250 | 3.750 |

A group is correct only when every provider-gold case is semantically correct and every epistemic control correctly abstains.

## Paired exact comparisons

| Budget | Baseline | Primary wins | Baseline wins | Ties | Difference | Exact p | Holm p |
|---:|---|---:|---:|---:|---:|---:|---:|
| 2 | `fixed_order` | 10 | 0 | 6 | 0.625 | 0.0020 | 0.0176 |
| 2 | `full_query` | 6 | 0 | 10 | 0.375 | 0.0312 | 0.1094 |
| 2 | `random_tool` | 10 | 0 | 6 | 0.625 | 0.0020 | 0.0176 |
| 4 | `fixed_order` | 7 | 0 | 9 | 0.438 | 0.0156 | 0.1094 |
| 4 | `full_query` | 7 | 0 | 9 | 0.438 | 0.0156 | 0.1094 |
| 4 | `random_tool` | 7 | 0 | 9 | 0.438 | 0.0156 | 0.1094 |
| 8 | `fixed_order` | 7 | 0 | 9 | 0.438 | 0.0156 | 0.1094 |
| 8 | `full_query` | 7 | 0 | 9 | 0.438 | 0.0156 | 0.1094 |
| 8 | `random_tool` | 7 | 0 | 9 | 0.438 | 0.0156 | 0.1094 |

## Interpretation boundary

The deterministic provider-aware method is expected to satisfy the frozen contract and therefore functions as a protocol sanity check. Its result is not an LLM effectiveness claim. The exact tests expose the limited number of independent groups, and the Holm correction prevents selecting a favorable budget after the fact.

The thesis main effectiveness claim still requires independent human-finalized gold and source-disjoint evaluation.
