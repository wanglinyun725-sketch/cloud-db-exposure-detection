# Local Qwen2.5-7B protocol-v8 diagnostic

## What this experiment is

The frozen v8 pilot exposed a method defect: compact tool results hid `scope_completeness`, while the dynamic policy schema treated every provider `allow` as end-to-end reachability. The v8.1 run keeps the same model digest, cases, seeds, budget, and methods, but exposes public oracle scope and rejects incomplete provider outcomes as path certificates. The v8 result is retained rather than overwritten.

This is a **post-hoc diagnostic replication**, not a frozen thesis effectiveness result.

## Independence-aware result

| Method | Groups | Correct before | Correct after | False-Reachable before | False-Reachable after | Latency before (s) | Latency after (s) |
|---|---:|---:|---:|---:|---:|---:|---:|
| `ec_react_full_langgraph` | 3 | 0.667 | 1.000 | 0.333 | 0.000 | 38.61 | 15.72 |
| `ec_react_full_linear` | 3 | 0.667 | 1.000 | 0.333 | 0.000 | 34.40 | 15.84 |
| `vanilla_react_linear` | 3 | 0.333 | 0.667 | 0.667 | 0.000 | 39.72 | 27.64 |

Group correctness is deliberately strict:

$$C_{m,g}=\bigwedge_{r\in g}\left[\mathbb{1}_{gold}(r)S_r + \mathbb{1}_{control}(r)A_r\right],$$

where $S_r$ is semantic state correctness and $A_r$ is correct Unknown abstention. Repeated seeds and related cases never increase the sample size.

## Pre/post paired diagnostic

| Method | Corrected groups | Regressed groups | Ties | Exact p |
|---|---:|---:|---:|---:|
| `ec_react_full_langgraph` | 1 | 0 | 2 | 1.0000 |
| `ec_react_full_linear` | 1 | 0 | 2 | 1.0000 |
| `vanilla_react_linear` | 2 | 1 | 0 | 1.0000 |

The two-sided exact paired value uses $p=2\sum_{k=0}^{\min(b,c)}\binom{b+c}{k}2^{-(b+c)}$.
With only three lineages it is descriptive; a non-significant value does not negate the directly reproduced software defect.

## Unknown-control behavior

| Method | Case | Before | After |
|---|---|---:|---:|
| `ec_react_full_linear` | RDS password reset | `{'Reachable': 3}` | `{'Unknown': 3}` |
| `ec_react_full_linear` | S3 ACL change | `{'Unknown': 3}` | `{'Unknown': 3}` |
| `ec_react_full_langgraph` | RDS password reset | `{'Reachable': 3}` | `{'Unknown': 3}` |
| `ec_react_full_langgraph` | S3 ACL change | `{'Unknown': 3}` | `{'Unknown': 3}` |
| `vanilla_react_linear` | RDS password reset | `{'Reachable': 3}` | `{'Unknown': 3}` |
| `vanilla_react_linear` | S3 ACL change | `{'Reachable': 3}` | `{'Unknown': 3}` |

## LangGraph result

Across 12 matched case-seed runs, linear and LangGraph had 0 state, 0 semantic-score, and 0 runner-decision mismatches.

Therefore LangGraph is an implementation/orchestration choice here, not an accuracy innovation. Any latency difference is descriptive.

## Full method versus vanilla ReAct

At the independence-group level the full method wins 1, vanilla wins 0, and 2 groups tie (exact p=1.0000).

## Audit boundary

The original JSONL had 49 records for 36 unique coordinates; 13 duplicate resume records were ignored after semantic-conflict checking. The replication had 36 records for 36 unique coordinates and 0 ignored duplicates.

Limitations:

- post-hoc diagnostic replication, not a preregistered main result
- only three independent lineages in this four-case subset
- three seeds test stability but are not independent samples
- provider-oracle labels and epistemic controls are not human gold
- the local seven-billion-parameter model is a reproducible systems probe, not evidence about all LLMs
