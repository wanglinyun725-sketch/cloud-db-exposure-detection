# Deterministic Config-to-Exposure Benchmark Plan

## 1. Why this replaces manual path invention

The benchmark will no longer ask a human annotator to infer every permission
edge from a long narrative. Each candidate begins with a frozen, public,
license-preserved configuration. A provider-native analyzer evaluates the
exact principal-action-resource claim. An authorized active probe then
establishes whether the deployed lab actually allowed or denied the operation.
Provider audit logs bind the successful operation back to the tested identity
and resource.

The upstream lab manual is useful for selecting the claims to test, but it is
never gold. The Agent does not see the manual or oracle verdict during
evaluation.

## 2. Two different questions and two different gold tiers

| Question | Required evidence | Positive | Negative | Silence |
|---|---|---|---|---|
| Is the frozen configuration permissive? | frozen IaC/deployed inventory + complete-scope provider-native analysis | explicit allow | explicit deny | `Unknown` |
| Did the path work in the deployed lab? | exact active probe + immutable response; successful probes also require matching audit evidence | success + audit record | explicit access denied | `Unknown` |

This separation prevents three common mistakes:

1. A permissive policy is not automatically described as a completed attack.
2. An analyzer with no finding is not automatically described as secure.
3. Obtaining database credentials is not automatically described as reading
   database records.

## 3. Path verdict semantics

Each mandatory edge has independent configuration and runtime states:
`Supported`, `Contradicted`, `Unknown`, or `Conflict`.

For a path whose edges are all mandatory:

- `Reachable`: all mandatory edges are supported at the selected layer.
- `NotReachable`: at least one mandatory edge has explicit refutation and no
  edge has conflicting evidence.
- `Unknown`: no edge is explicitly refuted, but at least one remains unknown.
- `Conflict`: at least one edge has both support and refutation.

This is implemented in
`src/verification/deterministic_exposure.py`. The result is compatible with
the existing CP-Cert conflict-preserving certificate design.

## 4. First frozen sources

| Source | Exact revision | Role | Main value | Current status |
|---|---|---|---|---|
| AWSGoat | `b24869a...` | executable AWS lab | SSRF→Lambda credentials→DynamoDB; ECS credentials→Secrets Manager | candidate, not gold |
| AzureGoat | `b970459...` | executable Azure lab | SSRF→Cosmos/Blob and production-denied/development-public Blob pair | candidate, not gold |
| GCPGoat | `44605c4...` | executable GCP lab | anonymous denied→set IAM policy→object listing transition | candidate, not gold |
| IAM Vulnerable | `0f29866...` | IAM path component library | 31 reproducible privilege-escalation modules | development only |
| TerraGoat | `729f8da...` | multi-cloud IaC corpus | independent static-checker fixtures | development only |
| Terraform IAM Policy Validator | `f75804e...` | AWS native-oracle adapter | invokes Access Analyzer checks on Terraform policies | tool, not data |

Every snapshot and license is stored under `data/real_sources/raw` and frozen
by SHA-256 in `data/real_sources/acquisition_manifest.json`.

## 5. First high-value control structures

### 5.1 Azure same-deployment negative/positive pair

The official AzureGoat walkthrough says that an anonymous list request to the
production Blob container is denied, while the similarly named development
container permits listing and reading. The experiment will send the same
unauthenticated operation to both containers in one deployment:

1. Freeze both container access configurations.
2. Save the production denial response.
3. Save the development list and blob-read responses.
4. Retain storage/data-plane logs.

This pair controls for provider, deployment, client, operation type, and time.
The primary changing factor is the container configuration.

### 5.2 GCP before/after authorization transition

The official GCPGoat walkthrough starts with anonymous object listing denied.
The anonymous principal has `storage.buckets.getIamPolicy` and
`storage.buckets.setIamPolicy` on the development bucket, can change the
policy, and can then list objects.

The experiment freezes two states:

- state T0: object listing denied, policy modification capability present;
- state T1: policy modified, object listing allowed.

The certificate must include the T0 denial, exact pre/post IAM policies,
`testIamPermissions`, policy-change audit event, and T1 success. The evaluator
tests whether the Agent discovers the transition rather than stopping at the
initial denial.

### 5.3 AWS path with honest endpoint boundaries

AWSGoat module 1 describes:

`registered user → SSRF/local environment → Lambda credentials → DynamoDB
ListTables/Scan/PutItem`.

The database path ends only after a DynamoDB data operation is proved. In
module 2, obtaining `RDS_CREDS` from Secrets Manager is gold for secret
exposure but not for RDS data access unless a separate database query is
captured. This distinction fixes a frequent overclaim in attack-path datasets.

## 6. Provider-native oracle adapters

### AWS

- IAM Access Analyzer external-access findings and policy checks.
- `terraform-iam-policy-validator` to run Terraform IAM policies through
  Access Analyzer `ValidatePolicy`, `CheckNoNewAccess`,
  `CheckAccessNotGranted`, and `CheckNoPublicAccess`.
- Exact authorized AWS API probe plus CloudTrail.

### Azure

- Defender for Cloud attack-path API for externally driven exploitable paths.
- Exact RBAC/resource configuration export for the principal and target.
- Data-plane list/read/write probe plus the appropriate Azure logs.

### GCP

- Policy Analyzer for principal-access-resource analysis.
- `testIamPermissions` for the exact principal and bucket/resource.
- Exact data operation plus Cloud Audit Logs.
- Because Policy Analyzer does not account for every policy system (for
  example, deny-policy limitations must be checked for the chosen query), an
  analyzer result and runtime result are stored separately.

## 7. Safety and reproducibility

- Deploy only to isolated, authorized student lab accounts/projects/
  subscriptions.
- Use least-cost regions and a run identifier on every resource.
- Capture `terraform plan`, `terraform apply` result, provider inventory,
  oracle requests/responses, active-probe responses, audit records, and
  `terraform destroy` result.
- Fail closed on unresolved resource identifiers or cleanup plans.
- Never run probes against arbitrary public endpoints or production systems.
- Redact credentials while preserving event IDs, request IDs, principals,
  actions, resources, timestamps, result codes, and raw-artifact hashes.

## 8. Dataset admission

A candidate enters the main benchmark only if:

1. its source and license are frozen and traceable;
2. it has an external or low-privilege entry;
3. it contains at least two causal/reachability relationships;
4. it reaches a cloud data target;
5. every critical edge has configuration or runtime oracle evidence;
6. its scenario/lineage group is not split across train and test.

Candidates that fail (2)–(4) may remain tool-development fixtures but do not
inflate the benchmark case count.

## 9. Human workload after the change

Humans are still needed, but not to invent every edge. They:

- approve source eligibility and scope;
- audit a stratified 10–20% sample of parsed claims and certificates;
- adjudicate provider-tool conflicts;
- review whether a probe stayed within the authorized lab;
- approve final scenario semantics and paper case studies.

The bulk permission decision is produced by deterministic provider tools and
replayable probes. This makes the thesis defensible even when the student is
not already a senior cloud-security analyst.

## 10. Primary references

- AWS IAM Access Analyzer concepts:
  https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-concepts.html
- Amazon S3 Access Analyzer:
  https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-analyzer.html
- Terraform IAM Policy Validator:
  https://github.com/awslabs/terraform-iam-policy-validator
- Azure Defender for Cloud attack-path API:
  https://learn.microsoft.com/en-us/azure/defender-for-cloud/attack-path-api
- GCP Policy Analyzer:
  https://docs.cloud.google.com/policy-intelligence/docs/analyze-iam-policies
- AWSGoat: https://github.com/ine-labs/AWSGoat
- AzureGoat: https://github.com/ine-labs/AzureGoat
- GCPGoat: https://github.com/ine-labs/GCPGoat
- IAM Vulnerable: https://github.com/BishopFox/iam-vulnerable
- TerraGoat: https://github.com/bridgecrewio/terragoat

## 11. First provider-oracle runtime result

The pinned cross-cloud DOI telemetry contains ten payload runs of the GCP
`scheduled_transfer` experiment. In every run:

1. Cloud Audit Logs contain Cloud Function creation, service-account `actAs`,
   and Cloud Scheduler job creation records.
2. The function service account attempts
   `storage.objects.list` against that run's Cloud Storage bucket.
3. GCP returns status code 7 and explicitly records
   `storage.objects.list` as denied.
4. A different project identity successfully lists the same bucket in the
   same run, ruling out a missing bucket or general service failure.

Across the ten runs, the denied function identity retries 44 times. Retries are
kept as evidence repetitions, not counted as independent benchmark cases.
The ten runs are instances of one lineage case:
`crosscloud:gcp:scheduled_transfer:blocked_bucket_list`.

The frozen upstream script also places both
`roles/storage.objectViewer` and `roles/pubsub.publisher` as two `--role`
arguments on one `gcloud projects add-iam-policy-binding` invocation. The
official CLI contract defines one binding as one member plus one role. This is
a plausible configuration explanation, but the negative runtime verdict does
not depend on that inference: it is certified directly by the ten provider
denials and same-target success controls.

The case now satisfies the separate
`configs/provider_oracle_gold_contract_v1.json` and has a
`provider_native_runtime` `NotReachable` label. It remains outside the frozen
human-v2 benchmark until protocol-v3 integration and a stratified semantic
audit; it is not reported as human gold.
