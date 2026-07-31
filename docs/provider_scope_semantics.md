# Provider outcome scope semantics

## Why a successful API call is not automatically a reachable data path

Cloud audit records answer different questions at different layers. AWS
explicitly distinguishes:

- **management events**, which describe control-plane operations on cloud
  resources; and
- **data events**, which describe operations performed on or inside a resource.

Reference: [AWS CloudTrail — Understanding CloudTrail
events](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-events.html).

For RDS, a `ModifyDBInstance` success therefore establishes that the provider
accepted a DB-instance management request. It does not establish a database
connection, authentication, SQL statement, or access to a row. AWS documents
those database-level facts separately: Database Activity Streams can record
connection information, SQL commands, affected row counts, and accessed
objects. References:

- [Monitoring database activity
  streams](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/DBActivityStreams.Monitoring.html)
- [Starting a database activity
  stream](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/DBActivityStreams.Enabling.html)

The protocol consequently treats a successful password reset without network,
authentication, or SQL evidence as `Unknown` for the claim “the principal
reached database records.” This is an epistemic boundary, not a claim that
access was impossible.

## Frozen decision rule

For an observation \(o\) and exact investigated claim \(q\), define

\[
D(o,q)=
\mathbf 1[\operatorname{decision}(o)\in\{\mathrm{allow},\mathrm{deny}\}]
\cdot
\mathbf 1[\operatorname{scope}(o)\succeq q].
\]

The implementation renders the second indicator as:

\[
\operatorname{scope}(o)\succeq q
\iff
\texttt{scope\_completeness}\in
\{\texttt{complete},\texttt{complete\_for\_*}\}.
\]

The finite string contract is deliberately conservative:

- `complete` and `complete_for_*` may constrain the requested path state;
- `incomplete_for_*`, `control_only`, and `unknown` cannot certify or refute
  the end-to-end claim;
- a missing field preserves legacy-fixture behavior, but every protocol-v8
  observation explicitly carries the field.

The state rule is:

\[
\hat y(q)=
\begin{cases}
\mathrm{Reachable},&
\exists o:\ D(o,q)=1\land \operatorname{decision}(o)=\mathrm{allow}
\land o\text{ covers every hard path premise};\\
\mathrm{NotReachable},&
\exists o:\ D(o,q)=1\land \operatorname{decision}(o)=\mathrm{deny}
\land o\text{ intersects the exact candidate path};\\
\mathrm{Unknown},&\text{otherwise}.
\end{cases}
\]

An exact-time denial is not overwritten by a later successful control call.
Conversely, a successful control-plane or configuration change is not promoted
to data-plane reachability.

## Tool and certificate enforcement

The rule is enforced at three independent boundaries:

1. compact Tool-Use results expose the public `oracle_kind` and
   `scope_completeness` fields;
2. the LLM action schema permits provider evidence to constrain path state only
   when its scope is decisive;
3. the deterministic CP-Cert verifier rejects support or refutation based on a
   rendered but non-decisive scope.

The scope fields are part of the agent-visible public packet. Evaluator-only
fields such as `gold_state`, support/refute gold IDs, and `label_origin` remain
outside the Tool-Use environment.

## Discovery history and reporting rule

The original v8 local-LLM pilot omitted the scope fields from compact tool
results and treated every provider `allow` as decisive. That pilot is retained
unchanged. The correction is evaluated in a separately identified v8.1
post-hoc diagnostic replication with the same cases, model digest, seeds,
budget, and methods.

This history must remain visible in the thesis. The repaired run demonstrates
that the software defect is reproducible and correctable; it is not a
preregistered population-effectiveness result.
