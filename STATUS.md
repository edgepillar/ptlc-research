# Reference-client delivery status

Status: **offline candidate development; application and core NO-GO**.
No signing, wallet access, node activation, broadcast, operational recovery or
funds are authorized by this status record.

## Active delivery work

The active work applies M3 to the public verification component: incomplete
input, process interruption and output loss. The same process cases are selected
by the small Rust package and the larger qualification crate. The
[scenario matrix](docs/NOM_PUBLIC_CLIENT_MATRIX.md) names the applicable checks
and their separate evidence requirements.

The M2a/M2b components retain their declared funding and public presignature
scope. The Python CLI rechecks the complete ordered funding prefix and derives
the selected message, key, full adaptor point and local context digest. A separate
Rust package checks the selected pinned library's public relation. It has no
signing, adaptation or extraction interface and grants no action.

These tools do not verify Create execution, agreement authentication, current
chain state, nonce safety or a complete swap protocol. RPC, a signing owner and
durable client state remain open. Implementation presence and component tests
require their own relevant qualification before publication or integration.

- [Roadmap and milestone acceptance](docs/REFERENCE_CLIENT_ROADMAP.md)
- [Protocol candidate and decision boundaries](docs/NOM_REFERENCE_CLIENT_PROTOCOL.md)
- [Preserved qualification reading index](README_QUALIFICATION_HISTORY.md)

Milestone acceptance is recorded against exact source and checks. Documentation,
an executable parser or a successful test does not close the application/release
gates below. New work must advance a named acceptance condition or fix a concrete
defect, with its verification scope declared before execution.

## Recorded accepted baseline

| Evidence | Selected scope |
| --- | --- |
| Source | [`366a4157fdd85fd5b32c5257b529c170430fe22e`](https://github.com/edgepillar/ptlc-research/tree/366a4157fdd85fd5b32c5257b529c170430fe22e) |
| Hosted main run | [40888304942, attempt 1](https://github.com/edgepillar/ptlc-research/actions/runs/40888304942/attempts/1) |
| Recorded acceptance | All 14 actual jobs, nine original artifact families and complete console accepted for that exact source; four fresh 4,578-case Python profiles and the selected native results |
| Meaning | Source-bound offline/native/hosted baseline evidence; no operational or independent-review acceptance |

The baseline contains a public adaptor verifier, reference journals, source-pinned
wire/hash and contract comparisons, and explicit failure/counterexample evidence.
These are completed research outputs. They are not an implemented swap client.
Later working-tree changes require their own relevant checks; the baseline run
cannot be relabeled as their qualification. Record failed and interrupted
attempts separately from later successful observations.
The earlier `db05a929` baseline and its main run `40670225920/1` remain historical
subjects. The [M2b PR record](https://github.com/edgepillar/ptlc-research/pull/215)
records the separate PR and main acceptance. Later M3 changes require their own
source and checks; the accepted baseline has two process cases and two small
package targets, rather than the current candidate's five cases and three targets.

## Open acceptance boundaries

| Boundary | Current state and next requirement |
| --- | --- |
| Active protocol | Candidate specification and decisions; no reviewed end-to-end signing construction |
| Signing and key custody | No production backend selected or connected; nonce/context and restore assumptions require explicit assessment |
| RPC and chain observation | No authenticated observer connected; canonicality, evaluation time, confirmation policy and reorg behavior remain separate requirements |
| Durable client recovery | Existing reference evidence is retained; no operational client state or automatic uncertain-outcome recovery selected |
| Local-devnet composition | Planned later milestone; no devnet execution or spork activation performed by the current offline slice |
| Independent assessment | Unfilled; source inventories and author/cross-implementation checks do not supply reviewer independence |
| Bitcoin extension | Historical CANDIDATE-01 preserved; any alternate graph is a separate later construction and assessment subject |
| Application, core and real funds | NO-GO; no activation, release or funds permission follows from local tests or CI |

The anchor-service requirements AS-1 through AS-7 remain unfilled for that
historical service construction. A future client may select a different declared
trust model. Requirements excluded from that model are marked out of scope or
deferred, rather than reported as passed.

## Review subject and historical records

The [current-source handoff](docs/NOM_CURRENT_REVIEW_HANDOFF.md) is preparation
only. It freezes source `e61aa17418cc96d82c21ebfdb651c339363230fd`, with 1,256
files, and preserves older subjects. Its name does not make it a review of the
accepted `db05a929` baseline or the later client work. The corresponding report
remains **NOT ASSESSED / UNFILLED**. Any eventual assessment must select its own
exact source, dependencies, evidence and exclusions.

The complete earlier README is retained without path rewriting at
[README_QUALIFICATION_HISTORY.md](README_QUALIFICATION_HISTORY.md). Historical
Stage labels and conditional execution statements are snapshots. This status
record supplies the delivery entry point without rewriting frozen evidence.
