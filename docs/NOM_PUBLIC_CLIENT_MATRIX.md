# NoM public client scenario matrix

Status: **selected offline component candidate; no operational matrix acceptance**.
This work advances M3 for the existing public client and mathematical checker.
It selects no signer, observer, durable client state, network or funds.
Application/core remain **NO-GO** and independent assessment is **UNFILLED**.

## Source and evidence boundaries

The accepted M2b baseline is
[`366a4157fdd85fd5b32c5257b529c170430fe22e`](https://github.com/edgepillar/ptlc-research/tree/366a4157fdd85fd5b32c5257b529c170430fe22e).
Its own [main run 40888304942/1](https://github.com/edgepillar/ptlc-research/actions/runs/40888304942/attempts/1)
and nine original artifact families were accepted separately from the PR run;
the [PR record](https://github.com/edgepillar/ptlc-research/pull/215) identifies
that boundary. The baseline has five library cases, two process cases and two
small-package targets. Its earlier results do not qualify this candidate.

The current selection adds three process cases and reuses their exact source
from the small package. It declares five library cases and five process cases,
with library, binary and integration-test targets. Case presence and an expected
count are not execution results. Fresh source, compiler, build context, complete
original outputs and applicable acceptance records accompany qualification.

The protocol still selects contract/account source `77ba9c7ee8c881e90911946756cdb67d8b586043`
and public backend `74d18bbf864f98e5cf7c18dcfb74ba1ecfe837ce`. This IO change
updates neither source selection, cryptographic construction nor action authority.

## Applicable public scenarios

The selectors below refer to the current
[agreement tests](../tests/test_client_agreement.py),
[preparation tests](../tests/test_client_presignature.py),
[shared checker tests](../public_crypto/src/lib.rs) and
[actual process tests](../qualification/tests/client_public_crypto_process.rs).
Every row needs the selected source's actual evidence before it is counted as
accepted. Declared projections establish consistency, not chain truth.

| ID | Scenario | Selected check |
| --- | --- | --- |
| PUBLIC-01 | No pre-funding entry ID or Unlock message is invented | `test_prefunding_agreement_has_no_invented_entry_ids_or_unlock_messages` |
| PUBLIC-02 | Long-only preparation and ordered short binding | `test_long_preparation_uses_its_real_declared_send_without_a_short_id`; `test_adding_short_keeps_the_long_request_stable_and_selects_the_short_message`; ordered-prefix refusals |
| PUBLIC-03 | Exact replay retains the complete prefix; a different Create hash cannot replace it | `test_replay_preserves_complete_prefix_and_never_regresses_to_one_leg`; `test_changed_valid_hash_candidate_cannot_replace_original_funding` |
| PUBLIC-04 | Economics, send fields and all retained bindings match | Economic-entry, send-field, cross-agreement and corrupt-unselected-binding refusals |
| PUBLIC-05 | Peer message, context, backend or executable fields are refused | `test_peer_message_context_backend_and_executable_fields_are_not_admitted` |
| PUBLIC-06 | Local economic commitment can change while the contract message stays equal | `test_counterparty_economics_are_committed_even_when_the_selected_message_is_unchanged` |
| PUBLIC-07 | Altered message, point, scalar or parity fails the relation | `changed_message_point_scalar_and_parity_are_not_validated` |
| PUBLIC-08 | Mathematical validity authenticates no caller context or action | `mathematical_validity_does_not_authenticate_a_caller_context`; preparation permission checks |
| PUBLIC-09 | Foreign, duplicate, noncanonical or oversized input is refused | Preparation CLI and shared-library refusal cases |
| PUBLIC-10 | The actual CLI admits one framing LF and refuses oversized input | `the_built_public_cli_accepts_one_framing_lf_and_refuses_oversized_input` |
| PUBLIC-11 | Locked package metadata retains three dependencies and the declared targets | `the_small_package_has_its_own_consistent_offline_lock_and_public_targets` |
| PUBLIC-12 | An owned child interrupted before input EOF produces no completed check | `interrupted_partial_input_is_not_a_completed_public_check` |
| PUBLIC-13 | A closed output pipe yields an IO refusal | `a_broken_output_pipe_refuses_public_result_delivery` |
| PUBLIC-14 | Zero exit with discarded output supplies no captured receipt | `a_zero_exit_without_captured_output_is_not_a_verification_receipt` |

PUBLIC-12 selects an incomplete-input window. It proves no exact instruction
cut, key-use history or signer restore safety. Its later fresh check is a public,
stateless verification. PUBLIC-13 checks local write/flush failure. Even successful
flushing cannot prove receiver custody; PUBLIC-14 preserves that distinction.
Public checker children have a bounded wait and only owned children are stopped.
Cargo metadata and the enclosing commands retain their declared qualification
budgets separately.

## Retained baseline counterexample

A separate measurement of baseline `366a4157` closed the only output reader
before supplying the complete canonical synthetic request. The actual process
exited zero with no stderr. Standard output was deliberately unavailable and
was recorded as **not collected / incomplete**, rather than an empty complete
result. The input digest was
`00a23ea5269a1f47ec336f4b6c08477a5f0a0b36f0fe9b90cac3888f556f4280`.
The selected build used Rust 1.90 and the unchanged three-dependency package;
its original source, tool, process and input/output records were retained.

This is a counterexample to treating process exit alone as a receipt. It is not
a failed mathematical relation, operational recovery test or disclosure claim.
The candidate explicitly checks writing and flushing before returning zero.
The original baseline observation remains separate from any later candidate pass.

## Python public IO candidate

This separate M3 slice covers the Python public preparation entry point. The
Rust subset above keeps its five library and five process cases. Neither subset
selects an operational client, signer, observer or recovery store.

An author-run bounded observation of Python source
[`285cd07e371c48743583dbd641b1133cb8e62e60`](https://github.com/edgepillar/ptlc-research/tree/285cd07e371c48743583dbd641b1133cb8e62e60)
used canonical synthetic terms with input SHA-256
`e0c9e2b75b308e1410f6c21653cc950cdbfac0a022691e399c610b2382d09aed`.
The stream entry point returned zero when an injected writer accepted no
characters. It also returned zero without calling an injected failing `flush`.
These are bounded stream-interface observations. In the actual standalone
closed-reader case the process exited **120**, rather than zero; its output
was deliberately uncollected. Discarding output to the null device exited zero
and supplied no captured receipt. Original outcomes remain separate from later
candidate results.

The candidate checks the complete character count and explicitly flushes before
returning success. It makes no second public-result write after a short or
failed write. Input/output OS errors produce a generic refusal, and an
unavailable diagnostic stream cannot turn refusal into success. The standalone
process redirects remaining standard-stream buffers to the null device after
refusal to avoid another failed flush at interpreter shutdown. This follows
the [Python shutdown-flush guidance](https://docs.python.org/3.13/library/signal.html#note-on-sigpipe).
It cannot recall bytes already written or establish receiver custody.

The seven new selectors below are in the existing
[Python component tests](../tests/test_reference_client.py). Their declared
presence is not source-bound execution, hosted acceptance or independent review.

| ID | Scenario | Selected check |
| --- | --- | --- |
| PUBLIC-15 | Complete local writing/flushing; read, write, flush and invalid write-count refusals without retry | `test_successful_public_output_is_fully_written_and_flushed`; `test_public_io_failures_return_sanitized_refusal`; `test_short_and_invalid_output_counts_are_refused_without_retry` |
| PUBLIC-16 | Missing diagnostics preserve refusal; actual closed output/diagnostic readers yield a sanitized or deliberately uncollected refusal | `test_diagnostic_io_failure_preserves_refusal`; `test_closed_output_reader_returns_sanitized_module_refusal`; `test_standalone_refusal_survives_closed_diagnostic_reader` |
| PUBLIC-17 | Zero exit with intentionally discarded Python output supplies no receipt | `test_zero_exit_with_discarded_python_output_is_not_a_receipt` |

The interrupted-input Rust row, injected Python stream faults and actual Python
process rows have distinct evidence scopes. They do not establish arbitrary
instruction-cut recovery. Partial, discarded or missing output stays UNKNOWN;
no JSON result is reconstructed. Local success still authenticates no peer,
agreement, chain state or delivered receipt and grants no retry, funding,
signing, disclosure, replacement or recovery authority.

## Python input completion candidate

Baseline source
[`008189664c851111167c93d6e1908d82719e1e4d`](https://github.com/edgepillar/ptlc-research/tree/008189664c851111167c93d6e1908d82719e1e4d)
made one bounded read from the supplied Python input stream. Small synthetic
controls reproduced three component counterexamples: a valid fragmented request
was refused, a valid prefix hid a later JSON value, and a valid prefix hid a
later read fault. Scope is the injectable Python input API. No standalone-process
attack or operational recovery failure was established.

The new candidate accumulates bounded bytes until the stream declares EOF.
It retains the 32 KiB cap, refuses the first excess byte before another read,
and emits no success when a later read faults or returns an invalid value.
Blocking standard-input behavior, producer authenticity and operational timing
remain distinct. The five selectors below require their own source-bound
execution and applicable hosted acceptance.

| ID | Scenario | Selected check |
| --- | --- | --- |
| PUBLIC-18 | Complete valid fragments, including the exact byte limit; stop at the first excess byte | `test_fragmented_valid_input_is_completed_before_success`; `test_fragmented_input_stops_at_the_existing_byte_limit` |
| PUBLIC-19 | A later JSON value, read fault or invalid read value prevents success output | `test_valid_json_prefix_does_not_hide_a_later_input_value`; `test_late_input_fault_prevents_public_success_output`; `test_invalid_late_input_values_refuse_without_emitting_a_result` |

Reading through declared EOF supplies no transport authentication, received
receipt, retry permission or recovery authority. Application/core remain NO-GO
and independent assessment remains UNFILLED.

## Focused feedback and remaining requirements

The [small-package command](../public_crypto/README.md) runs the selected library
and actual process cases using the same source as qualification. The manifest
adds no dependency and its lockfile selection stays unchanged. Declared owned
cache and target storage remain necessary for local qualification. Focused
feedback does not replace full offline regression, native scope or fresh hosted
original acceptance required for integration.

Actual bilateral funding/claims/refunds, contract and recipient receives,
balance outcomes, insufficient Plasma, current fees, reorgs, proxy behavior,
signer nonce/restore rules, durable rollback, possible witness disclosure and
ambiguous broadcast are **not executed by this public component**. They need
their own selected implementation, protocol assessment and explicit execution
authority. They must not be counted as passing rows in this matrix.
