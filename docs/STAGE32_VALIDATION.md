# Stage 32 validation: retained-resource and unsigned enrollment intent

Scope: two pure bounded encodings for one selected seven-commitment content class
and an unsigned owner-bound enrollment proposal. No signature/curve verification,
owner role, source/economic equivalence authority, registry or application path
is implemented. Existing codecs, journal/store behavior, mathematical predicates,
formats, models, qualifiers, workflows and dependencies are unchanged.

Source parent: [`2d41e7e1d130bf2ff1e9b2ca95430a5719074f74`](https://github.com/edgepillar/ptlc-research/tree/2d41e7e1d130bf2ff1e9b2ca95430a5719074f74).
Its [completed seven-job run](https://github.com/edgepillar/ptlc-research/actions/runs/37219021046)
ran 718 Python tests per Linux/macOS 3.11/3.13 job with required OpenSSL,
55 Rust tests, 13 Go top-level tests and 68 actual-worker cases including
17 v4 cases. Parent execution does not execute this new contract.

## Local execution

| Check | Result | Boundary |
| --- | --- | --- |
| First new contract suite | 26 passed in 11.231 seconds, no skips | Selected content equality, independent expectations, all scope/source bindings, canonical wire, replay and exhausted-journal preservation |
| Full required offline suite | 744 passed in 883.078 seconds, no skips | Required OpenSSL; all 26 new contract methods, unchanged 29 authority-codec and 26 enrollment-model methods, lifecycle and fixed inventory checks |
| Artifact, links, whitespace and frozen manifests | 428 index/worktree versions; 214 tracked files; 707 valid relative file links; two new Python sources parse; whitespace and both frozen hashes match | Limited ASCII/disclosure/source checks, not anonymity or independent assessment |

No Stage 32 test run failed. The first suite includes the current implementation
and its explicit non-authority cases; no rejected expectation is removed to make
the result pass. No Rust/Go or new owner-signature verifier is executed locally
for this pure Python delta. Required hosted Rust/Go and actual-worker jobs remain
separate; none implements the proposed enrollment owner.

The 26 methods cover the exact seven-field resource tuple and new hash domains;
all nine scope selections keeping the content key while changing intent;
three candidate signatures, copied snapshots, five changed source variants,
and both old-resource and old-live-scope refusal. New changed source remains
representable and supplies no economic-equivalence or fresh-quota authority.
Fixture sequencing accepts structurally retained false-math bytes deliberately;
this is no signature or source-truth oracle.

Intent checks cover independent owner and request ID, each scope selection,
request-label reuse without idempotency, matching zero-key encoding without
curve/control validation, exact field/type/size/domain checks, immutable values,
uninitialized/subclass/tampered objects, hostile input hooks, canonical/duplicate/
escaped/non-ASCII/deep values and cross-schema refusal. Matching unsigned intent
replays; an old expectation still parses after source change. Unknown path,
candidate, signer, verifier, authority and callback inputs are refused.

The reopened exhausted-journal test retains the exact original candidate,
consumed allowance, sequence, SQLite and checkpoint bytes across pure key/intent
preparation and repeated parsing. A separate recovery request still refuses
before its callback. These checks add no journal enforcement or restore defense.

## Requirement and evidence limits

The [selected resource class](RETAINED_RESOURCE_INTENT.md) is equality of seven
public commitment fields. Interpreting that as full-source equality relies on
the prior hash commitments; it proves no economic/funding identity, authenticated
source, first-registration policy, trusted namespace or global quota. Stable keys
alone cannot retain spent history across coherent restore or separate registries.

The owner pin is an independent input. Its encoding and unsigned message binding
do not establish curve membership, key control, role assignment, bootstrap,
delegation, compromise handling, current head or owner permission. A later actual
signature verifier needs its own tests and assessment. Completion-envelope
authentication and public-witness recovery remain distinct policies.

## Hosted and independent gates

All seven exact-head jobs remain required. The four Python/OpenSSL jobs must
execute all 26 new methods, the unchanged 29 authority-codec methods and all
26 enrollment-model methods, and both complete fixed inventories. Rust/Go and
nine actual-worker groups remain expected at 55, 13 and 68, including 17 v4 cases;
they provide no new owner verifier or enrollment backend.

CI configuration and parent results prove no current hosted execution. Completed
exact-head results must be recorded separately from this source report. Both
119/189-file independent subjects and unfilled reports are unchanged. This later
contract needs its own exact delta assessment. Backend selection, private signing,
funded recovery, core port, node activation and real funds remain no-go.
