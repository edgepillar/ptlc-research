# Stage 108 original actor compound faults

FINAL-SOURCE LOCAL REGRESSION PASSES; FRESH HOSTED QUALIFICATION PENDING AT THIS SNAPSHOT.

The selected immutable parent is `f5d814d797f2833ac581c3cfd342d68c1d3bea0c`,
tree `0108f468ce971c5c82cb117f8c18a54cefb8c659`. The original actor, store,
observer, classifiers, strict tests and all 324 preceding sources remain byte
exact. One new source adds ten unique in-process methods using the existing
input and pipe helpers. No external source code is copied. This changes selected
offline qualification, with no application, core, cleanup or retry change.

The terminal wrapper calls the actual store close, then raises a fresh selected
exception while the primary exception is active. This explicitly synthetic
post-successful-close fault is separate from a natural SQLite close error,
subprocess termination or an operating-system signal. Native output faults use a
real pipe with its reader closed; selected flush faults use synthetic EIO after
actual delivery to a local pipe consumer. Native SQLite setup and rollback
denials use the actual connection's authorizer. No test assigns a process status.

| Selected primary boundary | Separate terminal selection | Delivered bytes | Separate local/reopened original state |
| --- | --- | --- | --- |
| Readiness cancellation | Post-close EIO | Readiness marker | Zero originals; no transaction |
| Precommit cancellation | Post-close EIO | Pause marker | Rollback; zero originals |
| Postcommit cancellation | Post-close EIO | Pause marker | One committed original |
| Native SQLite setup denial before observer installation | Post-close cancellation | Empty | Zero originals; no transaction or native report |
| Native first allocation reply EPIPE | Post-close cancellation | Empty | One committed original |
| Native stale-policy refusal reply EPIPE | Post-close cancellation | Empty | Zero originals; refusal rollback |
| Native report EPIPE | Post-close cancellation | Allocation record only | One committed original |
| Selected first flush EIO after delivery | Post-close cancellation | Allocation record only | One committed original |
| Selected report flush EIO after delivery | Post-close cancellation | Allocation record and empty report | One committed original |
| Precommit cancellation with two native rollback denials | Terminal close skipped by already-disposed guard | Pause marker | Zero originals; locally held report has two null-code rollback entries |

Nine paired controls assert the exact terminal exception object outward and the
exact primary object at close, including identity through `__context__`. Both
have no explicit cause and no context suppression. Refusal output failure keeps
a three-object chain: terminal selection, native BrokenPipeError, and the actual
StoreRefused object. Other selected primary contexts are empty. The guard
control preserves the primary cancellation directly and leaves its terminal
object unraised. These are observations of the selected in-process executions,
not a guarantee for arbitrary error handling or fault combinations.

Every control checks constructor/allocation counts, selected transaction
authorizer callbacks, a disposed actor handle, exact local pipe delivery and
separate local/reopened rows and sequence values. All retain zero synthetic
effects. Authorizer callbacks do not prove successful statement execution or
exact disposal-call count. A locally held report is distinct from a report
received in output; the setup fault occurs before observer installation. Native
null-code entries are not reclassified as SQLITE_BUSY. The inherited process
response classifier records exit status as unavailable for these in-process
controls. Missing output is compatible with both zero and one retained original.
Even a received report before a flush fault does not establish normal completion.

The focused run passes ten methods in 0.054 s (runner 0.284 s), with required
OpenSSL and ResourceWarnings treated as errors. There were no focused failures
or retries. Complete final-source regression is recorded below; source preservation
and artifact hygiene remain separate gates.

The [scope note](POLICY_EFFECT_CONTENTION.md#original-actor-compound-faults)
keeps these selections separate from interrupted construction, natural
native-close failures, process signals, arbitrary concurrent faults, fragmented
transport, authenticated remote receipt, restored copies and physical
durability. No output, exception chain or readback observation authorizes
replacement, retry, refund, nonce allocation, signing or a physical effect.

Stage 99's original failure cause remains UNRESOLVED. SC01-SC12 remain OPEN;
physical F1-F4 and future A01-A12 remain NOT EXECUTED. Signer, custody,
current-policy ownership and a nonrollback anchor remain UNSELECTED /
NOT IMPLEMENTED. Independent assessment is absent. Application/core remain
NO-GO; this is offline synthetic research.

One complete run on the frozen final sources passes 2145 exact unique methods
in 1001.711 s (runner 1002.192 s), required OpenSSL,
no skips, failures or ResourceWarnings. All 2135 preceding IDs are retained and
ten disjoint IDs are added. All 324 preceding sources remain exact; one new
test source gives 325 frozen sources. Two documentation modifications and two
additions give 551 files, with 547 of 549 preceding files exact. There were no
preparatory or qualification failures and no qualification retry. Full
Rust/Go/Linux/Apple profiles were not rerun locally; fresh hosted execution and
independent assessment remain separate. Earlier failed logs and original
archives remain preserved without source or evidence cleanup.
