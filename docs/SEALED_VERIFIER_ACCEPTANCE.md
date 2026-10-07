# Sealed public verifier acceptance cutoff and descriptor policy

Status: selected opt-in reference construction. Application and core progression
remain **NO-GO**. The selected parent is
`c7bf13fb5cb3da2db9de3bf14e3fbdadf57d90cf`.
The preceding [sealed Linux entry construction](SEALED_PUBLIC_VERIFIER.md)
supplies per-call snapshot continuity under an explicitly trusted local runtime.
This addition narrows result acceptance and descriptor selection; it does not
supply authenticated distribution, a sandbox or private signing authority.

## Original result-acceptance cutoff

The existing public runner accepts a relative timeout and creates its own
monotonic deadline at runner entry. A pause after the adapter calculates that
relative timeout can move the runner's deadline beyond the adapter's earlier
deadline. A correct positive receipt alone does not enforce the earlier cutoff.

The optional sealed adapter retains its original monotonic deadline, beginning
after request serialization and the existing 32768-byte request bound. It checks
remaining time after the runner returns, after snapshot cleanup and after the
complete ASCII/JSON, exact canonical-byte and request-digest checks. Equality
with the deadline refuses. A valid late native receipt is discarded; no refresh,
retry, substitute receipt, extended budget or journal advancement is introduced.
Snapshot ownership still covers runner failure and direct cancellation.

This is acceptance at selected check points, not a hard wall-clock guarantee.
Request serialization precedes this deadline. File and process syscalls,
cleanup, Python execution and host scheduling can block or run late. In
particular, a pause after relative-budget calculation can still permit late
public worker launch, and a pause after the final check can delay delivery to
the caller. No process-creation deadline, real-time scheduling, physical failure
bound or chain timing policy is established. The existing public runner retains
its complete bytes and its documented cleanup limitations.

## Standard-descriptor alias refusal

The selected runner redirects stdin/stdout/stderr before execution. Snapshot
descriptors zero, one and two would occupy those same standard-stream slots.
Merely keeping such a descriptor open does not establish that its original file
remains in that slot after redirection.

The sealed adapter rejects a snapshot descriptor below three immediately after
allocation, before permissions, copying, seals, hashing or launch. The owning
context still closes both source and snapshot. There is no descriptor relocation,
numeric fallback, retry, pre-exec Python callback or standard-stream restoration.
A low source descriptor is allowed when the separately allocated snapshot is
at least three: the source is closed before transport and is never the launched
descriptor. The host's existing memfd execution policy remains in force.

The semantic review uses official CPython commit
`cbc944f4bc59639a444dd971c737788ba2283a91`:

- [Python subprocess selection and descriptor handoff](https://github.com/python/cpython/blob/cbc944f4bc59639a444dd971c737788ba2283a91/Lib/subprocess.py)
  passes retained descriptors to the native child path; this selected call does
  not use the optional posix_spawn branch.
- [Native child descriptor handling](https://github.com/python/cpython/blob/cbc944f4bc59639a444dd971c737788ba2283a91/Modules/_posixsubprocess.c)
  makes retained descriptors inheritable before standard-stream redirection and
  execution. This supports the conservative alias refusal; it is not evidence
  that the preceding adapter executed an attacker-selected program.
- [Subprocess contract](https://github.com/python/cpython/blob/cbc944f4bc59639a444dd971c737788ba2283a91/Doc/library/subprocess.rst)
  describes POSIX retained descriptors and standard-stream handling.
- [Upstream license](https://github.com/python/cpython/blob/cbc944f4bc59639a444dd971c737788ba2283a91/LICENSE)
  was inspected before implementation-source acquisition. The local code and
  harness are originally authored; no upstream implementation is copied.

These are immutable semantic source pins, not authentication of the installed
Python, kernel, loader, native binary or runtime closure. The preceding Linux
and glibc source pins retain their scope.

## Qualification and unresolved authority

Eight new portable modeled controls retain all twenty preceding modeled controls
and every other ordinary test. They exercise relative handoff delay, exact/late
cutoff, cleanup delay, receipt parsing/binding delay, timely canonical receipts,
low snapshot refusal and separate low source ownership. No modeled file API or
clock establishes real kernel or scheduling behavior.

Two appended actual-exchange methods retain all sixteen preceding methods and
the complete command-line entry. On Linux, the selected schedules require three
timely native positives and refusal of three delayed real native positives,
with six closed snapshots. Seven isolated closed-standard-descriptor schedules
repeat the same three original public requests: single closed slots require
nine native positives with distinct snapshots; two or three closed slots require
twelve alias refusals before runner entry. All 21 snapshots must be closed.
The isolated child's report pipe is never retained by the native verifier.
These are repeated execution schedules, not new cryptographic constructions or
27 distinct equation vectors. Unsupported macOS explicitly refuses without
skipping or launching snapshots. See [validation](STAGE85_VALIDATION.md) for the
separate local and hosted evidence.

All existing consumers, legacy/measured adapters, guarded observation profiles,
native sources, crypto fixtures, dependencies, actors and workflow jobs retain
their complete bytes. Both finite models, four fixed inventories and three
unfilled assessment reports remain unchanged. Source-to-worker and
reproducibility remain **NOT VERIFIED**; producer origin and private consumed
inputs remain **NOT AUTHENTICATED**; independent privacy remains
**NOT ASSESSED**. Nonce custody, restored-copy protection, independent review,
authenticated observation and application policy remain open. No wallet,
transaction, chain, funds, deployment, node activation or reviewer action is
selected.
