# Bounded offline NoM evidence retention

Application/core remain **NO-GO**. This additive POSIX backend retains public
synthetic claims locally. It supplies no observation authority, canonical branch,
funding permission, finality, signer or recovery-journal admission. The selected
host, filesystem, pathname ancestors and fsync implementation are trusted.

## Requirements and selected construction

A candidate fork, shorter reply, malformed packet or missing result must not
erase an earlier positive claim, the exact original bytes or possible disclosure.
Keep both versions and an explicit comparison. Revalidate funding and the live
entry before any future recovery, including when the funding header belongs to a
common prefix. A displaced-inclusion list is an incomplete admission checklist.

`offline_session.nom_retention.NomEvidenceRetention` selects one complete set of
fixed terms, chain identifier, supplied anchor claim and retained inclusions. It
binds the existing [momentum profile](NOM_MOMENTUM_CONFORMANCE.md) and PR #138
commit `45e1bbb48ce6fc19d44c5fbf59ccf5784981fced`. These are local selections,
not independently established genesis/spork or source authority. The six opaque
account headers in the existing corpus retain that corpus's limitations: their
former acknowledgement contexts are not composed with the synthetic momenta.
Retaining both inputs does not verify their account payload or contract execution.

The construction uses a hash-chained append-only file with a lifetime advisory
POSIX lock. The owned directory requires mode 0700 and the regular, single-link
file requires mode 0600. The open directory descriptor anchors the final name;
ancestor selection and hostile path changes remain external premises. Process,
thread and reentry checks reject borrowed handles. Inherited close releases only
that process's descriptor, without explicitly unlocking the parent's description.
Cooperating owners of the same file cannot write concurrently. Independent copies
have independent locks and can diverge.

## Retained data and acknowledgement ordering

- `retain_original(leg, wire)` retains one exact public synthetic claim envelope
  per leg under the selected terms. Another original for that leg is refused;
  exact replay writes nothing. The domain-separated digest is synthetic, not a
  Zenon account-block hash. Format validation does not authenticate its signature;
  a well-shaped zero signature is an explicit unsafe control.
- `retain_observation(id, wire, previous_id=..., disclosure_possible=...)` retains
  exact raw bytes and recomputes the frozen structural inspection/comparison.
  Malformed, empty, contradictory and incomplete replies within the byte bound
  are retained as claims with their refusals. A caller explicitly chooses a
  previous retained observation; no latest or accepted branch is selected.
- An observation identifier cannot be rebound to different bytes, comparison or
  disclosure flag. Exact replay returns the original local receipt without a new
  event. Equivalent JSON with different spacing remains different raw evidence.
- `note_possible_disclosure()` and observation flags only accumulate disclosure.
  A later false flag, reorg or absence cannot remove it from the current history.
  This records a possibility asserted locally, not proof of a remote disclosure.

Before each public operation, the complete bounded file must still equal its
owned image and satisfy the inode, permission and link checks. A prospective
event is validated before writing. Acknowledgement follows the complete record
write and file fsync. Initial creation also fsyncs the selected directory before
returning. Reopen validates every complete record, replays transitions and
recomputes inspection/comparison, then fsyncs the file and directory before
exposing the handle. This matters for complete bytes surviving a process kill
that preceded the original fsync. Reopen does not authenticate the image's age
or its original history.

An I/O or injected append failure returns `RetentionOutcomeUnknown` and poisons
the handle. It does not automatically retry, truncate, re-sign, select replacement
bytes or repair the file. Close and inspect separately. A complete event may be
present despite the lost acknowledgement; an incomplete final record quarantines
the entire file without deleting its valid prefix or torn suffix. Preserve the
original file externally before any future separately authorized repair design.

The pure comparison still reports `durable_retention: NOT_IMPLEMENTED`: that
function performs no I/O. This backend's separate receipt reports selected fsync
acknowledgement and explicitly unqualified power-loss behavior. It does not
upgrade the pure comparison's authority or supply authenticated signed-original
custody. All views and receipts keep recovery action `NONE` and application/core
`NO-GO`.

## Bounds and failure behavior

The selected profile limits the binding to 32 KiB, a synthetic original to 8 KiB,
each raw claim to 512 KiB, observations to 64, events to 128 and the whole file to
16 MiB. Encoded records have a separate bound accommodating hex expansion.
The existing parser bounds JSON depth before decoding and refuses duplicate keys
and nonfinite or non-ASCII input. The outer log requires canonical ASCII records
with exact sequence, previous digest and complete event grammar. Retention is
finite; exhaustion refuses new writes without evicting old evidence or clearing
disclosure. Out-of-bound inputs are refused before writing and require caller
retention elsewhere. The selected values are research limits, not a funded-swap
availability or network resource policy.

## Qualified behavior and remaining gates

[Validation](NOM_EVIDENCE_RETENTION_VALIDATION.md) exercises actual POSIX locks,
fork inheritance, process kill cuts, short writes, failed syncs and an actual
native file-size limit. Acknowledged records survive controlled process restart
under the selected runtime; torn records preserve failed evidence and quarantine.
Process kill and mocked fsync errors do not test power loss, device caches,
filesystem/VFS correctness, hostile hosts or hardware durability.

A coherent old complete file can be restored and accepted. It can erase locally
remembered disclosure and originals, replenish retention capacity and allow an
alternative future. Complete copies can accept incomparable candidates in
parallel. Hashes and advisory locks prevent neither counterexample. There is no
external nonrollback checkpoint, clone fencing, protected restore protocol or
authenticated current head. These remain independent gates before application
use or any recovery admission.

Next, define the independent authority and restore/freshness contract for network
profile, funding, live entry, exact original authorization, send/receive linkage,
contract payout and momentum lineage. Select and independently qualify those
premises before composing this backend with the unchanged recovery journal.
Producer signatures/election, changes execution, canonicality/finality, signing
custody and operational network validation remain unfilled. No deployment,
wallet operation, transaction construction, broadcast or real funds are enabled.
