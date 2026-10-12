# Actual public-worker reference journal cuts

Baseline: `9cf598b2bf935d54da140a846d8886af13e0df0a`. This separate
qualification preserves the existing reference journal, complete authority query
and pure partial-custody comparison. It adds no recovery admission policy.
Own implementation is MIT; the separately obtained GPL core stays unchanged.

The qualifier uses the existing public Rust executable, fixed synthetic terms,
public adaptor pair and exact synthetic observation allowlist. It selects an
empty child environment and retains requests before spawn and complete original
stdout, stderr and exit receipts without retries. All selected source bytes and
the executable are copied before the first spawn. Its single-thread capture
transport replaces the adapter runner only for this qualification. It is not an
application runner, runtime attestation or hostile-process sandbox. Complete
streams are captured in memory before size checks. Process creation, aggregate
memory, loader dependencies and escaped descendants remain outside that claim.

| Selected interruption | Journal charge | Public recovery entry | Journal result | Journal long original |
| --- | --- | --- | --- | --- |
| After remote-short fsync | 0 | 0 | Absent | Absent |
| After recovery-admitted fsync | 1 | 0 | Absent | Absent |
| Actual worker reply withheld | 1 | 1, returned | Absent | Absent |
| After recovered fsync | 1 | 1, returned | Retained | Absent |
| After original fsync | 1 | 1, returned | Retained | Retained |

The append hook runs after a complete record has been written, fsynced and
applied to the current owner. Its selected exception quarantines that owner.
These four post-fsync exceptions are not process-death experiments or interior
write/fsync faults. The withheld reply is deliberately raised before returning
to the journal; it is separately retained in qualification diagnostics. This
establishes absence from the original journal, not globally lost output. Missing
result or original bytes are never supplied from a matching fixture. The
zero-charge remote-short cut is outside the admitted partial-hold profile.

Each exact original journal is reopened without calling recovery, constructing a
long original, preparing an attempt or replenishing work. Original journal bytes,
charged work and possible disclosure stay unchanged. Actual pair, remote short
and retained-original math are checked by the public verifier. A result-only
reopen does not check long signature math; the qualifier explicitly performs that
check afterwards, without writing. No result-only status is labeled verified
merely because open passed.

Two separately retained adversarial controls expose the limits of replay.
Recomputing the local self-hash chain around a zero-valued result is accepted by
result-only open, then refused by separate actual public verification. A complete
older admitted prefix is accepted with its missing output. Neither self-hashes
nor old coherent copies provide external restore authority. Original journals
are never replaced by these adversarial copies. Persisted observations also do
not reinvoke the independent observation callback on open: replay succeeds even
with a rejecting callback. Replayed funding is historical data, not current
funding or authenticated chain state.

Run after building the trusted public example:

```sh
cargo test --locked --offline --manifest-path qualification/Cargo.toml
cargo build --locked --offline --manifest-path qualification/Cargo.toml --examples
python3 -B scripts/qualify_nom_recovery_cuts.py
```

For local custody, select a new private directory with `--evidence-directory`.
Existing evidence is never overwritten. Original journals and worker streams
remain present on a failed run. With no directory selected, the qualifier creates
a private temporary parent and retains the evidence until external host cleanup.
The public report includes hex copies of original synthetic requests, stdout,
stderr and original journal bytes. Complete hosted console ZIPs retain that
report; their integrity and semantics must be checked separately. Other existing
native qualification streams retain their previously documented custody limits.

Unit controls use an exact disclosed fixture oracle and do not establish native
math. The separate fresh native run supplies that evidence. No observation label,
refusal, replayed journal or public verification is converted into chain authority
or partial-hold admission. Current authenticated source, external durable custody,
restore fencing, atomic work admission, runtime independence and independent
assessment remain unfilled. Application/core NO-GO; recovery action NONE.
