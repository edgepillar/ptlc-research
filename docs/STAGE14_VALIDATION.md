# Stage 14 validation: selected model/journal correspondence

Scope: replay selected baseline model traces against real temporary journal
operations, with admission-time SQLite reads and state comparisons after reopen.
Execution code in `offline_session`, model rules, fixtures, dependencies and
journal v7 are unchanged. Existing CI gains one public qualification command.

## Executed checks

| Check | Result | Boundary |
| --- | --- | --- |
| New bridge discovery suite | 13 passed in 53.449 seconds | Explicit fake fixture oracles; selected traces and bridge rejection checks |
| Actual public-worker bridge qualifier | 9 passed in 52.270 seconds | Existing pinned executable inputs; explicit injected failures |
| Required-mode full Python suite | 326 passed in 396.231 seconds, no skips | Prior 313 tests plus 13 bridge tests |
| Artifact hygiene, links and whitespace | Passed; 301 local Markdown links resolve | Limited disclosure and consistency checks |

The focused run used Python 3.9.6 on macOS. Actual qualification uses previously
built pinned public artifact/completion executables and no private signing.
Injected failure/cancellation are explicitly labeled, and process-death traces
are excluded from this bridge. Unchanged Rust/Go suites and the three older
actual subprocess qualifiers are not independently rerun locally for this
test/qualification change; existing hosted CI runs them with the new qualifier.

The full run used
`REQUIRE_OPENSSL=1 python3 -B -m unittest discover -s tests -q` with OpenSSL
3.6.3 and passed without failed or skipped cases. Artifact checks used
`python3 -B scripts/check_artifacts.py`; all relative Markdown targets and Git
whitespace checks passed.

## Generated and concrete trace evidence

The complete baseline model searches at limits 1, 2 and 3 enumerate 118, 282
and 446 states respectively. Their shortest `recovery_allowance_exhausted`
counterexamples are replayed against fixed public candidate bytes. The bridge
compares the model's pending admission inside the journal callback, including
the separately read SQLite snapshot and checkpoint sequence, then closes and
reopens after every journal operation.

Additional selected traces cover repeated invalid retry, valid-input failure
followed by successful retry, raw public recovery without an envelope, positive
public replacement, failed/cancelled replacement followed by success, cancellation
exhaustion and free replay across external disclosure/inclusion/reorg events.
Those external events never fabricate a journal write or chain observation.
At exhaustion, an eligible valid retry/replacement must invoke no callback and
leave state, sequence, database and checkpoint bytes unchanged.

## Intermediate failures and correction

The first focused run completed 13 cases with two cancellation errors. The
first actual-executable run completed nine cases with the same two errors.
The bridge incorrectly expected `KeyboardInterrupt` to propagate from the
recovery callback. Existing `completion._run` catches `BaseException`, and the
journal reports the sanitized failure as `Conflict`. Existing cancellation
tests already specify that behavior.

The bridge expectation was corrected; no completion/journal behavior changed.
The corrected focused and actual-executable suites passed. This was a bridge assumption error, not a
new production cryptographic or persistence vulnerability.

## Evidence limits and next decision

The [correspondence design](RECOVERY_MODEL_CORRESPONDENCE.md) documents the exact
projection and omitted fields. Only selected baseline traces are replayed;
this is not an exhaustive refinement, liveness or cross-chain safety proof.
Authentication and local authorization remain external model premises, and
Alice's consumed ownership is not established by this Bob-only bridge.

The qualified exhaustion condition remains a recovery-availability blocker,
not evidence of funded loss. No reset/refill, emergency bypass, private signing,
node integration or source-authorization mechanism is introduced. The fixed
review subject and manifest remain unchanged; independent assessment and any
later delta review are still pending. Live swaps and a core port remain no-go.
