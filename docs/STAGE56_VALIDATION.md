# Stage 56 validation: witness creation and interruption

Parent candidate: `32e7a436b16b35e62fdd5b204afd093624d49845`.
Parent draft: [PR 50](https://github.com/edgepillar/ptlc-research/pull/50).
This delta changes only the existing test helper's constructor lifecycle,
adds a synthetic child actor, 20 normal methods, a 23-case actual-worker
qualifier, two documents, five append-only references and one focused CI step.
No application storage or authoritative recovery construction is selected.

## Local execution

| Check | Observed result |
| --- | --- |
| Final lifecycle regressions | 20 passed in 4.268 s; recorded runner 4.364 s. |
| Final actual-worker lifecycle qualifier | 23 passed in 5.954 s; recorded runner 6.053 s. |
| Retained witness regressions and actual qualifier | 33 passed in 14.772 s (runner 14.88 s); 37 passed in 19.221 s (runner 19.325 s). |
| Complete offline Python suite | 1395 passed in 957.262 s; recorded runner 957.578 s. Every discovered method id passed; zero skips, failures and ResourceWarning lines. |
| Fixed inventories | Complete observation subject: 189 files; frozen baseline: 119 files. |
| Safe SQLite runtime | SQLite 3.54.0, DELETE journal, synchronous EXTRA (3); authentication and physical entry false. |
| Artifact hygiene and relative links | 720 index/worktree versions across 360 tracked files; 1186 relative file links resolve. |

**All required local checks passed.**

The first targeted normal run and first actual-worker run each had one error
and one failure. The binding test prepared the historical-profile collision
under the wrong fixture scenario, so the unchanged query factory refused it.
The inherited-process control replaced the child's sole connection reference,
unintentionally finalizing inherited native SQLite; the child exited with
signal 11 before its ownership assertions. The control now retains the native
connection without operating or finalizing it, installs its access trap and
exits without Python cleanup. Both failed runs remain recorded. These errors
are test setup failures, not demonstrated witness transaction failures or a
claim that native inherited connection cleanup is safe.

Corrected runs passed. The final targeted runs also enable one-page cache
spilling in the creation actor and distinguish native hot-journal recovery
from application repair. No warning suppression, hosted retry or reduced
acceptance control is planned. The final source then requires the complete
offline suite before publication.

The normal suite's verifier flags are explicitly forged, not mathematics. The
actual qualifier inherits all 20 methods and adds cancellation after two
successful mathematical responses, zero-signature refusal after creation or
cancellation, and separated lost source/witness results. The retained witness
suite and retained actual qualifier also run locally after the narrow helper
change. No earlier hosted result is evidence for this new candidate.

These tests cover nine selected creation cuts, three opening and inspection
cuts each, six retention cuts, selected verifier cancellation, four genuine
inherited-owner commands, native creation contention, partial schemas/bindings,
nonregular paths and recreated-path knowledge loss. They do not cover actual
ENOSPC, power loss, hostile storage, close failures, all native platforms or an
application store. Independent security/privacy assessment remains pending.

The unchanged Rust 123 tests and Go 55 top-level tests are not rerun locally
for this Python-only delta. The retained 19 actual-worker groups / 201 cases
are not all rerun locally; the retained 37-case witness group is rerun locally,
and all retained groups plus the new 23-case group are required in hosted CI.
Earlier standalone model CLIs are not rerun locally; their regressions remain
in the full suite and their workflow steps remain required on the new head.

## Preservation and publication gates

All 355 prior files remain byte-preserved outside five append-only documents,
the one workflow insertion and the explicitly declared test-helper constructor
change. All earlier helper methods after the constructor, old tests/actors,
qualifiers, application/source/store/journal/sampler code, opening/prefix
composition, worker, grammars, fixtures, dependencies, models, workflow
steps/pins/matrix/timeouts and licenses remain unchanged. No external code,
signer or key material is copied. The constructor delta must be reviewed
separately rather than included in a blanket preservation claim.

The frozen baseline remains `e592633e4c630cfe3f4669876f6f63b80d2e33d6` / 119 files;
the observation subject remains `f81e376e96e339647bb065739b4461235f865d2c` / 189 files.
Inventory hashes remain `df9ae22448a71fc7bbec24cfe2654e0a7f88bc1792eefc97e7b780bff6636295`
and `2f463071bc4f96ba1adaa8e8eb206d47e51845170ca2efe0f2b58182559afd6f`.
Both independent reports remain unfilled; the lifecycle experiment is outside
both fixed subjects.

Snapshot-input SHA-256 remains
`0f0bdf4d916c5371f35eb7c2afee03dbcdef4a319999c01955f4b052d9d8fd01`;
public snapshot-response SHA-256 remains
`2d461a54413ef156df62db26c88ac6f789ed8ea27322f3b8b12800b74f8de1bb`.
Public worker source SHA-256 remains
`e96a8219e500cd0f79716796c146f64ce22e5f95bd3af26ccd2ad8a208c4834e`.
Executable measurements are separate runtime evidence.

Publication requires an owned destination, unchanged parent state and
explicit generic project author/committer metadata, UTC dates and unsigned
commits. Verify exact rendered English ASCII, immutable server blobs and all
seven jobs on the actual executed checkout/tree/parents. Hosted evidence goes
in the PR body, keeping the tested source tree unchanged.

## Decision

**GO** for bounded offline qualification and review.
**NO-GO** for application witness integration, authenticated/current/canonical
source claims, private signing, nonrollback guarantees, authoritative original
recovery, protected use, core port, activation, broadcast or funds.

See [lifecycle behavior and limits](ORIGINAL_WITNESS_LIFECYCLE_EXPERIMENT.md).
