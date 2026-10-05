# Stage 49 offline validation

Target parent: `38ee5559a1006f0682e3db6370b9912bcc55bade`.

This records test-only binding of actual local original-read samples to the
existing historical signature framing. It is outside both fixed review subjects.
It does not establish a secure swap, authenticated source, operational signing,
current truth, authoritative recovery or production readiness.

## Local execution

| Check | Result |
| --- | --- |
| Directed Python sample/message controls | 14 passed in 1.001 s; recorded runner 1.101 s. |
| New actual-public-worker harness | Eight passed in 1.203 s; recorded runner 1.307 s. |
| Complete offline Python suite | 1215 passed in 964.908 s; recorded runner 965.465 s. Zero skips, failures and ResourceWarning lines; every discovered method id passed. |
| Locked offline Rust qualification | 123 passed, zero failed/ignored; recorded runner 15.312 s, including six new methods. |
| Offline Go compatibility | 47 top-level methods passed, including four new methods; recorded runner 3.889 s. |
| Offline Bitcoin Go compatibility | Eight top-level methods passed; recorded runner 2.068 s. |
| Locked offline public examples build | Passed; recorded runner 0.283 s. No new executable or dependency. |
| Rust/Go formatting | Rust and both Go modules passed; no earlier file was reformatted. |
| Complete fixed review inventories | Complete observation subject: 189 files; frozen baseline: 119 files. |
| Artifact and relative-link checks | 656 index/worktree versions across 328 tracked files; 1082 relative file links resolve. |
| Safe local SQLite runtime | SQLite 3.54.0, DELETE journal, synchronous EXTRA (3); authentication and physical entry false. |

The Python suite includes the unchanged prior native policy-store and original
snapshot writer/death controls. No new native actor is added. The earlier sixteen
actual-worker script groups were not rerun locally: their workers and dependencies
are unchanged, and they remain required in hosted CI alongside the new eight-case
harness. This local run therefore claims eight newly executed actual-worker cases,
not the full hosted total of seventeen groups and 152 cases.

The selected local original-response executable is measured at SHA256
`e3255b96df664a5b5b7a5d4813a3b665d3c9e3cba7916b93091cae09cb2d9073`.
This checksum pins the selected local entry only; it supplies no independent
provenance, atomic launch or runtime isolation. Hosted builds are separate entries.

The initial directed Python run had one failure: the delayed-delivery test set an
unused attribute instead of patching the store's existing `_cut` hook. The policy
never changed and the assertion correctly failed. The test was corrected to invoke
the real post-commit hook; all 14 methods then passed. No application/store code
changed. Private inspection also encountered missing helper filenames before
locating the existing files; those reads were not execution evidence. An early private candidate check also stopped at an unresolved local-result
placeholder; the final check uses the recorded completed suite result. No test
failure, dependency installation or warning suppression is hidden.

## Public synthetic fixture pins

| Fixture | SHA256 |
| --- | --- |
| New unsigned actual-snapshot inputs, ten samples and six counterclaims | `0f0bdf4d916c5371f35eb7c2afee03dbcdef4a319999c01955f4b052d9d8fd01` |
| New public historical response fixture over those inputs | `2d461a54413ef156df62db26c88ac6f789ed8ea27322f3b8b12800b74f8de1bb` |
| Unchanged earlier original-read grammar fixture | `a0df63db7a366425bf789ac1c1c61c7fb1e9d9eec9d0ecb43b21331f356fb1cb` |
| Unchanged earlier original-response signature fixture | `f04f2bd3eb9fb86b2fc8a85cf3d508961a4ad3f3ad0208fac20dfb6e6cd23996` |

The unsigned fixture is 257701 bytes and the new public fixture is 522940 bytes.
The largest new individual worker request is 8955 bytes, within the unchanged
16384-byte bound. The Python fixture reproduction reads actual SQLite scenarios; the Rust
generator is confined to its integration test and emits public material only.
Separate Rust and Go checks reproduce tagged messages, both retained-head
commitments, complete request/result binding and mutations of every byte in both
signature arrays for all sixteen vectors.

## Evidence and remaining gates

Ten actual sampled states reproduce the exact existing historical response bytes
before incoming envelopes are consumed. The full old original profile is retained
after current owner/epoch/scope/cap changes. Absence, pending, completion and
unavailability retain their existing meanings; no read mutates records or refunds
old charges. The mode round trip preserves the policy digest while changing the
full record-history digest.

Six validly signed false/conflicting/stale counterclaims pass the actual public
worker under deliberately self-selected expectations. Actual independent store
expectations refuse all six before checker invocation. The retained SQL sampler
also refuses conflicting original tuples and stale heads or returns a different
actual claim. A valid response signature is not a row-truth proof.

Post-commit revocation can precede delivery of an old still-valid signed sample.
Coherent clones and restores reproduce exactly signed pending history and three
synthetic effects. Forged callbacks can return both flags for zero signatures,
but actual math refuses. Lost post-commit returns and unavailable/revoked/reduced
states preserve charges without retry, allocation, recovery, refund or effect.
Blind ideal external entry remains an unsafe counterexample, not a physical device.

Application modules, earlier schemas/workers/fixtures, store/journal code,
dependencies, fixed inventories and unfilled reports are byte-preserved. The
workflow adds only the isolated eight-case harness step; all earlier steps,
seven jobs, toolchain/action pins and timeouts are retained. No operational source
signer, authenticated transport/lookup, recovery or use adapter is connected.

**All required local checks passed.**

Fresh exact-head hosted execution and publication verification remain separate
from this local record. Isolated sample-to-message qualification is **GO** only
within its stated boundary. Authenticated source integration, private/application
signing, recovery integration, core port, activation, deployment, wallet access,
broadcasts, physical entry and funded execution remain **NO-GO**. Both independent
assessment reports remain unfilled; see the [construction and acceptance gates](ORIGINAL_READ_SNAPSHOT_SIGNATURE_BINDING.md).
