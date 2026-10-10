# Separate NoM public worker profile

Status: additive offline qualification packaging for CANDIDATE-02.
Application and core remain **NO-GO**. Independent assessment is **UNFILLED**.
No backend, signing interface, chain observer or activation is selected here.

## Immutable source and later packaging

`review/nom-worker-subject.json` inventories every tracked regular source file at
`c560f5dc504818252703fdeaecc2ff96a3f86059`, tree
`9a5f312218678cc9d3f8713f7f3d5cda4de6e451`: 620 files, including documentation,
tests, fixtures and CI. Its SHA256 is
`59d9b134d4be55f3dc98797529aff86d121fdce3d0e2ddce8dfd7b9c171cf179`.
The checker regenerates the complete canonical inventory from locally available
Git objects without network access. Caller-written omissions or substitutions,
including omitted non-build files, mutable refs and mismatched source trees,
are rejected. Matching inventory bytes do not authenticate their producer.

The build copy contains the exact 72 files under `qualification/` and
`compatibility/fixtures/`. Only these prefixes are copied, from the selected
immutable objects into a fresh owned private directory. The selected source
includes the real public worker `verify_nom_swap` and its synthetic NoM inputs.
Worktree and index build inputs must match that source. Extra or modified files
inside either copied prefix are rejected at comparison checkpoints.

The three historical independent report templates must also match their selected
original bytes. Their inventories, build profiles, target workers and unfilled
reports remain separate. None covers the new NoM executable by implication. The
new [assessment template](NOM_WORKER_REVIEW_REPORT_TEMPLATE.md) requests explicit
review of both the frozen source and later packaging. These new checkers,
adapter policy, documentation and CI are later packaging; they are **not** part
of the frozen `c560f5d` compilation subject.

## Selected dependencies and native build observations

`qualification/fixtures/nom_worker_resolution_v1.json` is a separate project
selection generated using Cargo 1.90.0, SHA256
`4a3efecfa0d9b4f66bc97e80e4c8adf69eac4c262b79211d44aee010f07ce368`.
It records normalized locked workspace claims for `aarch64-apple-darwin` and
`x86_64-unknown-linux-gnu`: 70 packages and 341 declared targets per profile,
with 110 and 109 selected dependency edges respectively. Cross-target metadata
is not evidence of native execution on the queried target. These are project
observations, not an independent dependency attestation or a compiled closure.

`scripts/qualify_nom_worker.py` requires the actual native host profile and
explicit Cargo, rustc, C compiler, dependency home and separate empty private
source/build/evidence directories. It compares locked registry archive contents
with extracted trees and selected Git objects with checkout trees. The source,
dependency contents, baseline and three selected native file digests must still
match after build and public recovery. These checks reuse bounded comparison
primitives; the old resolution baseline and manifests are unchanged.

Cargo metadata must match the selected NoM baseline. A fresh native debug build
must return zero and name the exact example, source path and executable within
the selected build directory. Cached-root claims, redirected paths, wrong
examples or profiles are rejected. Build-script and compiler messages remain
claims; their producer and complete compilation inputs are not authenticated.
A synthetic stream with only matching root and terminal claims can pass the
comparison without any compilation. That counterexample prevents interpreting
structural agreement as provenance.

The build receives only the explicitly assembled environment and selected
system search directories. Cargo configuration at the selected home or source
directory ancestors is refused at checkpoints rather than silently overridden.
The Apple profile additionally requires an explicit trusted SDK directory.
This selection does not inventory or authenticate SDK contents. Tool support
files, system utilities, headers, libraries, loader, host and quiescent ancestors
remain trusted inputs; three file digests are not their closure.

## Empty child environment and actual public mathematics

`NomPublicVerifier` offers `nom-empty-environment-v1` as an explicit caller
choice. Its compatibility default is `nom-inherited-environment-v1`. Unknown
profiles are refused before executable selection. Requests, response domains,
locally selected terms, adaptor pair and executable-byte comparisons are
unchanged. This local launch choice is not remote context, a cryptographic
binding or a durable journal selection. A caller must select it again on reopen.

The new choice passes an empty environment to the process at exec. It uses the
existing bounded pipe, transfer/exit deadline and owned-process cleanup rules.
It removes inherited application variables but does not authenticate loaded
libraries or prevent the runtime from changing its own environment. The current
directory, host, loader and executable remain trusted; this is not a sandbox or
complete descendant containment. An actual synthetic script returning a bound
positive can still pass the adapter. Pinning it and clearing its environment do
not turn it into a cryptographic verifier.

Separately, the native qualifier executes the real built Rust worker against the
copied immutable fixtures with this profile. The existing two-journal scenario
retains both original synthetic envelopes, preserves unknown outcomes and lost
acknowledgements across reopen, admits the selected synthetic confirmation,
recovers the public long signature and exercises invalid-completion controls.
No secret witness is returned. This observed public mathematics does not select
a signer, authenticate chain observations or prove live atomicity.

## Original evidence and reproduction

The native command helper retains original stdout and stderr in explicitly
private files created without replacement, with mode 0600. It records exact
private arguments, exit status, byte counts, stream completeness and hashes.
Stdout is bounded to 16 MiB, stderr to 4 MiB, and commands to 240 seconds.
Overflow records only a retained prefix and marks the truncated stream;
deadline/interruption evidence stays unknown. An ordinary failed command retains
its full original streams when within bounds. Failed directories are never
silently repaired or reused. Raw native records, binaries and local paths are
not public artifacts and receive no independent privacy assessment here.

After acquiring the immutable source object and locked dependencies separately,
check the selected source without building:

```sh
python3 -B scripts/check_nom_worker_subject.py \
  --expect-commit c560f5dc504818252703fdeaecc2ff96a3f86059 \
  --expect-manifest-sha256 59d9b134d4be55f3dc98797529aff86d121fdce3d0e2ddce8dfd7b9c171cf179
```

Use `scripts/qualify_nom_worker.py --help` for the explicit private directories,
cached dependency home, native platform and tool selections. It acquires no
dependencies. The Linux CI job runs its own fresh native build and public
recovery. Preserve the complete hosted archive separately from local execution;
a green PR check and a later push-triggered main check are different gates.

The first focused run exposed a test-directory permission assumption and an
unclosed stderr pipe on native failure paths. Those original results are
retained; the corrected focused run is separate. The first native build under
the minimal environment failed because the Apple system library was not found.
Its original compiler stream is retained. Requiring the explicit Apple SDK is a
new selected build profile, not a reclassification of that failure. Earlier
failed evidence, including the unexplained system-Python 3.9 native result,
remains unchanged. See [measured validation](NOM_WORKER_VALIDATION.md).

## Remaining acceptance gates

Independent review must assess the frozen NoM construction, later packaging,
source-to-runtime trust, dependency/build input closure and loader boundaries.
It must keep observed behavior separate from claims, assumptions and unknowns.
Signer custody and nonce ownership, non-rollbackable disclosure history,
authenticated chain/finality/reorg observation, real ABI/account-block originals
and account-chain/Plasma reconciliation remain separate unfilled gates. A
successful offline build or recovery does not satisfy them. Stage 0 authorizes
neither network composition nor funds, node activation or deployment.
