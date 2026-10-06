# Selected Cargo resolution evidence

Status: **Selected offline comparison construction; complete local checks
passed; exact candidate hosted checks required. NOT ASSESSED.
Application and core NO-GO.**

The fixed [witness subject](../review/witness-subject.json) remains the complete
360-file source at `bd4b4b523fb3453e2af191eb01973985d6431d66`, with manifest
SHA256 `0f449db4c5e7c65f826ab57c4fafe4cd288bb570b7920d29e583b6cfd62dd82f`.
This entry and its resolution baseline are outside that subject. All three
subject manifests and all three unfilled assessments retain their bytes.

## Requirements

- Keep fixed package/source expectations separate from a tool's reported graph.
- Bind every reported package to an already selected lock identity and installed
  source location. Compare opaque package IDs only within one input document.
- Account for all reported nodes, edges and feature selections, with no omissions,
  duplicates, dangling references, additional workspaces or substitute sources.
- Compare against an independently selected project baseline. A report cannot
  choose or modify that baseline; a project selection is not independent review.
- Keep private paths, author fields, environment data and raw tool output out of
  the public report. Refuse unsupported or excessive input with sanitized errors
  and no partial positive report.

## Selected construction

The selected workload is Cargo format-version 1 metadata for the fixed
qualification workspace, using the existing default feature selection and an
explicit `aarch64-apple-darwin` or `x86_64-unknown-linux-gnu` filter. It includes the
declaration of the `verify_original_read_response` example; it is workspace
resolution, not that example's exact compilation-unit graph.

The query runs separately from the read-only comparison, on a new owned copy of
all 55 fixed `qualification/` source files. Preparation checks immutable, indexed
and working bytes first; an existing nonempty destination is refused. Native
Cargo/rustc are explicitly selected trusted research tools. The query uses
`--locked --offline --format-version 1` and performs no build or worker invocation.
Missing dependencies refuse rather than authorizing acquisition or repair.
The complete selected cache must pass the content comparison before any query.
Cargo's offline option permits local cache writes; a complete quiescent cache is
a precondition, not a sandbox or an atomic measure-and-query fence.

The [Cargo 1.90.0 metadata source](https://github.com/rust-lang/cargo/blob/840b83a10fb0e039a83f4d70ad032892c287570a/src/cargo/ops/cargo_output_metadata.rs)
resolves with development units and exposes package-level feature selections.
Its [format reference](https://github.com/rust-lang/cargo/blob/840b83a10fb0e039a83f4d70ad032892c287570a/src/doc/src/commands/cargo-metadata.md)
requires explicit format selection and treats package/source IDs as opaque. The
selected local tools reported Cargo 1.90.0 / commit
`840b83a10fb0e039a83f4d70ad032892c287570a` and Rust 1.90.0 / commit
`1159e78c4747b02ef996e55082b704c09b970588`; these self-reports do not attest their
installation or distribution origin. The [Cargo license](https://github.com/rust-lang/cargo/blob/840b83a10fb0e039a83f4d70ad032892c287570a/LICENSE-MIT)
was inspected. No Cargo source or documentation text is copied into the checker.

Initial bounded local queries, before implementation, reported 70 packages/nodes
from 75 lock records on both selected platforms, with 110 edges for the Apple
filter and 109 for the Linux filter. The original fixed inputs remained unchanged.
Those observations select a project comparison baseline; they are not an
independent resolution proof or a source-to-executable attestation. Both initial
filter baselines were collected on the selected Apple host. Native Linux
comparison is a separate acceptance check; host/tool configuration is unassessed.

Registry manifests must be at the selected installed `name-version` location.
The six Git package manifests have separately selected relative locations within
the two measured revisions: `musig2` at `Cargo.toml`; `schnorr_fun`, `secp256kfun`,
`sigma_fun` and `vrf_fun` in their named directories; arithmetic macros at
`arithmetic_macros/Cargo.toml`. The local manifest and every declared local target
must bind to the prepared fixed source copy. Full selected dependency contents
remain subject to the unchanged [content comparison](OFFLINE_DEPENDENCY_CONTENTS.md).

## Evidence and unresolved decisions

A matching baseline reports selected logical package identities, target paths,
enabled features, declared-feature digests, typed edges, counts and digests.
Other package dependency declarations are bounded but not semver-resolved by
this checker; every reported edge must also exist in the fixed lock superset.
Sensitive nonoperative metadata is bounded and discarded. A fabricated report matching the selected baseline can
still pass: the parser cannot authenticate who generated it or which command ran.
Hosted query execution is separate measured evidence under trusted tool/host
assumptions; neither layer establishes independent assessment.

Input limits are 8 MiB of UTF-8 JSON, depth 32, 100,000 values, 512 packages,
8,192 edges and 4,096 declared targets. Operative strings follow a narrow ASCII
profile. At most 1,024 distinct manifest/target files and 64 MiB are measured,
with at most 16 MiB per file; repeated file references reuse one measurement.
The selected baseline is canonical ASCII, at most 1 MiB, and must match the
independently selected SHA256 and its index bytes. Unknown fields and unsupported
encodings refuse rather than selecting a different format.

The [checker](../scripts/check_cargo_resolution.py) and
[companion](../scripts/qualify_cargo_resolution.py) invoke native Git only for
local immutable source inspection. The [preparation entry](../scripts/prepare_cargo_resolution.py)
writes the explicit owned source copy. None of these entries invokes Cargo,
rustc, a build script, dependency code or a public verification worker. One
operator command shape, after selecting the tools and Cargo home, is:

```sh
python3 -B scripts/qualify_dependency_contents.py --cargo-home "$SELECTED_CARGO_HOME"
ptlc_resolution_workspace="$(mktemp -d)"
python3 -B scripts/prepare_cargo_resolution.py --output "$ptlc_resolution_workspace"
CARGO_HOME="$SELECTED_CARGO_HOME" CARGO_NET_OFFLINE=true RUSTC="$SELECTED_RUSTC" \
  "$SELECTED_CARGO" metadata --locked --offline --format-version 1 \
  --manifest-path "$ptlc_resolution_workspace/qualification/Cargo.toml" \
  --filter-platform x86_64-unknown-linux-gnu > "$ptlc_resolution_workspace/metadata.json"
python3 -B scripts/qualify_cargo_resolution.py --workspace "$ptlc_resolution_workspace" \
  --metadata "$ptlc_resolution_workspace/metadata.json" --cargo-home "$SELECTED_CARGO_HOME" \
  --platform x86_64-unknown-linux-gnu
```

The selected [baseline](../qualification/fixtures/cargo_resolution.json) SHA256 is
`c55ccb81a2730b8d5779011e0eceda7659b039593d5e7a2fc930112f174df9d5`.
It contains logical resolution facts and source digests; upstream feature
definitions, source text and author fields are not redistributed. Baseline
selection remains a project decision, with no independent attestation or filled
assessment. See [validation](STAGE60_VALIDATION.md).

Cargo metadata does not establish exact per-unit feature activation, native
build-script inputs/outputs, compiler support files, linker inputs, generated
source, build environment, compiled closure, reproducibility or source-to-worker
linkage. Selecting and qualifying a bounded worker-build receipt remains an
unresolved later decision. No application signer/backend, source authority,
current/canonical selection, nonrollback ownership, protected-use permission,
core integration, deployment, activation, wallet, broadcast or funds is added.
