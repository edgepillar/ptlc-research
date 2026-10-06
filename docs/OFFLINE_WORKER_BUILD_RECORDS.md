# Selected worker build artifact claims

Status: **Selected offline research construction; complete local checks passed;
exact candidate hosted checks required. NOT ASSESSED. Application and core NO-GO.**

## Requirements

Keep the fixed source expectations, tool output claims, locally measured files
and actual execution observations separate. A matching output record must not
authenticate its generator, prove a complete compiled closure or certify an
application cryptographic implementation. Refuse unsupported records without a
partial positive report. Keep private paths, diagnostic text, environment values
and raw tool output out of public evidence.

## Selected construction

Select only the existing `verify_original_read_response` example, debug profile,
default feature selection and one native platform: `aarch64-apple-darwin` locally
or `x86_64-unknown-linux-gnu` in hosted qualification. Prepare all 55 fixed
qualification source files at witness commit
`bd4b4b523fb3453e2af191eb01973985d6431d66` using the unchanged
[preparation entry](../scripts/prepare_cargo_resolution.py). Use a new private
owned empty build directory outside that source tree. No dependency acquisition
or cache repair is selected for the comparison. The complete existing cache
must match the [fixed content expectations](OFFLINE_DEPENDENCY_CONTENTS.md)
before the separate native operation.

Run an explicitly selected Cargo 1.90.0 metadata query first and compare it using
the unchanged [resolution construction](OFFLINE_CARGO_RESOLUTION.md). The query
uses a separate `metadata-target` directory inside the prepared workspace,
outside its fixed `qualification/` source subtree. The selected build directory
must still be empty immediately before the build. Then run
the explicitly selected Cargo/rustc/C compiler with `build --locked --offline
--message-format=json --example verify_original_read_response --target` and
the selected native platform and explicit new target directory. These are
separate trusted native operations, not actions performed by the read-only
record checker. Selected dependency build scripts can execute during the build.
Cargo's offline option is not a network or child-process sandbox.

The checker will bind opaque package IDs across the metadata and build records
from that same prepared copy, without assigning authority to their syntax. Bind
each reported manifest and target to the selected resolution and source digest.
Require one unambiguous selected worker artifact with the selected target,
profile and features, no cached artifact claim, exactly one successful terminal
record and an explicit operator-reported exit status of zero. Measure only the
selected executable and explicitly selected native tools against their selected
SHA256 values. Pre/post comparisons require quiescent selections and trusted
parent directories; they are not an atomic measure-and-execute fence.

The pinned [Cargo build output reference](https://github.com/rust-lang/cargo/blob/840b83a10fb0e039a83f4d70ad032892c287570a/src/doc/src/reference/external-tools.md)
describes compiler artifacts, freshness, cached build-script output and terminal
success. The [build command reference](https://github.com/rust-lang/cargo/blob/840b83a10fb0e039a83f4d70ad032892c287570a/src/doc/src/commands/cargo-build.md)
supports explicit example and output selection. The
[Cargo license](https://github.com/rust-lang/cargo/blob/840b83a10fb0e039a83f4d70ad032892c287570a/LICENSE-MIT)
was inspected; no source or documentation text is copied into the implementation.
These references define reported semantics, not independently attested behavior
of the selected tool installation.

## Unresolved evidence and authority

The [read-only checker](../scripts/check_worker_build.py) accepts at most 16 MiB,
4,096 LF-terminated JSON records, 1 MiB per line, depth 32 and 200,000 aggregate
values. The existing JSON reader also limits individual strings and objects.
Unknown Cargo envelope fields/reasons, duplicate keys, incomplete/trailing
records, failed diagnostics, type aliases, cached artifacts, duplicate operative
artifacts, escaped output paths and inconsistent target declarations refuse.
One selected worker record must bind the exact debug profile and empty features.
Other artifacts bind declared source targets and bounded profile/feature claims;
their exact units, support inputs and output bytes are not determined. The local
library artifact is separate from the selected example. Only the selected
executable and three native files are measured, at most 256 MiB each.

Compiler diagnostic details and build-script vectors are bounded and discarded.
Only warning/note/help levels are selected. A build-script claim must reference a
package with a declared custom-build target; cached/repeated script values do not
prove execution. The [explicit native companion](../scripts/qualify_worker_build.py)
enforces the selected native host profile, performs separate bounded query/build
operations, restores its environment and working directory after failure and
compares selected source, complete contents and tool bytes before/after the build.
Host profile self-reports are not host attestations. The caller supplies two new
private empty directories and all three tool paths. Native digests, including
the produced worker's digest, are selected locally in that run.

A forged stream and caller-selected executable bytes can
still agree. Omitting an unrelated dependency artifact can still pass the
selected-root comparison; the checker does not enumerate all compilation units.
Build-script records can contain cached values without executing in that run.
Diagnostic contents, build-script environment and linker directives are bounded
private inputs, not a complete verified inventory of build inputs or effects.

An executable driver can dispatch to additional compiler or linker components;
measuring that selected file does not measure those components. Compiler support
files, Cargo configuration, process environment, headers,
linker inputs, generated source, dependency execution effects, host origin and
reproducibility remain unassessed. Tool hashes selected in the same run are not
release or distribution attestations. Generator origin remains NOT AUTHENTICATED,
compiled closure NOT DETERMINED, source-to-worker provenance NOT VERIFIED and
independent assessment NOT ASSESSED. Independent reproduction and provenance
assessment remain later acceptance decisions.

All three fixed subject manifests and all three unfilled reports retain their
bytes. Existing workers, cryptographic helpers, fixtures and qualifiers retain
their bytes. No application signer/backend, source authority, current/canonical
selection, nonrollback ownership, protected-use permission, core integration,
deployment, activation, wallet access, broadcast or funds is added.
