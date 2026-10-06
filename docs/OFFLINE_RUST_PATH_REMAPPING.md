# Selected target-only Rust path remapping experiment

Status: **Selected offline construction before native execution; complete local
checks passed; exact candidate hosted checks required. NOT ASSESSED. Core NO-GO.**

## Requirement and selected construction

Two preceding debug artifacts differ in complete bytes and contain all four
selected private directory prefixes. The cause of their difference is not
isolated. Select a separate controlled build experiment; preserve the original
[build companion](OFFLINE_WORKER_BUILD_RECORDS.md) and
[read-only scanner](OFFLINE_ARTIFACT_PREFIXES.md) exactly.

Prepare two fresh copies of the same immutable 55-file source selection and
two separate owned empty build directories. Keep the witness source commit,
manifest, lock, dependency content expectations, Cargo resolution baseline,
native target, root example, empty root features and original debug profile
unchanged. Select the same three native executables explicitly. Measure source,
cache contents and native files before and after each build. Cross-compare the
selected native measurements and logical source/resolution/contents for both
builds. A change refuses without a pair report. These comparisons do not attest
tool distribution or execution provenance.

The additional profile is exactly four `--remap-path-prefix` Rust options,
transported through `CARGO_ENCODED_RUSTFLAGS` with ASCII unit separators. Each
FROM is an explicitly selected directory's lexical absolute ASCII path plus a
trailing slash. No private mapping file, environment discovery or caller-defined
replacement is used. Reject control characters, equals signs, unsupported path
syntax, duplicate roles, direct links, foreign ownership and overlapping cache
with either source/build selection. All four source/build directories are
distinct and pairwise nonnested. The repository may contain source/build/cache
locations; trusted ancestors remain a precondition.

Use these fixed public synthetic destinations:

| Fixed role | Replacement prefix |
| --- | --- |
| selected-source-location | `/ptlc/source/` |
| selected-build-location | `/ptlc/build/` |
| selected-cache-location | `/ptlc/cache/` |
| selected-repository-location | `/ptlc/repository/` |

Order private rules from shortest byte prefix to longest, breaking ties by the
fixed role order. This lets a more specific directory override a containing
directory under the documented last-match rule. A trailing slash limits textual
sibling matches; an occurrence of the directory alone, relative spelling,
alternate encoding or unselected location is outside that mapping scope. Physical
working-directory spelling can differ from a lexical selection through a trusted
higher ancestor alias; that alternate prefix is not discovered or remapped. The
scanner still searches the original exact directory bytes without the slash.
No rule values, their lengths, hashes or actual private ordering are reported.

Clear inherited Rust extra flags, wrapper selections and default-target controls
as in the preceding native construction, then install only the four selected
encoded options for metadata and build invocations. Set the same explicit
native Rust/C executables, target linker and offline cache. Save and restore the
process environment and attempt to restore the current directory on every exit,
including cancellation. Restore the environment even if the operating system
refuses directory restoration; such a failure provides no positive pair report.
The CLI owns its process environment and working directory exclusively. The
importable research helper is not thread safe and supplies no environment/cwd
lock or protection against a concurrent caller changing those global values.
This changes the effective Rust flag profile even when Cargo's root profile
claim is identical. The incoming Cargo claim cannot select or attest that profile.

Execute only offline locked metadata and build commands with the existing
bounded trusted transport. Retain metadata/build streams privately. No dependency
acquisition or verification-worker launch occurs in the new companion. Run the
existing 14-case public-math qualifier separately for each selected output.
Cargo's offline selection does not sandbox the native tools or contain build
scripts' network/filesystem access. Those selected tools and scripts are trusted.

Supply the already selected private cache/native paths and four fresh owned
empty directories to the [pair driver](../scripts/qualify_worker_remapping.py):

```sh
python3 -B scripts/qualify_worker_remapping.py \
  --root "$PTLC_REPOSITORY" \
  --first-workspace "$PTLC_FIRST_SOURCE" \
  --first-build-directory "$PTLC_FIRST_BUILD" \
  --second-workspace "$PTLC_SECOND_SOURCE" \
  --second-build-directory "$PTLC_SECOND_BUILD" \
  --cargo-home "$PTLC_PRIVATE_CARGO_HOME" \
  --platform "$PTLC_NATIVE_PLATFORM" \
  --cargo "$PTLC_SELECTED_CARGO" --rustc "$PTLC_SELECTED_RUSTC" \
  --c-compiler "$PTLC_SELECTED_C_COMPILER"
```

These variables are private explicit selections, not discovery instructions.
Missing dependencies or a failed build do not trigger fetching or an automatic
retry. Already written private directories/streams remain available for
inspection. Incomplete subprocess output and native stderr are discarded by the
bounded transport; a failed build does not promise a saved diagnostic stream.

## Deliberate coverage limit and pinned source facts

Rust documents textual prefix replacement and selection of the last matching
rule. This is a compiler option's documented behavior, not proof of artifact
privacy or reproducibility. [Rust source at
1159e78c](https://github.com/rust-lang/rust/blob/1159e78c4747b02ef996e55082b704c09b970588/src/doc/rustc/src/command-line-arguments.md#option-remap-path-prefix).

Cargo documents unit-separated encoded flags and their priority over other
extra-flag sources. With an explicit `--target`, these options cover target
compilation; host build-script and procedural-macro compilation does not receive
them. A build script's visibility of an encoded environment value is not coverage
of its own compilation. [Cargo environment source at
840b83a1](https://github.com/rust-lang/cargo/blob/840b83a10fb0e039a83f4d70ad032892c287570a/src/doc/src/reference/environment-variables.md)
and [Cargo configuration source at
840b83a1](https://github.com/rust-lang/cargo/blob/840b83a10fb0e039a83f4d70ad032892c287570a/src/doc/src/reference/config.md#buildrustflags).
No third-party implementation or documentation text is copied.

No C/C++ remapping flags, host Rust flags, linker rewriting, stripping, release
profile, incremental changes, timestamp normalization or binary mutation is
selected. Existing C/linker/support configuration, host/generated values,
sysroot, environment and all tool inputs remain incompletely assessed. Native
paths resolve explicitly at the CLI, but trusted tool/support bytes and trusted
filesystem ancestors are assumptions. Host self-report is not attestation.

## Pair observations and publication boundary

After both builds pass, feed their locally selected SHA256/size expectations and
four original directory prefixes into the unchanged read-only scanner. Compare
both complete streams; report only existing logical build evidence, a fixed
public profile description and scanner measurements. Do not print raw flags,
paths, prefix encodings, locations, environment, diagnostics or private stream
contents. Retain all raw artifacts and build selections privately under either
scan or byte result. Prefix absence does not imply complete privacy; byte equality
does not authenticate independent reproducibility. Differences do not isolate
which input caused them.

No original-output comparison is folded into the pair's same-profile byte result.
The retained original-profile scan is a separate earlier observation. Synthetic
tests of command construction and restoration are not native measurements.
Public-math tests are neither current authority nor source-to-worker provenance.
All three assessment reports remain unfilled; no reviewer is contacted.

## Open decisions

Complete private-input qualification, host/C/linker coverage, support-file
selection, authenticated source-to-worker provenance and independent privacy or
reproducibility assessment remain unresolved. Artifact release is not selected.
The existing current/canonical selection, nonrollback ownership, signer custody,
lookup/disclosure, original recovery and protected-use gates remain unchanged.
Application/core progression, deployment, wallet access, transaction broadcast
and funded use remain **NO-GO**. See [Stage 63 validation](STAGE63_VALIDATION.md).
