# Separate selected C debug-prefix profile

Status: offline research construction. Private observations supply no producer
identity, independent privacy assessment or artifact-release qualification.

The preceding [target-only Rust profile](OFFLINE_RUST_PATH_REMAPPING.md) and its
[debug-name observation](OFFLINE_WORKER_DEBUG_NAMES.md) remain unchanged. Select
two additional fresh worker builds under one combined logical profile. Reuse
the fixed-source preparation and source/content/resolution/native-byte gates;
do not reinterpret earlier builds as causal controls. Different private build
locations and unauthenticated execution prevent isolated producer attribution.

## Selected arguments and transport

Keep the existing four target-only Rust rules, ordering, trailing-slash scope,
explicit native target and UNIT SEPARATOR transport. Add four C arguments of
the form `-fdebug-prefix-map=FROM/=DESTINATION/`, using the same four fixed roles
and synthetic destinations. Shorter private prefixes precede longer ones; fixed
role order breaks length ties. All four selections are validated before either
metadata or build command. Names, private arguments and actual prefixes are
never emitted.

C paths must satisfy the preceding exact built-in, absolute, lexical, bounded,
owned and nonaliased selection rules. Additionally allow only ASCII letters,
digits, underscore, dot, slash and hyphen. Reject whitespace, quotes, backslash,
equals, shell punctuation, control bytes and non-ASCII before native work. This
restriction permits four unquoted space-separated arguments without shell
interpolation. Trailing slashes exclude bare directory spellings and lexical
siblings; relative paths, other spellings and support inputs remain unassessed.

Use only unqualified `CFLAGS`. Clear inherited unqualified and underscore-suffix
variants of `CFLAGS`, `HOST_CFLAGS`, `TARGET_CFLAGS`, `CC_SHELL_ESCAPED_FLAGS` and
`CC_ENABLE_DEBUG_OUTPUT`; set shell parsing to `0`. Do not repeat the four rules
in target or host variables: the selected cc-rs implementation accumulates flags
from those variables. Preserve other environment entries, including project
custom flag variables, C++ settings and unrelated linker/support controls.
Their consumption and coverage are not qualified. Restore the entire environment
on success, refusal and cancellation. The unchanged Rust environment guard owns
cwd restoration; its failure also unwinds the C guard. These process-global
helpers require exclusive trusted-driver use and are not thread-safe.

## Native operations selected before execution

This driver selects exactly two fresh native worker builds, with two bounded
`cargo metadata` commands and two bounded `cargo build` commands. Reuse unchanged
30-second metadata and 240-second build limits, offline/locked mode, three
explicit native tools, 55 prepared source files, root profile/features and all
source/content/resolution pre/post gates. No version probe, tool discovery,
analysis executable, stripping, rewriting or worker launch is added. A Cargo
command can launch trusted build scripts, compiler probes, internal retries and
other native children; the count of two builds is not a count of all processes
or proof of operating-system isolation. Failure retains private streams and
does not retry, repair or reselect the driver operation.

After both reports agree on their fixed-source, resolution, root and native
measurements, scan two complete worker streams under the existing scanner. Then
acquire two additional pinned debug-name streams under the unchanged bounded
reader, running preceding section/symbol grammars in memory from those same
bytes. Require complete measured-row and byte-relation agreement. Builder
measurements, two complete scan acquisitions and two debug-name acquisitions
remain separate; no atomic pair or future-launch binding is supplied. Require
no positive class, prefix absence, equality, producer attribution or privacy
improvement. Both MATCH and DIFFER can be observed without artifact release.

The calling local/hosted orchestration separately selects one unchanged 14-case
public original-response mathematics run per new artifact: two groups and 28
cases. These launches are outside this builder and are not authenticated by
its output. Preserve all preceding builds, 23 groups/266 cases and ten earlier
section/symbol/debug acquisitions in their original order and scope. Insert one
separate command block after earlier observations in the existing Linux step, without changing jobs, matrices,
platforms, pins or timeouts. No native artifact, carrier or raw stream is uploaded.

## Attributed primary sources

- Selected cc-rs 1.5.1 package source matches immutable upstream
  [`d279cdda99af5bf0eec594ee0626218fa91052ab`](https://github.com/rust-lang/cc-rs/blob/d279cdda99af5bf0eec594ee0626218fa91052ab/src/lib.rs).
  Its environment flag collector appends base, build-kind, underscore-target and
  literal-target values. Its unquoted parser splits ASCII whitespace; shell
  parsing is separately configurable. cc-rs is dual MIT/Apache-2.0; licenses
  were inspected. No implementation or prose is copied.
- Clang 19.1.7 option declarations at
  [`cd708029e0b2869e80abe31ddb175f7c35361f90`](https://github.com/llvm/llvm-project/blob/cd708029e0b2869e80abe31ddb175f7c35361f90/clang/include/clang/Driver/Options.td)
  document debug-path mapping and last-matching-option precedence. LLVM's
  Apache-2.0 license with LLVM exception was inspected; no declarations are copied.
- GCC 14.2 documentation at
  [`04696df09633baf97cdbbdd6e9929b9d472161d3`](https://github.com/gcc-mirror/gcc/blob/04696df09633baf97cdbbdd6e9929b9d472161d3/gcc/doc/invoke.texi)
  describes debug-prefix mapping. The source license and documentation license notice were inspected;
  documentation attribution is reference only, with no copied prose.

These references select an intended argument grammar; they authenticate no
installed compiler distribution or vendor behavior. Successful selected builds
and class observations do not attest argument consumption by every producer.
No broader file/macro/coverage mapping is selected.

## Acceptance boundary

See [Stage 67 validation](STAGE67_VALIDATION.md). All three independent reports
remain unfilled. Selected tool bytes, caller expectations, build scripts, host,
transport and higher ancestors remain trusted or unassessed. No canonical/current
authority, nonrollback ownership, signer custody, source-to-worker provenance,
independent reproducibility or protected-use guarantee is added. Keep all
artifacts private. Application/core and funded use remain **NO-GO**.
