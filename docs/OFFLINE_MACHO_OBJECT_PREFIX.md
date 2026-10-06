# Separate selected Mach-O object-prefix profile

Status: offline research construction. Application and core progression remain
NO-GO. Private observations qualify no artifact release or production signer.

Preserve the [C profile](OFFLINE_C_DEBUG_REMAPPING.md), its
[retained symbol observations](OFFLINE_C_WORKER_SYMBOLS.md), and all preceding
source, fixtures, tests and native checks. Historical pairs remain separate;
they are not isolated causal controls for the new profile.

## Selected construction

Select two fresh builds on the native `aarch64-apple-darwin` platform. Refuse
Linux, other platforms and cross-host selections before native work. Keep the
four target-only Rust remapping rules and four C debug-prefix rules, ordering,
environment restoration, source/content/resolution gates and native input
measurements. Append exactly one token
`-Clink-arg=-Wl,-oso_prefix,PREFIX/` to the existing ASCII UNIT SEPARATOR Rust
transport. The selected C compiler remains the explicit target linker driver.
This token conveys one option and its one path operand through comma splitting;
it is not a four-rule replacement mapping.

The caller must explicitly supply the same private object-prefix string for
both builds. Accept an exact built-in string of 8 through 4096 ASCII bytes,
with a trailing slash. Its directory spelling must be absolute, lexical,
nonaliased, existent and owned. Allow only ASCII letters, digits, underscore,
dot, slash and hyphen. Reject root-only, relative, dot/cwd shorthand, missing or
repeated trailing slash, dot components, whitespace, commas, equals, control
bytes, non-ASCII and shell punctuation. The driver must not infer the prefix from the
environment, common ancestors, cwd or the four existing selections. The prefix
need not cover every role; actual matches remain observations. Validate both
pair selections, all C/Rust arguments and the object prefix before metadata,
build commands or environment changes. Never emit the prefix, its length,
fingerprint, encodings or formatted private arguments.

## Operations and observations

Reuse fixed witness source `bd4b4b523fb3453e2af191eb01973985d6431d66`,
manifest `0f449db4c5e7c65f826ab57c4fafe4cd288bb570b7920d29e583b6cfd62dd82f`
and Cargo baseline `c55ccb81a2730b8d5779011e0eceda7659b039593d5e7a2fc930112f174df9d5`.
Prepare 55 source files per build. Select exactly two metadata commands bounded
by 30 seconds and two build commands bounded by 240 seconds, as in the old
driver. Tools and build scripts can start support processes or probes; these
counts do not describe every OS process or provide isolation.

After both builds, require matching pair fields, root claims and three selected
native input measurements. Read two complete artifact streams for the earlier
byte scanner and two additional streams for the unchanged bounded symbol
grammar. Require exact measurement and byte-relation agreement, and the exact
thin little-endian 64-bit Mach-O format. Earlier section parsing runs in memory.
No new debug-name stream, private carrier read, native analysis tool query,
rewriting or stripping is selected. Builder/input digest measurements are
separate from these four observation acquisitions.

Emit only existing fixed four-role/eight-symbol-class booleans, complete
artifact measurements, MATCH/DIFFER and fixed logical profile/limitations.
Both positive and absent matches, and both equal and different bytes, can pass.
Do not require absence or infer privacy improvement. Interpret no private
names, reference counts, indices, offsets, metadata or object existence.
The builder launches no verification worker. Separately run the existing 14
public mathematics cases on each newly selected executable, with no signing,
funds, source mutation or future-launch attestation.

Preserve all preceding seven hosted jobs byte for byte. Append a distinct macOS
job with the same pinned checkout and Rust 1.90.0, explicit private directories,
one caller-selected prefix, these two fresh builds/four observations and two
separate mathematics groups. No private artifacts or environment logs are
uploaded. The old Linux 25 groups/294 cases remain unchanged; the additional
Apple two groups/28 cases are qualified separately.

## Primary source and attribution

Apple ld64 commit `f60a74eaa2c99585de1dc0f2820e7a9f8aaf522c` stores one
[`-oso_prefix` setting](https://github.com/apple-oss-distributions/ld64/blob/f60a74eaa2c99585de1dc0f2820e7a9f8aaf522c/src/ld/Options.cpp);
later occurrences overwrite that field. A dot operand expands cwd in this
source; this construction refuses it. The
[`canonicalOSOPath` routine](https://github.com/apple-oss-distributions/ld64/blob/f60a74eaa2c99585de1dc0f2820e7a9f8aaf522c/src/ld/OutputFile.cpp)
first supplies a full spelling and removes the selected exact leading bytes
once on a match, retaining the full spelling otherwise. Its N_OSO synthesis
uses that routine. Relative spellings can be prefixed by cwd; absolute spelling
is not authenticated filesystem identity. Options.cpp SHA256
`5caa8f728689afbf82eeaaa75d06efc268f10804a4b7f2dc0fe77f87209ea53d`;
OutputFile.cpp SHA256 `2aa17386d5334d297d1f27aa7a6b072ac44f8e075a238b98eadb352c0ab7d953`.
APSL 2.0 source headers and the complete
[Apple license](https://github.com/apple-oss-distributions/ld64/blob/f60a74eaa2c99585de1dc0f2820e7a9f8aaf522c/APPLE_LICENSE)
were inspected.

Rust 1.90.0 commit `1159e78c4747b02ef996e55082b704c09b970588`
[`link-arg` documentation](https://github.com/rust-lang/rust/blob/1159e78c4747b02ef996e55082b704c09b970588/src/doc/rustc/src/codegen-options/index.md)
describes appending one linker argument and passing `-Wl,` through a C compiler
driver. Complete document SHA256
`1dd36c5e48b6a17d86096c5210e86d23e3634609c56ce050079d98983b9c0ecc`;
MIT and Apache 2.0 notices were inspected. LLVM Clang 19.1.7 commit
`cd708029e0b2869e80abe31ddb175f7c35361f90`
[`Wl_COMMA` declaration](https://github.com/llvm/llvm-project/blob/cd708029e0b2869e80abe31ddb175f7c35361f90/clang/include/clang/Driver/Options.td)
declares comma-joined forwarding; the preceding C construction records its
complete source measurement and Apache 2.0 with LLVM exception attribution.
No third-party code or prose is copied.

Published source and intended transport do not identify the installed linker,
prove argument consumption, source-to-worker provenance or causal attribution.
Selected C compiler bytes are measured; its invoked linker/support chain is
not separately authenticated. Host, tools, scripts, caller selections,
transport and directory ancestors remain trusted or unassessed. There is no
hostile-filesystem exclusion, atomic pair snapshot, nonrollback state or future
use binding. Privacy is NOT ASSESSED; reproducibility and source-to-worker are
NOT VERIFIED. All three independent reports remain unfilled. Both artifacts,
private streams and selections remain private.
