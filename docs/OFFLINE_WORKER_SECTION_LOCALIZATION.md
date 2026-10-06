# Bounded private worker section localization

Status: construction selected before inspecting retained native artifacts;
implementation and native observations require separate qualification.

## Requirement and selected construction

The preceding target-only Rust profile reduced selected path observations but
did not remove them. Two local Apple outputs retained build/cache/repository
roles and differed. Two hosted Linux outputs retained the cache role and
matched. These facts do not identify a producer or establish privacy,
reproducibility or source-to-worker provenance.

Select a new read-only Python container reader. It observes the same four exact
private strings, using explicit artifact byte expectations and the existing
owned-file/stability guards. It runs no compiler, native reader, worker,
subprocess or network operation. Preserve both preceding constructions, all
source/resolution/content pins, workers, public mathematics, subjects and
unfilled assessments.

Supported containers are little-endian ELF64 with an ordinary section/name
table, and thin little-endian Mach-O64 with bounded load commands. This is a
limited raw range selection, not a loader or complete format validator. Refuse
unknown, 32-bit, big-endian, universal/fat, extended-index, missing-table,
truncated, overlapping and over-bound selected layouts. ELF program-header
framing is bounded but its entries are not interpreted. Unknown Mach-O commands
are bounded and left uninterpreted.

Each artifact is at most 32 MiB; there are at most 4096 section/range or command
records, 1 MiB of Mach-O commands, 1 MiB of ELF section names and 256 bytes per
selected ELF name. Two bounded byte buffers can be retained together; this is
not a process CPU/memory isolation mechanism. No arbitrary container labels are
emitted. Classifications are fixed design choices:

| Public group | Selected raw declaration |
| --- | --- |
| `declared-compressed-section` | ELF compression flag or selected `.zdebug_` name convention; no decompression |
| `declared-symbol-or-string-table` | ELF symbol/string types or Mach-O symbol/string ranges |
| `declared-debug-section` | Selected ELF `.debug_`/`.debug` name convention or Mach-O debug attribute |
| `other-file-backed-section` | Other selected nonempty file-backed section |
| `outside-selected-ranges` | File bytes outside the selected disjoint ranges, including headers, uninterpreted commands/tables and padding |
| `crosses-selected-boundary` | A complete selected string crosses a selected range/gap boundary |

Names and attributes are declarations, not authenticated semantic labels.
ELF `NOBITS` and Mach-O zero-fill section types select no file bytes. Empty
ranges select no bytes. Nonempty ranges must be disjoint, in the file and
outside the selected header/command tables. Mach-O file-backed sections must
also fit their declaring segment. Symbol entries, debug units, relocation
records, architecture/ABI validity, signatures, encryption and producer
identity are not decoded or authenticated.

Within each range/gap, test complete string containment. At every boundary,
test a bounded window that permits only crossing matches. This handles adjacent
sections even when their public groups match. The union of the six group
booleans must equal the existing whole-stream presence observation for every
role. Complete hashes/sizes and byte agreement still come from the selected
complete streams, not group labels or hash-claim equality. All repeated matches
remain presence-only observations.

## Private carrier and hosted integration

A companion consumes the exact canonical public report and terminal line from
the unchanged remapping driver through an owned 0600 private record. It checks
the reported fixed profile/source/platform and pair consistency, then uses its selected
worker hashes/sizes and current explicit directory selections for the reader.
The new comparison must match the earlier whole-stream rows and byte relation.
Carrier bytes are trusted local workflow input; matching them does not
authenticate the driver, execution history or artifact origin. Equal copied
files and caller-created matching claims remain possible.

In hosted checks, retain the original native build and all existing qualifiers.
Capture the new pair's already public output privately with a checked pipeline;
append the read-only companion after both existing 14-case public-math runs.
This introduces no new flags, build profile, native analysis tool, worker launch, job,
platform, toolchain, timeout or binary upload. The candidate's complete hosted
logs must independently bind the section report to the preceding build/scan
report and actual immutable checkout tree.

The shell and standard `tee` carrier transport remain trusted workflow inputs,
without an independent tool or execution attestation. An explicit `pipefail`
check retains failure of either pipeline process; the record is removed on
step exit. It is not a sandbox or an authenticated carrier channel.

Local qualification selects retained Stage 63 Apple artifacts and their saved
pair report. This is a new read of old selected outputs, not a new build or
rerun of their public mathematics. Linux requires a new exact-candidate hosted
build/read result. A positive section observation can guide another separately
selected experiment; it cannot identify Rust, a build script, C or a linker as
the producer.

## Primary format references and attribution

ELF layouts, ordinary header/table framing, file-backed section boundaries,
inactive space, name indexing and `NOBITS` semantics are summarized from the
versioned Xinuos ELF Object File Format 4.2
[header](https://gabi.xinuos.com/v42/elf/02-eheader.html),
[sections](https://gabi.xinuos.com/v42/elf/03-sheader.html) and
[strings](https://gabi.xinuos.com/v42/elf/04-strtab.html) references, accessed
2026-10-06. These are versioned URLs; no immutable repository commit is selected.
The pages retain their published copyright notices. No prose or implementation
is copied.

Mach-O framing, 64-bit section declarations, zero-fill types and symbol/string
locations are summarized from Apple XNU commit
`f6217f891ac0bb64f3d375211650a4c1ff8ca1ea`,
[loader header](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/EXTERNAL_HEADERS/mach-o/loader.h)
and [symbol header](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/EXTERNAL_HEADERS/mach-o/nlist.h).
Their Apple Public Source License 2.0 notices were inspected. The independently
written Python reader and synthetic fixtures copy no source implementation,
comments, header declarations or source text. Numeric layouts and classifications
do not imply Apple or Xinuos review of this construction.

## Boundaries retained under every outcome

Never emit raw strings, encodings, lengths, fingerprints, offsets, occurrence
counts, container names, context, environment or native streams. Full selected
artifact sizes/hashes and fixed group/role booleans are the only measurements.
Both artifacts remain private even with no selected matches or equal bytes.
Compressed/encoded values, alternate spellings, unselected identities and
supporting files remain outside this raw-byte observation.

Expected hashes and the carrier origin remain caller-selected. Inputs must be
owned and quiescent; higher ancestors remain trusted. No hostile-filesystem
exclusion, atomic pair snapshot or future worker-launch binding is supplied.
Independent privacy/reproducibility/source-to-worker assessments remain
unfilled. Application/core and funded execution remain **NO-GO**.
