# Retained C-profile worker symbol observations

Status: selected construction before any new retained native acquisition.
Implementation, local observations and hosted acceptance remain separate.

## Requirement and construction

Accepted Stage 67 commit `8300fae921f54285ae2f2bf59179c225b11fdb76`
selects two combined C-debug/target-Rust builds. Its Apple debug-name observations
place build and repository selections in the raw Mach-O table and the broad
other-name class. That class alone does not separate object-file declarations.
The unchanged Stage 65 symbol reader already selects exact type 0x66. Reuse its
grammar rather than introduce a duplicate object-STAB parser.

Select a new read-only companion for the Stage 67 C pair. Before opening either
artifact, validate explicit owned directories and a separately acquired canonical
private C carrier. Require the exact C pair schema and logical profile; never
translate it into the earlier Rust-only carrier or invent another build report.

Acquire one private carrier, bounded to 256 KiB, through the existing owned-file
and regular-descriptor guards. Require private mode, ASCII canonical JSON followed
by the exact C-driver terminal line. Bound JSON containers to depth 12 before
decoding; allow only nonnegative integer tokens of at most ten digits, booleans,
strings, arrays and objects under ordinary JSON. Refuse duplicate keys, different
serialization, negative/float/nonfinite numbers, missing or extra terminal bytes.
Canonical representation is a caller-claim check, not authenticity.

Require fixed top-level C-driver declarations, exact first/second selections,
the unchanged combined profile and the complete comparison/debug report shapes.
Require typed four-role booleans, exact measured hashes/sizes and role counts,
matching byte relation, supported formats and exact ten debug-class booleans.
Require each debug row's complete-scan union. Validate the pinned witness/source/
resolution baseline, platform, 55 prepared files, root profile/empty features/
nonfresh-build claim/relative worker path, and matching pair fields, root and three
selected native measurement rows. Validate syntax, positive bounded sizes and
selected/measured hash equality; do not remeasure those historical inputs. Other
build-record fields are uninterpreted bounded claims and are never emitted.

Validate both explicit directory pairs before artifact acquisition: owned,
absolute, nonaliased, mutually separate source/build directories with unchanged
private role derivation. Recheck the selected C path alphabet without invoking
metadata, tools, builds or workers. The platform selects a supported grammar;
this read-only companion does not require the current host to match it.

Then acquire exactly two complete pinned artifact streams, one per selection,
using the unchanged 32 MiB bound, regular-file descriptor/named-file guards,
owner and distinct-inode checks. Apply the existing symbol, debug-name and section
grammars in memory to those same bytes. No extra section/debug artifact read,
compiler, native analysis tool, file named by a reference or worker is invoked.
Require actual complete rows, format, byte relation and all ten debug booleans
to match the carrier. Report only the existing eight symbol classes and four
private roles, full artifact measurements and fixed limitations.

Require exact equality of the Mach-O raw table classes. Object-STAB/non-STAB
positives imply the old other-name class. Source/included-source positives imply
the other-STAB class. Each other-STAB positive must be covered by source,
included-source or other-name positives; other-name positives must be covered by
one of the three referenced Mach-O symbol classes. Their referenced-class unions
must agree. Require no positive class, absence, byte equality or attribution.
ELF symbol references and the two selected debug pools remain separate regions;
only their actual report/measurement/format checks are shared.

The old symbol grammar retains its 131072-record, 16 MiB distinct string-table
and 8192-byte referenced-name bounds. The old debug grammar retains its two exact
uncompressed pools, 16 MiB pool total, 131072 entries and 65536-byte entry bound.
Interior suffix references, zero indices, repeated/cross-class references,
opaque byte selections and complement/boundary semantics remain unchanged.
No descriptor, section/value meaning, STAB sequence, text/path, file existence,
timestamp or producer identity is interpreted. These are bounded parsing rules,
not process CPU/memory isolation.

## Acquisition and integration plan

Locally select only the retained Stage 67 C pair and its exact original stdout,
copied into a new private carrier after construction selection. Select one
carrier acquisition and two additional artifact streams. No new build, native
tool query, public mathematics run or independent assessment is selected.

Hosted CI preserves all seven jobs, pins, timeouts, old profiles, builds,
mathematics and observation order. In the existing Linux step, create a separate
private C carrier and extend its exit cleanup to both carriers. Capture the
unchanged C-driver stdout through tee under the existing pipefail rule. After
both existing C mathematics runs, append the new companion with the same C
directories and carrier. No private carrier or artifact is uploaded. Removing
the added fragments and tee suffix restores the entire Stage 67 workflow.

Prior native coverage remains Rust 123, Go 55 and 25 groups/294 cases. Prior 14
selected artifact observations remain; the new two bring that scope to 16.
Builder/input measurements and separately acquired carriers remain distinct.
Select 36 synthetic controls and a full offline suite retaining all 1773 earlier
unique methods. Test real CLI success/refusal, carrier framing/ownership,
fixed claims/type aliases, same-stream parser agreement, private output,
mutation and cancellation without changing the old readers or acceptance rules.

## Primary reference and limits

The existing [symbol construction](OFFLINE_WORKER_SYMBOL_REFERENCES.md) and
[debug-name construction](OFFLINE_WORKER_DEBUG_NAMES.md) retain their primary
references. Apple XNU [STAB declarations](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/EXTERNAL_HEADERS/mach-o/stab.h)
at immutable commit `f6217f891ac0bb64f3d375211650a4c1ff8ca1ea` declare
object-file type 0x66, source type 0x64 and included-source type 0x84. The complete
selected header has SHA-256
`a0b4de1ca40ef7d8f9807c5427799386886962d62fff4d7d8b5dfd6a14ea408e`.
Its APSL 2.0 and historical Berkeley notices were inspected. No third-party
code or prose is copied; existing repository grammars remain byte unchanged.

Matching complete bytes, carrier syntax, declared types and copied caller claims
authenticate no producer, source, build execution, argument consumption or prior
math launch. The companion does not independently requalify historical source,
tools, input closure or execution. Caller, host, scripts, tools, transport and
ancestors remain trusted or unassessed. No atomic pair, hostile-filesystem
isolation, rollback defense or future-launch binding is added. Keep both artifacts
and all names, strings, locations, encodings, selection fingerprints, counts and
reference metadata private. Only complete artifact measurements and fixed
role/class booleans are emitted. Independent reports remain unfilled. Privacy
is NOT ASSESSED; reproducibility and source-to-worker provenance are NOT VERIFIED.
Application/core progression, deployment, node/wallet activity, broadcast and
funded use remain **NO-GO**.
