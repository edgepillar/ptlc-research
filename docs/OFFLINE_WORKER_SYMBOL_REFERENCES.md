# Bounded private worker symbol-name references

Status: construction selected before new retained native reads; implementation
and observations require separate qualification. Producer influence remains an
unselected later experiment.

## Requirement and selected construction

Stage 64 localizes selected strings in raw declared ranges. Its retained Apple
outputs place build/cache/repository roles in symbol/string ranges. Its new
hosted Linux outputs place only the cache role in debug ranges. These separate
observations do not identify a producer or select compiler/linker controls.

Select a read-only Python symbol-name reference reader before opening retained
native bytes. Preserve the complete existing builders, scanners, section reader,
cryptographic workers, fixtures, source/content/resolution pins, all three fixed
subjects and unfilled reports. No native reader, compiler flag, build profile,
worker launch, job, platform, toolchain or timeout is added or changed.

First apply the unchanged Stage 64 raw container framing. Support only its
ordinary little-endian ELF64 and thin little-endian Mach-O64 constructions.
Then select the following bounded declarations:

- ELF symbol sections of types 2 and 11 use 24-byte records and a bounded
  section link to an uncompressed type-3 string table. Require exact record
  divisibility and an all-zero first record when nonempty. Linked string tables
  require nonempty, initially/finally zero bytes. Reject compressed selected
  symbol/string tables. Observe only the name index and the low four type bits;
  type 4 selects the file-name class. Other bindings, visibility, section/value
  semantics and extended symbol indices are not validated or used.
- A bounded Mach-O symbol command supplies 16-byte records and its string table.
  Index zero denotes no name even when the table's first byte is not zero.
  Nonzero indices require a bounded terminating zero. Observe the type byte:
  exact 0x66 selects the object-STAB class, other 0xe0-mask positives select the
  other-STAB class, and remaining types select the non-STAB class. No descriptor,
  section, value, indirect target or timestamp semantics are interpreted.

Each artifact remains bounded to 32 MiB. Select at most 131072 symbol records
in total, 16 MiB of distinct selected string tables, and 8192 bytes before a
referenced string's terminator. Keep the earlier section/command/name-table
bounds. Empty and absent symbol selections are allowed under the framing rules;
unsupported or over-bound declarations refuse the complete observation. Bounded
work is not process CPU/memory isolation.

String-table reference indices may select interior suffixes. Overlapping and
repeated references are permitted; repeated matches remain presence-only.
Selected private strings are opaque bytes, including possible zero bytes. A
reference name excludes its terminator; raw table observations retain complete
matches across internal terminators. Do not decode text, demangle, infer a real
file's existence, open a referenced path or follow indirect symbol values.

Report eight fixed boolean classes for each unchanged private role:

| Class | Selected observation |
| --- | --- |
| `raw-selected-string-table` | Complete match inside a distinct selected linked string table |
| `referenced-elf-file-name` | Complete match between a nonzero ELF name index and its terminator, with declared type 4 |
| `referenced-elf-other-name` | Same bounded name reference with another declared ELF type |
| `referenced-macho-object-stab-name` | Same bounded name reference with exact Mach-O type 0x66 |
| `referenced-macho-other-stab-name` | Same bounded name reference with another positive 0xe0-mask type |
| `referenced-macho-non-stab-name` | Same bounded name reference without those mask bits |
| `outside-selected-string-tables` | Complete match in the complement of the selected string tables |
| `crosses-selected-string-table-boundary` | Complete match crossing a selected table/complement boundary |

Every referenced class must imply the raw-table class. Raw table, complement and
boundary observations must cover the unchanged complete stream scan exactly for
every role. The raw-table class must imply the preceding declared symbol/string
group from the same bytes. Complete hashes/sizes and direct byte agreement still
come from the two selected streams. Declarations supply no authenticated semantic
label, compiler contribution, object identity or source-to-worker provenance.

## Private carrier and integration

A companion reuses the unchanged Stage 64 carrier qualifier, including its
fixed profile/source/platform and whole-stream/section checks. It then performs
two new pinned symbol reads and requires exact measured rows, byte relation and
format agreement with that earlier observation. The new companion performs two
preceding section revalidation reads and two new symbol reads. These are separate
owned, quiescent acquisitions; they supply no atomic pair snapshot.

Locally, use the same retained Stage 63 Apple outputs and canonical private
carrier already qualified by Stage 64. No new native build or public-math run
is selected. In the existing hosted remapping step, preserve both builders,
their separate 14-case mathematics and the original Stage 64 read. Append only
the new companion using the same private carrier and explicit directories.
The unchanged original section read plus the new companion therefore performs
six artifact acquisitions in that step. No private carrier or raw artifact is
uploaded; trusted shell/tee transport and its existing cleanup remain unchanged.

## Primary references and attribution

Name indices, the 64-bit entry layout and file-type number are summarized from
the versioned ELF Object File Format 4.2 [symbol table](https://gabi.xinuos.com/v42/elf/05-symtab.html)
and [section-link table](https://gabi.xinuos.com/v42/elf/03-sheader.html), accessed
2026-10-06. Their published copyright notices were inspected; no immutable
repository commit is selected for these versioned pages.

Mach-O name-index/type framing is summarized from Apple XNU commit
`f6217f891ac0bb64f3d375211650a4c1ff8ca1ea`, [nlist header](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/EXTERNAL_HEADERS/mach-o/nlist.h)
and [STAB header](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/EXTERNAL_HEADERS/mach-o/stab.h).
Both retain Apple Public Source License 2.0 and historical Berkeley four-clause
notices, which were inspected. The new reader and synthetic fixtures are
independently written from numeric layout facts; no header implementation,
declarations, comments or prose are copied. No third-party endorsement is claimed.

## Boundaries retained under every outcome

Emit no selected strings, encodings, lengths, fingerprints, offsets, reference
counts, symbol/container names, context, timestamps or private native streams.
Only complete selected artifact measurements and fixed boolean classes are
observed. Keep both binaries private, including equal/no-match outcomes.

Selected digests, private directory choices and carrier history remain trusted
caller expectations. Higher ancestors and inputs must remain trusted/quiescent.
There is no full loader/symbol/DWARF validation, demangling, decompression,
producer attestation, source authentication, rollback defense or future-launch
binding. All three independent assessments remain unfilled. Privacy remains
NOT ASSESSED; reproducibility and source-to-worker provenance remain NOT VERIFIED.
Application/core and funded use remain **NO-GO**.
