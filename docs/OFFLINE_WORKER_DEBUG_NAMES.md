# Bounded private worker debug-name observations

Status: construction selected before new retained native reads. This is a
declared-name observation; producer influence is not selected or authenticated.

## Requirement and selected construction

Stage 65 observes declared symbol-name references. Its retained Apple outputs
place build roles in object-STAB names and cache/repository roles in other STAB
names. Its hosted Linux cache match is outside selected symbol string tables.
These facts do not select compiler/linker controls or an artifact release.

Select a pure Python read-only refinement. Preserve all existing workers,
builders, complete scans, section/symbol readers, fixed subjects and unfilled
reports. Apply the unchanged bounded container and symbol-name grammar first,
including its 32 MiB artifact bound, 131072 symbol records, 16 MiB distinct symbol
string tables and 8192-byte referenced-name bound.

- In ordinary little-endian ELF64, select at most one section named `.debug_str`
  and at most one named `.debug_line_str`. Require file-backed type 1 and no
  compressed flag. Refuse either selected compressed spelling `.zdebug_str` or
  `.zdebug_line_str`, duplicate selected names, non-file-backed/type alternatives,
  unsupported selected framing and incomplete termination. Other sections,
  including unselected split/supplementary pools, remain outside this selection.
- Selected ELF pools may be empty and need no initial zero. Walk the entire pool
  as successive zero-terminated opaque byte entries, counting empty entries.
  Select at most 16 MiB of pool bytes in total, 131072 entries across both pools
  and 65536 bytes before each terminator. Do not follow DWARF offsets, forms,
  units, DIEs, line programs, supplementary files or version claims. Pool framing
  does not prove that an entry is referenced, a pathname or a source identity.
- In thin little-endian Mach-O64, reuse the bounded symbol command/string table.
  Exact type 0x64 selects a source-STAB name class; exact type 0x84 selects an
  included-source-STAB class; every other type selects an other-name class.
  Index zero denotes no name. Nonzero indices retain the preceding bounded NUL
  terminator and suffix-reference semantics. Descriptors, sections, values,
  timestamps, STAB sequence/directory semantics and indirect targets are unused.

No text is decoded. Selected strings remain opaque bytes, including possible
zero bytes. A terminated entry/reference excludes its terminator; raw region
observations retain matches across internal terminators. Never open a name as a
path, demangle it or infer a real file's existence. Bounded work is not OS CPU or
memory isolation. No native analysis executable, compiler flag, build profile,
worker launch, native build/math run, job, platform, toolchain or timeout is added.

Report ten fixed boolean classes for each unchanged private role:

| Class | Observation |
| --- | --- |
| `raw-elf-debug-str-pool` | Complete match inside the selected debug string pool |
| `terminated-elf-debug-str-entry` | Complete match within one bounded non-terminator entry |
| `raw-elf-debug-line-str-pool` | Complete match inside the selected line string pool |
| `terminated-elf-debug-line-str-entry` | Complete match within one bounded non-terminator line pool entry |
| `raw-macho-symbol-string-table` | Complete match within the selected Mach-O string table |
| `referenced-macho-source-stab-name` | Bounded name reference with exact declared type 0x64 |
| `referenced-macho-included-source-stab-name` | Bounded name reference with exact declared type 0x84 |
| `referenced-macho-other-name` | Bounded name reference with another declared type |
| `outside-selected-name-regions` | Complete match in the complement of individually selected regions |
| `crosses-selected-name-region-boundary` | Complete match across any selected-region boundary, including adjacent regions |

Terminated/reference classes imply their raw pool/table class. ELF raw pool
classes imply the preceding declared-debug group from these same bytes. Mach-O
raw table presence equals the preceding symbol reader's raw-table observation;
the two source-STAB classes imply its other-STAB reference class. All ten classes
must cover each complete role scan exactly. No specific presence, absence, class
or byte equality is required for qualification.

## Integration and acquisition scope

A companion reuses the unchanged Stage 64 canonical carrier/section qualifier,
then acquires two new pinned streams. It computes the unchanged symbol observation
in memory from those same streams and requires exact section measurement, format
and byte agreement. Two section revalidations plus two new debug-name reads are
separate owned quiescent acquisitions; they supply no atomic pair snapshot.

Use the same retained Stage 63 Apple outputs and private carrier locally. Do not
rebuild them or rerun their earlier public mathematics for this reader. Append
one companion command in the existing Linux remapping step, after the unchanged
section and symbol companions. The original section reader contributes two
acquisitions, the symbol companion four, and this companion four: ten selected
section/symbol/debug observation acquisitions. Existing builder measurements,
complete comparisons and their separate 14-case mathematics remain unchanged
and separate from this observation-read count. No carrier or binary is uploaded;
existing trusted shell/tee transport, pipefail and cleanup remain unchanged.

## Primary references and attribution

The DWARF Version 5 standard dated February 13, 2017 describes byte-string and
line string pooling in its string-class and line-number sections. The official
[standard page](https://dwarfstd.org/dwarf5std.html) links the
[PDF](https://dwarfstd.org/doc/DWARF5.pdf), retrieved 2026-10-06, complete SHA-256
`cc9a9b49163aa7c65923b45ade0df6f5dff5ee50ecf8e5938c03ffbfa06a25e4`.
Its copyright/GNU Free Documentation License 1.3 notices were inspected. The PDF
is not redistributed here. Section names and termination facts are independently
implemented; no standard prose, tables or implementation are copied.

Mach-O type numbers come from Apple XNU commit
`f6217f891ac0bb64f3d375211650a4c1ff8ca1ea`,
[STAB header](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/EXTERNAL_HEADERS/mach-o/stab.h).
Its Apple Public Source License 2.0 and historical Berkeley four-clause notices
were inspected. Reuse only independently written numeric facts and the preceding
repository-owned framing; no header code, declarations, comments or prose are
copied. No third-party endorsement is claimed.

## Boundaries

Emit no names, paths, encodings, prefix lengths/fingerprints, offsets, entry or
reference counts, timestamps, context or native streams. Report only complete
artifact measurements and fixed role/class booleans. Keep both binaries private.

Caller pins, directories, carrier history, host/tools/transport and higher
ancestors remain trusted or unassessed. These partial declarations authenticate
no producer, source or previous execution. There is no full symbol/loader/DWARF
validation, decompression, rollback defense, atomic snapshot or future-launch
binding. All three independent reports remain unfilled. Privacy is NOT ASSESSED;
reproducibility and source-to-worker provenance are NOT VERIFIED. No release is
qualified. Application/core and funded use remain **NO-GO**.
