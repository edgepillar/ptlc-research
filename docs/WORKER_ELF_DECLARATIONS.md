# Bounded public worker ELF declarations

Status: selected offline observation construction. Application and core
progression remain **NO-GO**. The accepted parent is
`b6e6e3fe936f8504f5ecd79493f63183c711966f`.

## Requirement and selected construction

Entry continuity and a correct public verification receipt do not authenticate
the loader or dependencies used by an executable. A separate observation can
describe a selected entry's bounded loader declarations without resolving them
or publishing their raw strings. It must remain separate from the accepted
[sealed adapter](SEALED_PUBLIC_VERIFIER.md), its
[submitted-wire binding](SEALED_VERIFIER_SUBMITTED_WIRE.md), exchange consumers
and the existing [section reader](OFFLINE_WORKER_SECTION_LOCALIZATION.md).

The selected observer reads one caller-pinned, owned, quiescent complete file.
It checks the expected whole-entry SHA256 and byte count through the existing
regular-file guard. The pin and file ownership are local selection premises,
not authenticated producer or distribution evidence. The guard retains its
trusted-ancestor and quiescent-input assumptions; it is not an atomic snapshot
or a hard I/O deadline.

The observation policy accepts ELF64 little-endian ET_EXEC or ET_DYN declarations
with version one, a 64-byte header and 56-byte program-header records. It bounds
the file to 32 MiB and the nonzero program-header count to 1024. Extended numbering
and other formats refuse. Every declared file span must lie in the selected
stream. Unknown program types, machine compatibility, executable permissions,
virtual addresses, memory sizes, alignment and section declarations are not
interpreted or validated for execution.

At most one PT_INTERP and one PT_DYNAMIC declaration are selected. Selected
metadata payloads must not overlap the header, program table or each other.
Ordinary PT_LOAD enclosure and repeated unknown declarations remain allowed.
An interpreter payload must contain between two and 4096 bytes, with one NUL at
its end and none earlier. The dynamic payload must contain between 16 and 65536
bytes in 16-byte units. These are chosen observation bounds and framing rules;
they are not a complete ELF or kernel-loader conformance test. Dynamic tags,
values and strings are not decoded; a DT_NULL termination condition is not
qualified.

The fixed output reports declared entry kind, interpreter presence and dynamic
segment presence, along with the measured whole-entry digest and byte count.
It does not emit interpreter paths, their lengths or digests, raw dynamic strings,
offsets, virtual addresses, machine values, environment details or producer names.
It never opens or executes a declared interpreter, resolves dynamic dependencies
or invokes a native reader. A missing interpreter declaration does not establish
static linkage, loader absence, loadability or authenticated runtime closure.

## Immutable semantic sources and reuse boundary

The semantic reference is Linux
`7d0a66e4bb9081d75c82ec4957c50034cb0ea449`:

- [ELF public declarations](https://github.com/torvalds/linux/blob/7d0a66e4bb9081d75c82ec4957c50034cb0ea449/include/uapi/linux/elf.h)
  define the selected record layout and program-type identifiers.
- [Kernel ELF loader](https://github.com/torvalds/linux/blob/7d0a66e4bb9081d75c82ec4957c50034cb0ea449/fs/binfmt_elf.c)
  reads PT_INTERP bytes and separately opens the interpreter. Its program-table
  checks and ET_DYN handling do not make this observer a loader validator.
- [Kernel licensing entry](https://github.com/torvalds/linux/blob/7d0a66e4bb9081d75c82ec4957c50034cb0ea449/COPYING)
  was reviewed before the immutable source-object comparisons.

No upstream implementation is copied. These source facts do not authenticate an
installed kernel, a selected binary's build origin or loaded runtime bytes. The
existing section reader retains its complete bytes and its original observation
scope; its bounds are not silently promoted into loader validation.

## Qualification and unresolved authority

Twenty-four new portable synthetic methods cover fixed output, string suppression,
unknown declarations, malformed tables and spans, duplicate or overlapping
metadata, bounded framing, caller pin selection, owned-file refusal, descriptor
cleanup and CLI error privacy. Instrumented API controls observe one selected
file opening and no interpreter or native launch. They do not prove protection
against a malicious host or kernel.

One appended actual exchange method retains all nineteen preceding methods and
the complete CLI. Its Linux schedule must read the selected actual ELF worker
and bind a complete metadata observation to its locally measured bytes. An
unsupported-format refusal cannot qualify that Linux schedule. A selected
macOS Mach-O worker explicitly refuses without skips; this does not qualify an
actual ELF observation. Two direct test-only before/after whole-file digests
remain separate from the observer's own complete-stream measurement. No new
native actor, mathematical vector, signing step
or exchange state transition is added. See the separate
[validation snapshot](STAGE87_VALIDATION.md).

All preceding adapter and consumer bytes, native sources, actors, fixtures,
dependencies, finite models, four fixed inventories and three unfilled assessment
reports remain unchanged. Independent review remains unfilled. Source-to-worker
and reproducibility remain **NOT VERIFIED**; producer origin, private consumed
inputs and runtime closure remain **NOT AUTHENTICATED**; independent privacy
remains **NOT ASSESSED**. Durable nonce custody and restored-copy protection remain
open. No wallet, funds, transaction, chain, broadcast, deployment, activation,
reviewer contact or core action is selected.
