# Selected private-prefix and artifact-byte comparison

Status: **Selected offline research construction; complete local checks passed;
exact candidate hosted checks required. NOT ASSESSED. Application and core NO-GO.**

## Requirement and selected construction

The preceding fresh-build construction compares selected source, resolution,
build claims and native files. It does not establish artifact privacy or
reproducibility. Two fresh local outputs have different bytes and contain all
four caller-selected location prefixes. The cause of the difference is not
isolated. A separate bounded observation must neither emit those prefixes nor
turn their absence into permission to publish an artifact.

Select exactly two distinct regular files, each with an explicit independently
selected SHA256 and byte count. Supply a private prefix selection for each file.
Each selection has exactly these four logical roles:

- `selected-source-location`
- `selected-build-location`
- `selected-cache-location`
- `selected-repository-location`

Each value is an exact byte string of 8 through 4096 bytes. Values within one
selection must be distinct. Nested or overlapping prefixes are allowed, so
their presence results are not independent observations. Shared values across
the two selections are allowed. Roles cannot contain caller-selected labels.
No path discovery, implicit expected hash, normalization, decoding of artifact
contents, case folding or alternate encoding search is selected.

Stream both complete files in 64 KiB chunks, each bounded to 256 MiB. Hash the
same bytes that are compared. For each unobserved prefix, retain at most its
maximum length minus one bytes between chunks so boundary crossings are
detected. Stop searching a role after finding its first exact occurrence; still
consume and compare all remaining artifact bytes. Report only each artifact's
SHA256, byte count, fixed-role booleans, number of present roles and complete
stream byte agreement. Do not report occurrence counts, positions, context,
prefix values, lengths, encodings, fingerprints or a digest of the selection.

Equal artifact hashes are not a substitute for the actual stream comparison.
Different files with equal bytes can match. Selecting the same file or two
hard links to the same inode refuses. An artifact change, mismatched independent
pin or size, empty/oversized file, linked file, linked immediate parent or
incomplete/ambiguous prefix selection refuses without a partial report.

The private JSON input uses the schema
`ptlc-offline-private-prefix-selection-v1`, with `first` and `second` objects
mapping the four fixed roles to canonical lowercase hexadecimal bytes. The
input is at most 128 KiB; JSON nesting is bounded before decoding. Duplicate
keys, extra fields, numeric aliases, non-ASCII wire bytes and noncanonical hex
refuse. Keep this input private, owned and without group/other permissions.
Hex encoding is not confidentiality. Do not commit a real selection file.

Supply the private selections and independently selected expectations explicitly:

```sh
python3 -B scripts/check_artifact_prefixes.py \
  --first "$PTLC_FIRST_ARTIFACT" \
  --expect-first-sha256 "$PTLC_FIRST_SHA256" \
  --expect-first-bytes "$PTLC_FIRST_BYTES" \
  --second "$PTLC_SECOND_ARTIFACT" \
  --expect-second-sha256 "$PTLC_SECOND_SHA256" \
  --expect-second-bytes "$PTLC_SECOND_BYTES" \
  --private-prefixes "$PTLC_PRIVATE_PREFIX_SELECTION"
```

The variables are supplied privately by the caller; no file, prefix or digest
is discovered or selected by default.

## Filesystem and output boundary

Files and the private selection must be owned by the current effective user.
Direct files and immediate parents must be real regular files/directories.
Descriptor identity, size and modification/change times are compared across
the read, and the path must still select the same measured file at the final
check. Owned quiescent inputs and trusted ancestors remain explicit
preconditions. This does not exclude hostile ancestor replacement, provide a
multi-file atomic snapshot, lock the inputs or establish future launch bytes.
Higher ancestor symlinks are not fenced by this construction.

The checker creates no output files and invokes no Git, Cargo, compiler,
build script, worker, network, signer, wallet or chain interface. It emits one
logical JSON report only after both stable reads and all pins succeed.
Argument, input and filesystem failures use a fixed sanitized refusal.
Cancellation propagates without a completed report. Use only synthetic
selections for shared examples and tests.

## Meaning and unresolved decisions

Presence proves only that an exact caller-selected byte string occurred in the
measured stream under the filesystem assumptions. Absence means only that the
four selected byte strings were not observed. Unselected paths, identities,
encodings, debug data, metadata, credentials and other sensitive information
remain outside the observation. Neither result establishes complete privacy;
both artifacts remain private. The report cannot prove how its caller selected
the expected hashes, sizes or prefixes.

Byte agreement applies only to these two measured files. They may be copies,
unrelated files, arbitrary caller-selected bytes or outputs of unauthenticated
generators. Agreement does not prove source-to-worker provenance, independent
builds, reproducibility, current/canonical authority or protocol security.
Different bytes do not identify which input caused the difference. The checker
does not interpret the previous build reports or attest their relationship to
the two selected files.

Path remapping, new build flags, native rebuilds, stripping, binary rewriting,
artifact upload/release, general sensitive-data discovery, independent privacy
assessment, authenticated build provenance and reproducible-build qualification
are **unselected**. They require separately documented constructions and
acceptance evidence. The three review subjects and unfilled reports remain
unchanged. Existing authentication, ownership, rollback protection, signer
custody, recovery and protected-use gates remain open.

This is an original read-only observation outside all three fixed subjects.
No third-party implementation or source text is copied.
