# Offline dependency content comparison

This selected construction extends the evidence beside the fixed witness subject.
The [Stage 58 input checker](OFFLINE_BUILD_INPUTS.md) measures archive and selected
native bytes. The new [content checker](../scripts/check_dependency_contents.py)
compares archives, pinned Git objects and installed contents without executing
dependencies. The [qualification entry](../scripts/qualify_dependency_contents.py)
selects existing cache layouts and refuses unavailable or ambiguous selections.

## Requirements and selected construction

The requirement is an independently selected expected source record. Cache
markers, current checkouts and successful builds cannot choose replacement
expectations. Complete selected file sets must agree; omissions, additions,
type changes, unsafe names and unsupported inputs refuse before a success report.

The selected witness commit is `bd4b4b523fb3453e2af191eb01973985d6431d66`, with
manifest SHA256 `0f449db4c5e7c65f826ab57c4fafe4cd288bb570b7920d29e583b6cfd62dd82f`.
The unchanged source-selection entry checks its complete 360-file inventory and
the immutable/index/worktree bytes of ten source and dependency records. All
three earlier manifests and all three unfilled assessments remain fixed. New
packaging and downloaded sources are outside those inventories.

| Profile | Expected record | Measured content | Unresolved scope |
| --- | --- | --- | --- |
| Cargo registry | Selected lock SHA256 | All 68 archives and every decoded regular member against the installed tree | Features, build scripts and compiled closure |
| Cargo Git | Two full revisions in six lock records | Complete local Git blobs and checkout contents | Repository ownership, upstream approval and compiled closure |
| Go | Required content and definition `h1` in selected sums | ZIP, complete installed files and cached definitions for six and nine declared requirements | Other checksum history, graph resolution and compiled closure |

Git commit, recursive tree and blob bytes are independently rehashed using the
selected SHA1 object format, including object type/length headers. An object
stored under the expected filename cannot supply replacement content. The
complete measured inventory follows only the rehashed commit's tree. This checks
the selected legacy Git identities; it does not authenticate their ownership or
establish a new collision-resistance claim. Parent history is outside the scope.
The format follows the primary [Git object documentation](https://git-scm.com/book/en/v2/Git-Internals-Git-Objects);
the parser and hash checks are original code, with no upstream code copied.

Git revisions are
[`5a09b1197b1b5c621a5a9abc60fa95fa84a1da30`](https://github.com/conduition/musig2/tree/5a09b1197b1b5c621a5a9abc60fa95fa84a1da30)
and
[`74d18bbf864f98e5cf7c18dcfb74ba1ecfe837ce`](https://github.com/LLFourn/secp256kfun/tree/74d18bbf864f98e5cf7c18dcfb74ba1ecfe837ce).
The second includes one tracked relative symlink. Exact target bytes and link
type are compared without following it; the pinned target must be an internal
regular tracked file. Extra links, external targets, cycles, submodules and
regular-file substitutions refuse. Executable permission bits, Git index state
and Git configuration are not attested.

## Go format and attribution

The selected `Hash1` format sorts logical filenames and hashes a summary of each
file's hexadecimal SHA256, two spaces, filename and newline. SHA256 of the summary
is encoded as `h1:` plus Base64. Module filenames include the original module and
version prefix; a cached `.mod` is separately hashed under `go.mod`. ZIP timestamps,
compression and ordering are excluded. This differs from raw archive SHA256.

The format and cache-verification distinction were checked against Go 1.23.12,
immutable commit `dd8b7ad9268c2fbde675132a41b4e4da02eef94d`:
[`dirhash`](https://github.com/golang/go/blob/dd8b7ad9268c2fbde675132a41b4e4da02eef94d/src/cmd/vendor/golang.org/x/mod/sumdb/dirhash/hash.go)
and
[`go mod verify`](https://github.com/golang/go/blob/dd8b7ad9268c2fbde675132a41b4e4da02eef94d/src/cmd/go/internal/modcmd/verify.go).
The latter checks content against local `.ziphash` and can omit missing downloads.
This checker requires ZIP, installed directory and module definition, and takes
expectations from fixed source sums. It does not read `.ziphash` as authority,
invoke Go or resolve a module graph.

The Go Authors' [BSD-style license](https://github.com/golang/go/blob/dd8b7ad9268c2fbde675132a41b4e4da02eef94d/LICENSE)
was checked before implementation. The Python entry is original code implementing
the documented format. No upstream code, cache or license text is copied.
Existing [third-party notices](../THIRD_PARTY_NOTICES.md) remain unchanged.
Counts of matching license/notice-named files are observations only, without a
compliance, redistribution or ownership verdict.

## Bounds and assumptions

The selected portable ASCII path profile permits at most 512 characters per name
and 255 per component. It refuses absolute paths, controls, backslashes, colons,
empty/dot/parent/Git-metadata components, duplicate names and case aliases.
TAR links/devices/sparse files and ZIP links/encryption/unsupported compression
refuse. Nothing is extracted to disk. Decoded TAR input is bounded before header
parsing. Regular member contents and installed files are hashed in bounded reads.

Limits are 64 MiB per compressed archive, 80 MiB per decoded TAR, 16 MiB per regular
file, 64 MiB per package payload, 8,192 entries per package or installed tree,
256 MiB aggregate payload per profile and 512 MiB aggregate registry archives.
Git bounds each commit, tree and blob object to 2 MiB. The trusted local Git reader disables
replacement objects and lazy fetching. No upstream code, filters, hooks or build
scripts run.

Installed file sets must match exactly, including empty files. Extra directories
refuse. Cargo permits two optional root metadata names: `.cargo-ok` is empty or
the known version-one marker; `.cargo-checksum.json`, when present, must contain
the selected package checksum and exact member digest map. Neither selects an
expectation. Git excludes only its owned `.git` directory and optional empty
`.cargo-ok`. Go permits no installed metadata exceptions. Other cache trees are
outside the selected comparison.

The operator selects an owned, quiescent cache and trusted parent directories.
Direct selected file/directory symlinks refuse. Held regular descriptors receive
identity, size and time stability checks. This is no atomic snapshot of a hostile
or concurrently rewritten filesystem, runtime support-file attestation, or binding
between the comparison and a later build or worker invocation.

## Offline entry points

The companion requires one existing registry namespace and each exact Git revision
from the selected Cargo home. Multiple matching checkouts refuse. Go profiles
select one qualification module at a time. Use relative operator-selected paths:

```sh
python3 -B scripts/qualify_dependency_contents.py --cargo-home offline-cargo
python3 -B scripts/qualify_dependency_contents.py --go-cache offline-go --go-module qualification-go
python3 -B scripts/qualify_dependency_contents.py --go-cache offline-go --go-module qualification-bitcoin-go
```

For explicit independent selections, `check_dependency_contents.py` requires
`--expect-commit`, `--expect-manifest-sha256` and `--profile cargo` or `go`.
Cargo also requires `--registry-cache`, `--registry-src` and one
`--git-checkout COMMIT PATH` per revision. Go requires `--go-cache` and `--go-module`.
Mixed profiles, repeated pins, missing and malformed selections refuse. Failure
emits a generic message, exit one and no partial success JSON.

Acquisition is separate. Hosted steps explicitly acquire the fixed project object
and already recorded dependencies before read-only inspection. Neither entry
downloads, repairs, substitutes, builds or executes dependencies, toolchains or
workers. Reports contain logical identities, digests, counts and explicit unknowns;
they include no local paths or third-party payloads.

## Qualification and remaining gates

[Stage 59 validation](STAGE59_VALIDATION.md) records synthetic tampering and
unavailable-input controls alongside real cached content comparison. Declared
requirements do not determine the resolved or compiled closure. Matching
license-named files do not establish license compliance.

Authenticated acquisition, toolchain origin/support files, build environment,
source-to-binary relationship, reproducibility and independent assessment remain
unverified. No report is filled and no reviewer contacted. Application and core
remain **NO-GO** pending source authentication, current/canonical selection,
nonrollback ownership, signer custody, lookup/disclosure, original recovery and
protected-use gates. This adds no application cryptography, signer/backend,
deployment, node activation, wallet access, transaction broadcast or funds.
