# Offline dependency and worker input evidence

Status: **Review evidence only; NOT ASSESSED. Application and core NO-GO.**
The [witness subject](../review/witness-subject.json) remains the complete
360-file source at `bd4b4b523fb3453e2af191eb01973985d6431d66`, with manifest
SHA256 `0f449db4c5e7c65f826ab57c4fafe4cd288bb570b7920d29e583b6cfd62dd82f`.
This entry is outside that fixed subject. All three manifests and all three
unfilled assessment reports retain their bytes.

## Distinct evidence layers

| Layer | Selected input and check | Interpretation |
| --- | --- | --- |
| Immutable project source | Complete witness manifest against local immutable Git objects; ten source inputs against the selected tree, index and working copy | Exact selected source bytes; neither trusted authorship nor completed assessment |
| Cargo records | All 75 package records: 68 registry, six Git, one local | Recorded resolution, including optional/other-target packages; no minimal compiled worker closure |
| Registry archives | All 68 named `.crate` files in one explicitly selected cache; bounded streamed SHA256 against selected lock checksums | Actual archive bytes match selected records; unpacked sources and registry origin remain unverified |
| Git dependencies | Six records at two explicit immutable revisions | References only; Git checkout content is not measured by this entry |
| Go records | Six/nine declared requirements and 13/119 checksum-history records in the two modules | Recorded requirements and hashes; no resolved build graph or module-content verification |
| Native selections | Explicit Cargo, rustc, C compiler and original-response worker files; caller-selected expected SHA256 | Selected file bytes match; installation, compiler libraries, executed build and source-to-binary link are not attested |
| Licenses and source context | Exact project LICENSE and THIRD_PARTY_NOTICES bytes in the selected source | Review references only; no new third-party redistribution or license-compliance assessment |

The public original-response worker uses `bitcoin::secp256k1` through `bitcoin`
0.32.7 / `secp256k1` 0.29.1 and the selected root worker source module. Its two
tracked Rust files are measured separately from external packages. The broader
adaptor harness also selects `musig2` and `schnorr_fun`; this entry does not turn
the latter into the worker's arithmetic implementation or claim a complete
compiled closure. See the immutable [worker source](https://github.com/edgepillar/ptlc-research/blob/bd4b4b523fb3453e2af191eb01973985d6431d66/qualification/examples/verify_original_read_response.rs).

Cargo's registry format defines the checksum over the `.crate` file, as
documented in the [Cargo registry index specification](https://doc.rust-lang.org/cargo/reference/registry-index.html#json-schema).
Go `h1` sums describe module contents or a `go.mod` file using Go's content
hashing rules, as documented in the [Go modules reference](https://go.dev/ref/mod#go-sum-files).
This entry records Go sums without applying that algorithm. A Go module zip's
ordinary SHA256 is not a substitute for its recorded `h1` sum. These living
format references provide context; the selected source/records remain pinned.

## Explicit read-only inspection

The [checker](../scripts/check_build_inputs.py) requires the independently
selected source commit, witness-manifest SHA256, a single flat registry cache
and four explicit native file paths with four expected SHA256 values. It reads
local objects/files only. It never runs Cargo, a compiler, a verifier, network
acquisition, a build script or a wallet. It emits a canonical ASCII JSON report
only after every required selected input matches; failures emit one sanitized
message, exit nonzero and emit no partial success report.

The command shape is:

```text
python3 -B scripts/check_build_inputs.py \
  --expect-commit SELECTED_COMMIT \
  --expect-manifest-sha256 SELECTED_MANIFEST_SHA256 \
  --registry-cache SELECTED_FLAT_REGISTRY_CACHE \
  --cargo SELECTED_CARGO --expect-cargo-sha256 SELECTED_CARGO_SHA256 \
  --rustc SELECTED_RUSTC --expect-rustc-sha256 SELECTED_RUSTC_SHA256 \
  --c-compiler SELECTED_CC --expect-c-compiler-sha256 SELECTED_CC_SHA256 \
  --original-response-worker SELECTED_WORKER \
  --expect-original-response-worker-sha256 SELECTED_WORKER_SHA256
```

Expected native digests are caller selections. Supplying a digest learned from
the same installation is measurement consistency, not independent attestation.
The manifest must also match its index version. Each selected source input must
match immutable bytes in both index and working copy. Other checkout edits do
not change the fixed source selection.

The generated Cargo v4 and selected Go record readers accept a narrow literal
grammar, refuse unknown fields/directives and enforce encoding/count bounds.
They are not general TOML/Go manifest parsers or replacements for dependency
resolution. Unsupported records require an explicit reviewed change. The
checker does not unpack archives, trust `.cargo-checksum.json`, inspect cache
configuration or discover alternate caches. Every locked registry archive must
be present at the selected cache. Unrelated extra cache files are ignored;
they are not part of a claimed complete cache inventory.

Each archive is nonempty and at most 64 MiB, with at most 512 MiB measured across
archives. Each native file is nonempty and at most 256 MiB. Streaming observes
descriptor identity, size and timestamps during reading. Direct file/directory
symlinks are refused by the checker. Parent directories, Git executable,
object store, filesystem and operator selections are trusted. This is not a
hostile-filesystem sandbox, atomic measure-and-launch fence, power-loss test or
guarantee against concurrent adversarial replacement.

## Same-run qualification and hosted evidence

The [qualification entry](../scripts/qualify_build_inputs.py) takes an explicit
Cargo home and native paths. It requires exactly one registry cache directory,
resolves caller-selected native links, selects their digests locally before
inspection, and labels that selection method in its output. It never searches
PATH or substitutes another cache, toolchain or worker. Missing/ambiguous inputs
refuse. Its successful report does not attest that those files produced the
worker; support libraries, headers, linkers, unpacked Git/registry sources,
build environment and command execution remain outside its measurements.

The retained hosted adaptor job builds examples through its existing pinned
Rust 1.90.0 selection, then supplies the exact toolchain paths and worker path
to this new entry. Acquisition of the already fixed source object is a separate
explicit workflow operation. Each hosted native digest is selected in that
job, not a project release pin. Host-specific executable hashes can differ.
Existing Rust/Go/mathematical qualification remains distinct from this report.

## Open acceptance gates

A full source-to-build assessment still needs the exact used unpacked dependency
trees, Git checkout content and object/revision relations, effective Cargo/Go
configuration, features/target/build graph, compiler support files and native
toolchain distribution provenance. It must account for generated/build-script
outputs, environment inputs, license obligations and the actual source-to-binary
relationship. Reproducibility and portable or release artifact provenance need
their own selected construction and independent reproduction.

No successful archive/hash comparison establishes source authority,
reviewer independence, canonical/current selection, source or consumer
nonrollback ownership, signer custody, original recovery or protected entry.
The [witness assessment](WITNESS_REVIEW_REPORT_TEMPLATE.md) is unfilled. See
[Stage 58 validation](STAGE58_VALIDATION.md). Application/core productization,
deployment, activation, wallet access, broadcast and funds remain **NO-GO**.
