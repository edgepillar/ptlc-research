# Exact signed-wire NoM recovery candidate

Status: **offline research candidate; application and core NO-GO**. This is author
development and qualification, not an independent security assessment. No signer,
wallet access, chain authority, deployment, node activation, transaction broadcast
or real funds are selected.

## Selected source and public inputs

The [manifest](../compatibility/nom_signed_originals_manifest.json) selects
[go-zenon `137fc528f10ad1ac37ca6d9c4f90ed4b9ee8e598`](https://github.com/zenon-network/go-zenon/tree/137fc528f10ad1ac37ca6d9c4f90ed4b9ee8e598)
and the complete 443-file Git tree
`1897e82296a7cc0d558a39d00398840495638bfd`. The separate source index reconstructs
that tree from every name, mode and blob identifier. Preparation checks the exact
archive, member bounds, CRCs, content SHA-256 and Git blob identifiers before
writing a new source directory. It adds one original project test file, giving
444 files for qualification. No existing checkout is adopted or modified.

The probe uses the two public signed Unlock sends from the existing complete
synthetic supervisor trace. Twelve variants per leg produce 24 records and 25
test/subtest outcomes including the parent. Selected hash, signature and producer
helpers accept 12; 12 selected invalid cases refuse. This is transaction-only
source behavior, not account frontier, Plasma, complete admission or chain truth.

Unknown protobuf fields and repeated version fields can preserve the decoded
transaction while changing its original bytes. ChangesHash and Base/total Plasma
can also change bytes without changing the selected node hash or account
signature. The corpus retains each exact wire and its SHA-256 separately from
the node identifier. A typed reencoding is a diagnostic value, never a replacement
for a retained original or a selected canonical network policy.

JSON wrapper commitments use a declared canonical record map; file hashes also
bind the separately formatted fixture. This does not normalize account bytes.
The historical terms keep their frozen protocol-profile pin at
`45e1bbb48ce6fc19d44c5fbf59ccf5784981fced`. The new raw-source context separately
binds the selected `137fc528` execution source, tree, corpus and immutable terms.
Neither source identifier is an activation claim.

The source remains separately obtained upstream GPL-covered material. Its
[GPL version 3 license text](https://github.com/zenon-network/go-zenon/blob/137fc528f10ad1ac37ca6d9c4f90ed4b9ee8e598/LICENSE)
was checked with SHA-256
`3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986`.
The independently written probe, adapters and locally generated synthetic outputs
do not vendor or relicense the node implementation. See
[source-specific notice](NOM_SIGNED_RECOVERY_NOTICE.md) and the preserved
[general notices](../THIRD_PARTY_NOTICES.md).

## Two separate long-leg phases

[`SignedNomRecoveryCandidate`](../offline_session/nom_signed_recovery.py) adds
explicit event kinds to the preserved actual POSIX journal. It does not migrate
historical logs. The old writer refuses these new events, and this candidate
refuses an old journal lacking its selected signed context.

1. Retain the exact signed short account bytes and immutable verified fact bytes.
   The selected source context, terms, node hash, SHA-256, entry, caller, contract
   and inner witness must agree. A different raw original cannot replace the
   first selection, even when it has the same node identifier and valid outer
   signature.
2. Admit the complete immutable observation wrapper. It binds both the real
   account identifiers and the explicitly separate synthetic reference
   derivative. The observer examines this exact wrapper; no differently labeled
   reference proof is silently substituted after approval. Send acknowledgement
   alone refuses recovery.
3. Persist the admitted recovery charge before the public adaptor worker enters.
   An interrupted or invalid result leaves UNKNOWN work. Reopen, lookup and a
   repeated call do not grant another recovery attempt.
4. Verify and retain only the recovered public long completion. **The signed
   long account original remains absent**, including across reopen. A completion,
   receipt, source lookup or normalized object cannot manufacture that original.
5. Accept separately supplied, already signed public long bytes only after their
   selected inner witness matches the retained completion. This candidate never
   constructs or signs those account bytes.
6. Persist OUTCOME_UNKNOWN before returning an owned raw original for a handoff.
   Repeated explicit output returns those same bytes and node/SHA-256 bindings.
   It supplies no transport, replacement transaction, automatic retry or chain
   settlement decision.

The source-corpus lookup is a disclosed finite qualification allowlist, not a
general account signature verifier. The observation allowlist is synthetic and
supplies no source authentication, canonicality or finality. This profile selects
the fixed recipient as caller as well; **the core's direct Unlock path is not
generally restricted to that caller**. Relayers, ProxyUnlock and wildcard locks
are outside this selected client profile.

Pair and completion verification calls are separate from the single charged
recovery operation. This journal does not implement an aggregate decoder,
verification-worker or transport resource governor. The selected public worker's
construction, build/loader provenance and execution bounds keep their independent
requirements.

## Actual retention and remaining failures

The candidate retains cooperating POSIX ownership and bounded append semantics.
It additionally checks the complete selected file image before operations and
the expected complete image after append, and fsyncs an admitted reopen before
returning local state. A same-size edit, malformed replay, torn history or lost
append acknowledgement refuses without truncation, reconstruction or repair.
Foreign callbacks cannot reenter the public signed-wire operations.

These checks do not authenticate a callback, contain arbitrary Python code,
guarantee atomic reads against a hostile concurrent writer, establish physical
power-loss durability or protect pathname ancestors. The host, interpreter,
filesystem and selected path remain trusted premises.

Most importantly, a coherent old journal can still lose an earlier recovery
charge. A complete copied owner can also have its own apparent allowance. The
old-restore counterexample remains an explicit successful unsafe control.
An independently provisioned nonrollback authority is still required; a local
fsync or fresh worker invocation cannot fill that gate.

## Qualification and original evidence

The journal fault tests use an explicitly named fixture oracle. They do not
silently substitute for public signature mathematics. Synthetic structured Go
frames exercise fragment boundaries, missing/duplicated outcomes, cross-test
fragments, changed node/leg labels and normalized-original substitutions. Fresh
Go execution is a separate required profile with default vet on the full pinned
source plus the physical probe file.

The actual public-worker scenario uses two journals, a separate invalid-wire
control, public source-corpus values, lost output acknowledgement, reopen,
completion-before-original retention and same-hash replacement refusal. It
requires 19 complete worker calls, one recovery entry/return and two expected
invalid-completion exit-2 refusals. The 79 original journal/request/reply/error/
receipt files remain distinct. The CLI writes an explicit retention manifest and
qualification result, including known partial output when qualification fails.
No directory is recursively packaged and no environment or binary is bundled.

Replace the tokens below with explicitly selected absolute owned paths and
measured values. Scope acquisition, caches and evidence separately before local
execution. The Go profile requires version 1.23.12 and must not silently download
or select another toolchain. The node source can be prepared from the manifest's
exact archive; it is not a running node.

```text
python3 -B scripts/prepare_nom_signed_originals.py --archive CORE_ARCHIVE --destination NEW_CORE_SOURCE
python3 -B scripts/qualify_nom_signed_originals.py --checkout NEW_CORE_SOURCE --go GO_EXECUTABLE --evidence EMPTY_SOURCE_EVIDENCE
python3 -B scripts/qualify_nom_signed_recovery.py --executable PUBLIC_WORKER --expect-executable-sha256 EXPECTED_SHA256 --evidence EMPTY_JOURNAL_EVIDENCE
```

An optional `--subject-commit` binds each selected current source file to that
Git commit. Uncommitted local qualification must omit this publication claim.
Hosted PR and later push/main acceptance require their own exact source, complete
original console and original artifact metadata/bytes. Local tests, a manifest
and a passing source profile do not substitute for those runs or independent
protocol, custody, signer, observation and operational assessment. All seven
service acceptance gates remain unfilled.
