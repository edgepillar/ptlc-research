# Pinned unsigned RPC quote corpus

Status: **offline source qualification candidate; application/core NO-GO**.
This is author development and comparison, not independent security assessment.
No wallet, signer, network RPC, node activation, transaction broadcast or funds
are selected. All seven service acceptance gates remain unfilled.

## Selected source and observations

The [manifest](../compatibility/nom_rpc_quotes_manifest.json) selects
[go-zenon `b5f93c20c15b0622bc8ed1a175b613d6917be3b2`](https://github.com/zenon-network/go-zenon/tree/b5f93c20c15b0622bc8ed1a175b613d6917be3b2)
and complete 443-file Git tree `d9083d4b7aa7b13d6dee68b09d82c11b662be1a4`.
The archive is selected through its immutable API zipball endpoint, byte count,
SHA-256, complete per-file SHA-256/Git-blob inventory and reconstructed Git tree.
It is separately obtained GPL version 3 source; see [notice](NOM_RPC_QUOTES_NOTICE.md).
No upstream implementation or test helper is vendored.

Three original project probes are added to a new source directory, producing
446 selected files. The two unchanged public signed Unlock originals are read
from the existing corpus. Twenty-four transaction-helper records must remain
identical to that frozen benchmark. Twelve accepted and twelve selected refused
variants are transaction-only source behavior, not complete block admission.

The quote probes retain 30 records: 13 ordinary-address handler calls, one
separate typed-zero serialization and 16 PTLC Unlock handler calls across both
legs. Their source-test stores explicitly supply synthetic feature flags,
fusion amounts, zero committed/uncommitted Plasma and selected frontier prices.
They do not authenticate a chain state, frontier, balance or spork activation.
The PTLC probe selects PTLC availability only inside those synthetic stores;
no global spork state is mutated.

`requiredFusedPlasma` is the **total fused-only payment target**. It is an
alternative to the PoW recommendation using available fusion, not an extra
fusion amount to attach to that recommendation. A separate Python integer
model compares ceiling operations, partial fusion, no fusion, legacy behavior
and the first-v2 boundary. The PTLC inputs bind the exact selected public wire
digest, node identifier, caller, contract and Unlock data. Their selected base
cost is 73500, matching the frozen VM-cost benchmark; ordinary-address examples
use different costs. This finite model is not a general quote client, resource
governor or arbitrary-price/stake policy.

The retained JSON bytes come from the selected Go result type's marshal method.
They are **not captured HTTP responses** or replacement signed account bytes.
The typed-zero case tests serialization only and is not a successful RPC call.
Quotes for hypothetical price contexts do not establish that an older signed
original is admissible there. No original, fee, witness, context or recovery
allowance is rewritten. Existing journal and source profiles retain their old
immutable selections; this profile performs no journal source upgrade.

## Reproduction and original evidence

Admission, archive transport, source/cache ownership and dependency acquisition
are separate caller responsibilities. Select new bounded private storage first.
The destination must be absent and the evidence directory private, mode 0700
and empty. Use the already selected Go 1.23.12 executable and its measured
SHA-256. The native command permits only an offline cache or an explicitly
selected local file proxy; it does not acquire modules from network proxies.

```text
python3 -B scripts/prepare_nom_rpc_quotes.py --archive SELECTED_ARCHIVE --destination NEW_SOURCE
python3 -B scripts/qualify_nom_rpc_quotes.py --checkout NEW_SOURCE --go SELECTED_GO --expect-go-sha256 GO_SHA256 --evidence EMPTY_PRIVATE_EVIDENCE
python3 -B scripts/qualify_nom_rpc_quotes.py --evidence RETAINED_EVIDENCE --artifact-files
```

The source qualifier requires 71 actual Go test/subtest outcomes: 25 original
transaction-helper outcomes, 15 generic/typed-zero quote outcomes, 17 PTLC quote
outcomes and 14 selected existing upstream RPC outcomes. All four test commands
use default vet and disable the test-result cache. Exact source inputs are
checked before imports/execution and after execution. Python optimization
refuses at the CLI entry before source, evidence or compiler access.

Thirteen explicit files retain source selection, five original stdout/stderr
pairs, result and retention manifest. No binary, environment dump or recursive
directory archive is selected. Known failed or incomplete output can be listed
with `--artifact-files --allow-incomplete-for-retention`; this never grants a
successful comparison or reruns a command. Over-limit collection retains a
bounded original prefix with incomplete status. Unknown files remain outside
selection and must be preserved separately. Privacy refusal is not permission
to normalize, discard or repair the originals.

An optional `--subject-commit` binds the selected project files to that immutable
Git subject. A manifest, digest or compiler hash is selection/content evidence,
not producer, loader or dependency authentication. Collection trusts the
compiler and uses post-collection stream limits; it is not an OS allocation or
hostile-process sandbox and makes no independent descendant-containment claim.
The host, interpreter, path ancestors and filesystem remain trusted premises.

Fresh local CLI qualification, complete regression, artifact checks, exact-head
hosted PR acceptance and the later distinct push/main acceptance are separate
gates. None fills independent protocol, custody, observation, signer or service
assessment. Preparing this source/corpus does not grant application operation.
