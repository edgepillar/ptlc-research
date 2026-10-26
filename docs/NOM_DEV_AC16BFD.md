# Source and runtime comparison at ac16bfd

Status: additive source selection, reference expectations and runtime readers.
Native execution, complete original-output retention, hosted PR acceptance and
the subsequent main push acceptance are separate gates. A declared test plan or
manufactured reader control satisfies none of those execution gates.
Application and core remain **NO-GO**, recovery action is **NONE** and independent
assessment remains **UNFILLED**.

## Immutable source and retained history

The input is go-zenon
[`ac16bfd7c083e0b808a17014c38a5a77cc0141f1`](https://github.com/zenon-network/go-zenon/tree/ac16bfd7c083e0b808a17014c38a5a77cc0141f1),
Git tree `6706aeccac61c64f2497a53a526623473bb6e46a`.
The [inventory](../compatibility/nom_dev_ac16bfd_source_v1.json) binds all 514
files by byte count, SHA-256, Git blob and logical mode. Its SHA-256 is
`4622893952d3ffc0a3944c9543ac909ec4d20e71fabcba62d411de4b6b9ae85f`.

Against [5a2593](NOM_DEV_5A2593.md), 14 files are added, 31 change and 469 remain
byte-identical. No file is removed. All eighteen selected PTLC files, `LICENSE`,
`go.mod` and `go.sum` are byte-identical. Dependency and lifecycle changes still
require a new execution: earlier PTLC results do not establish current behavior.
The separately acquired upstream GPL version 3 implementation is neither
vendored nor relicensed. Historical inventories, producers, fixtures, original
evidence and recovery-journal pins remain intact.

The target includes the merged
[library lifecycle change](https://github.com/zenon-network/go-zenon/pull/212),
[decoder path tests](https://github.com/zenon-network/go-zenon/pull/219) and
[request budgets](https://github.com/zenon-network/go-zenon/pull/220).
Changes to database/cache closure and spork tombstone handling are included in
the complete source inventory. A source commit or merged PR is not deployment,
activation, canonical observation or durable recovery evidence.

## Independent reference values and upstream runtime assertions

The [combined selection](../compatibility/nom_dev_ac16bfd_manifest.json) retains
twenty legacy profiles and one reclaim profile: 479 historical outcomes plus
77 reclaim outcomes, including each selected parent. Their 556 outcomes retain
the prior independent expectations; newly observed Go output cannot replace
them. The four legacy source-label descendants have exact textual inverses to
their historical originals. Reclaim expectations retain the earlier values.

The separate [runtime selection](../compatibility/nom_dev_ac16bfd_runtime_v1.json)
adds no project Go producer and selects these upstream test functions:

| Profile | Required top-level functions | Selected behavior |
| --- | ---: | --- |
| Manager guards | 3 | Already-running refusal, pointer retention and bare-manager stop |
| Node stop | 3 | Stop-step execution, joined errors and cleanup after core-stop failure |
| Spork tombstone | 1 | Deleted entries are omitted from the spork list |
| Decoder limits | 8 | Error paths, round trips and recursive decoder limits |
| Database closure | 6 | Idempotence, failed close, frontier recheck and concurrent add/stop |
| Cache closure | 4 | Stop handling and corrupt or unreadable frontier refusal |
| Request budgets | 27 | Shared charging, pacing, refill, reply limits and abandoned waits |

These 52 functions are upstream implementation assertions, not independent PTLC
value calculations or independent protocol review. Readers require every
declared top-level test, matching package and valid event lifecycle, with all
observed descendants closed successfully. The descendant count is observed;
it is not a separately enumerated expected case count. Failures, skips, missing
tests, foreign tests, malformed events and incomplete output are refused.
Reader success establishes neither actual command exit nor execution origin.

The manager selection avoids node constructors and the real-node-start test
`TestRunWithConfig_StartDoesNotBlock`. Node-stop tests use stub core and network
components, temporary local locks and ephemeral loopback HTTP listeners.
Request-budget tests use synthetic peers, message pipes and clocks. These
fixtures do not operate a node, access a wallet or contact a chain. This
selection does not qualify real node startup, RPC draining, cancellation,
bounded shutdown under arbitrary conditions or real sequencer scheduling.

## One workspace, explicit original streams

The selected source view has 514 upstream files, 21 reference producers and three test logging
initializers, 538 files in total. Twenty-eight profiles share one source view, one compiler
cache and one cold-build command over their complete package set. Default vet
remains enabled and test result caching is disabled by `-count=1`.
The 32 required actual Go commands comprise the 28 profiles, Go version,
cold build, upstream-definition test and module verification. All 56 original
profile streams must be retained and compared; receipts, completeness and
actual exits remain separate obligations.

The existing `nom-current-core` job selects this source instead of adding a
second current-source build. Historical CI selections remain unchanged. The
bootstrap dependency copy may acquire additional canonical checksums only
while preserving every original checksum and exact requirements. The source
module files remain byte-identical. This input check does not authenticate
the compiler, SDK or dependency transport.

Private native qualification must preserve failed or interrupted attempts,
original streams and source/tool/run pins before retiring owned reproducible
scratch. Public artifact selection must check exact completeness and privacy;
it cannot silently replace original output with a sanitized transcript.

One exact upstream Protobuf corruption diagnostic can contain a nonbreaking
space after `proto:`. The current-source checker permits that character only
in the complete structured Go output event for
`TestGetFrontierIdentifierCorrupted` in the selected cache-storage package, with
the fixed English error text. Duplicate keys, unexpected fields, other Unicode,
private paths, hostnames and credentials remain refused. A temporary ASCII audit
view is used only for inspection; original UTF-8 or escaped bytes and their
digests remain unchanged. This exception establishes no execution origin.

## Explicit diagnostic profile

Three inventoried test-only initializers in node, cache storage and protocol
configure the log15 root handler to discard structured diagnostics before tests.
They do not redirect Go framework streams, alter assertions or replace retained
output. The selected upstream functions and their failure/skip checks remain
unchanged. These fixtures qualify their explicit logging configuration, rather
than the default diagnostic handler.

The Go compiler profile sets `GOFLAGS=-trimpath` before compilation. A selected
corrupt-frontier test intentionally prints a recovered panic stack. Trimming
source paths at build time prevents that stack from exposing the local compiler
or workspace location. The original framework output remains intact; no stack
is filtered or rewritten after capture. The native report and retention reader
bind this explicit source-path profile. A run built without this setting cannot
qualify the changed profile.

With an explicitly selected Darwin SDK, the compiler environment retains Go's
`-O2 -g` defaults and adds `-Wno-deprecated-declarations`. This named diagnostic
category can otherwise emit an SDK include path through IOKit deprecation notes.
Other compiler diagnostics and failures remain captured. The native report binds
the selected diagnostic profile. SDK and transitive compiler authentication
remain unfilled. Linux retains the default Go C compiler flags.

The earlier author execution completed the selected tests but its export was
refused for private diagnostics. Its original source, streams, failure status and
evidence remain retained privately. They are not rewritten or promoted into
acceptance of this changed source. Fresh qualification is required.

## Remaining recovery obligations

The recovery journal deliberately retains its existing source context. Neither
an unchanged PTLC file nor this runtime selection authorizes its upgrade.
Further work must establish coherent entry/lock and price observations, dropped
event and rollback handling, exact signed-account custody, outer admission,
chain insertion, canonicality and recipient credit under the intended session
and recovery protocol. Reclaim-key reuse remains prohibited by the research
protocol even where the node permits a later same-terms entry.

Independent review must assess the whole protocol and recovery assumptions.
An author review, extra tests or a green hosted run cannot fill that role.
Bitcoin construction, adaptor signing, transport and durable client recovery
remain outside the core node contribution. No deployment or live-chain action
is authorized by this corpus.
