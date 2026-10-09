# Stage 111 constructor path and provisioning boundaries

FINAL-SOURCE LOCAL REGRESSION PASSES; FRESH HOSTED QUALIFICATION PENDING AT THIS SNAPSHOT.

Parent `41f83c46b693003f4c84ec1dd4da5e0f79245a44`, tree
`d93505337b4c7d079f7612ca703b3148cd624f94`, pins the preceding source. All
327 preceding sources, actor, store, observer, classifiers and strict tests
remain byte exact. One new test source adds fourteen disjoint methods. No
external code is copied. Application, core, allocation and retry behavior
remain unchanged.

Each test seeds one original charge, sequence 1, with no effect. Forwarding
hooks execute the real constructor, pathlib methods except at an explicit
selection, native SQLite connect, exclusive file open and descriptor close.
There are five actual native failure cases and nine synthetic selections.
Eight cases enter the original actor and six enter direct valid-profile
provisioning. The actor accepts no initial provisioning profile.

| Boundary | Cases | Outward result | Disposal / SQLite connect / file open / file close |
| --- | --- | --- | --- |
| Selected absolute conversion EIO/cancellation | 2 actor | Exact primary, no context | 0 / 0 / 0 / 0 |
| Selected symlink inspection EIO/cancellation | 2 actor | Exact primary, no context | 0 / 0 / 0 / 0 |
| Selected URI EIO/cancellation | 2 actor | Suppressed-primary unknown / exact cancellation | 1 / 0 / 0 / 0 |
| Native directory / regular-parent SQLite open | 2 actor | Suppressed-native unknown; primary CANTOPEN | 1 / 1 / 0 / 0 |
| Native existing source / directory provisioning | 2 direct | Suppressed-native unknown; EEXIST | 1 / 0 / 1 / 0 |
| Native regular-parent provisioning | 1 direct | Suppressed-native unknown; ENOTDIR | 1 / 0 / 1 / 0 |
| Selected EIO after successful native descriptor close | 1 direct | Suppressed-primary unknown; empty reservation | 1 / 0 / 1 / 1 |
| Selected URI EIO/cancellation after native provisioning | 2 direct | Suppressed-primary unknown / exact cancellation; empty reservation | 1 / 0 / 1 / 1 |

All cases have initialized owner/label/busy/closed/database fields, no SQLite
handle, false busy and no constructor return, allocation or public close.
Four pre-guard cases have no disposal and false closed; ten later cases have
one disposal and true closed. Exact primary identity, explicit cause, context
and suppression are checked separately. Native SQLite primary code is tested
without requiring an identical extended code across runtimes. Only actor cases
claim empty actor output and absent observer installation; process status is
unavailable. No context or private flag establishes delivered diagnostics.

Native provisioning failures preserve existing bytes and entries. Three
post-provision selections retain exactly one new empty file, mode 0600. Each
descriptor was closed successfully before the selection; fstat independently
reports EBADF before state readback. This is not a natural close-failure test.
Cleanup tracks still-owned descriptors without repeating successful closes.
The reservation remains through verification; it is not an initialized database
or authorization for another provisioning attempt.

Every case checks unchanged original bytes and the exact expected entries
before complete local/reopened readback. Both reads agree: one raw operation,
one retained complete original, charge sequence 1, no effect sequence, one
charged operation, zero effects and event sequence 1. No duplicate or replacement
operation is allocated, including where a separate empty file was created.

Six prior local exploratory executions pass on Python 3.12.14 / SQLite 3.53.1,
with the existing original preserved. Five informed selected native cases;
one overlong-component observation is excluded from matrix qualification.
The first focused candidate passes fourteen methods in 0.059 s (runner
0.174 s). Its successful source/log/result are preserved. A descriptor-ownership
review narrows fixture cleanup; the final focused source passes fourteen
methods in 0.052 s (runner 0.164 s). Both runs have no failures, skips or
ResourceWarnings. Complete final-source regression is recorded below; source preservation and
artifact hygiene remain separate gates.

The [scope note](POLICY_EFFECT_CONTENTION.md#constructor-path-and-provisioning-boundaries)
excludes arbitrary paths, native overlong-component matrix behavior, descriptor
and symlink races, natural close failures, signals, child status, authenticated
delivery, restored copies and physical durability. No observation authorizes
replacement, retry, refund, signing, nonce allocation or a physical effect.

Stage 99's original failure cause remains UNRESOLVED. SC01-SC12 remain OPEN;
physical F1-F4/future A01-A12 remain NOT EXECUTED. Signer, custody,
current-policy ownership and a nonrollback anchor remain UNSELECTED /
NOT IMPLEMENTED. Independent assessment is absent. Application/core remain
NO-GO; this is offline synthetic research.

One complete run on frozen final sources passes 2185 exact unique methods in
945.274 s (runner 945.73 s), required OpenSSL,
no skips, failures or ResourceWarnings. All 2171 preceding IDs and 327 sources
remain exact; fourteen disjoint methods give 328 frozen sources. Two document
modifications and two additions give 557 files, with 553 of 555 preceding files
exact. Both focused versions passed; the source review and local exploration
remain separately recorded. There is no final-source full-regression or hosted
workflow retry, qualification or preparatory failure at this snapshot. Full
Rust/Go/Linux/Apple profiles were not rerun locally; fresh hosted execution and
independent assessment remain separate. Earlier failed sources, logs and
original archives remain preserved without cleanup.
