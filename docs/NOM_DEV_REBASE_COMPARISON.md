# Pinned dev rebase comparison

Status: **AUTHOR-SELECTED OFFLINE COMPARISON. Independent assessment UNFILLED.**
Application/core remain **NO-GO**, recovery **NONE**. This is a separate source
and comparison subject; historical fixtures, qualifiers, reports and synthetic
recovery journals remain unchanged.

## Source and producer inputs

The [selection](../compatibility/nom_dev_rebase_manifest.json) pins go-zenon
[`c25a596436432a544325a4b2ebb0257012d04fa1`](https://github.com/zenon-network/go-zenon/tree/c25a596436432a544325a4b2ebb0257012d04fa1),
tree `7803fd4673c097439a68072791a2bc2ccda8eb6c`, with all 441 regular source
files. Its canonical source index SHA-256 is
`37eb2024567fb683d8b34acde3635e000bd28f1ba534be9d67e41eec82d2baef`.
The independently written native producer inputs remain the 133 files measured
at research commit `02a258792a9dcf198e7349d0b517e3c69d16566b`, with canonical
index SHA-256 `68d7054d74256fca81ed36feaa6c4035770b64f0a1b366bbdd70148c0a0ffb4c`.
The selected old fixtures retain their original PR #138 source and behavior.

The new dev source is eleven commits ahead of previously compared
`0df0c3e25a3286fd53906730106bbf39513ee304`. Its
[account-pool rebuild](https://github.com/zenon-network/go-zenon/blob/c25a596436432a544325a4b2ebb0257012d04fa1/chain/account_pool.go)
uses the new
[versioned-manager Rebase](https://github.com/zenon-network/go-zenon/blob/c25a596436432a544325a4b2ebb0257012d04fa1/common/db/versioned_db.go).
Pop also removes intermediate versions sharing the popped batch head's database.
This source is obtained separately under GPL-3.0. No node implementation is
copied into this MIT research workspace. Source and index identity do not
authenticate a producer, dependency closure, loaded runtime or canonical chain.

## Two explicit changes

The new [pure reader](../scripts/compare_nom_dev_rebase.py) derives expectations
from the frozen public inputs, rather than from the observed output. It compares
the complete actual records against those separate expectations with strict
types, keys, list membership and values. It never alters an observed record or
fills a missing original.

| Profile | Selected c25 behavior | Preserved comparison |
| --- | --- | --- |
| Account pool, two cases | Four child aliases of removed parent batches become absent: no frontier, patch or logical state. Sixteen scalar fields change. | Aliases of retained parents, pending originals, all account/contract states, admission results and every other record field stay exact. |
| Dependent eviction, three cases | Seven surviving prefix views retain the exact patch captured at original admission. The old extra three frontier writes are absent after Rebase. Seven patch fields change. | Every original wire, signature, admission trace, stable/pending checkpoint, eviction, frontier and logical state stays exact. |

For the first row, the expectation selects only child identifiers recorded at
admission whose parent original is absent from the retained pending set. For the
second, it selects retained prefix views and requires the original trace patch;
the earlier fixture must contain exactly that patch plus its repeated frontier
writes. All other bytes and fields remain part of the comparison. There is no
general alias deletion, patch normalization, acceptable-difference wildcard or
conversion of historical records into current evidence.

The old profile intentionally requires the old aliases and rebuilt patches.
Both historical validators still reject the c25 records. They are not weakened,
repinned or assigned a retroactive pass. These source observations do not assert
an application vulnerability, complete correctness of Rebase or recovery safety.

## Original execution and reader evidence

The initial c25 comparison stopped at the account-pool mismatch. Its native
commands had zero exits; the semantic comparison failed, and the failed attempt
remains retained. A separate diagnostic run completed the native commands and
recorded **NOT_QUALIFIED_HISTORICAL_DIFFERENCES** for two profiles. It did not
convert a command exit or observation-task success into compatibility acceptance.

That diagnostic executed 342 stateful test/subtest outcomes, including parents.
The unchanged historical comparisons matched 335 outcomes. The remaining seven
outcomes belong to these two profiles and require this separately selected
comparison. Original records differ in exactly the 23 fields above. The same
run separately reproduced 48 messages, 26 witnesses, 15 destination cases, two
completed witnesses and 45 ABI/hash outcomes including their parent.

The exact existing upstream test file was also executed against the c25 source:
eleven vector cases plus their parent, and twenty outcomes in the full definition
package, with normal default vet. The targeted outcomes overlap the package run;
they must not be added together. These are local source/toolchain observations,
not target-repository hosted CI or independent-machine qualification. New reader
and whole-workspace regression results are separate acceptance steps.

## Offline reproduction of the selected comparison

Acquire the immutable source independently and preserve the original native
JSONL from the selected account-pool and dependency producers. Retain the actual
command exits, completeness, tools and source pins separately. Then run:

```sh
python3 -B scripts/compare_nom_dev_rebase.py \
  --core-source CORE_SOURCE \
  --expect-core-commit c25a596436432a544325a4b2ebb0257012d04fa1 \
  --expect-source-index-sha256 37eb2024567fb683d8b34acde3635e000bd28f1ba534be9d67e41eec82d2baef \
  --account-pool-jsonl ACCOUNT_POOL_JSONL \
  --pool-dependencies-jsonl POOL_DEPENDENCIES_JSONL
```

This reader starts no compiler, subprocess, network request or native test. Its
source check compares complete content against Git blob and SHA-256 pins; it
does not attest filesystem executable modes. Root Git metadata is excluded.
Other unexpected entries, missing files, links and changed content refuse.
Individual source/profile files are bounded at 8 MiB, each complete inventory at
40 MiB, the manifest at 1 MiB and native streams at 16 MiB. The earlier 4/8 MiB
per-record bounds remain. These are trusted-host application checks, not a
hostile-parser sandbox or operating-system memory quota.

Go pass labels and supplied records are claims until bound to independently
retained actual execution. The reader authenticates no producer or chain. Its
unit streams are explicitly synthetic framing controls. A passing comparison
grants no current-state observation, original-byte custody, journal admission,
re-signing, replacement, private signing, deployment, node activation, broadcast,
controlled network composition or funds. All independent NoM and service gates
remain unfilled. The [separate review subject](NOM_RECOVERY_DELTA_REVIEW.md)
keeps its fixed source; this later reader/manifest/packaging needs its own review.
