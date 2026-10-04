# Governor provenance and current-policy comparison

Status: **Stage 36 pure finite offline model. Root trust, complete assignment
and intent signature validity, and current authority are environmental premises.
No certificate, provisioning mechanism, new signed wire, registry or worker
admission is implemented.**

The [local governor profile](LOCAL_GOVERNOR_PROFILE.md) makes selected rules
explicit but does not establish their provenance or current status. This model
compares those separate obligations before choosing another credential format
or enrollment backend. It imports only the Python standard library and leaves
every existing application helper, worker, message and journal unchanged.

## Requirements versus modeling hypothesis

A future construction must establish authorized role/scope, bind any required
policy version and reject superseded or revoked authority at its chosen
authorization instant. Independently selecting a key is insufficient unless the
selection also establishes those facts. A mathematical signature cannot supply
the provenance or freshness of the selected expectations.

For this comparison only, a hypothetical trusted root issues complete immutable
profile assignments. The environment independently supplies whether assignment
and intent signatures are valid under their respective keys. These facts are
not peer Booleans, application verification results or modeled private signing.
An assignment from another root can be mathematically valid without being trusted.
Direct independently authenticated provisioning could be another construction;
this model does not select certificates as the universal required mechanism.

The stronger policies additionally assume an intent that binds the full selected
profile. This is **hypothetical**: the unchanged Stage 32 eight-field intent does
not commit the Stage 35 profile digest. Rejecting a modeled unbound proposal says
nothing about the mathematical validity of an existing v1 signature. No new
message domain, migration or cross-language signature fixture is introduced.

## Fixed domain and independent current world

There are two caller copies, seven immutable profile symbols and twelve fixed
proposals. Profile symbols stand for complete content, not hashes computed here.
The protected scope is synthetic resource zero, namespace zero and governor
role zero. Other resource, namespace and role profiles are separate controls,
not application packets that pass an independently selected expected codec.

The first profile uses owner zero and caps two. The second keeps that key and
the opaque authority label but changes both caps to three. The third rotates
to owner one. Other profiles test a peer root and another resource, namespace
or role. Proposals include legacy unbound intents, correctly bound hypothetical
intents, a swapped profile and independently invalid signature facts. All
proposals fit their modeled caps; actual allocation and requested limits are
outside this experiment.

The trusted world advances monotonically through four phases: initial profile,
updated policy, rotated key and revocation. This phase is the auditor's independent
environmental state, **not an authenticated wire epoch, clock or implemented
latest-state service**. The protected resource ID is a fixed semantic assumption,
not authenticated economic/source equivalence or a new journal field.

Each caller selects/checks one proposal and attempts one abstract use. Environment
updates can occur between those events. The audit retains the world phase at
each use; later rotation/revocation does not retroactively invalidate a previously
allowed instant. Both callers can select and admit the same packet. No allowance,
enrollment ID, replay defense, registry or dispatcher follows from this decision.

## Seven policies

| Policy | Selected check | Remaining modeled failure |
| --- | --- | --- |
| `self-selected` | Intent signature fact alone | Peer-root assignment, wrong scope/role, unbound intent and superseded/revoked authority can admit |
| `anchored-key` | Also require the independently pinned initial owner key | Resource/namespace/role and assignment provenance remain unchecked; rotation and revocation remain unsafe |
| `scoped-role` | Valid assignment under the trusted root and exact protected scope/role | Intent need not bind the complete profile; a correctly issued old assignment remains replayable |
| `profile-bound` | Also bind the intent to the exact complete profile symbol | Static signatures and binding still establish no current authority |
| `checked-current` | Also check the trusted world's current profile when the caller prepares | A cached positive can admit after policy change, rotation or revocation; a cached negative can refuse a newly valid proposal |
| `atomic-current` | Recheck trusted current authority at the abstract use instant | Conditional authorization holds in this domain; repeated packet admission and all real provisioning/actuation obligations remain |
| `rollbackable-current` | Same use-time rule but read a coherently restorable local current view | Restoring the initial key/profile/view permits old proposals after update, rotation or revocation |

Only the last policy permits one local anchor restore and one later refresh.
Restoring the local view never rewinds the independent trusted world or audit.
Refresh is another ideal external event, not implemented authenticated I/O,
guaranteed delivery or eventual availability. The strongest policy forbids local
restore by premise; its `State` class is no real anti-rollback protection.

## Executed finite comparison

All seven default command-line searches completed. Each caller checks/uses at
most once; at most three trusted-world advances, one permitted local restore
and one permitted refresh give a finite graph. Rejected use consumes the caller's
single modeled decision, not any application quota. The default search cap is
250,000 states; reaching a cap returns `incomplete` and exit two, never a safety
or absence-of-counterexamples result.

| Policy | Reachable states | Transitions | Safety finding classes |
| --- | ---: | ---: | ---: |
| `self-selected` | 8,116 | 12,651 | 8 |
| `anchored-key` | 8,116 | 12,651 | 8 |
| `scoped-role` | 8,116 | 12,651 | 4 |
| `profile-bound` | 8,116 | 12,651 | 3 |
| `checked-current` | 44,788 | 52,563 | 3 |
| `atomic-current` | 8,116 | 12,651 | 0 |
| `rollbackable-current` | 41,242 | 72,325 | 3 |

The total is 126,610 states and 188,143 transitions across these separate policy
graphs. Zero findings for `atomic-current` are conditional on ideal trusted
inputs and an indivisible current check at use. They prove no unbounded safety,
native transaction, chain freshness, credential system or funded recovery.
Every policy includes a repeated-packet admission witness; authorization does
not imply registration uniqueness or idempotency. [Validation](STAGE36_VALIDATION.md)
records executed commands and separates new evidence from historical CI.

```sh
python3 -B scripts/model_governor_authority.py --policy atomic-current
python3 -B scripts/model_governor_authority.py --policy checked-current
python3 -B scripts/model_governor_authority.py --policy rollbackable-current
python3 -B scripts/model_governor_authority.py --max-states 1
python3 -B -m unittest discover -s tests -p test_governor_authority_model.py -v
```

The [standalone model](../scripts/model_governor_authority.py) follows the internal
MIT finite-comparison style of the unchanged
[enrollment model at the parent](https://github.com/edgepillar/ptlc-research/blob/1c44c8b834b4c3032ae5362bca6f98fb977a2856/scripts/model_observation_enrollment.py).
No external implementation or dependency is copied. The
[24 unit methods](../tests/test_governor_authority_model.py) replay every returned
witness through validated transitions and cover bad types, bound exhaustion,
no retroactive judgment, conditional current checking and replay boundaries.
The fixed 119-file and 189-file subjects and their unfilled reports remain
unchanged. This exact later model requires separate assessment.

## Next construction gates

Specify independently authenticated governor provisioning and role/scope
evidence, complete policy binding without self-reference, rotation/revocation
and the exact authorization instant. Choose how a caller establishes trustworthy
current state and what happens on outage, stale information, compromise or
coherent restore. Model root compromise/rotation, additional updates, source
equivalence and a public-witness recovery path separately; they are outside this
domain. Then qualify any selected wire and actual signature verifier without
silently changing the existing intent or allocating quota.

Enrollment still requires canonical source/economic identity, first-registration
capture rules, atomic uniqueness, non-rollbackable charged lineage, scoped
idempotency, bounded verification work and trusted unique dispatch. Neither a
certificate nor a use-time Boolean implements those mechanisms.

**GO:** further offline credential and current-authority contract qualification.
**NO-GO:** use the model transition as application admission, claim real bootstrap
or restore defense, connect a registry/dispatcher, integrate private signing,
port current-node consensus rules or use real funds.
