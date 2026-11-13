# Complete history validation within each invocation

History discovery validates the complete retained lineage in one fresh recursive
checkpoint walk per invocation. That walk collects root-to-head snapshots while
checking every selected context, retained capsule and journal continuation.
Discovery uses those snapshots to build the history, and queries use the already
computed head fields. It does not reopen every ancestor separately or repeat the
walk to derive the same query head.

Every later history or public query invocation performs validation again. No
reference, query, process or filesystem cache is introduced. Recursive type, cycle
and checkpoint bounds remain enforced, and discovery checks the collected history
limit before framing it. This does not establish an atomic snapshot against
concurrent mutation or hostile class edits. The returned
history remains a fresh value, with no authority to restore absent originals,
reset UNKNOWN work or enter recovery.

The [frozen reference function](../compatibility/fixtures/nom_checkpoint_history_reference.py.txt)
is copied exactly from `_history` at the public
[`b74bd41` source](https://github.com/edgepillar/ptlc-research/blob/b74bd411750b579a549b98435e05dfdaa8e5b67f/offline_session/nom_checkpoint_discovery.py).
Its SHA-256 is
`2d0bb5c441c8d315660a7327bf572c8eeaa66771be13337f3eab349e8c64c039`.
It is original project code under the repository MIT license, not an independent
implementation or security assessment.

Four methods check every selected context on each invocation, five selected
histories, later success/refusal/restoration, ancestor claim mutation, reused
public queries and isolated returned values. One method compares 35 finite values or exact refusal
classes and messages with the frozen function while prohibiting file operations
and subprocess entry. These observations are not a general equivalence proof.

The seven dependent qualification manifests bind the changed runtime source and
their preceding manifests with updated SHA-256 values. Their complete input
sets, corpus values and NO-GO boundaries remain selected; input verification
still refuses any unexpected source change.

No journal operation, file boundary, public worker execution or effectful
qualification is replaced by a cached result. The change supplies no service
authentication, nonrollback storage, custody permission or chain observation.
All existing HOLD and recovery NONE boundaries remain selected.

Current-source full regression, artifact/disclosure checks, hosted PR acceptance
and later push/main acceptance remain separate requirements. A method-call
reduction does not establish a complete-suite or production speedup. Independent
assessment and AS1-AS7 remain UNFILLED; application/core remain NO-GO. No
deployment, activation, wallet, application signing, broadcast or real funds are
connected.
