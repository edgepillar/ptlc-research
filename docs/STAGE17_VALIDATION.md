# Stage 17 validation: exact observation evidence and claims

Scope: implement a pure candidate/session binding and a strict mathematical
statement codec before selecting a source, verifier producer or cache policy.
Source parent: `c90f7e2318372a3f6416e50d7c1d6bde82828214`.

The existing candidate/lifecycle/journal code, all three recovery models,
cryptographic fixtures/dependencies, actual-worker qualifiers and frozen review
manifest are unchanged. The Python CI job limit increases from 15 to 20 minutes
for the growing full suite; commands, matrix and required checks are unchanged.
The new module invokes none of the
workers and grants no authority, mathematical truth or recovery admission.

## Executed checks

| Check | Result | Boundary |
| --- | --- | --- |
| Initial evidence suite | 26 passed in 46.719 seconds | Before early rejection of malformed claims |
| Final focused evidence suite | 26 passed in 35.646 seconds | Includes cheap syntax rejection before local target derivation |
| Required full offline Python suite | 396 passed in 471.894 seconds, no skips | Prior 370 tests plus 26 new tests |
| Artifact, Markdown links and whitespace | Passed; 350 local links resolve | Disclosure/consistency checks, not proof of anonymity or cryptographic security |

Both focused runs passed with no failed or skipped cases. The runs cover the
same 26 tests and are repeated evidence, not 52 unique cases. The parser was
changed after the initial run to reject malformed claims before reconstructing
public state; the final run verifies that rejection invokes no target builder.

## Covered behavior

- Independent reconstruction of the exact packet, both request digests, binding
  digest and profile-separated key using explicit domain bytes and canonical JSON.
- Identical signature bytes cannot transfer a claim across sessions, terms or
  nonce rounds. Changed Zenon bundles separate identical candidate packets;
  changed Bitcoin bundles separate identical Zenon-only predicate requests.
- Exact targets remain stable when another candidate is retained or the same
  candidate is observed, without authorizing a later comparison or replacement.
- All three explicit outcomes are parsed as claims only. A forged positive
  statement for invalid fixture bytes parses, demonstrating the external trust
  obligation rather than claiming a cryptographic verifier.
- Legacy positive/negative result schemas cannot be mistaken for new statements.
  Unknown encoding accepts no exception text, worker payload or reason field.
- Each fixed field, changed profile, different signature, extra authority/source
  field, missing field, invalid outcome, duplicate key, alternate encoding,
  oversized input and unsupported/custom type is rejected.
- Public target/statement fields are immutable. Hostile input subclasses execute
  no custom conversion/equality/copy methods. Malformed state remains unchanged.
- Preparing and parsing all claim outcomes after journal reopen and recovery
  exhaustion preserves the database, checkpoint, sequence, retained observation
  and consumed allowance exactly. A forged positive cannot bypass exhaustion,
  invoke recovery or replace/archive the original candidate.

These are offline data/lifecycle tests. The fixture callbacks that construct
the source snapshots and synthetic statements do not verify cryptography.
There is no actual-worker qualification of a normal-negative producer: none is
implemented. Existing actual workers cannot supply that distinction.

## Independent execution and limits

The focused and full runs used Python 3.9.6 on macOS with OpenSSL 3.6.3. Required full validation used
`REQUIRE_OPENSSL=1 python3 -B -m unittest discover -s tests -q`; artifact checks use
`python3 -B scripts/check_artifacts.py`.

The previous Stage 16 hosted Python 3.13 Ubuntu job took 13 minutes 9 seconds
in run `37170834333`. The new focused suite adds work to the full matrix; its
job limit is extended to 20 minutes to preserve headroom without dropping tests
or independent required verification. The locally executed code is unchanged
by that workflow deadline adjustment.

Unchanged Rust/Go suites and actual subprocess qualifiers are not independently
rerun locally for this pure data-contract change; existing hosted CI runs them.
A hosted green result for those earlier integrations does not qualify a new
statement producer, which is absent. External construction/contract assessment
and delta review remain pending.

The [contract](OBSERVATION_EVIDENCE_CONTRACT.md) separates required trusted
producer behavior from the selected binding/codec and these observed tests.
Profile provisioning, source authority, durable cache policy, aggregate resources,
restored-copy protection, actual chain evidence and funded acceptance remain
open. Live swaps, private signing and a core port remain no-go.
