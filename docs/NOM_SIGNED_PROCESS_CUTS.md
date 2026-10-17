# Signed-wire recovery process cuts

Status: **offline author qualification candidate; application/core NO-GO**.
This additive profile selects the signed-wire candidate based on
[`35298ee88478f04fd62a976deab1900fd0588215`](https://github.com/edgepillar/ptlc-research/tree/35298ee88478f04fd62a976deab1900fd0588215).
It leaves that writer, historical subjects and prior evidence unchanged.
It is not an independent security assessment or application recovery permission.

The actor calls `os._exit(72)` at six selected boundaries. Unlike an exception,
this bypasses the Python owner and context-manager cleanup. Each selected append
has already returned from complete fsync, or the public worker reply has been
fully collected and reaped. These are self-exit experiments, not external
SIGKILL, interior write/fsync faults, hardware power loss or hostile-process
containment. The host, interpreter, path ancestors and nonforking workers remain
trusted premises.

| Selected cut | Charge | Diagnostic completion | Journal completion | Signed long original |
| --- | --- | --- | --- | --- |
| Signed short retained | 0 | Absent | Absent | Absent |
| Recovery admitted | 1 | Absent | Absent | Absent |
| Public reply before append | 1 | Retained separately | Absent | Absent |
| Public completion retained | 1 | Retained separately | Retained | Absent |
| Separately supplied signed long retained | 1 | Retained separately | Retained | Retained |
| Unknown long handoff retained | 1 | Retained separately | Retained | Retained |

The six journals are separate test owners. Their 21 actor worker calls include
four recoveries, each in a different journal. The 17 reopen verification calls
include zero recoveries. Explicit retry at the two unknown charged cuts refuses
without adding work or changing journal bytes. Reopen does not consume an
observation callback, invent a signed long original, copy a diagnostic result
into the journal or turn historical observations into current chain authority.
The final cut retains OUTCOME_UNKNOWN before raw output could be returned.

The raw verifier is the disclosed finite source-corpus lookup and the observer
is the synthetic allowlist from the signed-wire profile. The selected upstream
source remains the separately qualified, GPL-covered `137fc528` corpus described
in [the source notice](NOM_SIGNED_RECOVERY_NOTICE.md). No upstream node, signer,
key material, wallet, network peer or broadcast is added.

The [manifest](../compatibility/nom_signed_process_cuts_manifest.json) pins the
selected existing inputs and three new qualification sources. The actor checks
the complete selected source map before importing the subject. Runtime paths
are passed separately; retained selection records contain relative source names,
hashes and the selected cut. They contain no environment dump, local path or
executable binary. Hashes bind bytes and do not authenticate their producer,
source/build closure, loader or runtime dependencies.

Each successful CLI run selects 189 original journal, selection, marker, receipt
and request/reply/error files, plus a result and explicit retention manifest:
191 files. Known partial failed files remain at their original names and can be
selected without labeling an incomplete run successful. The artifact selector
checks the explicit table, sizes, SHA-256, regular single-link files and disclosure
patterns before returning relative members. It never recursively packages an
evidence directory, normalizes an original, uploads a binary or repairs a log.

The data reader compares every journal with the declared finite event sequence
without calling the journal implementation's `_apply` method. It also checks all
38 retained worker requests/replies and the six actual actor exit receipts.
Adverse controls change coherent self-hashes, remove a recovery charge, promote
a diagnostic reply, substitute a same-nodehash raw alias, change native requests
or replies, forge exits and insert duplicate JSON keys or Boolean counters.
These are author-run finite-scenario checks. They do not provide independent
protocol review or an external rollback fence. A coherent old copy can still
be a valid historical journal outside this particular completed scenario.

Unit tests use a plainly named exact public fixture worker. They execute the
process and file flow but perform no signature mathematics. A separately selected
public Rust worker must supply the native mathematical component; the CLI requires
its explicit path and expected byte digest. It refuses Python optimization before
evidence or worker access. Select a new empty owned evidence directory:

```text
python3 -B scripts/qualify_nom_signed_process_cuts.py --executable PUBLIC_WORKER --expect-executable-sha256 EXPECTED_SHA256 --evidence EMPTY_PROCESS_EVIDENCE
```

An optional `--subject-commit` binds every selected project source and the new
manifest to that commit. Omit it for uncommitted local development. Full regression,
artifact checks, exact hosted PR evidence and the later distinct push/main run
remain separate requirements. Independent assessment, nonrollback authority and
all seven service gates remain unfilled. Deployment, activation, application
signing, controlled network composition, transaction broadcast and funds remain
outside this profile.
