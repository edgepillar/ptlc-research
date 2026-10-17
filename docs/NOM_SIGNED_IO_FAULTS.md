# Signed-wire fixture I/O fault profile

Status: **offline author qualification candidate; application/core NO-GO**.
The selected signed-wire writer and earlier process profile are preserved from
[`176d772265103379b312f1e0481e1a2fdf6e2c71`](https://github.com/edgepillar/ptlc-research/tree/176d772265103379b312f1e0481e1a2fdf6e2c71).
This additive qualifier changes no journal transition or recovery allowance.
It fills no independent assessment, signer, observer or service acceptance gate.

Five append targets use separate actual private file journals: signed short
retention, recovery admission, recovered completion, signed long retention and
the UNKNOWN long handoff. Each target exercises six selected Python boundary
injections. The source writer's real write loop, local fsync and reopen paths
execute where the injection permits them.

| Injection | Selected retained image and limit |
| --- | --- |
| Before write | A Python wrapper raises before entering the file write. The target record is absent. |
| Zero write | A Python wrapper returns zero without a kernel write. The source writer refuses. |
| Partial write | The wrapper writes 17 real bytes, then raises on the next call. The torn original is quarantined without trimming. |
| Complete write, lost result | The wrapper writes the complete record, then raises before returning its count. This is a userspace ambiguity model, not a claimed kernel error after success. |
| File-sync refusal | The complete write returns, then the selected file-sync wrapper raises before calling fsync. |
| Post-sync refusal | The real file fsync returns, then the source hook raises before the append acknowledgment returns. |

All 30 target operations refuse before returning their result. The current owner
is poisoned. Twenty-five existing complete images reopen, while five torn images
remain quarantined at their exact names and bytes. Reopen enters zero recoveries.
Five complete histories with charged UNKNOWN recovery refuse an explicit repeat
without additional recovery or changed journal bytes. A missing signed long
original remains absent even when the public completion is retained. A complete
unacknowledged handoff remains OUTCOME_UNKNOWN.

The raw-source verifier is the disclosed finite corpus lookup. The public
signature verifier is the explicitly named fixture oracle and performs **no
signature mathematics**. No Rust worker, Go probe, signer, node, key, peer or
network operation is launched. Native public mathematics from earlier profiles
is a separate component; it is not an execution of this new profile.

The [manifest](../compatibility/nom_signed_io_faults_manifest.json) retains all
28 prior process-profile input pins and adds its unchanged manifest and three
new sources. The qualifier checks these 32 inputs before importing the selected
actor and fixture oracle, and checks them again afterward. An optional immutable
subject checks the selected blobs against that commit. Hash agreement does not
authenticate the source, interpreter, loader, dependencies or host. Path ancestors,
cooperating processes and the selected Python runtime remain trusted premises.

One successful run selects 91 source-selection, before-image, journal and case
originals, plus a qualification result and explicit retention manifest: **93
files**. The data reader reconstructs the finite expected event sequences and
hash chains without creating a journal owner or calling its `_apply` method.
It compares complete and 17-byte partial images, real written-byte counts,
intercepted Python API call counts, completed fsync calls, reopen state and retry
refusals. The fixture corpus and selected expected sequences remain its oracles;
this is not an independent protocol verifier or actor authentication.

The selector enumerates known relative names with byte limits, SHA-256, ASCII
disclosure checks and regular single-link file checks. Known incomplete files
may be retained with an explicitly failed/incomplete manifest. They receive no
successful comparison or recovery permission. No original is normalized,
reconstructed, repaired or replaced. Unknown files are outside the selection and
must remain preserved separately; selection is not permission to remove them.

The unit controls include coherent self-hash substitutions, diagnostic promotion,
Boolean counters, duplicate keys, missing/extra originals, reflected source pins,
incomplete retention and early optimization refusal. Unsafe-file metadata
controls are explicitly synthetic metadata checks, not native link qualification.

Use a new empty private evidence directory, with the source already selected:

```text
python3 -B scripts/qualify_nom_signed_io_faults.py --evidence EMPTY_PRIVATE_EVIDENCE
python3 -B scripts/qualify_nom_signed_io_faults.py --evidence RETAINED_EVIDENCE --artifact-files
```

`--subject-commit` optionally selects the immutable source. For an unsuccessful
run, `--artifact-files --allow-incomplete-for-retention` lists only the explicitly
retained incomplete originals. This option does not rerun a scenario or relabel
failure. Python optimization refuses before input, evidence or actor access.

These controlled exceptions are not external SIGKILL, device fault injection,
physical power loss, independent-machine durability or an external rollback
fence. They cannot prevent coherent restore/copies, authenticate canonical chain
observations or establish atomicity, timeout economics or service currentness.
Independent assessment and all seven service gates remain unfilled. Deployment,
activation, application signing, wallet access, broadcast and funds remain
outside the profile. Complete local regression, exact hosted originals and the
later distinct push/main acceptance remain separate requirements.
