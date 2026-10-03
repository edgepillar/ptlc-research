# Stage 6: explicit reconciliation of a retained completion

Status: offline public-input reconciliation. This extends Bob's [completion lifecycle](COMPLETION_LIFECYCLE.md); it does not add peer authentication, chain observation, private signing or transaction submission.

## Problem and acceptance rule

The ordinary `complete_exchange_bitcoin` API durably retains a structurally matching Zenon completion before executing public cryptographic recovery. If that packet is invalid, ordinary recovery cannot replace it with a later valid packet. A failed executable is not sufficient evidence that the packet is invalid: a timeout, unavailable process or malformed response has the same unsuccessful outcome.

The new `reconcile_exchange_bitcoin` API therefore requires positive verification of a replacement. The caller supplies the exact new packet and the expected digest of the currently retained packet. It is available only in `RELEASE_RECORDED`, with a retained observation and no completed Bitcoin output. It never resets an operation or changes Alice's completion ownership.

The compare-and-swap digest is:

```text
SHA256("PTLC/completion-observation/v1\0" || exact_retained_packet_bytes)
```

`completion.observation_digest` returns this lowercase 32-byte digest encoding for bounded, nonempty public bytes. The digest is an exact-input guard, not authentication or a cryptographic validity assertion. The journal compares it before invoking recovery. The replacement must differ from the retained packet and use the exact canonical Alice/Bob role labels, session, chain binding and nonce round reconstructed from Bob's stored contexts. An identical packet uses ordinary recovery instead.

The trusted recovery adapter must positively verify the replacement's final Zenon signature and extraction point, both retained bundles, and the completed Bitcoin signature. The existing Rust executable supplies this boundary; its protocol and dependency selections are unchanged. A callback exception, timeout, rejected packet, malformed result or mismatched response digest cannot authorize replacement. Fake test callbacks provide sequencing evidence only.

## One completed transition

After successful verification, the next exchange snapshot contains all of:

- The new `zenon_completion_packet_hex`.
- The completed Bitcoin packet and its request-bound receipt.
- The exact original packet in `superseded_zenon_completion_packet_hex`.
- Sealed stage `BTC_COMPLETION_RECORDED`.

The original release, bundles, nonce pins, existing artifact receipts and possible-exposure marker remain unchanged. The superseded packet is not labeled invalid: this transition establishes acceptance of the replacement, not a separate verdict about the historical packet. The archive has one entry because successful reconciliation immediately seals completion; there is no mutable or unbounded replacement history.

The process/thread owner and mutation guard cover comparison, callback, validation and persistence. Reentrant mutations or close, foreign-thread use and competing ownership are rejected. The pure helper snapshots the input before calling the trusted adapter. The journal validates and persists the complete resulting state before returning output.

Normal completion leaves the archive null. Stored archives are allowed only in completed state, must be canonical packets with the same exact context, and must differ from the current packet. Reload checks these relationships and the existing total-state bound without invoking an external verifier. The archive and receipt rely on the existing trusted local checkpoint/storage assumptions; they are not independently signed evidence against a hostile host.

## Crash and retry boundary

Reconciliation performs public computation **before** writing the replacement. No unverified pending-replacement slot is introduced. Before the database commit, the original observation remains authoritative; the caller must resupply the replacement to retry. The journal cannot recover an uncommitted replacement from memory after process death. Repeating this computation does not reuse a signing nonce.

The resulting snapshot uses one database commit followed by the existing separate checkpoint update. This is not an atomic transaction across both storage locations:

| Interruption | Recovery |
| --- | --- |
| During recovery, after successful recovery, or before database commit | Original candidate remains; replacement is not retained; caller may explicitly resupply it |
| After database commit, before matching checkpoint | Quarantine; no automatic repair or retry |
| After matching checkpoint persistence, including before API return | Completed replacement, original archive and exact Bitcoin output replay |

Recovery rejection leaves both storage copies unchanged. Persistence uncertainty may quarantine or leave a completed state on reopening; an exception is not proof that no commit occurred. Once completed, ordinary completion and reconciliation both reject another attempt. Exact Bitcoin output and original release replay remain available.

## Compatibility and remaining scope

Journal storage/domain v5 adds the required nullable archive field. Versions 1-4 are quarantined without modifying either copy or migrating state. This research repository has no supported funded-session migration. External artifact requests and release/completion packet schemas are unchanged.

The bounded path removes permanent pinning by an invalid original candidate when a correctly bound valid replacement is available and the trusted caller selects it. It does not authenticate the sender, validate funding or deadlines, prevent denial of service through repeated verification requests, authorize network delivery, or protect against restoring both matching old storage copies. Alice's synthetic producer and secret-owner integration remain unchanged. See [Stage 6 validation](STAGE6_VALIDATION.md) for executed tests and remaining gates.
