# Captured public checker composition

Status: **M2b/M3 offline component candidate; fresh complete qualification required**.
This component executes only an explicitly selected local public checker over
public preparation data. It selects no signer, observer, operational store, node,
wallet, signing, broadcast or funds. Application/core remain **NO-GO** and
independent assessment remains **UNFILLED**.

## Owner selection and trust

The existing `inspect-presignature-result` command still inspects supplied JSON
without invoking a backend. The separate `reference_client.checker` entry point
captures one selected process and passes its exact result to that inspector.

Only the local command line supplies the executable and expected SHA-256. The
public JSON is exactly the existing `prepare-presignature-check` input: its full
ordered funding prefix is rechecked and its message, point, key and context are
derived locally. Peer executable, digest, environment, argument, message or
backend overrides are not admitted by that input contract.

Set `PTLC_CHECKER` to an already built, owned absolute path to the selected
[public Rust checker](../public_crypto/README.md). Set `PTLC_CHECKER_SHA256` from
the local build selection. Neither hashing an arbitrary file nor a backend label
authenticates its source, dependencies, build or runtime. Qualification must
separately retain and assess those inputs. This command performs no build or
fetch and copies no executable.

```sh
python3 -B -m reference_client.checker \
  --executable "$PTLC_CHECKER" --sha256 "$PTLC_CHECKER_SHA256" \
  < reference_client/synthetic_presignature_request.json
```

The selection is POSIX-only. The path and ancestors must not be symbolic links;
the file must be regular, owned by the caller, executable and not writable by
group or others. Size, identity and digest consistency are checked before and
after execution. The local owner must protect the path and every alias for the
entire operation. These checks do not defeat adversarial replacement followed
by restoration, authenticate the executed image or sandbox an arbitrary local
program. The tool adopts no binary as stored evidence and creates no hard link.

## Complete capture and refusal

The process receives one locally derived canonical request, through explicit
input EOF, with no caller-selected arguments. Its launcher environment contains
only the selected generic path, locale and time-zone values. It inherits no
private environment values from the client. An interpreter or selected program
can change its own environment; this is not a general isolation boundary.

| Boundary | Limit |
| --- | --- |
| Public preparation | Existing 32 KiB input boundary, read through declared EOF |
| Canonical backend request | Existing 8 KiB limit |
| Selected executable | 128 MiB, read in bounded chunks without copying |
| Captured stdout | Existing 4 KiB canonical result boundary; no framing LF is added or stripped |
| Captured stderr | 16 KiB; bounded diagnostic bytes do not automatically fail a complete result |
| Captured-result response | 8 KiB including the Python CLI framing LF |
| Observed process | 10-second post-launch IO/exit deadline, then at most one second for the owned child reap |

The process deadline does not bound the initial public input producer, filesystem
reads or uninterruptible OS operations. Both output pipes are drained with caps;
neither EOF nor a zero exit alone supplies success. The entire request must have
been written, both streams must reach EOF, the direct child must complete with
zero exit, executable consistency must still hold, and the complete exact result
must pass the existing canonical request/context/scope association checks.

Empty, partial, noncanonical, oversized, late or mismatching output refuses.
Nonzero exit, launch/IO faults, timeout and observed executable changes refuse.
Only the directly owned child is stopped and joined; a selected program's
arbitrary descendants or hostile host are outside this construction. There is
no automatic retry and no response reconstructed from an exit code, digest or
partial bytes. Refusal exits two without echoing input, paths or diagnostics.
Interrupts propagate after owned-child cleanup. No persistent receipt is written.

## Result meaning

A successful `ptlc-nom-client-captured-public-check-v1` response includes the
exact ASCII `checker_result_json`, its `result_digest_hex`, the rederived request
and context digests, the selected executable digest/size and complete-process
observations. Stderr is represented by its byte count and digest, without raw
diagnostic text. The executable path and private filesystem identities are not
reported. The outer CLI writes and flushes one canonical JSON document plus LF.

`COMPLETE_SELECTED_LOCAL_PROCESS` describes this invocation's observed capture.
`CAPTURE_AND_ASSOCIATION_ONLY` and `SELECTED_EXECUTABLE_REPORTED_VALID` preserve
the trust boundary: an owner-selected fabricated program can emit every matching
field, including for an invalid presignature. Accordingly source authentication
remains `NOT_ESTABLISHED_BY_THIS_TOOL`. A qualified build of the selected Rust
checker supplies a separately scoped public mathematical check; this response
does not authenticate such a build by itself.

Context, agreement consent, funding execution, chain truth, timing, key/nonce
safety and recovery authority remain unverified or unselected. Action permission
is always `NONE`. Even a fully captured backend result does not prove the outer
response reached its caller; discarded or partial delivery remains unknown.

## Verification scope and stop condition

The [19 Python controls](../tests/test_client_checker.py) use small regular
synthetic programs. They cover exact capture, explicit fabricated-claim limits,
peer/prefix refusal, selection changes, exit and stream failures, caps, timeout,
environment isolation, outer discarded/closed output, output failure and interrupt cleanup. Nonregular and
large-file selection controls use mocked metadata or a reduced isolated cap;
they create no link, FIFO, socket or large binary fixture. Timeout controls do
not establish an exact instruction or output-write cancellation point.

The existing
`the_built_public_cli_accepts_one_framing_lf_and_refuses_oversized_input` case in
the [shared Rust process test](../qualification/tests/client_public_crypto_process.rs)
also runs this Python entry point with that package's actual built public
checker. It compares the captured original bytes with the direct checker result
and requires refusal for an invalid public scalar. The existing five library
and five process case counts remain unchanged; those new assertions are not
additional Rust cases. No binary copy or new dependency is introduced.

Acceptance requires fresh full Python regression, artifact/privacy checks, the
actual built-checker assertions and the applicable hosted original gates for
the exact new source. The focused fabricated-program run alone is insufficient.
The public-tier producer explicitly registers the five matching Python modules
and their result prefixes, including the new checker controls. The policy names
only the new public component and test file; new executable additions, changes
to the policy/producer, unknown/shared source and every main push still select
full CI. Later eligible component-only PRs can use the existing focused tier
with these tests and the same actual Rust process case.
Stop this item when those component conditions are met. It supplies no actual
bilateral exchange, durable recovery, independent assessment or application/core
approval; those remain the separate [roadmap](REFERENCE_CLIENT_ROADMAP.md) gates.
