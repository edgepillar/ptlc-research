# Bounded public worker transport

Status: offline subprocess qualification on Linux/macOS. This transport runs explicitly selected trusted local executables with public synthetic inputs. It is not a private signing boundary or an operating-system sandbox.

## Problem and scope

The original adapters accepted at most 4,096 output bytes but first sent all stdout to a temporary file. A faulty executable could exhaust temporary storage before that acceptance check or the timeout. Both adapters now share `offline_session.public_worker`, which bounds output while transferring it through pipes and creates no output spool file.

`SubprocessVerifier` retains its 32,768-byte request limit; `SubprocessCompletion` retains its 65,536-byte limit. Both retain their canonical JSON, request-digest and positive-result checks after the transport succeeds. The completion executable can verify a public Zenon completion, extract its witness internally and adapt the Bitcoin signature. The transport introduces no cryptographic algorithm, signing key, nonce generation, chain observation or network action.

## Transfer and acceptance

The runner uses an absolute executable path, no shell, a new POSIX session/process group, nonblocking stdin/stdout pipes and discarded stderr. It writes the request and reads the response concurrently so a worker that writes before consuming stdin cannot deadlock the parent. Stdin closes after the complete request is sent.

The runner retains no more than the 4,096-byte output allowance plus one byte used to detect overflow. Byte 4,097 rejects the invocation immediately; the allowance includes any trailing newline. A single monotonic deadline covers input transfer, output transfer and waiting for the direct child's exit. Acceptance requires complete request delivery, stdout EOF and exit status zero within that deadline. Closing stdout alone or exiting while another process keeps stdout open cannot produce a successful result.

The default deadline is five seconds, with finite positive configuration up to thirty seconds. This is a per-invocation transfer/exit deadline. Process creation, operating-system scheduling and cleanup can add time; it is not a hard guarantee that the calling function returns within that number of seconds.

## Cleanup and trust limits

On overflow, timeout or an I/O failure while the direct child is still owned and unreaped, cleanup attempts to kill its process group before reaping it. This also addresses ordinary descendants retaining inherited pipes. Once the direct child has been reaped, cleanup must not signal its cached numeric group ID, which the operating system can reuse. JSON/result rejection after a completed transport does not grant new authority to signal that old ID.

The caller must give this runner exclusive responsibility for reaping its direct child. Automatic `SIGCHLD` reaping or another thread/handler calling `waitpid` on that child breaks the ownership assumption. These conditions are execution requirements, not properties established by the worker's response.

Cleanup gives the direct child a separate one-second reap grace. If the operating system does not complete that wait, the runner reports a cleanup failure rather than accepting a result. The grace is an attempted wait bound, not a guarantee against uninterruptible operating-system behavior.

Process-group cleanup is best effort. A descendant can escape the group, close inherited pipes or outlive an already reaped worker. The parent does not enumerate arbitrary process trees. The deadline and pipe limit do not bound the executable's own memory, CPU, filesystem writes or network access. The executable, caller, inherited execution environment and host remain trusted. Paths, requests and stderr are not included in adapter error messages.

This change also does not impose admission control, a persistent attempt budget or a limit on total concurrent invocations. Repeated-verification denial of service remains a separate gate before exposing these adapters through authenticated peer transport. Worker failure is not a cryptographic verdict about a retained observation and does not authorize resetting Alice, discarding Bob's candidate or bypassing explicit reconciliation.

## Compatibility and evidence

Journal storage remains v5. Public packet schemas, signature encodings, result schemas, fixture values and request digests are unchanged. The actual Rust integration must pass through the new runner, in addition to synthetic process tests. Synthetic workers demonstrate transport behavior only; they are not cryptographic verifiers. See [Stage 7 validation](STAGE7_VALIDATION.md) for executed tests and limitations.
