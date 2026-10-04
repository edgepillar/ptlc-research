# Explicit resources for one admitted public worker

Status: **Stage 23 offline Linux CPU/address-space qualification, separate from
persistent store policy. Unsupported hosts reject before guard creation. No
signer, chain source, resource sandbox or funded availability policy is added.**

Source parent: [`6473542e6f333e3f02863a5a7c55924001860a25`](https://github.com/edgepillar/ptlc-research/tree/6473542e6f333e3f02863a5a7c55924001860a25).
The [shared pool](SHARED_WORKER_ADMISSION.md) bounds simultaneous cooperating work
on the same physical files. It supplies no per-worker CPU or memory ceiling. This
separate [policy module](../offline_session/worker_resources.py) and
[exec launcher](../offline_session/resource_launcher.py) qualify explicit maxima
before selecting a durable policy or changing the owned store.

## Requirement, construction and boundary

| Requirement | Selected construction | Boundary |
| --- | --- | --- |
| Finite CPU for one selected process | Both RLIMIT_CPU values lowered to the effective finite cap before exec | CPU seconds, not elapsed time, fairness, throughput or a process-tree allowance |
| Finite virtual address space | Both RLIMIT_AS values lowered before exec | Virtual mappings, not RSS accounting or a host-wide RAM budget |
| Refuse incomplete setup | Exact readback for CPU, address space and disabled core dumps before exec | Readback is configuration evidence; native enforcement needs separate execution |
| Preserve stricter inherited caps | Minimum of requested and both inherited finite values; never raise either value | Zero inherited CPU/address space rejects; no reset or restore attempt |
| Preserve live ownership and capacity | Same tracked process execs with both owner references and one slot | Selected nonforking worker must retain them; hostile escape/privilege remains outside trust |
| Keep resource failure separate from rejection | Setup/exec/process failure yields unknown through the existing adapter | A normal negative still requires the exact unchanged mathematical result |

The fixed construction supports Linux with the required resource constants and
a nonzero effective UID. macOS and other platforms reject this profile. A local
isolated macOS probe could not install the selected 128 MiB address-space cap;
that failed setup is not evidence of portable memory enforcement. Root rejection
does not prove absence of elevated capabilities in another process. The selected
worker must lack authority to raise its hard caps; runtime, modules and host are
trusted. This does not assess privilege isolation or arbitrary executables.

## Explicit policy and execution

`WorkerResourceLimits(cpu_seconds, address_space_bytes)` is frozen public data.
CPU is a plain integer from 1 through 30; address space is a plain integer from
64 MiB through 1 GiB. These are qualification format bounds, not production
defaults or a selected swap budget. No implicit policy is supplied. The profile
is SHA256 of domain `PTLC/public-worker-resources/v1`, a NUL byte and canonical
JSON containing schema `ptlc-worker-resource-policy-v1`, implementation
`linux-rlimit-exec-v1`, both requested maxima and `core_bytes: 0`. It authenticates
neither provisioning nor runtime behavior. The profile remains separate from
the unchanged mathematical verifier profile and result schema.

`run_limited_public_worker` and `SubprocessObservation.observe_limited` require
both ownership descriptors, a distinct admission descriptor and explicit limits.
Missing/invalid policy or an unsupported host launches no guard or selected
worker. There is no fallback to the admitted, two-lease guarded or direct path.
The guard validates bounded canonical control fields and requires all three
capabilities before reading input and remeasuring the selected entry.

The guard launches a Python limit installer as its owned direct child with the
same three inherited references. The installer checks their private distinct
file identities and inheritability, remeasures the entry, restores the default
CPU signal disposition, disables core dumps and lowers both resource caps. It
checks each exact readback before `os.execv`. Partial setup or exec failure exits
with fixed diagnostics; it never runs the entry or restores old caps. No paths,
resource diagnostics, process identifiers or worker output enter a statement.

Exec keeps the tracked PID, group, pipes and capabilities. This avoids parent
limit changes, a post-launch PID-update race, `preexec_fn` and an extra selected
worker process. Launcher/interpreter startup and entry measurement occur before
the selected caps; guard and caller/preflight resources remain outside them.
Previously consumed CPU belongs to that same process. Existing bounded pipe
transfer, owner monitoring, wall deadline and exclusive child-reaping premises
remain in place. An uninterruptible task still has no hard elapsed-time guarantee.

## Store and evidence boundaries

The ordinary `ObservationStore.open` entry remains v3 and invokes
`observe_admitted`, with no resource policy field or automatic limited selection. Session journal, pure
records, pool profile and cryptographic sources remain unchanged. The separate
[Stage 24 v4 entry](DURABLE_RESOURCE_POLICY.md) explicitly binds requested policy
and checks continuity before SQLite/recovery; it requires its own delta assessment. A
mathematical verdict is not an attestation of resource policy or source authority.

Native Linux tests separately check a denied 256 MiB anonymous mapping under a
128 MiB cap, exact readback and three inherited references. A direct tracked
launcher probe ignores the soft CPU signal and must terminate by SIGKILL under
the hard cap, with parent limits unchanged. Guard-loss work retains both owner
locks and shared capacity until its limited worker exits; cancellation releases
capacity without a cooperative release shortcut. On macOS these cases exercise
explicit refusal, never Linux enforcement and never a skipped success claim.

The actual Rust qualifier checks normal positive/negative results under explicit
limits and unknown without fallback for missing limits, preserving journal bytes
and mathematical profile. Synthetic process probes establish no signature truth.
Configured CI is not executed evidence; platform results must be recorded in
[Stage 23 validation](STAGE23_VALIDATION.md).

## Primary premises and remaining gates

[Linux getrlimit(2)](https://man7.org/linux/man-pages/man2/getrlimit.2.html)
(man-pages 6.19, inspected 2026-10-04) describes CPU/address-space enforcement,
hard-limit privilege and preservation across exec. It does not provide a hard
elapsed-time or aggregate-descendant guarantee. [Pinned CPython resource docs](https://github.com/python/cpython/blob/de54cf5be371a6f5e2e9f208c38def5f81d3ef02/Doc/library/resource.rst)
describe platform-specific support and readback/set APIs; [pinned subprocess docs](https://github.com/python/cpython/blob/de54cf5be371a6f5e2e9f208c38def5f81d3ef02/Doc/library/subprocess.rst)
identify the thread-safety limitation of preexec callbacks. The [archived Apple
manual](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/getrlimit.2.html)
is historical documentation, not current macOS memory qualification. No external
source code is copied by this construction.

**Go:** assess this exact launcher/policy/adapter delta and specify durable
the v4 selection delta separately and qualify its full real storage/recovery cut matrix. **No-go:** claim RSS or aggregate RAM/CPU,
cumulative rate, fairness, trusted enrollment, anti-clone/restore defense, funded
recovery availability, independent security review or core activation. The frozen
119-file subject remains unchanged; this later delta needs its own assessment.
