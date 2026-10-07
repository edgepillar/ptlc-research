# Opt-in sealed public verifier execution

Stage 84 selects one separate Linux-only reference adapter. It closes the
selected entry-file measurement-to-launch gap under a trusted caller, Python
runtime and kernel. It authenticates neither the selected pin nor the complete
program runtime. Application and core progression remain **NO-GO**.

## Requirement and selected construction

The requirement is to execute the same entry bytes whose SHA256 the caller
selected. A retained descriptor for an ordinary mutable file is insufficient.
The construction in [sealed_artifact_verifier.py](../offline_session/sealed_artifact_verifier.py)
copies the public entry into a fresh anonymous file on each call, installs
write, grow, shrink and further-sealing restrictions, checks their complete
mask, and hashes the sealed snapshot. Only a matching snapshot is launched.

`SealedSubprocessVerifier` takes an absolute selected path, an independently
supplied lowercase 64-character SHA256 and a numeric deadline in `(0, 30]`.
The constructor performs syntax and Linux capability checks; it does not read,
measure or retain an executable. Each call repeats the capability checks and
owns its own source and snapshot descriptors. An unavailable or changed file
therefore refuses at call time. Selection never falls back to another adapter.

The source is opened nonblocking with close-on-exec and no final symlink
following. Its opened metadata must describe a regular executable file of
1 through 64 MiB. Copying and subsequent snapshot hashing are streamed and
bounded; short, growing, unexecutable or nonregular entries refuse. An ELF
magic prefix is required. This rejects script wrappers, but does not validate
an ELF file, prove that it is static, or measure its interpreter and libraries.
The kernel remains responsible for executable-format acceptance.

The anonymous file uses the exposed `MFD_CLOEXEC | MFD_ALLOW_SEALING` constants.
No numeric execution-enabling flag is invented or retried. The adapter requests
owner read/execute permissions and accepts only successful seal installation
and inspection. A host policy that prohibits executable memfds, a missing
constant, inaccessible procfs or a launch refusal fails closed. It does not
change kernel execution policy or bypass it with an alternative launch path.

The same sealed descriptor is passed through `Popen` to the existing bounded
pipe runner. The child launches `/proc/self/fd/<descriptor>` in its own process
context; it does not reopen the original selected pathname. The parent keeps
close-on-exec ownership; only the explicit descriptor is passed to the child.
The source descriptor closes before launch. Snapshot ownership lasts until
runner return or its failure/cancellation cleanup, then closes in a `finally`
block. No descriptor is retained between calls or installed in a public store.
The inherited public entry descriptor is not a secret or a nonce capability.

The selected deadline starts before acquisition and is checked during copying,
hashing and before launch. The runner receives its remaining interval. This
does not impose hard bounds on kernel calls, process creation, scheduling,
request serialization or aggregate concurrent memory consumption. The existing
runner's direct-child reap, group cleanup, escaped-descendant limitations and
exclusive reaping ownership remain applicable. There is no Python `preexec_fn`,
new launcher actor, admission lease, resource policy or worker sandbox.

Responses retain the existing exact public schema, complete request digest,
exact `true`, canonical bytes and optional single LF rule. Preparation and
transport failures are sanitized; ordinary cancellation propagates after
descriptor cleanup. A hostile same-process caller, monkeypatch, runtime or
kernel is outside this construction's trust boundary.

## Immutable platform source review

These are semantic source pins, not claims that hosted kernels, libc binaries
or Python interpreters were built from those commits:

| Source | Immutable review selection | Reviewed boundary |
| --- | --- | --- |
| Linux v6.18 | [memfd implementation](https://github.com/torvalds/linux/blob/7d0a66e4bb9081d75c82ec4957c50034cb0ea449/mm/memfd.c), [UAPI flags](https://github.com/torvalds/linux/blob/7d0a66e4bb9081d75c82ec4957c50034cb0ea449/include/uapi/linux/memfd.h), [procfs descriptor links](https://github.com/torvalds/linux/blob/7d0a66e4bb9081d75c82ec4957c50034cb0ea449/fs/proc/fd.c) | Seals apply to the underlying anonymous inode; seals cannot be removed. The default execution flags depend on the host's memfd policy. Procfs resolves the child's retained file descriptor. |
| glibc 2.42 | [declared syscall wrapper](https://github.com/bminor/glibc/blob/d2097651cc57834dbfcaa102ddfacae0d86cfb66/sysdeps/unix/sysv/linux/syscalls.list) | `memfd_create` is declared as a syscall wrapper; this is not libc runtime authentication or an `fexecve` construction. |
| CPython 3.13.16 | [os documentation](https://github.com/python/cpython/blob/cbc944f4bc59639a444dd971c737788ba2283a91/Doc/library/os.rst), [subprocess documentation](https://github.com/python/cpython/blob/cbc944f4bc59639a444dd971c737788ba2283a91/Doc/library/subprocess.rst), [fcntl documentation](https://github.com/python/cpython/blob/cbc944f4bc59639a444dd971c737788ba2283a91/Doc/library/fcntl.rst) | Linux capability availability, POSIX descriptor inheritance and native session setup; threaded pre-exec callbacks are unsafe. |

The [Linux licensing declaration](https://github.com/torvalds/linux/blob/7d0a66e4bb9081d75c82ec4957c50034cb0ea449/COPYING),
[glibc library license](https://github.com/bminor/glibc/blob/d2097651cc57834dbfcaa102ddfacae0d86cfb66/COPYING.LIB)
and [Python license](https://github.com/python/cpython/blob/cbc944f4bc59639a444dd971c737788ba2283a91/LICENSE)
were inspected before source acquisition. No upstream implementation was copied.
The original adapter and test controls are authored in this workspace.

## Selected qualification and remaining gates

Twenty portable controls in [the separate test module](../tests/test_sealed_artifact_verifier.py)
model the file API to test ownership, sanitized failures, capability refusal,
deadline sharing, request/result binding and cancellation. They qualify no
kernel or native execution behavior.

Two new methods in [the actual exchange qualifier](../scripts/qualify_exchange.py)
require real sealed native execution on Linux. One checks three original public
request kinds before and after restoration, plus six script-wrapper refusals
and six changed-ELF hash refusals without launch. The other delegates to the
actual snapshot, inserts six deterministic pathname substitutions after sealing
and measurement, then lets the unchanged real runner execute that descriptor.
Original equations accept all three valid requests and refuse all three existing
scalar mutations. Actual writes, shrinking, growing and shared writable mappings
refuse with kernel errors: 24 mutation attempts over six snapshots. Each retained
parent descriptor is observed closed afterward. No spontaneous-race probability,
hostile-host containment or process-tree resource guarantee is inferred.

On macOS the two new methods explicitly exercise unsupported-host refusal
without skipping, snapshot creation or worker launch. That branch is not Linux
qualification. All fourteen preceding actual methods and the command-line entry
retain exact bytes. Existing legacy and measured adapters, consumers and guarded
profiles are not migrated. [Stage 84 validation](STAGE84_VALIDATION.md) keeps local
and hosted evidence separate.

This construction measures entry bytes only. Loader, dynamic libraries,
environment, working directory, configuration, imported data, authenticated
distribution, pin provisioning and source-to-worker proof remain external
premises. A matching pin can deliberately select a lying native program. A
canonical positive result still depends on that program's trusted equations.
Passing a sealed snapshot does not authorize signing, private consumed inputs,
nonce ownership, restored-copy protection, real funds or node integration.
Both finite models, four fixed inventories and three unfilled independent
assessment reports remain unchanged. Independent review remains open.
