"""Explicit Linux per-process limits, separate from math and store admission.

These cap CPU time and virtual address space for one unprivileged selected
nonforking process. They are not RSS accounting, a sandbox, a cumulative pool
budget or a portable macOS memory guarantee. Only the exec launcher installs
limits; callers and the parent-watching guard retain their existing boundary.
"""

from dataclasses import dataclass
import hashlib
import os
import sys

try:
    import resource
except ImportError:
    resource = None

from . import exchange
from .public_worker import WorkerError


MIN_ADDRESS_SPACE_BYTES = 64 * 1024 * 1024
MAX_ADDRESS_SPACE_BYTES = 1024 * 1024 * 1024
MAX_CPU_SECONDS = 30


@dataclass(frozen=True)
class WorkerResourceLimits:
    """Finite explicit local maxima; no production defaults or enrollment."""

    cpu_seconds: int
    address_space_bytes: int

    def __post_init__(self):
        if (type(self.cpu_seconds) is not int or not 1 <= self.cpu_seconds <= MAX_CPU_SECONDS
                or type(self.address_space_bytes) is not int
                or not MIN_ADDRESS_SPACE_BYTES <= self.address_space_bytes <= MAX_ADDRESS_SPACE_BYTES):
            raise WorkerError("invalid public worker resource limits")

    @property
    def profile_digest_hex(self):
        self.__post_init__()
        wire = exchange.canonical({"schema": "ptlc-worker-resource-policy-v1",
            "implementation": "linux-rlimit-exec-v1", "cpu_seconds": self.cpu_seconds,
            "address_space_bytes": self.address_space_bytes, "core_bytes": 0})
        return hashlib.sha256(b"PTLC/public-worker-resources/v1\x00" + wire).hexdigest()


def _supported(limits):
    if type(limits) is not WorkerResourceLimits:
        raise WorkerError("explicit public worker resource limits are required")
    limits.__post_init__()
    if (os.name != "posix" or sys.platform != "linux" or resource is None
            or os.geteuid() == 0
            or any(not hasattr(resource, name) for name in ("RLIMIT_CPU", "RLIMIT_AS", "RLIMIT_CORE"))):
        raise WorkerError("public worker resource policy is unsupported")
    return limits


def _encode(limits):
    _supported(limits)
    return str(limits.cpu_seconds) + "," + str(limits.address_space_bytes)


def _decode(raw):
    try:
        if type(raw) is not str or len(raw) > 32:
            raise WorkerError("invalid public worker resource encoding")
        parts = raw.split(",")
        if len(parts) != 2:
            raise WorkerError("invalid public worker resource encoding")
        limits = WorkerResourceLimits(int(parts[0]), int(parts[1]))
        if _encode(limits) != raw:
            raise WorkerError("invalid public worker resource encoding")
        return limits
    except (ValueError, TypeError):
        raise WorkerError("invalid public worker resource encoding") from None


def _ceiling(requested, previous):
    """Never increase either inherited finite limit, including a lower soft cap."""
    if (type(previous) is not tuple or len(previous) != 2
            or any(type(value) is not int for value in previous)):
        raise WorkerError("invalid inherited public worker limits")
    finite = []
    for value in previous:
        if value == resource.RLIM_INFINITY:
            continue
        if value < 0:
            raise WorkerError("invalid inherited public worker limits")
        finite.append(value)
    value = min([requested] + finite)
    if requested and value == 0:
        raise WorkerError("inherited public worker limits are unavailable")
    return value


def _install(limits):
    """Child-only: lower limits and verify exact readback before exec.

    Failure can leave this launcher with partially lowered limits. It must exit,
    never restore an earlier value or execute the selected entry after failure.
    """
    _supported(limits)
    try:
        selected = ((resource.RLIMIT_CORE, 0), (resource.RLIMIT_CPU, limits.cpu_seconds),
                    (resource.RLIMIT_AS, limits.address_space_bytes))
        ceilings = [(kind, _ceiling(value, resource.getrlimit(kind))) for kind, value in selected]
        for kind, ceiling in ceilings:
            resource.setrlimit(kind, (ceiling, ceiling))
            if resource.getrlimit(kind) != (ceiling, ceiling):
                raise WorkerError("public worker resource limits did not persist")
    except (OSError, ValueError, TypeError, OverflowError):
        raise WorkerError("public worker resource setup failed") from None
