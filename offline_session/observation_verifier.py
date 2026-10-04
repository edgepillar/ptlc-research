"""Explicitly pinned local public worker; no source, cache or admission policy.

Only an exact normal verdict from the selected executable becomes a mathematical
statement. Worker and protocol failures yield unknown. A hash pin measures the
entry file, not its provenance, interpreter, libraries or host trustworthiness.
"""

import hashlib
import json
import os
from pathlib import Path
import stat

from . import exchange, observation_evidence as evidence
from .public_worker import WorkerError, run_admitted_public_worker, run_guarded_public_worker, run_public_worker


RESULT_SCHEMA = "ptlc-observation-verifier-result-v1"
PROFILE_SCHEMA = "ptlc-observation-verifier-profile-v1"
MAX_EXECUTABLE_BYTES = 64 * 1024 * 1024


def _file_digest(path):
    """Bound the local measurement; no raw file or filesystem details escape."""
    # Nonblocking open keeps a replaced FIFO from waiting for another endpoint.
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NONBLOCK), "rb") as source:
        metadata = os.fstat(source.fileno())
        if (not stat.S_ISREG(metadata.st_mode)
                or not 0 < metadata.st_size <= MAX_EXECUTABLE_BYTES):
            raise evidence.EvidenceError("invalid selected observation executable")
        digest = hashlib.sha256()
        consumed = 0
        while True:
            chunk = source.read(min(65536, MAX_EXECUTABLE_BYTES + 1 - consumed))
            if not chunk:
                break
            consumed += len(chunk)
            if consumed > MAX_EXECUTABLE_BYTES:
                raise evidence.EvidenceError("invalid selected observation executable")
            digest.update(chunk)
        if consumed != metadata.st_size:
            raise evidence.EvidenceError("selected observation executable changed")
        return digest.hexdigest()


class SubprocessObservation:
    """Caller-provisioned executable pin and local profile on Linux or macOS.

    Measurement is repeated before every launch. Path replacement after that
    measurement remains within the trusted-host boundary, not an atomic launch
    guarantee. No durable attempt, retry, global resource or evidence store is
    provided. Caller cancellation propagates after the pipe runner cleans up.
    """

    def __init__(self, executable, *, expected_executable_sha256_hex, timeout=5):
        try:
            evidence._profile(expected_executable_sha256_hex)
            path = Path(executable)
            if (not path.is_absolute() or not path.is_file()
                    or not os.access(path, os.X_OK)
                    or type(timeout) not in (int, float) or not 0 < timeout <= 30
                    or _file_digest(path) != expected_executable_sha256_hex):
                raise evidence.EvidenceError("invalid selected observation verifier")
            profile = exchange.canonical({
                "schema": PROFILE_SCHEMA,
                "construction": "CANDIDATE-01",
                "predicate": evidence.PREDICATE,
                "request_schema": "ptlc-completion-request-v1",
                "result_schema": RESULT_SCHEMA,
                "statement_schema": evidence.STATEMENT_SCHEMA,
                "adapter": "ptlc-observation-adapter-v1",
                "executable_sha256_hex": expected_executable_sha256_hex,
            })
            self._executable = path
            self._executable_digest = expected_executable_sha256_hex
            self._timeout = timeout
            self._profile_digest = hashlib.sha256(
                b"PTLC/observation-verifier-profile/v1\x00" + profile).hexdigest()
        except (OSError, ValueError, TypeError):
            raise evidence.EvidenceError("invalid selected observation verifier") from None

    @property
    def profile_digest_hex(self):
        return self._profile_digest

    def __call__(self, state, signature):
        return self._observe(state, signature, None, owned=False, admitted=False)

    def observe_owned(self, state, signature, *, ownership_descriptors):
        """Use the same mathematical profile with guarded store-held leases.

        Runtime supervision is separate from predicate/profile identity, as is
        the configured deadline. Unsupported lease/guard failures are unknown.
        Only the selected cooperative, nonforking public worker is supported.
        """
        return self._observe(state, signature, ownership_descriptors, owned=True, admitted=False)

    def observe_admitted(self, state, signature, *, ownership_descriptors, admission_descriptor):
        """Require shared live-worker admission without changing the math profile."""
        return self._observe(state, signature, ownership_descriptors, owned=True,
                             admitted=True, admission_descriptor=admission_descriptor)

    def _observe(self, state, signature, ownership_descriptors, *, owned, admitted,
                 admission_descriptor=None):
        # Invalid local targets are configuration/input errors, not statements.
        target = evidence.prepare(state, signature)
        fields = evidence._fields(target, self._profile_digest)
        outcome = "unknown"
        try:
            if _file_digest(self._executable) != self._executable_digest:
                raise evidence.EvidenceError("selected observation executable changed")
            if not owned:
                response = run_public_worker(str(self._executable), target.verification_request,
                    timeout=self._timeout, max_input_bytes=65536, max_output_bytes=evidence.MAX_STATEMENT_BYTES)
            elif not admitted:
                response = run_guarded_public_worker(str(self._executable), target.verification_request,
                    timeout=self._timeout, max_input_bytes=65536, max_output_bytes=evidence.MAX_STATEMENT_BYTES,
                    expected_executable_sha256_hex=self._executable_digest,
                    ownership_descriptors=ownership_descriptors)
            else:
                response = run_admitted_public_worker(str(self._executable), target.verification_request,
                    timeout=self._timeout, max_input_bytes=65536, max_output_bytes=evidence.MAX_STATEMENT_BYTES,
                    expected_executable_sha256_hex=self._executable_digest,
                    ownership_descriptors=ownership_descriptors,
                    admission_descriptor=admission_descriptor)
            value = json.loads(response.decode("ascii"))
            if (type(value) is not dict
                    or set(value) != {"schema", "predicate", "request_digest_hex", "outcome"}
                    or any(type(item) is not str for item in value.values())
                    or value["schema"] != RESULT_SCHEMA or value["predicate"] != evidence.PREDICATE
                    or value["request_digest_hex"] != fields["request_digest_hex"]
                    or value["outcome"] not in ("verified", "rejected")
                    or response not in (exchange.canonical(value), exchange.canonical(value) + b"\n")):
                raise evidence.EvidenceError("invalid observation verifier result")
            outcome = value["outcome"]
        except (OSError, ValueError, TypeError, RecursionError, WorkerError):
            # Never derive a negative from stderr, exception text or exit status.
            pass
        return exchange.canonical(dict(fields, outcome=outcome))
