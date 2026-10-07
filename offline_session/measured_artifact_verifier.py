"""Opt-in entry-file measurement for the trusted public exchange verifier.

The caller provisions an expected SHA256; it is never learned from a received
program. Matching bytes do not authenticate source, execution or the runtime.
The host remains trusted between measurement and launch. No consumer is migrated.
"""

from pathlib import Path
import re

from .artifact_verifier import SubprocessVerifier
from .exchange import VerificationError
from .observation_verifier import _file_digest


class MeasuredSubprocessVerifier(SubprocessVerifier):
    """Retain the legacy public receipt contract with an explicit entry pin.

    Construction and every call compare the bounded existing file measurement
    with the caller's exact expectation. No pin refresh, source authentication,
    atomic launch, historical receipt reassessment or rollback protection is
    supplied. The selected program, its interpreter and dependencies are trusted.
    """

    def __init__(self, executable, *, expected_executable_sha256_hex, timeout=5):
        try:
            if (type(expected_executable_sha256_hex) is not str
                    or re.fullmatch(r"[0-9a-f]{64}", expected_executable_sha256_hex) is None):
                raise VerificationError("invalid measured public verifier selection")
            super().__init__(executable, timeout=timeout)
            if _file_digest(Path(self._executable)) != expected_executable_sha256_hex:
                raise VerificationError("invalid measured public verifier selection")
            self._expected_executable_sha256_hex = expected_executable_sha256_hex
        except (OSError, ValueError, TypeError):
            raise VerificationError("invalid measured public verifier selection") from None

    def __call__(self, request):
        try:
            if _file_digest(Path(self._executable)) != self._expected_executable_sha256_hex:
                raise VerificationError("selected public verifier is unavailable or changed")
        except (OSError, ValueError, TypeError):
            raise VerificationError("selected public verifier is unavailable or changed") from None
        return super().__call__(request)
