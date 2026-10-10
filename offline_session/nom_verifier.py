"""Bounded adapter to an explicitly trusted public-only NoM qualifier.

The executable pin detects changed file bytes around each call. It does not
qualify loader/runtime dependencies, contain a malicious executable or establish
chain observation, local key provenance, signing custody or production readiness.
"""

import hashlib
import os
from pathlib import Path

from .nom_recovery import (
    RecoveryError, canonical, decode, validate_terms, validate_pair,
    verification_context_digest, context,
)
from .pr138 import PROFILE, CompatibilityError, fixed_hex, unlock_message
from .public_worker import WorkerError, run_public_worker


class NomPublicVerifier:
    def __init__(self, executable, expected_sha256_hex, terms, pair):
        self._terms = validate_terms(terms); self._pair = validate_pair(pair)
        self.context_digest_hex = verification_context_digest(terms, pair)
        try:
            fixed_hex(expected_sha256_hex, 32)
            path = Path(executable)
            if not path.is_absolute() or not path.is_file() or not os.access(path, os.X_OK):
                raise RecoveryError("an existing trusted public executable is required")
            self._executable = path; self._pin = expected_sha256_hex
            self._measure()
        except (OSError, TypeError, CompatibilityError):
            raise RecoveryError("invalid public qualifier selection") from None

    def _measure(self):
        try:
            digest = hashlib.sha256()
            with self._executable.open("rb") as stream:
                for chunk in iter(lambda: stream.read(65536), b""): digest.update(chunk)
            if digest.hexdigest() != self._pin: raise RecoveryError("public qualifier bytes changed")
        except OSError: raise RecoveryError("public qualifier is unavailable") from None

    @property
    def terms(self): return validate_terms(self._terms)

    @property
    def pair(self): return validate_pair(self._pair)

    def request(self, mode, signature_hex=""):
        if mode not in ("verify-pair", "verify-long", "verify-short", "recover-long"):
            raise RecoveryError("unsupported public verification mode")
        if mode == "verify-pair":
            if signature_hex != "": raise RecoveryError("pair request includes a completion")
        else:
            try: fixed_hex(signature_hex, 64)
            except CompatibilityError: raise RecoveryError("invalid public completion") from None
        request = {"schema": "ptlc-nom-public-verification-v1", "profile": PROFILE,
                   "context_digest_hex": self.context_digest_hex, "mode": mode,
                   "adaptor_point_sec1_hex": self.terms["adaptor_point_sec1_hex"], "completion_hex": signature_hex}
        for leg in ("long", "short"):
            request[leg] = {"key_xonly_hex": self.terms[leg]["funder_key_xonly_hex"],
                            "message_hex": unlock_message(context(self.terms, leg)),
                            "presignature_hex": self.pair[leg + "_presignature_hex"]}
        return request

    def _verify(self, mode, signature=""):
        wire = canonical(self.request(mode, signature))
        self._measure()
        try:
            reply = run_public_worker(str(self._executable), wire, timeout=5, max_input_bytes=8192)
            value = decode(reply)
            completed = value.get("completed_long_hex") if type(value) is dict else None
            if mode == "recover-long": fixed_hex(completed, 64)
            elif completed != "": raise RecoveryError("qualifier returned unexpected completion data")
            expected = {"schema": "ptlc-nom-public-verification-result-v1", "request_digest_hex": hashlib.sha256(wire).hexdigest(),
                        "valid": True, "completed_long_hex": completed}
            if reply != canonical(expected): raise RecoveryError("invalid bound public qualifier reply")
            self._measure()
            return completed
        except (OSError, WorkerError, CompatibilityError, ValueError, TypeError):
            raise RecoveryError("public NoM qualification failed") from None

    def verify_pair(self): self._verify("verify-pair"); return True
    def verify_claim(self, leg, signature_hex):
        if leg not in ("long", "short"): raise RecoveryError("unknown swap leg")
        self._verify("verify-" + leg, signature_hex); return True
    def recover_long(self, signature_hex): return self._verify("recover-long", signature_hex)
