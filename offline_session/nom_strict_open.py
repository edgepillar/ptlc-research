"""Explicit read-only reference open with independent retained-result checks.

This selected profile reuses the frozen v1 journal parser and claim rules. It
never creates a journal, writes evidence, constructs an absent original, enters
recovery or authorizes an application action. Retained observations are history,
not current chain authority. A cooperative lock does not prevent coherent old
copies or establish a restore fence. Application and core remain NO-GO.
"""

import os
import stat
import threading

from .nom_recovery import (
    NomRecovery, Quarantined, RecoveryError, fcntl, validate_pair, validate_terms,
    verification_context_digest,
)


PROFILE = "ptlc-nom-strict-read-only-open-v1"


class StrictNomRecovery(NomRecovery):
    """A separately selected owner; legacy writer/open behavior is unchanged."""

    @classmethod
    def open(cls, path, terms, pair, *, role, verifier, observation_verifier):
        instance = cls.__new__(cls)
        instance._fd = None; instance._dir = None; instance._closed = False; instance._poisoned = False
        instance._pid = os.getpid(); instance._thread = threading.current_thread(); instance._hook = None
        try:
            instance._terms = validate_terms(terms); instance._pair = validate_pair(pair)
            if role not in ("alice", "bob") or not callable(observation_verifier):
                raise RecoveryError("explicit role and observation verifier are required")
            expected = verification_context_digest(terms, pair)
            if verifier.context_digest_hex != expected or verifier.verify_pair() is not True:
                raise RecoveryError("adaptor pair verification failed")
            instance._role = role; instance._verifier = verifier; instance._observer = observation_verifier
            if fcntl is None or os.name != "posix":
                raise RecoveryError("reference journal requires POSIX ownership")
            parent, name = os.path.split(os.fspath(path))
            if not name or name in (".", ".."):
                raise RecoveryError("invalid journal selection")
            instance._name = name
            instance._dir = os.open(parent or ".", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            directory = os.fstat(instance._dir)
            if directory.st_uid != os.getuid() or stat.S_IMODE(directory.st_mode) != 0o700:
                raise RecoveryError("a private owned journal directory is required")
            # No O_CREAT or write-capable descriptor, including on refusal.
            instance._fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=instance._dir)
            try:
                fcntl.flock(instance._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise RecoveryError("journal already has an owner") from None
            instance._state = {"initialized": False, "funded": {}, "originals": {}, "remote_short_hex": "",
                               "recovery_count": 0, "recovered_long_hex": "", "attempts": {}, "phases": {},
                               "disclosure_possible": False, "observations": [], "confirmations": {}}
            instance._head = "00" * 32; instance._sequence = 0; instance._size = 0
            instance._check_file(); instance._load()
            for leg, encoded in instance._state["originals"].items():
                instance._verify_claim(leg, bytes.fromhex(encoded))
            if instance._state["remote_short_hex"]:
                instance._verify_claim("short", bytes.fromhex(instance._state["remote_short_hex"]))
            retained = instance._state["recovered_long_hex"]
            # A public completion is checked directly; no envelope is invented.
            if retained and instance._verifier.verify_claim("long", retained) is not True:
                raise RecoveryError("retained long completion verification failed")
            instance._check()
            return instance
        except RecoveryError:
            instance.close(); raise
        except (OSError, ValueError, TypeError, AttributeError, RecursionError):
            instance.close(); raise Quarantined("unable to open the strict reference journal") from None
        except BaseException:
            # Interruptions must not strand this selected cooperating owner.
            instance.close(); raise

    def _read_only(self, *args, **kwargs):
        raise RecoveryError("strict reference open is read-only")

    _append = _read_only
    record_observation = _read_only
    retain_original = _read_only
    prepare_attempt = _read_only
    recover_long = _read_only
