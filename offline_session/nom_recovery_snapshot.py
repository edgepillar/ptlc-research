"""Offline observation snapshots over the preserved reference journal.

This opt-in entry fixes new observation handoffs only. It retains the historical
synthetic envelope and journal format, and does not authenticate an observer or
retroactively validate old records. It supplies no signed-wire integration,
anti-rollback authority, application signer or production recovery permission.
"""

import copy

from .nom_recovery import NomRecovery, RecoveryError, canonical, decode


class SnapshotNomRecovery(NomRecovery):
    """Retain the selected observation even when a caller changes its alias.

    The verifier remains explicitly trusted. Its argument must be unchanged on
    return; this check cannot prove its internal behavior or isolate its code.
    Existing log replay retains the historical trust and restore assumptions.
    """

    def record_observation(self, proof):
        self._check()
        selected = copy.deepcopy(proof)
        self._validate_observation(selected, self._state)
        wire = canonical(selected)
        examined = decode(wire)
        approved = self._observer(examined)
        if canonical(examined) != wire:
            raise RecoveryError("reference observation verifier changed its input")
        if approved is not True:
            raise RecoveryError("reference observation refused")
        selected = decode(wire)
        prior = next((item for item in reversed(self._state["observations"])
                      if item["leg"] == selected["leg"]), None)
        if prior == selected:
            return
        self._append({"kind": "observation", "proof": selected})

    def recover_long(self, original_short, proof):
        # Freeze before any foreign public-verifier callback, not just observe.
        return super().recover_long(original_short, copy.deepcopy(proof))
