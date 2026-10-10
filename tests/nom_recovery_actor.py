"""Disposable process-death actor using public exact-fixture oracles only."""

import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from test_nom_recovery import TERMS, PAIR, FIXTURE, FixtureVerifier
from offline_session.nom_recovery import NomRecovery, observation, synthetic_claim, synthetic_transaction_hash


def main():
    path, role, cut = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
    def hook(kind):
        if kind == cut: os._exit(72)
    short = synthetic_claim(TERMS, "short", FIXTURE["short_signature_hex"])
    with NomRecovery.open(path, TERMS, PAIR, role=role, verifier=FixtureVerifier(),
                          observation_verifier=lambda _: True, hook=hook) as store:
        for leg in ("long", "short"): store.record_observation(observation(TERMS, leg, "funded"))
        if role == "alice":
            store.retain_original("short", short); store.prepare_attempt("short")
        else:
            proof = observation(TERMS, "short", "unlock-confirmed", transaction_hash_hex=synthetic_transaction_hash(short),
                                send_timestamp="900", send_momentum_hash_hex="aa"*32,
                                receive_timestamp="1100", receive_momentum_hash_hex="bb"*32)
            store.recover_long(short, proof)
    return 0


if __name__ == "__main__": sys.exit(main())
