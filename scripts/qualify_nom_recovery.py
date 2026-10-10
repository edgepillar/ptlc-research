#!/usr/bin/env python3
"""Exercise two offline journals with the actual public Rust qualifier.

The observation allowlist is deliberately synthetic scenario evidence. It is
neither an RPC observer nor a proof/finality verifier. No network or signer runs.
"""

import argparse
import hashlib
import json
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from offline_session.nom_recovery import (  # noqa: E402
    NomRecovery, RecoveryError, canonical, observation, synthetic_claim, synthetic_transaction_hash,
)
from offline_session.nom_verifier import NomPublicVerifier  # noqa: E402


def qualify(executable):
    terms = json.loads((ROOT / "compatibility/fixtures/nom_terms_v1.json").read_text("ascii"))
    fixture = json.loads((ROOT / "compatibility/fixtures/nom_completions_v1.json").read_text("ascii"))
    executable = executable.resolve()
    pin = hashlib.sha256(executable.read_bytes()).hexdigest()
    verifier = NomPublicVerifier(executable, pin, terms, fixture["pair"])
    short = synthetic_claim(terms, "short", fixture["short_signature_hex"])
    long = synthetic_claim(terms, "long", fixture["long_signature_hex"])
    funded = [observation(terms, leg, "funded") for leg in ("long", "short")]
    short_confirmed = observation(terms, "short", "unlock-confirmed", transaction_hash_hex=synthetic_transaction_hash(short),
                                  send_timestamp="900", send_momentum_hash_hex="aa" * 32,
                                  receive_timestamp="1100", receive_momentum_hash_hex="bb" * 32)
    unseen = observation(terms, "short", "unseen", transaction_hash_hex=synthetic_transaction_hash(short))
    allowed = {canonical(proof) for proof in funded + [short_confirmed, unseen]}
    observer = lambda proof: canonical(proof) in allowed
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory); root.chmod(0o700)
        def open_store(role):
            return NomRecovery.open(root / (role + ".log"), terms, fixture["pair"], role=role,
                                    verifier=verifier, observation_verifier=observer)
        with open_store("alice") as alice:
            for proof in funded: alice.record_observation(proof)
            alice.retain_original("short", short)
            assert alice.prepare_attempt("short") == short
        with open_store("alice") as alice:
            assert alice.status()["phases"]["short"] == "OUTCOME_UNKNOWN"
            alice.record_observation(unseen)
            assert alice.prepare_attempt("short") == short
            alice.record_observation(short_confirmed)
        with open_store("bob") as bob:
            for proof in funded: bob.record_observation(proof)
            assert bob.recover_long(short, short_confirmed) == long
            assert bob.prepare_attempt("long") == long
        with open_store("bob") as bob:
            assert bob.prepare_attempt("long") == long
            assert bob.recover_long(short, short_confirmed) == long
            assert bob.status()["recovery_count"] == 1
    for leg in ("long", "short"):
        try: verifier.verify_claim(leg, "00" * 64)
        except RecoveryError: pass
        else: raise RecoveryError("invalid public completion was accepted")
    return {"schema": "ptlc-nom-offline-qualification-result-v1", "public_worker": "verified",
            "two_journal_original_recovery": "verified", "invalid_completions": "refused",
            "observation_source": "synthetic-reference-only", "application": "NO-GO", "core": "NO-GO"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executable", type=Path, default=ROOT / "qualification/target/debug/examples/verify_nom_swap")
    args = parser.parse_args()
    try: result = qualify(args.executable)
    except (OSError, RecoveryError, AssertionError, ValueError):
        print("FAIL: offline NoM original recovery qualification", file=sys.stderr); return 1
    print(json.dumps(result, sort_keys=True)); return 0


if __name__ == "__main__": sys.exit(main())
