#!/usr/bin/env python3
"""Exercise the frozen public recovery path with send-derived public contexts.

Only synthetic originals and allowlisted observation claims are used. Public
worker verification and controlled reopen do not authenticate the chain, admit
account blocks, protect rollback or join core execution to journal admission.
"""

import argparse
import hashlib
import json
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from offline_session.nom_recovery import (NomRecovery, RecoveryError, canonical, observation,
                                         synthetic_claim, synthetic_transaction_hash)
from offline_session.nom_verifier import NomPublicVerifier, CLEAN_EXECUTION_PROFILE
from scripts.generate_nom_created_funding import COMPLETIONS
from scripts.qualify_nom_created_core import inputs


def qualify(executable, *, root=ROOT):
    _, corpus, before = inputs(root)
    completions = json.loads((root / COMPLETIONS).read_text("ascii"))
    old = json.loads((root / "compatibility/fixtures/nom_completions_v1.json").read_text("ascii"))
    executable = executable.resolve()
    pin = hashlib.sha256(executable.read_bytes()).hexdigest()
    verifier = NomPublicVerifier(executable, pin, corpus["terms"], completions["pair"], execution_profile=CLEAN_EXECUTION_PROFILE)
    for leg in ("long", "short"):
        for signature in (old[leg + "_signature_hex"], completions[("short" if leg == "long" else "long") + "_signature_hex"]):
            try: verifier.verify_claim(leg, signature)
            except RecoveryError: pass
            else: raise RecoveryError("different public witness context was accepted")
    terms = corpus["terms"]
    short = synthetic_claim(terms, "short", completions["short_signature_hex"])
    long = synthetic_claim(terms, "long", completions["long_signature_hex"])
    funded = [observation(terms, leg, "funded") for leg in ("long", "short")]
    # These remain caller-selected confirmation claims. The later receive
    # inclusion time is not the method's acknowledged frontier timestamp.
    short_confirmed = observation(terms, "short", "unlock-confirmed", transaction_hash_hex=synthetic_transaction_hash(short),
                                  send_timestamp="900", send_momentum_hash_hex="aa" * 32,
                                  receive_timestamp="950", receive_momentum_hash_hex="bb" * 32)
    assert 100 < 900 < 950 < int(terms["short"]["expires_at"]) < int(terms["long"]["expires_at"])
    unseen = observation(terms, "short", "unseen", transaction_hash_hex=synthetic_transaction_hash(short))
    allowed = {canonical(proof) for proof in funded + [short_confirmed, unseen]}
    with tempfile.TemporaryDirectory(prefix="nom-created-public-") as directory:
        selected = Path(directory); selected.chmod(0o700)
        def open_store(role):
            return NomRecovery.open(selected / (role + ".log"), terms, completions["pair"], role=role,
                                    verifier=verifier, observation_verifier=lambda proof: canonical(proof) in allowed)
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
    if inputs(root)[2] != before or hashlib.sha256(executable.read_bytes()).hexdigest() != pin:
        raise RecoveryError("public qualification input changed")
    return {"schema": "ptlc-nom-created-reference-recovery-result-v1", "outcome": "PASS",
            "context_origin": "COMPUTED PUBLIC CREATE HASH INPUTS; NOT ADMITTED FUNDING",
            "context_ids_hex": {leg: corpus["terms"][leg]["entry_id_hex"] for leg in ("long", "short")},
            "execution_profile": CLEAN_EXECUTION_PROFILE, "public_worker_sha256": pin,
            "receive_confirmation_is_execution_context": False,
            "original_recovery": {"two_journal_original_recovery": "verified",
                                  "observation_source": "synthetic-reference-only",
                                  "declared_short_send_timestamp": "900", "declared_short_receive_timestamp": "950"},
            "old_and_cross_leg_completions": "REFUSED",
            "core_journal_composition": "NOT_PERFORMED", "source_authentication": "UNFILLED",
            "canonicality": "UNFILLED", "finality": "UNFILLED", "rollback_protection": "UNFILLED",
            "application": "NO-GO", "core": "NO-GO", "input_sha256": before}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executable", type=Path, default=ROOT / "qualification/target/debug/examples/verify_nom_swap")
    args = parser.parse_args()
    try: print(json.dumps(qualify(args.executable), sort_keys=True)); return 0
    except (OSError, ValueError, TypeError, KeyError, RecoveryError, AssertionError):
        print("FAIL: created-funding public reference recovery", file=sys.stderr); return 1


if __name__ == "__main__": sys.exit(main())
