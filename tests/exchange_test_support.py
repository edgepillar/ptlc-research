"""Shared public exchange fixtures and an explicitly noncryptographic test verifier."""

import json
from pathlib import Path

from offline_session.exchange import RESULT_SCHEMA, request_digest
from offline_session.transcript import (
    agree_terms, bind_bitcoin, bind_zenon, commit_nonce_round, reveal_nonce_round, signing_context,
)


def artifacts():
    root = Path(__file__).resolve().parents[1]
    fixture = json.loads((root / "tests/fixtures/session_terms.json").read_text("ascii"))
    rounds = json.loads((root / "qualification/fixtures/nonce_rounds.json").read_text("ascii"))["vectors"]
    terms = agree_terms(fixture["terms"])
    bitcoin = bind_bitcoin(terms, fixture["bitcoin_binding"])
    bindings = (bitcoin, bind_zenon(bitcoin, fixture["zenon_binding"]))
    contexts, bundles = [], []
    for binding, vector in zip(bindings, rounds):
        committed = commit_nonce_round(binding, vector["round_id_hex"], *vector["nonce_commitments_hex"])
        nonce_round = reveal_nonce_round(committed, *vector["public_nonces_hex"])
        contexts.append(signing_context(binding, "bob", binding.stage + "-claim-partial", nonce_round=nonce_round))
        bundles.append({field: vector[field] for field in ("partial_signatures_hex", "adaptor_presignature_hex")})
    return (terms, *contexts, *bundles)


def accepted(request):
    """A fake verifier for sequencing tests only; it performs no cryptography."""
    return {"schema": RESULT_SCHEMA, "request_digest_hex": request_digest(request), "valid": True}


def prepare(journal, *, verifier=accepted, recovery_limit=8, authentication_pins=None):
    terms, bitcoin, zenon, btc_bundle, znn_bundle = artifacts()
    journal.create_session(terms.session_id, terms.digest_hex)
    journal.start_exchange(terms.session_id, bitcoin, recovery_limit=recovery_limit,
                           authentication_pins=authentication_pins)
    journal.retain_exchange_bitcoin(terms.session_id, btc_bundle, verifier=verifier)
    journal.bind_exchange_zenon(terms.session_id, zenon)
    journal.retain_exchange_alice_partial(terms.session_id, znn_bundle["partial_signatures_hex"][0], verifier=verifier)
    journal.retain_exchange_zenon(terms.session_id, znn_bundle, verifier=verifier)
    return terms.session_id
