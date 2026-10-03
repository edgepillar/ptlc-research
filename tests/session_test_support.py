"""Public fixture helpers shared by offline session qualification tests."""

import json
from pathlib import Path

from offline_session.transcript import (
    agree_terms, bind_bitcoin, bind_zenon, commit_nonce_round, reveal_nonce_round, signing_context,
)


def session_context(purpose="zenon-claim-complete", *, dynamic=False):
    data = json.loads((Path(__file__).parent / "fixtures" / "session_terms.json").read_text("ascii"))
    terms = agree_terms(data["terms"])
    bitcoin = bind_bitcoin(terms, data["bitcoin_binding"])
    binding = bind_zenon(bitcoin, data["zenon_binding"]) if purpose.startswith("zenon-") else bitcoin
    role = "bob" if purpose == "bitcoin-claim-complete" else "alice"
    nonce_round = None
    if dynamic:
        fixture = Path(__file__).resolve().parents[1] / "qualification" / "fixtures" / "nonce_rounds.json"
        vectors = json.loads(fixture.read_text("ascii"))["vectors"]
        vector = next(item for item in vectors if item["leg"] == binding.stage)
        commitments = commit_nonce_round(binding, vector["round_id_hex"], *vector["nonce_commitments_hex"])
        nonce_round = reveal_nonce_round(commitments, *vector["public_nonces_hex"])
    return terms, signing_context(binding, role=role, purpose=purpose, nonce_round=nonce_round)


OPERATION_ID = "31" * 32
NONCE_TAG = "42" * 32
PUBLIC_OUTPUT = b"synthetic-public-output-v1"
