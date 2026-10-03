"""Public completion fixtures; fake callbacks are not cryptographic evidence."""

import json
from pathlib import Path

from offline_session import completion, exchange
from exchange_test_support import accepted, artifacts


def final_signatures():
    root = Path(__file__).resolve().parents[1]
    vectors = json.loads((root / "qualification/fixtures/nonce_rounds.json").read_text("ascii"))["vectors"]
    return bytes.fromhex(vectors[1]["signature_hex"]), bytes.fromhex(vectors[0]["signature_hex"])


def released_bob():
    _, bitcoin, zenon, btc_bundle, znn_bundle = artifacts()
    state = exchange.start(bitcoin)
    state = exchange.retain_bitcoin(state, btc_bundle, accepted)
    state = exchange.bind_zenon(state, zenon)
    state = exchange.retain_alice_partial(state, znn_bundle["partial_signatures_hex"][0], accepted)
    state = exchange.retain_zenon(state, znn_bundle, accepted)
    return exchange.release(state)[0]


def bob_release():
    return exchange.replay(released_bob())


def alice_context():
    return completion.recontext(artifacts()[2], "alice", "zenon-claim-partial")


def completion_accepted(request):
    """Fake sequencing callback: only the integration executable verifies math."""
    return {"schema": completion.RESULT_SCHEMA, "request_digest_hex": completion.request_digest(request),
            "valid": True, "bitcoin_signature_hex": "" if request["kind"] == "verify-zenon-completion" else final_signatures()[1].hex()}


recovery_accepted = completion_accepted


def alice_ready():
    state = completion.start(alice_context(), artifacts()[4]["partial_signatures_hex"][0], accepted)
    return completion.accept_release(state, bob_release(), accepted)


def alice_packet():
    return completion.record(completion.consume(alice_ready()), final_signatures()[0], completion_accepted)[1]


def prepare_alice(journal, *, verifier=accepted, release_packet=None):
    terms, _, _, _, znn_bundle = artifacts()
    journal.create_session(terms.session_id, terms.digest_hex)
    journal.start_alice(terms.session_id, alice_context(), znn_bundle["partial_signatures_hex"][0], verifier=verifier)
    journal.accept_alice_release(terms.session_id, bob_release() if release_packet is None else release_packet, verifier=verifier)
    return terms.session_id
