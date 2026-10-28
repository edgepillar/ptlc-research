"""Prepare a selected public leg for a separate public-only crypto checker.

Preparation checks declared projection consistency and derives the exact message.
It neither verifies the supplied curve relation nor authenticates chain facts.
"""

import hashlib

from offline_session.pr138 import PROFILE, CompatibilityError, fixed_hex, unlock_message
from reference_client.agreement import REQUEST_SCHEMA as FUNDING_REQUEST_SCHEMA, bind_funding
from reference_client.plan import canonical


SCHEMA = "ptlc-nom-client-prepare-presignature-v1"
BACKEND = "schnorr_fun-encrypted-v1"
BACKEND_COMMIT = "74d18bbf864f98e5cf7c18dcfb74ba1ecfe837ce"
MAX_CRYPTO_REQUEST = 8192


def prepare_presignature(value):
    if (type(value) is not dict or value.keys() != {
            "schema", "agreement", "bindings", "leg", "presignature"}
            or value["schema"] != SCHEMA):
        raise CompatibilityError("unexpected public presignature preparation")
    canonical(value)
    records = value["bindings"]
    if type(records) is not list or not 1 <= len(records) <= 2:
        raise CompatibilityError("a declared funding binding is required")
    # Replaying the last record rechecks the complete ordered prefix. It creates
    # no missing entry, transaction, curve proof, chain fact or action permission.
    checked = bind_funding(dict(schema=FUNDING_REQUEST_SCHEMA,
        agreement=value["agreement"], bindings=records, funding=records[-1]))
    name = value["leg"]
    if type(name) is not str or name not in ("long", "short"):
        raise CompatibilityError("invalid public leg selection")
    record = next((item for item in checked["bindings"] if item["leg"] == name), None)
    if record is None:
        raise CompatibilityError("the selected leg has no declared funding binding")
    supplied = value["presignature"]
    if (type(supplied) is not dict or supplied.keys() != {
            "r_x_hex", "s_hat_hex", "needs_negation"}
            or type(supplied["needs_negation"]) is not bool):
        raise CompatibilityError("unexpected selected-backend presignature")
    fixed_hex(supplied["r_x_hex"], 32)
    fixed_hex(supplied["s_hat_hex"], 32)
    agreement = checked["agreement"]
    leg = agreement[name]
    context = dict(profile=PROFILE, chain_id=agreement["chain_id"], point_type=1,
        entry_id_hex=record["entry_projection"]["entry_id_hex"],
        destination_hex=agreement[leg["recipient"] + "_address_hex"])
    # A leg remains bound to its own exact Create declaration and to the entire
    # economic agreement when the other leg is appended later. The digest is a
    # local commitment, not an authenticated peer statement or durable journal.
    committed = dict(agreement_digest_hex=checked["agreement_digest_hex"],
        leg=name, funding=record)
    context_digest = hashlib.sha256(b"ptlc-nom-client-public-leg-v1\0" + canonical(committed)).hexdigest()
    request = dict(schema="ptlc-nom-client-presignature-check-v1", backend=BACKEND,
        backend_commit=BACKEND_COMMIT, context_digest_hex=context_digest,
        key_xonly_hex=leg["funder_key_xonly_hex"], message_hex=unlock_message(context),
        adaptor_point_sec1_hex=agreement["adaptor_point_sec1_hex"],
        presignature=dict(supplied))
    raw = canonical(request)
    if len(raw) > MAX_CRYPTO_REQUEST:
        raise CompatibilityError("public crypto request exceeds its boundary")
    return dict(schema="ptlc-nom-client-prepared-presignature-v1", crypto_request=request,
        request_digest_hex=hashlib.sha256(raw).hexdigest(), leg=name,
        agreement_digest_hex=checked["agreement_digest_hex"],
        declared_entry_id_hex=record["entry_projection"]["entry_id_hex"],
        verification="NOT_PERFORMED; USE SELECTED PUBLIC-ONLY BACKEND",
        context_authentication="NOT_VERIFIED", chain_state="DECLARED_ONLY",
        outer_signature="NOT_VERIFIED", contract_execution="NOT_VERIFIED",
        timing_policy="UNSELECTED", action_permission="NONE", application="NO-GO",
        core="NO-GO", independent_assessment="UNFILLED")
