"""Prepare a selected public leg for a separate public-only crypto checker.

Preparation checks declared projection consistency and derives the exact message.
It neither verifies the supplied curve relation nor authenticates chain facts.
"""

import hashlib
import json

from offline_session.pr138 import PROFILE, CompatibilityError, fixed_hex, unlock_message
from reference_client.agreement import REQUEST_SCHEMA as FUNDING_REQUEST_SCHEMA, bind_funding
from reference_client.plan import canonical


SCHEMA = "ptlc-nom-client-prepare-presignature-v1"
BACKEND = "schnorr_fun-encrypted-v1"
BACKEND_COMMIT = "74d18bbf864f98e5cf7c18dcfb74ba1ecfe837ce"
MAX_CRYPTO_REQUEST = 8192
RESULT_INSPECTION_SCHEMA = "ptlc-nom-client-inspect-presignature-result-v1"
MAX_CRYPTO_RESULT = 4096


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


def inspect_presignature_result(value):
    """Associate a supplied claim with a locally rederived public request.

    A matching JSON claim can be fabricated. This function neither runs the
    backend nor establishes mathematical validity, execution or provenance.
    """
    if (type(value) is not dict or value.keys() != {
            "schema", "preparation", "result_json"}
            or value["schema"] != RESULT_INSPECTION_SCHEMA):
        raise CompatibilityError("unexpected public result inspection")
    canonical(value)
    prepared = prepare_presignature(value["preparation"])
    text = value["result_json"]
    if type(text) is not str or not 0 < len(text) <= MAX_CRYPTO_RESULT:
        raise CompatibilityError("public crypto result exceeds its boundary")
    try:
        raw = text.encode("ascii")
        supplied = json.loads(raw)
    except (UnicodeError, ValueError, RecursionError) as error:
        raise CompatibilityError("invalid supplied public result") from error
    expected = dict(schema="ptlc-nom-client-presignature-result-v1",
        request_digest_hex=prepared["request_digest_hex"],
        context_digest_hex=prepared["crypto_request"]["context_digest_hex"],
        presignature_valid=True, scope="PUBLIC_MATHEMATICS_ONLY",
        action_permission="NONE", application="NO-GO", core="NO-GO",
        independent_assessment="UNFILLED", context_authentication="NOT_VERIFIED",
        chain_state="NOT_VERIFIED", signer_safety="NOT_ASSESSED")
    # Canonical roundtrip also refuses duplicate fields and alternate framing.
    # Exact boolean type prevents a JSON integer from posing as the claim.
    if (type(supplied) is not dict or supplied != expected
            or supplied["presignature_valid"] is not True or canonical(supplied) != raw):
        raise CompatibilityError("public result does not match the declared request")
    return dict(schema="ptlc-nom-client-inspected-presignature-result-v1",
        association="MATCHING_DECLARED_REQUEST", leg=prepared["leg"],
        agreement_digest_hex=prepared["agreement_digest_hex"],
        declared_entry_id_hex=prepared["declared_entry_id_hex"],
        request_digest_hex=prepared["request_digest_hex"],
        context_digest_hex=expected["context_digest_hex"],
        supplied_result_digest_hex=hashlib.sha256(raw).hexdigest(),
        supplied_claim="PUBLIC_RELATION_VALID", verification="NOT_PERFORMED",
        backend_execution="NOT_ESTABLISHED", context_authentication="NOT_VERIFIED",
        chain_state="DECLARED_ONLY", outer_signature="NOT_VERIFIED",
        contract_execution="NOT_VERIFIED", signer_safety="NOT_ASSESSED",
        timing_policy="UNSELECTED", action_permission="NONE", application="NO-GO",
        core="NO-GO", independent_assessment="UNFILLED")
