"""Staged public agreement and declared funding bindings, without invented IDs.

Account hash inputs and entry projections are supplied claims. Matching them
proves neither signatures, successful Create execution nor current chain state.
No signer, node, wallet, durable owner or action permission is implemented.
"""

import copy
import hashlib

from offline_session.nom_wire import account_block_hash, encode_call
from offline_session.pr138 import CONTRACT_HEX, CompatibilityError, decimal
from .plan import SCHEMA, _checked_terms, _create_call, canonical, inspect_terms


AGREEMENT_SCHEMA = "ptlc-nom-client-agreement-v1"
FUNDING_SCHEMA = "ptlc-nom-client-declared-funding-v1"
REQUEST_SCHEMA = "ptlc-nom-client-bind-funding-v1"
FUNDING_FIELDS = frozenset({"schema", "agreement_digest_hex", "leg", "account_block", "entry_projection"})


def _agreement(value):
    return _checked_terms(value, schema=AGREEMENT_SCHEMA, funded=False)


def _digest(domain, value):
    return hashlib.sha256(domain.encode("ascii") + b"\0" + canonical(value)).hexdigest()


def _boundary():
    return dict(action_permission="NONE", application="NO-GO", core="NO-GO",
                chain_state="DECLARED_ONLY", outer_signature="NOT_VERIFIED",
                contract_execution="NOT_VERIFIED", curve_points="NOT_VERIFIED",
                presignatures="NOT_VERIFIED", independent_assessment="UNFILLED")


def agreement_digest(value):
    return _digest(AGREEMENT_SCHEMA, _agreement(value))


def inspect_agreement(value):
    agreement = _agreement(value)
    calls = {name: _create_call(agreement, name) for name in ("long", "short")}
    return dict(schema="ptlc-nom-client-agreement-plan-v1", agreement=agreement,
                agreement_digest_hex=agreement_digest(agreement),
                phase="AGREEMENT_ONLY; NO FUNDING OR ENTRY CLAIMS",
                create_calls=calls,
                create_data_hex={name: encode_call(call).hex() for name, call in calls.items()},
                entry_ids="UNBOUND; DERIVE FROM EACH ACTUAL CREATE SEND",
                observation_policy="UNSELECTED", timing_policy="UNSELECTED", **_boundary())


def _funding(agreement, value, name):
    if type(value) is not dict or value.keys() != FUNDING_FIELDS:
        raise CompatibilityError("unexpected public funding fields")
    if (value["schema"] != FUNDING_SCHEMA or value["leg"] != name
            or value["agreement_digest_hex"] != agreement_digest(agreement)):
        raise CompatibilityError("funding is not bound to the selected agreement and leg")
    block = value["account_block"]
    entry_id = account_block_hash(block)
    leg = agreement[name]
    expected = dict(version="1", chain_id=agreement["chain_id"], block_type="2",
                    address_hex=agreement[leg["funder"] + "_address_hex"], to_address_hex=CONTRACT_HEX,
                    amount=leg["amount"], token_standard_hex=leg["token_standard_hex"],
                    from_block_hash_hex="00" * 32, descendant_hashes_hex=[],
                    data_hex=encode_call(_create_call(agreement, name)).hex())
    if any(block[field] != wanted for field, wanted in expected.items()):
        raise CompatibilityError("funding hash inputs conflict with the public agreement")
    height = decimal(block["height"], 64, positive=True)
    decimal(block["momentum_height"], 64, positive=True)
    if (block["previous_hash_hex"] == "00" * 32) != (height == 1):
        raise CompatibilityError("funding predecessor shape is inconsistent")
    entry = value["entry_projection"]
    wanted = dict(entry_id_hex=entry_id, creator_hex=expected["address_hex"],
                  point_type=1, point_lock_hex=leg["funder_key_xonly_hex"],
                  destination_hex=agreement[leg["recipient"] + "_address_hex"],
                  token_standard_hex=leg["token_standard_hex"], amount=leg["amount"],
                  expires_at=leg["expires_at"])
    if (type(entry) is not dict or entry.keys() != wanted.keys()
            or type(entry.get("point_type")) is not int or entry != wanted):
        raise CompatibilityError("declared entry does not match the Create hash and terms")
    return copy.deepcopy(value)


def bind_funding(value):
    """Append a declared long/short binding, or replay its exact public record.

    This is an offline projection transition. Its digest is a commitment to
    supplied public data, not authentication, nonrollback storage or permission.
    """
    if (type(value) is not dict or value.keys() != {"schema", "agreement", "bindings", "funding"}
            or value["schema"] != REQUEST_SCHEMA):
        raise CompatibilityError("unexpected public funding request")
    canonical(value)
    agreement = _agreement(value["agreement"])
    records = value["bindings"]
    if type(records) is not list or len(records) > 2:
        raise CompatibilityError("invalid public funding prefix")
    names = ("long", "short")
    retained = [_funding(agreement, record, names[i]) for i, record in enumerate(records)]
    incoming = value["funding"]
    if type(incoming) is not dict or type(incoming.get("leg")) is not str:
        raise CompatibilityError("invalid public funding leg")
    name = incoming["leg"]
    existing = next((record for record in retained if record["leg"] == name), None)
    if existing is not None:
        checked = _funding(agreement, incoming, name)
        if canonical(checked) != canonical(existing):
            raise CompatibilityError("a conflicting funding candidate cannot replace an original")
        transition = "EXACT_DECLARED_REPLAY"
    else:
        if len(retained) == 2 or name != names[len(retained)]:
            raise CompatibilityError("funding must bind the long leg before the short leg")
        retained.append(_funding(agreement, incoming, name))
        transition = "DECLARED_BINDING_APPENDED"
    plan = None
    if len(retained) == 2:
        terms = copy.deepcopy(agreement)
        terms["schema"] = SCHEMA
        for record in retained:
            terms[record["leg"]]["entry_id_hex"] = record["entry_projection"]["entry_id_hex"]
        plan = inspect_terms(terms)
    commitment = dict(agreement_digest_hex=agreement_digest(agreement), bindings=retained)
    return dict(schema="ptlc-nom-client-funding-prefix-v1", agreement=agreement,
                **commitment, binding_digest_hex=_digest("ptlc-nom-client-funding-prefix-v1", commitment),
                phase="DECLARED_BOTH_BOUND" if len(retained) == 2 else "DECLARED_LONG_BOUND",
                transition=transition, postfunding_plan=plan,
                replay_scope="CANONICAL PUBLIC PROJECTION; NOT ORIGINAL SIGNED WIRE",
                remaining_requirements=["authenticate-counterparty-agreement", "verify-presignatures",
                    "confirm-create-execution-and-current-live-entries", "select-observation-and-timing-policy",
                    "retain-exact-signed-originals-under-a-selected-owner"], **_boundary())
