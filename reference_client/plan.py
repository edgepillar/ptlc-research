"""Derive public calls and messages from declared post-funding terms.

This module performs encoding and structural checks only. It authenticates no
entry, curve point, node, funding, deadline or signer. It grants no action.
"""

import copy
import hashlib
import json

from offline_session.nom_wire import encode_call
from offline_session.pr138 import (
    CONTRACT_HEX, PROFILE, CompatibilityError, decimal, fixed_hex, payable,
    unlock_message, unlock_preimage,
)


SCHEMA = "ptlc-nom-client-terms-v1"
SOURCE_COMMIT = "77ba9c7ee8c881e90911946756cdb67d8b586043"
MAX_INPUT = 32768
FIELDS = frozenset({
    "schema", "source_commit", "session_id_hex", "chain_id", "genesis_hash_hex",
    "alice_address_hex", "bob_address_hex", "adaptor_point_sec1_hex",
    "minimum_expiry_gap_seconds", "long", "short",
})
LEG_FIELDS = frozenset({
    "entry_id_hex", "funder", "recipient", "funder_key_xonly_hex",
    "token_standard_hex", "amount", "expires_at",
})


def canonical(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=True, allow_nan=False).encode("ascii")
    if len(raw) > MAX_INPUT:
        raise CompatibilityError("public plan exceeds its boundary")
    return raw


def _checked_terms(terms, *, schema=SCHEMA, funded=True):
    """Check one selected public schema; no observation or signing is admitted."""
    if type(terms) is not dict or terms.keys() != FIELDS:
        raise CompatibilityError("unexpected public terms fields")
    if (terms["schema"] != schema or terms["source_commit"] != SOURCE_COMMIT
            or terms["chain_id"] != "69"):
        raise CompatibilityError("unsupported offline client profile")
    canonical(terms)
    for field in ("session_id_hex", "genesis_hash_hex"):
        fixed_hex(terms[field], 32)
    addresses = [terms[role + "_address_hex"] for role in ("alice", "bob")]
    if addresses[0] == addresses[1] or not all(payable(value) for value in addresses):
        raise CompatibilityError("distinct payable recipients are required")
    point = fixed_hex(terms["adaptor_point_sec1_hex"], 33)
    if point[0] not in (2, 3):
        raise CompatibilityError("invalid adaptor point encoding")
    gap = decimal(terms["minimum_expiry_gap_seconds"], 63, positive=True)
    for name, funder, recipient in (("long", "alice", "bob"), ("short", "bob", "alice")):
        leg = terms[name]
        expected = LEG_FIELDS if funded else LEG_FIELDS - {"entry_id_hex"}
        if type(leg) is not dict or leg.keys() != expected:
            raise CompatibilityError("unexpected public leg fields")
        if leg["funder"] != funder or leg["recipient"] != recipient:
            raise CompatibilityError("fixed-recipient roles do not match")
        if funded:
            fixed_hex(leg["entry_id_hex"], 32)
        fixed_hex(leg["funder_key_xonly_hex"], 32)
        fixed_hex(leg["token_standard_hex"], 10)
        decimal(leg["amount"], 256, positive=True)
        decimal(leg["expires_at"], 63, positive=True)
    if ((funded and terms["long"]["entry_id_hex"] == terms["short"]["entry_id_hex"])
            or terms["long"]["funder_key_xonly_hex"] == terms["short"]["funder_key_xonly_hex"]
            or int(terms["long"]["expires_at"]) - int(terms["short"]["expires_at"]) < gap):
        raise CompatibilityError("entry, key or expiry separation is invalid")
    return copy.deepcopy(terms)


def _create_call(terms, name):
    leg = terms[name]
    return dict(method="Create", expiration_time=leg["expires_at"], point_type=1,
                point_lock_hex=leg["funder_key_xonly_hex"],
                destination_hex=terms[leg["recipient"] + "_address_hex"])


def inspect_terms(terms):
    """Return a post-funding public projection, never an executable plan."""
    terms = _checked_terms(terms)
    legs = {}
    for name, funder, recipient in (("long", "alice", "bob"), ("short", "bob", "alice")):
        leg = terms[name]
        context = dict(profile=PROFILE, chain_id=terms["chain_id"], point_type=1,
                       entry_id_hex=leg["entry_id_hex"],
                       destination_hex=terms[recipient + "_address_hex"])
        create = _create_call(terms, name)
        legs[name] = dict(
            declared_entry_id_hex=leg["entry_id_hex"],
            funding_sender_hex=terms[funder + "_address_hex"],
            funding_to_hex=CONTRACT_HEX, funding_amount=leg["amount"],
            funding_token_standard_hex=leg["token_standard_hex"],
            create_call=create, create_data_hex=encode_call(create).hex(),
            unlock_context=context, unlock_preimage_hex=unlock_preimage(context).hex(),
            unlock_message_hex=unlock_message(context),
            direct_unlock_sender_hex=context["destination_hex"],
            reclaim_sender_hex=terms[funder + "_address_hex"],
            reclaim_data_hex=encode_call(dict(method="Reclaim", entry_id_hex=leg["entry_id_hex"])).hex(),
        )
    return dict(
        schema="ptlc-nom-client-public-plan-v1", source_commit=SOURCE_COMMIT,
        terms_digest_hex=hashlib.sha256(SCHEMA.encode("ascii") + b"\0" + canonical(terms)).hexdigest(),
        terms=copy.deepcopy(terms), legs=legs, action_permission="NONE",
        application="NO-GO", core="NO-GO", independent_assessment="UNFILLED",
        entry_status="DECLARED_ONLY", curve_points="NOT_VERIFIED",
        expiry_gap="DECLARED_ONLY; NO INCLUSION OR SAFETY GUARANTEE",
        required_event_order=[
            "agree-economic-terms-and-dedicated-keys-before-funding",
            "long-create-send-confirmation-and-successful-contract-receive",
            "bind-long-entry-and-verify-alice-presignature-before-short-funding",
            "short-create-send-confirmation-and-successful-contract-receive",
            "bind-short-entry-and-verify-bob-presignature-before-disclosure",
            "persist-possible-disclosure-before-short-unlock-leaves-process",
            "distinguish-send-confirmation-contract-execution-and-payout",
            "recover-long-under-selected-observation-and-inclusion-assumptions",
            "receive-exact-payouts-and-confirm-recipient-balances",
        ],
    )
