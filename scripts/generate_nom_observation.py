#!/usr/bin/env python3
"""Generate public synthetic structural claims and independent source controls.

No signer is used. The old public BIP340 witness belongs to the old synthetic
entry id, not the newly computed Create hash. MATCH is never authentication.
"""

import copy
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from offline_session.nom_observation import PROFILE, ROLES, SUCCESS_DATA
from offline_session.nom_wire import account_block_hash, encode_call, decode_call
from offline_session.pr138 import CORE_COMMIT, CONTRACT_HEX


def tag(label):
    return hashlib.sha3_256(("public-nom-observation:" + label).encode("ascii")).hexdigest()


def corpus():
    old = json.loads((ROOT / "compatibility/fixtures/nom_terms_v1.json").read_text("ascii"))
    signatures = json.loads((ROOT / "compatibility/fixtures/nom_completions_v1.json").read_text("ascii"))
    leg = old["long"]
    terms = {"chain_id": old["chain_id"], "funder_hex": old["alice_address_hex"],
             "recipient_hex": old["bob_address_hex"], "token_standard_hex": leg["token_standard_hex"],
             "amount": leg["amount"], "expiration_time": leg["expires_at"], "point_type": 1,
             "point_lock_hex": leg["funder_key_xonly_hex"]}
    def ctx(name, height, timestamp):
        return {"hash_hex": tag(name), "height": str(height), "timestamp": str(timestamp)}
    contexts = {"funding_confirmation": ctx("funding-context", 100, 100),
                "original_confirmation": ctx("unlock-context", 110, 700),
                "payout_confirmation": ctx("payout-context", 111, 710),
                "recipient_confirmation": ctx("receipt-context", 112, 720)}
    view = ctx("selected-view-claim", 120, 800)
    zero_hash, zero_address, zero_token = "00" * 32, "00" * 20, "00" * 10
    def record(kind, address, height, previous, momentum, *, to=zero_address, amount="0", token=zero_token,
               from_hash=zero_hash, data="", descendants=None):
        block = {"version": "1", "chain_id": terms["chain_id"], "block_type": str(kind),
                 "address_hex": address, "height": str(height), "previous_hash_hex": previous,
                 "momentum_hash_hex": momentum["hash_hex"], "momentum_height": momentum["height"],
                 "to_address_hex": to, "amount": amount, "token_standard_hex": token,
                 "from_block_hash_hex": from_hash, "descendant_hashes_hex": descendants or [], "data_hex": data,
                 "fused_plasma": "0", "difficulty": "0", "nonce_hex": "00" * 8}
        return {"block": block, "hash_hex": account_block_hash(block)}
    create = {"method": "Create", "expiration_time": terms["expiration_time"], "point_type": 1,
              "point_lock_hex": terms["point_lock_hex"], "destination_hex": terms["recipient_hex"]}
    funding = record(2, terms["funder_hex"], 7, tag("funder-previous"), ctx("funding-ack", 99, 90),
                     to=CONTRACT_HEX, amount=terms["amount"], token=terms["token_standard_hex"],
                     data=encode_call(create).hex())
    funding_receive = record(5, CONTRACT_HEX, 10, tag("contract-previous"), contexts["funding_confirmation"],
                             from_hash=funding["hash_hex"], data=SUCCESS_DATA)
    original = record(2, terms["recipient_hex"], 4, tag("recipient-previous"), contexts["funding_confirmation"],
                      to=CONTRACT_HEX, data=encode_call({"method": "Unlock", "entry_id_hex": funding["hash_hex"],
                                                       "witness_hex": signatures["long_signature_hex"]}).hex())
    payout = record(4, CONTRACT_HEX, 11, funding_receive["hash_hex"], contexts["original_confirmation"],
                    to=terms["recipient_hex"], amount=terms["amount"], token=terms["token_standard_hex"])
    parent = record(5, CONTRACT_HEX, 12, payout["hash_hex"], contexts["original_confirmation"],
                    from_hash=original["hash_hex"], data=SUCCESS_DATA, descendants=[payout["hash_hex"]])
    receipt = record(3, terms["recipient_hex"], 5, original["hash_hex"], contexts["payout_confirmation"],
                     from_hash=payout["hash_hex"])
    entry = {"id_hex": funding["hash_hex"], "time_locked_hex": terms["funder_hex"],
             "token_standard_hex": terms["token_standard_hex"], "amount": terms["amount"],
             "expiration_time": terms["expiration_time"], "point_type": 1,
             "point_lock_hex": terms["point_lock_hex"], "destination_hex": terms["recipient_hex"]}
    baseline = {"schema": "zenon-nom-observation-claim-v1", "profile": PROFILE, "core_commit": CORE_COMMIT,
                "records": dict(zip(ROLES, (funding, funding_receive, original, payout, parent, receipt))),
                "entry": entry, "contexts": contexts, "view": view, "post_entry_present": False}

    def refresh(value):
        records = value["records"]
        old_hashes = {name: item["hash_hex"] for name, item in records.items() if item is not None}
        def link(role, field, target):
            if records[role] is not None and records[target] is not None:
                block = records[role]["block"]
                if block[field] == old_hashes[target]:
                    block[field] = records[target]["hash_hex"]
        def seal(role):
            if records[role] is not None:
                records[role]["hash_hex"] = account_block_hash(records[role]["block"])
        seal("funding")
        if value["entry"] is not None and value["entry"]["id_hex"] == old_hashes.get("funding"):
            value["entry"]["id_hex"] = records["funding"]["hash_hex"]
        link("funding_receive", "from_block_hash_hex", "funding"); seal("funding_receive")
        if records["original"] is not None and records["funding"] is not None:
            try:
                call = decode_call(bytes.fromhex(records["original"]["block"]["data_hex"]))
                if call.get("entry_id_hex") == old_hashes["funding"]:
                    call["entry_id_hex"] = records["funding"]["hash_hex"]
                    records["original"]["block"]["data_hex"] = encode_call(call).hex()
            except ValueError:
                pass
        seal("original")
        link("payout", "previous_hash_hex", "funding_receive"); seal("payout")
        link("contract_receive", "from_block_hash_hex", "original")
        link("contract_receive", "previous_hash_hex", "payout")
        if records["contract_receive"] is not None and records["payout"] is not None:
            hashes = records["contract_receive"]["block"]["descendant_hashes_hex"]
            records["contract_receive"]["block"]["descendant_hashes_hex"] = [
                records["payout"]["hash_hex"] if h == old_hashes["payout"] else h for h in hashes]
        seal("contract_receive")
        link("recipient_receive", "from_block_hash_hex", "payout")
        link("recipient_receive", "previous_hash_hex", "original"); seal("recipient_receive")

    vectors = []
    def add(name, mutate=None, *, structure="REFUSED", reason, seal=True, select_view=False):
        claim = copy.deepcopy(baseline)
        if mutate is not None: mutate(claim)
        if seal: refresh(claim)
        vectors.append({"id": name, "claim": claim, "selected_view_claim": copy.deepcopy(claim["view"] if select_view else view),
                        "expect_structure": structure, "expect_reason": reason})
    add("complete-unsigned-structure", structure="MATCH", reason="STRUCTURAL_CLAIMS_ONLY")
    add("matching-peer-claims-still-unauthenticated", structure="MATCH", reason="STRUCTURAL_CLAIMS_ONLY")
    add("self-selected-fork-still-matches", lambda c: c["view"].update(hash_hex=tag("other-fork")),
        structure="MATCH", reason="STRUCTURAL_CLAIMS_ONLY", select_view=True)
    for name in ROLES:
        add("missing-" + name, lambda c, name=name: c["records"].update({name: None}),
            structure="INCOMPLETE", reason="ABSENCE_IS_NOT_OUTCOME")
    add("missing-entry", lambda c: c.update(entry=None), structure="INCOMPLETE", reason="ABSENCE_IS_NOT_OUTCOME")
    add("entry-absence-and-empty-history", lambda c: c.update(entry=None, records=dict.fromkeys(ROLES)),
        structure="INCOMPLETE", reason="ABSENCE_IS_NOT_OUTCOME")
    def block_change(role, **fields):
        return lambda c: c["records"][role]["block"].update(fields)
    add("wrong-funder", block_change("funding", address_hex=terms["recipient_hex"]), reason="FUNDING_TERMS")
    add("wrong-funding-amount", block_change("funding", amount="101"), reason="FUNDING_TERMS")
    def call_change(role, **fields):
        def change(c):
            call = decode_call(bytes.fromhex(c["records"][role]["block"]["data_hex"]))
            call.update(fields); c["records"][role]["block"]["data_hex"] = encode_call(call).hex()
        return change
    add("wrong-create-recipient", call_change("funding", destination_hex=terms["funder_hex"]), reason="CREATE_TERMS")
    for field, changed in (("id_hex", tag("wrong-entry")), ("time_locked_hex", terms["recipient_hex"]),
                           ("amount", "101"), ("token_standard_hex", "02" * 10), ("expiration_time", "2001"),
                           ("point_type", 0), ("point_lock_hex", "00" * 32), ("destination_hex", terms["funder_hex"])):
        add("entry-change-" + field, lambda c, field=field, changed=changed: c["entry"].update({field: changed}), reason="ENTRY_TERMS")
    add("wrong-original-entry", call_change("original", entry_id_hex=tag("wrong-entry")), reason="SELECTED_UNLOCK_CALL")
    add("wrong-original-witness-width", call_change("original", witness_hex="ab" * 32), reason="SELECTED_UNLOCK_CALL")
    add("wrong-original-caller", block_change("original", address_hex=terms["funder_hex"]), reason="ORIGINAL_TERMS")
    add("aliased-original-is-not-normalized", lambda c: c["records"]["original"]["block"].update(
        data_hex=c["records"]["original"]["block"]["data_hex"] + "00" * 32), reason="INVALID_PUBLIC_ENCODING")
    add("wrong-contract-from-hash", block_change("contract_receive", from_block_hash_hex=tag("wrong-send")), reason="CONTRACT_RECEIVE_LINK")
    add("wrong-confirming-height", block_change("contract_receive", momentum_height="111"), reason="CONFIRMING_CONTEXT")
    add("same-height-wrong-confirming-hash", block_change("contract_receive", momentum_hash_hex=tag("other-fork")), reason="CONFIRMING_CONTEXT")
    for role in ("funding_receive", "contract_receive"):
        add(role + "-failed-status", block_change(role, data_hex="0000000000000002"), reason="EXECUTION_STATUS_CLAIM")
    add("changed-child-retains-advertised-hash", block_change("payout", amount="101"), reason="ADVERTISED_HASH_MISMATCH", seal=False)
    add("wrong-payout-recipient", block_change("payout", to_address_hex=terms["funder_hex"]), reason="PAYOUT_TERMS")
    add("wrong-payout-token", block_change("payout", token_standard_hex="02" * 10), reason="PAYOUT_TERMS")
    add("wrong-payout-amount", block_change("payout", amount="101"), reason="PAYOUT_TERMS")
    add("wrong-child-context", block_change("payout", momentum_hash_hex=tag("other-fork")), reason="DESCENDANT_CONTEXT")
    add("wrong-child-account-link", block_change("payout", previous_hash_hex=tag("wrong-previous")), reason="CONTRACT_ACCOUNT_LINK")
    add("wrong-parent-account-link", block_change("contract_receive", previous_hash_hex=tag("wrong-previous")), reason="CONTRACT_ACCOUNT_LINK")
    add("extra-advertised-child", block_change("contract_receive", descendant_hashes_hex=[payout["hash_hex"], tag("extra-child")]), reason="DESCENDANT_CLAIMS")
    add("wrong-recipient-from-hash", block_change("recipient_receive", from_block_hash_hex=tag("wrong-payout")), reason="RECIPIENT_RECEIVE_LINK")
    add("wrong-recipient-address", block_change("recipient_receive", address_hex=terms["funder_hex"]), reason="RECIPIENT_RECEIVE_LINK")
    add("wrong-recipient-account-link", block_change("recipient_receive", previous_hash_hex=tag("wrong-previous")), reason="RECIPIENT_ACCOUNT_LINK")
    add("recipient-before-payout-confirmation", block_change("recipient_receive", momentum_height="110"), reason="RECEIPT_CONFIRMATION_ORDER")
    for role in ("original", "recipient_receive"):
        add(role + "-known-height-wrong-ack-hash", block_change(role, momentum_hash_hex=tag("other-fork")), reason="ACKNOWLEDGEMENT_HASH_CLAIM")
    add("selected-view-fork", lambda c: c["view"].update(hash_hex=tag("other-fork")), reason="SELECTED_VIEW_MISMATCH")
    add("entry-presence-conflicts-with-terminal-claim", lambda c: c.update(post_entry_present=True), reason="ENTRY_STATE_CONFLICT")
    def expired(c):
        for name, at in (("original_confirmation", "2000"), ("payout_confirmation", "2001"), ("recipient_confirmation", "2002")):
            c["contexts"][name]["timestamp"] = at
        c["view"]["timestamp"] = "2003"
    add("unlock-at-expiry-context", expired, reason="EXPIRED_EXECUTION_CONTEXT", select_view=True)

    seed_entry = copy.deepcopy(entry); seed_entry["id_hex"] = leg["entry_id_hex"]
    stateful = []
    def state(name, origin, method, at, error="NONE", *, caller=None, destination=None,
              chain=None, witness=None, after=True, payout_to=None):
        stateful.append({"id": name, "entry_origin": origin, "method": method, "timestamp": str(at),
                         "caller_hex": caller or terms["recipient_hex"], "destination_hex": destination or terms["recipient_hex"],
                         "chain_id": chain or terms["chain_id"], "witness_hex": witness or signatures["long_signature_hex"],
                         "expect_error": error, "expect_entry_after": after, "expect_payout_to_hex": payout_to})
    state("create-store-send-hash", "none", "Create", 100, caller=terms["funder_hex"])
    state("create-at-expiry", "none", "Create", 2000, "ErrInvalidExpirationTime", caller=terms["funder_hex"], after=False)
    state("created-reclaim-before-expiry", "created", "Reclaim", 1999, "ReclaimNotDue", caller=terms["funder_hex"])
    state("created-reclaim-at-expiry", "created", "Reclaim", 2000, caller=terms["funder_hex"], after=False, payout_to=terms["funder_hex"])
    state("created-reclaim-after-expiry", "created", "Reclaim", 2001, caller=terms["funder_hex"], after=False, payout_to=terms["funder_hex"])
    state("created-reclaim-wrong-caller", "created", "Reclaim", 2000, "ErrPermissionDenied")
    state("created-id-refuses-old-witness", "created", "Unlock", 700, "ErrInvalidPointSignature")
    state("seeded-unlock-before-expiry", "seeded", "Unlock", 1999, after=False, payout_to=terms["recipient_hex"])
    state("seeded-unlock-at-expiry", "seeded", "Unlock", 2000, "ErrExpired")
    state("seeded-proxy-fixed-recipient", "seeded", "ProxyUnlock", 700, caller=terms["funder_hex"], after=False, payout_to=terms["recipient_hex"])
    state("seeded-unlock-wrong-caller", "seeded", "Unlock", 700, "ErrPermissionDenied", caller=terms["funder_hex"])
    state("seeded-proxy-wrong-recipient", "seeded", "ProxyUnlock", 700, "ErrPermissionDenied", destination=terms["funder_hex"])
    invalid = bytearray.fromhex(signatures["long_signature_hex"]); invalid[0] ^= 1
    state("seeded-invalid-witness", "seeded", "Unlock", 700, "ErrInvalidPointSignature", witness=invalid.hex())
    state("seeded-wrong-chain", "seeded", "Unlock", 700, "ErrInvalidPointSignature", chain="70")
    state("seeded-reclaim-at-expiry", "seeded", "Reclaim", 2000, caller=terms["funder_hex"], after=False, payout_to=terms["funder_hex"])
    state("unknown-entry-unlock", "none", "Unlock", 700, "ErrDataNonExistent", after=False)
    verifier = ["all-public-record-hashes", "contract-confirming-context", "child-context-mismatch",
                "wrong-send-confirmation-height", "wrong-momentum-hash", "recipient-from-payout",
                "unconfirmed-payout", "missing-payout", "already-received-payout",
                "wrong-receiver-at-enforcement", "wrong-receiver-before-enforcement-helper-accepts", "receive-amount-refusal",
                "recipient-acknowledged-context", "recipient-known-height-wrong-ack-hash"]
    vm = ["funding-finalize", "unlock-child-before-parent", "failure-status-is-distinct", "account-header-is-only-a-claim"]
    return {"schema": "zenon-nom-observation-corpus-v1", "profile": PROFILE, "core_commit": CORE_COMMIT,
            "origin": "Public synthetic claims, unauthenticated contexts, no signer or account signatures.",
            "terms": terms, "baseline": baseline, "seed_entry": seed_entry, "claim_vectors": vectors,
            "stateful_vectors": stateful, "verifier_vectors": verifier, "vm_vectors": vm,
            "witness_boundary": "The structural baseline uses the old public witness under a different computed Create id. Source stateful verification rejects it. Successful witness cases use explicitly seeded old entries only.",
            "application": "NO-GO", "core": "NO-GO"}


if __name__ == "__main__":
    target = ROOT / "compatibility/fixtures/nom_observation_v1.json"
    target.write_text(json.dumps(corpus(), sort_keys=True, indent=2) + "\n", encoding="ascii")
