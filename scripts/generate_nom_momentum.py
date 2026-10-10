#!/usr/bin/env python3
"""Generate unsigned public momentum claims; no signer or network is used.

Existing observation headers are copied as opaque public claims. Their former
acknowledgement contexts are not composed with these new synthetic momenta.
"""

import copy
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from offline_session.nom_momentum import PROFILE, content_bytes, momentum_hash, momentum_preimage
from offline_session.pr138 import CORE_COMMIT


def tag(name):
    return hashlib.sha3_256(("public-nom-momentum:" + name).encode("ascii")).hexdigest()


def corpus():
    observation = json.loads((ROOT / "compatibility/fixtures/nom_observation_v1.json").read_text("ascii"))
    records = observation["baseline"]["records"]
    chain_id = observation["terms"]["chain_id"]
    headers = {name: {"address_hex": record["block"]["address_hex"], "height": record["block"]["height"],
                      "hash_hex": record["hash_hex"]} for name, record in records.items()}
    anchor = {"hash_hex": tag("untrusted-anchor"), "height": "100", "timestamp": "1000"}
    def make(previous, names, *, version="1"):
        block = {"version": version, "chain_id": chain_id, "previous_hash_hex": previous["hash_hex"],
                 "height": str(int(previous["height"]) + 1), "timestamp": str(int(previous["timestamp"]) + 10),
                 "data_hex": "", "content": [copy.deepcopy(headers[name]) for name in names],
                 "changes_hash_hex": tag("unexecuted-changes-" + previous["height"]),
                 "next_fusion_price": "0" if version == "1" else "1000",
                 "next_work_price": "0" if version == "1" else "1000"}
        return {"momentum": block, "hash_hex": momentum_hash(block),
                "public_key_hex": "00" * 32, "signature_hex": "00" * 64}
    def context(record):
        return {"hash_hex": record["hash_hex"], "height": record["momentum"]["height"],
                "timestamp": record["momentum"]["timestamp"]}
    first = make(anchor, ["funding", "funding_receive"])
    second = make(context(first), ["original", "payout", "contract_receive"])
    third = make(context(second), ["recipient_receive"])
    baseline = {"schema": "zenon-nom-momentum-claim-v1", "profile": PROFILE, "core_commit": CORE_COMMIT,
                "anchor": anchor, "momenta": [first, second, third]}
    inclusions = [{"id": name, "header": copy.deepcopy(headers[name]), "confirmation": context(record)}
                  for record, names in ((first, ("funding", "funding_receive")),
                                        (second, ("original", "payout", "contract_receive")),
                                        (third, ("recipient_receive",))) for name in names]
    def reseal(claim):
        previous = claim["anchor"]["hash_hex"]
        for record in claim["momenta"]:
            record["momentum"]["previous_hash_hex"] = previous
            record["hash_hex"] = momentum_hash(record["momentum"])
            previous = record["hash_hex"]
    def rematch(claim, required):
        by_height = {record["momentum"]["height"]: context(record) for record in claim["momenta"]}
        for item in required:
            if item["confirmation"]["height"] in by_height:
                item["confirmation"] = copy.deepcopy(by_height[item["confirmation"]["height"]])

    hash_vectors = []
    def raw(name, **changes):
        block = copy.deepcopy(first["momentum"])
        block.update(changes)
        data = content_bytes(block["content"])
        hash_vectors.append({"id": name, "momentum": block, "content_bytes_hex": data.hex(),
                             "content_hash_hex": hashlib.sha3_256(data).hexdigest(),
                             "preimage_hex": momentum_preimage(block).hex(), "hash_hex": momentum_hash(block)})
    raw("legacy-layout")
    raw("dynamic-layout", version="2", next_fusion_price="1000", next_work_price="2000")
    raw("empty-content", content=[])
    raw("supplied-content-order", content=list(reversed(first["momentum"]["content"])))
    raw("legacy-prices-not-hashed", next_fusion_price="999999", next_work_price="123456")
    raw("dynamic-fusion-price", version="2", next_fusion_price="1001", next_work_price="2000")
    raw("dynamic-work-price", version="2", next_fusion_price="1000", next_work_price="2001")
    raw("unadmitted-version-zero", version="0")
    raw("unadmitted-version-three", version="3", next_fusion_price="1000", next_work_price="2000")
    for field in ("version", "chain_id", "height", "timestamp", "next_fusion_price", "next_work_price"):
        changes = {"version": "2", "next_fusion_price": "1000", "next_work_price": "1000", field: str((1 << 64) - 1)}
        raw("uint64-max-" + field.replace("_", "-"), **changes)
    raw("raw-data", data_hex="01020304")
    raw("raw-data-bound", data_hex="ab" * 4096)
    raw("changed-previous", previous_hash_hex=tag("different-previous"))
    raw("changed-unexecuted-changes", changes_hash_hex=tag("different-changes"))
    for field, value in (("address_hex", "00" + "de" * 19), ("height", "8"), ("hash_hex", tag("other-header"))):
        content = copy.deepcopy(first["momentum"]["content"])
        content[0][field] = value
        raw("header-" + field.replace("_", "-"), content=content)
    raw("raw-duplicate-header-hashes", content=[headers["funding"], headers["funding"]])
    raw("raw-content-bound", content=[headers["funding"]] * 64)

    claim_vectors = []
    def add(name, mutate=None, *, structure="REFUSED", reason, seal=True, select=False, required_change=None):
        claim, required, selected_anchor = copy.deepcopy(baseline), copy.deepcopy(inclusions), copy.deepcopy(anchor)
        if mutate: mutate(claim)
        if seal: reseal(claim)
        if select: rematch(claim, required)
        if required_change: required_change(required)
        claim_vectors.append({"id": name, "claim": claim, "chain_id": chain_id, "selected_anchor_claim": selected_anchor,
                              "required_inclusions": required, "expect_structure": structure, "expect_reason": reason})
    add("complete-unsigned-branch", structure="MATCH", reason="STRUCTURAL_CLAIMS_ONLY")
    add("matching-forged-producer", lambda c: c["momenta"][1].update(public_key_hex="de" * 32, signature_hex="ad" * 64),
        structure="MATCH", reason="STRUCTURAL_CLAIMS_ONLY")
    add("self-selected-fork", lambda c: c["momenta"][1]["momentum"].update(changes_hash_hex=tag("forged-state")),
        structure="MATCH", reason="STRUCTURAL_CLAIMS_ONLY", select=True)
    add("ordered-header-membership", lambda c: c["momenta"][0]["momentum"]["content"].reverse(),
        structure="MATCH", reason="STRUCTURAL_CLAIMS_ONLY", select=True)
    add("dynamic-layout-not-spork-proof", lambda c: c["momenta"][1]["momentum"].update(
        version="2", next_fusion_price="1000", next_work_price="1000"),
        structure="MATCH", reason="STRUCTURAL_CLAIMS_ONLY", select=True)
    def change(**values):
        return lambda c: c["momenta"][1]["momentum"].update(values)
    add("advertised-hash-mismatch", lambda c: c["momenta"][1].update(hash_hex=tag("lie")),
        reason="ADVERTISED_HASH_MISMATCH", seal=False)
    add("changed-child-header-retains-momentum-hash", lambda c: c["momenta"][1]["momentum"]["content"][1].update(hash_hex=tag("lie")),
        reason="ADVERTISED_HASH_MISMATCH", seal=False)
    add("wrong-anchor", lambda c: c["anchor"].update(hash_hex=tag("other-anchor")), reason="ANCHOR_MISMATCH")
    add("wrong-chain", change(chain_id="999"), reason="CHAIN_ID_MISMATCH")
    add("height-gap", change(height="104"), reason="PREVIOUS_CONTEXT")
    add("wrong-previous-hash", change(previous_hash_hex=tag("other-previous")), reason="PREVIOUS_CONTEXT", seal=False)
    # A valid raw hash with a wrong previous binding is different from a stale advertised hash.
    claim_vectors[-1]["claim"]["momenta"][1]["hash_hex"] = momentum_hash(claim_vectors[-1]["claim"]["momenta"][1]["momentum"])
    add("equal-timestamp", change(timestamp="1010"), reason="TIMESTAMP_ORDER")
    add("backward-timestamp", change(timestamp="1009"), reason="TIMESTAMP_ORDER")
    add("timestamp-not-signed-int64", change(timestamp=str(1 << 63)), reason="INVALID_PUBLIC_ENCODING")
    add("unselected-version-three", change(version="3"), reason="UNSELECTED_VERSION")
    add("unselected-version-zero", change(version="0"), reason="UNSELECTED_VERSION")
    add("legacy-price-digest-alias", change(next_fusion_price="1000"), reason="SOURCE_PRICE_RULE")
    add("legacy-work-price-digest-alias", change(next_work_price="1000"), reason="SOURCE_PRICE_RULE")
    add("dynamic-fusion-below-source-floor", change(version="2", next_fusion_price="999", next_work_price="1000"), reason="SOURCE_PRICE_RULE")
    add("dynamic-work-below-source-floor", change(version="2", next_fusion_price="1000", next_work_price="0"), reason="SOURCE_PRICE_RULE")
    add("nonempty-data-hashes-but-is-not-admitted", change(data_hex="01"), reason="SOURCE_DATA_RULE")
    add("duplicate-content-identifier", lambda c: c["momenta"][1]["momentum"]["content"].append(copy.deepcopy(headers["payout"])),
        reason="DUPLICATE_CONTENT_IDENTIFIER")
    def duplicate_address(c):
        duplicate = copy.deepcopy(headers["payout"]); duplicate["address_hex"] = headers["original"]["address_hex"]
        c["momenta"][1]["momentum"]["content"].append(duplicate)
    add("same-identifier-other-address", duplicate_address, reason="DUPLICATE_CONTENT_IDENTIFIER")
    add("repeated-header-later-momentum", lambda c: c["momenta"][2]["momentum"]["content"].append(copy.deepcopy(headers["payout"])),
        reason="REPEATED_BRANCH_HEADER")
    add("missing-header", lambda c: c["momenta"][1]["momentum"]["content"].pop(1),
        structure="INCOMPLETE", reason="ABSENCE_IS_NOT_OUTCOME", select=True)
    add("wrong-required-header-address", structure="INCOMPLETE", reason="ABSENCE_IS_NOT_OUTCOME",
        required_change=lambda r: r[2]["header"].update(address_hex=headers["funding"]["address_hex"]))
    add("wrong-confirming-hash", reason="CONFIRMATION_CONTEXT_MISMATCH",
        required_change=lambda r: r[2]["confirmation"].update(hash_hex=tag("other-fork")))
    add("wrong-confirming-time", reason="CONFIRMATION_CONTEXT_MISMATCH",
        required_change=lambda r: r[2]["confirmation"].update(timestamp="999"))
    add("missing-confirming-height", structure="INCOMPLETE", reason="ABSENCE_IS_NOT_OUTCOME",
        required_change=lambda r: r[2]["confirmation"].update(height="999"))
    add("empty-history", lambda c: c.update(momenta=[]), structure="INCOMPLETE", reason="ABSENCE_IS_NOT_OUTCOME")
    add("truncated-history", lambda c: c["momenta"].pop(), structure="INCOMPLETE", reason="ABSENCE_IS_NOT_OUTCOME")
    add("duplicate-required-id", reason="INCLUSION_ID", required_change=lambda r: r.append(copy.deepcopy(r[0])))

    plans = []
    def plan(name, candidate, relation, rechecks):
        plans.append({"id": name, "previous": copy.deepcopy(baseline), "candidate": candidate,
                      "chain_id": chain_id, "selected_anchor_claim": copy.deepcopy(anchor),
                      "retained_inclusions": copy.deepcopy(inclusions), "expect_relation": relation,
                      "expect_recheck_inclusions": rechecks})
    plan("unchanged", copy.deepcopy(baseline), "SAME", [])
    extension = copy.deepcopy(baseline)
    extension["momenta"].append(make(context(third), []))
    plan("extension-is-not-finality", extension, "EXTENSION", [])
    shorter = copy.deepcopy(baseline); shorter["momenta"].pop()
    plan("shorter-prefix-retains-receipt", shorter, "SHORTER_PREFIX", ["recipient_receive"])
    fork = copy.deepcopy(baseline); fork["momenta"][1]["momentum"].update(changes_hash_hex=tag("competing-state")); reseal(fork)
    plan("divergent-fork-rechecks-displaced", fork, "FORK", ["original", "payout", "contract_receive", "recipient_receive"])
    absent = copy.deepcopy(fork); absent["momenta"][1]["momentum"]["content"] = []; absent["momenta"][2]["momentum"]["content"] = []; reseal(absent)
    plan("absent-on-fork-does-not-undo-disclosure", absent, "FORK", ["original", "payout", "contract_receive", "recipient_receive"])
    genesis_fork = copy.deepcopy(fork); genesis_fork["anchor"]["hash_hex"] = tag("other-anchor"); reseal(genesis_fork)
    plan("unrelated-anchor-needs-authority", genesis_fork, "UNKNOWN", [])
    plan("empty-candidate-is-unknown", dict(copy.deepcopy(baseline), momenta=[]), "UNKNOWN", [])
    invalid = copy.deepcopy(fork); invalid["momenta"][1]["hash_hex"] = tag("lie")
    plan("invalid-candidate-still-retained", invalid, "UNKNOWN", [])

    controls = ["version-one-legacy", "version-two-dynamic", "version-one-dynamic-refused", "version-two-legacy-refused",
                "version-zero-refused", "version-three-refused", "legacy-fusion-price-refused", "legacy-work-price-refused",
                "dynamic-fusion-floor", "dynamic-work-below-floor", "empty-data", "nonempty-data-refused",
                "previous-context", "wrong-previous-hash", "wrong-previous-height", "content-ordered-membership",
                "content-wrong-address", "content-wrong-hash", "content-duplicate-header", "content-duplicate-block",
                "content-missing-block", "content-account-gap", "static-missing-signature", "static-invalid-signature",
                "static-changed-payload", "excluded-key-signature-not-hashed"]
    return {"schema": "zenon-nom-momentum-corpus-v1", "profile": PROFILE, "core_commit": CORE_COMMIT,
            "chain_id": chain_id, "baseline": baseline, "required_inclusions": inclusions,
            "header_origin": "Existing unsigned public header claims only; former account acknowledgement contexts are not composed",
            "hash_vectors": hash_vectors, "claim_vectors": claim_vectors, "reorg_vectors": plans,
            "source_controls": controls, "application": "NO-GO", "core": "NO-GO", "independent_assessment": "UNFILLED"}


def main():
    output = ROOT / "compatibility/fixtures/nom_momentum_v1.json"
    output.write_text(json.dumps(corpus(), sort_keys=True, indent=2) + "\n", encoding="ascii")


if __name__ == "__main__": main()
