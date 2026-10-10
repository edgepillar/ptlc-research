#!/usr/bin/env python3
"""Regenerate only the independent public PR #138 message/policy fixture."""

import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from offline_session.pr138 import (  # noqa: E402
    CONTRACT_HEX, CORE_COMMIT, PROFILE, unlock_message, unlock_preimage,
    create_destination_allowed, payable,
)


def corpus():
    vectors = []
    for chain in ("0", "1", "69", "18446744073709551615"):
        for point in range(3):
            for entry in ("11" * 32, bytes(range(32)).hex()):
                for destination in ("00" + "22" * 19, "00" + "33" * 19):
                    context = {"profile": PROFILE, "chain_id": chain, "point_type": point,
                               "entry_id_hex": entry, "destination_hex": destination}
                    vectors.append({"id": "message-{:02d}".format(len(vectors)), "context": context,
                                    "preimage_hex": unlock_preimage(context).hex(),
                                    "message_hex": unlock_message(context),
                                    "legacy_message_hex": hashlib.sha3_256(
                                        bytes.fromhex(entry + destination)).hexdigest()})
    policies = []
    for point in range(3):
        for destination in ("00" * 20, "00" + "22" * 19, "01" + "22" * 19,
                            "02" + "22" * 19, "ff" + "22" * 19):
            policies.append({"point_type": point, "destination_hex": destination,
                             "create_allowed": create_destination_allowed(point, destination),
                             "payable": payable(destination)})
    return {"schema": "zenon-pr138-message-corpus-v1", "profile": PROFILE,
            "core_commit": CORE_COMMIT, "contract_hex": CONTRACT_HEX,
            "message_vectors": vectors, "destination_vectors": policies}


if __name__ == "__main__":
    path = ROOT / "compatibility" / "fixtures" / "pr138_messages_v1.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(corpus(), indent=2, sort_keys=True) + "\n", encoding="ascii")
