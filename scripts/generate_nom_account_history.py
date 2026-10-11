#!/usr/bin/env python3
"""Project bounded public windows after validating all original VM source cases.

Projection orders trusted, parsed source records by height. The consumer does
not reorder an incoming claim. No raw logs or actual private patches are copied.
"""

import argparse
import copy
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from offline_session import enrollment_contract as codec, nom_account_history as history
from offline_session import nom_authority_contract as authority
from offline_session.pr138 import CONTRACT_HEX
from scripts import generate_nom_vm_openings as roles, qualify_nom_vm_path as vm

PROFILE = "zenon-pr138-bounded-account-history-v1"
FIXTURE = "compatibility/fixtures/nom_account_history_v1.json"
BASE = "1bc024f2361e9012f680995ab84a0a76bbccaf9a"
BOUNDARY = {**roles.BOUNDARY, "whole_chain_coverage": "NOT_ESTABLISHED", "auxiliary_authority_fact": "NONE"}


def corpus(records):
    frozen = roles.corpus(records)
    cases = {}
    for kind in roles.KINDS:
        legs = {}
        for leg in history.LEGS:
            blocks = records[leg + "-" + kind]["blocks"]
            contract = [copy.deepcopy(record) for record in blocks.values()
                        if record["block"]["address_hex"] == CONTRACT_HEX
                        and record["block"]["block_type"] in ("4", "5")]
            recipient = [copy.deepcopy(record) for name, record in blocks.items()
                         if name in ("recipient-receive", "raw-replayed-recipient-receive")]
            for items in (contract, recipient):
                items.sort(key=lambda record: int(record["block"]["height"]))
            legs[leg] = {"contract": contract, "recipient": recipient}
        cases[kind] = {"roles": frozen["source_cases"][kind], "history": legs}
    return {"schema": "zenon-nom-account-history-corpus-v1", "profile": PROFILE,
        "core_commit": authority.CORE_COMMIT, "research_baseline_commit": BASE,
        "source_cases": cases, "boundary": BOUNDARY,
        "source_selection": "UNCHANGED VM; LOCAL NUMBERED MOMENTUM STUBS AND INDEPENDENT ACCOUNT FRONTIERS"}


def windows(case):
    """Choose explicit local windows, preserving the old role selections."""
    result = {}
    for leg in history.LEGS:
        result[leg] = {}
        for role in history.ACCOUNTS:
            records = case["history"][leg][role]
            last = records[-1]
            result[leg][role] = {"address_hex": last["block"]["address_hex"], "first_height": "1",
                "last_height": last["block"]["height"], "head_hash_hex": last["hash_hex"],
                "anchor": {"height": "0", "hash_hex": "00" * 32} if role == "contract" else None}
    return result


def packet(expected, payload, *, status="supported", missing=False):
    digest = None if status == "unknown" else history.history_digest(expected, status, payload)
    return codec._canonical(dict(schema=history.SCHEMA, query_digest_hex=expected.digest_hex,
        status=status, evidence_digest_hex=digest, payload=None if missing or status == "unknown" else payload))


def query(case, selected=None):
    selected = roles.selection() if selected is None else selected
    read = authority.read_query(**selected)
    wires = roles.packet(read, selected, case["roles"])
    return history.history_query(read, *wires, windows(case))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vm-stream", type=Path, required=True)
    args = parser.parse_args()
    _, fixture, _ = vm.inputs(ROOT)
    raw = args.vm_stream.read_bytes()
    names = vm.expected_tests(fixture)["github.com/zenon-network/go-zenon/vm"]
    vm.selected_outcome(raw, {"github.com/zenon-network/go-zenon/vm": names})
    records = vm.collect_vm_records(raw, fixture, json.loads((ROOT / vm.FUNDING).read_text("ascii")))
    (ROOT / FIXTURE).write_text(json.dumps(corpus(records), indent=2, sort_keys=True) + "\n", encoding="ascii")


if __name__ == "__main__":
    main()
