#!/usr/bin/env python3
"""Select public account authorization and exact protobuf-byte controls.

Only explicitly public test seeds are used by the isolated Go test overlay.
No application signing, network admission or recovery permission is selected.
"""

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from offline_session.pr138 import CORE_COMMIT

PROFILE = "zenon-pr138-account-authorization-v1"
FIXTURE = "compatibility/fixtures/nom_account_authorization_v1.json"
BASE = "6286383a12ac9db72a34d084f81d3ce0f60c4d2c"
USER_ROLES = ("funding", "unlock-send", "recipient-receive")
EMBEDDED_ROLES = ("create-receive", "unlock-payout-0", "unlock-receive")
USER_KINDS = (
    "unsigned", "foreign-signature", "relocated-authorized",
    "changed-data-old-hash", "changed-data-old-signature", "changed-data-resigned",
    "missing-signature", "missing-key", "short-key", "short-signature", "bad-signature",
    "changed-changes-hash", "changed-base-plasma", "changed-total-plasma",
    "unknown-protobuf-field", "duplicate-protobuf-version",
)
EMBEDDED_KINDS = (
    "empty-authorization", "nonempty-key", "nonempty-signature",
    "unknown-protobuf-field", "duplicate-protobuf-version",
)
BOUNDARY = {
    "application": "NO-GO", "core": "NO-GO", "recovery_action": "NONE",
    "application_signing": "NOT_PERFORMED", "journal_composition": "NOT_PERFORMED",
    "account_admission": "NOT_PERFORMED", "supervisor_and_plasma_admission": "NOT_PERFORMED",
    "source_authentication": "UNFILLED", "canonicality": "UNFILLED", "finality": "UNFILLED",
    "restore_fence": "UNFILLED", "independent_assessment": "UNFILLED",
    "outer_checks": "SELECTED SOURCE HASH, SIGNATURE AND PRODUCER HELPERS ONLY",
    "test_signatures": "PUBLIC SYNTHETIC SEEDS; NO WALLET OR APPLICATION SIGNER",
    "protobuf": "OBSERVED PINNED TYPED SERIALIZATION; NOT A CANONICAL NETWORK WIRE SELECTION",
}


def vectors():
    return [{"id": leg + "-" + role + "-" + kind, "leg": leg, "role": role, "kind": kind}
            for leg in ("long", "short")
            for roles, kinds in ((USER_ROLES, USER_KINDS), (EMBEDDED_ROLES, EMBEDDED_KINDS))
            for role in roles for kind in kinds]


def corpus(records):
    if set(records) != {v["id"] for v in vectors()}:
        raise ValueError("complete selected authorization controls required")
    return {"schema": "zenon-nom-account-authorization-corpus-v1", "profile": PROFILE,
            "core_commit": CORE_COMMIT, "research_baseline_commit": BASE,
            "vectors": vectors(), "records": records, "boundary": BOUNDARY}


def main():
    from scripts.qualify_nom_account_authorization import collect_records, expected_tests
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--authorization-stream", type=Path, required=True)
    parser.add_argument("--vm-stream", type=Path, required=True)
    args = parser.parse_args()
    from scripts import qualify_nom_vm_path as vm
    from scripts.qualify_nom_observation_core import parse_outcome
    _, fixture, _ = vm.inputs(ROOT)
    vm_wire = args.vm_stream.read_bytes()
    package = "github.com/zenon-network/go-zenon/vm"
    vm.selected_outcome(vm_wire, {package: vm.expected_tests(fixture)[package]})
    source = vm.collect_vm_records(vm_wire, fixture, json.loads((ROOT / vm.FUNDING).read_text("ascii")))
    wire = args.authorization_stream.read_bytes()
    parse_outcome(wire, expected_tests())
    (ROOT / FIXTURE).write_text(json.dumps(corpus(collect_records(wire, source)), indent=2, sort_keys=True)
                              + "\n", encoding="ascii")


if __name__ == "__main__":
    main()
