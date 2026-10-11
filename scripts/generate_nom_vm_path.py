#!/usr/bin/env python3
"""Select additive, synthetic VM-path and receipt-verifier controls.

The preserved Create hash inputs and public witnesses are reused without a
signer. Caller-selected ledgers and spork gates are not admitted chain state.
"""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROFILE = "zenon-pr138-composed-vm-path-v1"
FIXTURE = "compatibility/fixtures/nom_vm_path_v1.json"
BASE = "07df9a96e0ac9caf71dfa0ad7d40f001207baaa8"
CORE = "45e1bbb48ce6fc19d44c5fbf59ccf5784981fced"
VM_KINDS = (
    "direct-success", "proxy-funder-success", "proxy-third-success",
    "invalid-witness-then-valid", "wrong-caller-then-valid",
    "wrong-proxy-recipient-then-valid", "old-witness-then-valid",
    "cross-leg-witness-then-valid", "unlock-at-expiry-then-reclaim",
    "early-reclaim-then-unlock", "unlock-replay-after-deletion",
    "proxy-then-direct-replay", "create-at-expiry-refunds",
    "insufficient-funding-balance", "insufficient-contract-balance-rolls-back",
    "raw-receive-replay-needs-verifier",
)
VERIFIER_KINDS = (
    "source-generated-hashes", "parent-child-confirming-context",
    "child-context-mismatch", "parent-wrong-confirmation-height",
    "recipient-from-generated-payout", "missing-payout", "unconfirmed-payout",
    "already-received-payout", "wrong-recipient-at-enforcement",
    "wrong-recipient-before-enforcement-helper-allows",
    "known-height-wrong-ack-hash", "parent-mutated-ack-hash",
)
BOUNDARY = {
    "application": "NO-GO", "core": "NO-GO",
    "account_admission": "NOT_PERFORMED", "activation": "NOT_PERFORMED",
    "application_signing": "NOT_PERFORMED", "chain_observation": "NOT_PERFORMED",
    "source_authentication": "UNFILLED", "canonicality": "UNFILLED",
    "finality": "UNFILLED", "rollback_protection": "UNFILLED",
    "independent_assessment": "UNFILLED", "core_journal_composition": "NOT_PERFORMED",
    "supervisor_and_plasma_admission": "NOT_PERFORMED",
    "ledger_and_spork_gate": "CALLER_SELECTED_SYNTHETIC_STUBS",
    "account_storage": "ACTUAL MEMORY ACCOUNT STORES AND VM CONTEXT LIFECYCLE",
    "receipt_replay": "RAW VM CREDIT IS NOT AN ADMISSION GUARD",
}


def corpus():
    return {"schema": "zenon-nom-vm-path-corpus-v1", "profile": PROFILE,
            "core_commit": CORE, "research_baseline_commit": BASE,
            "funding_fixture": "compatibility/fixtures/nom_created_funding_v1.json",
            "public_completions": "compatibility/fixtures/nom_created_completions_v1.json",
            "vm_vectors": [{"id": leg + "-" + kind, "leg": leg, "kind": kind}
                           for leg in ("long", "short") for kind in VM_KINDS],
            "verifier_vectors": [{"id": leg + "-" + kind, "leg": leg, "kind": kind}
                                 for leg in ("long", "short") for kind in VERIFIER_KINDS],
            "boundary": BOUNDARY}


if __name__ == "__main__":
    (ROOT / FIXTURE).write_text(json.dumps(corpus(), indent=2, sort_keys=True) + "\n", encoding="ascii")
