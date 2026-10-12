#!/usr/bin/env python3
"""Select actual local momentum execution with disclosed plain controls only."""

from offline_session.pr138 import CORE_COMMIT

PROFILE = "zenon-pr138-momentum-admission-v1"
BASE = "83ce93b86527e01922e6bb0828037e8d429210c4"
FIXTURE = "compatibility/fixtures/nom_momentum_admission_v1.json"
CASE = "ordered-send-then-receive"
CONTROLS = ("reversed-content", "duplicate-content", "duplicate-prefetch", "nil-prefetch",
            "wrong-header-address", "missing-prefetch", "wrong-chain", "non-increasing-time",
            "changes-hash", "outer-hash", "outer-signature", "producer-rejected", "producer-error")
PRODUCER_KEY = "2bc2800b3316e009209ffd757dab19ccf0ae84bc7ae90654e1e81712d270f653"
BOUNDARY = {
    "application": "NO-GO", "core": "NO-GO", "recovery_action": "NONE",
    "subject": "SEPARATE ZERO-AMOUNT PLAIN CONTROLS; EVERY OLD SWAP ORIGINAL AND INNER WITNESS PRESERVED",
    "execution": "ACTUAL SUPERVISOR GENERATE AND EXACT APPLY MOMENTUM, ACTUAL MOMENTUM STORE AND LOCAL MEMORY MANAGER ADD",
    "producer": "EXPLICIT ACCEPT, REJECT AND ERROR RESPONSES; ELECTED PRODUCER AUTHENTICATION UNFILLED",
    "anchor": "SYNTHETIC UNVERIFIED MOMENTUM; NO AUTHENTICATED GENESIS OR CHAIN",
    "snapshots": "FRESH ACTUAL MANAGER SNAPSHOT FOR EVERY EXACT PREVIOUS MOMENTUM QUERY",
    "state": "COMPLETE INDEPENDENT ACCOUNT, GLOBAL HEADER, CONFIRMATION, BALANCE INDEX AND MAILBOX PROJECTION",
    "signing": "DISCLOSED PUBLIC 0x61, 0x62 AND 0x64 TEST SEEDS ONLY; EXACT APPLY AND REFUSALS SIGN ZERO TIMES",
    "pool": "THREE NORMAL ADMISSIONS AND TWO ACTUAL INSERT CALLBACKS AFTER LOCAL MANAGER INSERTION",
    "prefetch": "ACTUAL COMMITTED CONTROL STORE CONTENT LOOKUP; EXACT ORIGINAL WIRES IN ADVERTISED ORDER",
    "atomicity": "NOT_PERFORMED; SINGLE-THREADED MEMORY CONTROLS",
    "dynamic_plasma": "NOT_SELECTED; ACTUAL EMPTY SPORK STORE AND SELECTED LEGACY CACHE",
    "batched_content": "NOT_SELECTED", "rollback_caller": "NOT_SELECTED", "persistent_manager": "NOT_SELECTED",
    "network_node_admission": "NOT_PERFORMED", "application_signing": "NOT_PERFORMED",
    "journal_composition": "NOT_PERFORMED", "source_authentication": "UNFILLED", "canonicality": "UNFILLED",
    "finality": "UNFILLED", "original_custody": "UNFILLED", "restore_fence": "UNFILLED",
    "independent_assessment": "UNFILLED", "construction_security": "NOT ESTABLISHED BY PUBLIC MEMORY CONTROLS",
}


def corpus(records):
    return {"schema": "zenon-nom-momentum-admission-corpus-v1", "profile": PROFILE,
            "core_commit": CORE_COMMIT, "research_baseline_commit": BASE, "records": records, **BOUNDARY}
