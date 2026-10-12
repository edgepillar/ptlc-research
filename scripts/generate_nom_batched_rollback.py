#!/usr/bin/env python3
"""Select actual batched content, memory insertion and rollback callbacks."""

from offline_session.pr138 import CORE_COMMIT

PROFILE = "zenon-pr138-batched-rollback-v1"
BASE = "d1ab005b199b826519f505c9d7adc89dcaadd3e2"
FIXTURE = "compatibility/fixtures/nom_batched_rollback_v1.json"
CASE = "preserved-parent-and-fresh-dependent-controls"
CONTROLS = ("missing-add-locker", "missing-rollback-locker", "wrong-target-height", "wrong-target-hash", "old-receipt-before-confirmation")
BOUNDARY = {
    "application": "NO-GO", "core": "NO-GO", "recovery_action": "NONE",
    "subject": "EXACT PRESERVED CONTRACT PARENT AND CHILD; FRESH SEPARATELY LABELED PUBLIC MEMORY CONTROLS",
    "execution": "ACTUAL SUPERVISOR EXACT PARENT APPLY, MOMENTUM GENERATE AND APPLY, PUBLIC MOMENTUM POOL ADD AND ROLLBACK",
    "content": "ACTUAL ACCOUNT POOL SELECTOR; CHILD THEN PARENT WITHOUT MANUAL CALLBACK CONTENT",
    "callbacks": "ACTUAL PREFETCH BEFORE POP; ACTUAL LISTENER ORDER; COMPLETE STABLE RESTORE BEFORE DELETE CALLBACK",
    "admission": "FRESH RECEIPT AND SUFFIX EXACT APPLY; OLD SYNTHETIC RECEIPT REFUSED AND NEVER INSERTED",
    "eviction": "BOTH ROLLED SEND AND STALE ACK CONDITIONS APPLY; UNIQUE CAUSE NOT ESTABLISHED",
    "preservation": "ALL PRIOR FUNDING, INNER WITNESS, RECEIPT, SOURCE PROFILES AND FAILED EVIDENCE UNCHANGED",
    "anchor": "SELECTED SYNTHETIC GLOBAL STATE AND MOMENTUM; NOT AN AUTHENTICATED CHAIN",
    "producer": "EXPLICIT SELECTED ACCEPT RESPONSE; ELECTED PRODUCER AUTHENTICATION UNFILLED",
    "signing": "DISCLOSED PUBLIC 0x41, 0x61 AND 0x64 TEST SEEDS ONLY; EXACT APPLY AND REFUSALS SIGN ZERO TIMES",
    "sporks": "SELECTED PTLC ACCOUNT CACHE; ACTUAL EMPTY SPORK STORE; NO NODE OR NETWORK ACTIVATION",
    "dynamic_plasma": "NOT_SELECTED; LEGACY INACTIVE PRICING",
    "persistent_manager": "NOT_SELECTED", "batch_capacity_boundary": "NOT_SELECTED",
    "atomicity": "NOT_PERFORMED; SINGLE-THREADED MEMORY CONTROLS",
    "network_node_admission": "NOT_PERFORMED", "application_signing": "NOT_PERFORMED",
    "journal_composition": "NOT_PERFORMED", "source_authentication": "UNFILLED", "canonicality": "UNFILLED",
    "finality": "UNFILLED", "original_custody": "UNFILLED", "restore_fence": "UNFILLED",
    "independent_assessment": "UNFILLED", "construction_security": "NOT ESTABLISHED BY PUBLIC MEMORY CONTROLS",
}


def corpus(records):
    return {"schema": "zenon-nom-batched-rollback-corpus-v1", "profile": PROFILE,
            "core_commit": CORE_COMMIT, "research_baseline_commit": BASE, "records": records, **BOUNDARY}
