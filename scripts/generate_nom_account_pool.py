#!/usr/bin/env python3
"""Select unchanged public originals for bounded actual account-pool comparison."""

from offline_session.pr138 import CORE_COMMIT

PROFILE = "zenon-pr138-account-pool-v1"
BASE = "3cefef0efeab8d2d8424f8fd4f604edb91a2b85b"
FIXTURE = "compatibility/fixtures/nom_account_pool_v1.json"
CASES = ("complete", "old-inner-before-valid")
BOUNDARY = {
    "application": "NO-GO", "core": "NO-GO", "recovery_action": "NONE",
    "subject": "EXACT PRESERVED SUPERVISOR ORIGINALS; NO NEW FUNDING OR INNER WITNESSES",
    "execution": "ACTUAL PUBLIC POOL, NORMAL ADD, VERSIONED MEMORY MANAGER AND SELECTED DELETE CALLBACK",
    "stable": "UNCHANGED SYNTHETIC MEMORY BASES; NO COMMITTED CHAIN",
    "ledger": "SELECTED SYNTHETIC MOMENTA, CONFIRMATIONS AND MAILBOX; NO NODE INIT OR START",
    "account_pool": "SELECTED ADMISSION, IDEMPOTENCE AND STALE-ACKNOWLEDGEMENT SUFFIX ONLY",
    "rollback": "PUBLIC DELETE CALLBACK WITH ZERO INCLUDED BLOCKS; NOT CHAIN ROLLBACK OR EVENT AUTHENTICATION",
    "patches": "ACTUAL ORDERED AUGMENTED DELTAS AND COMPLETE LOGICAL MEMORY ITERATION",
    "view_authority": "HISTORICAL OR ALIASED GET RESULTS ARE NOT CURRENTNESS OR RECOVERY PERMISSION",
    "duplicate_authority": "IDENTIFIER IDEMPOTENCE IS NOT ORIGINAL BYTE IDENTITY",
    "caller_review": "SOURCE ONLY; NO RPC, BROADCASTER, PEER OR MOMENTUM PIPELINE EXECUTION",
    "competing_forks": "NOT_PERFORMED", "uncommitted_cap": "NOT_PERFORMED",
    "dynamic_plasma": "NOT_SELECTED; LEGACY INACTIVE PRICING VIEW",
    "momentum_admission": "NOT_PERFORMED", "complete_admission": "UNFILLED",
    "application_signing": "NOT_PERFORMED", "journal_composition": "NOT_PERFORMED",
    "source_authentication": "UNFILLED", "canonicality": "UNFILLED", "finality": "UNFILLED",
    "original_custody": "UNFILLED", "restore_fence": "UNFILLED", "independent_assessment": "UNFILLED",
    "construction_security": "NOT ESTABLISHED BY SYNTHETIC POOL OR PUBLIC RECOVERY TESTS",
}


def corpus(records):
    if type(records) is not dict or set(records) != set(CASES):
        raise ValueError("complete selected pool records required")
    return {"schema": "zenon-nom-account-pool-corpus-v1", "profile": PROFILE, "core_commit": CORE_COMMIT,
            "research_baseline_commit": BASE, "records": records, "boundary": BOUNDARY}
