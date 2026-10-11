#!/usr/bin/env python3
"""Select separate public account controls without replacing any swap original."""

from offline_session.pr138 import CORE_COMMIT

PROFILE = "zenon-pr138-pool-forks-v1"
BASE = "1b8cc453f1bc5753f7995c054d384df1f6d0ad42"
FIXTURE = "compatibility/fixtures/nom_pool_forks_v1.json"
CASES = ("ratio-higher", "ratio-lower", "tie-smaller", "tie-larger", "actual-cap-500")
PUBLIC_KEY = "c050c5637a44fa8629fff3cccce2300cb362a63d99d95fc54145266f4332445a"
ADDRESS = "00aa0949eb2d91e5befcc1b87d531ba8b8f696e8"
RECIPIENT = "00846a341965141a2968efd7c3c76d94da6748bb"
NONCE = "b46a980000000000"
BOUNDARY = {
    "application": "NO-GO", "core": "NO-GO", "recovery_action": "NONE",
    "subject": "SEPARATE ZERO-AMOUNT USER CONTROLS; ALL OLD SWAP ORIGINALS AND INNER WITNESSES PRESERVED",
    "execution": "ACTUAL SUPERVISOR GENERATE AND EXACT APPLY, NORMAL PUBLIC POOL ADD AND HISTORICAL MEMORY VIEWS",
    "stable": "UNCHANGED EMPTY SYNTHETIC BASE AT HEIGHT ZERO; NO COMMITTED CHAIN",
    "ledger": "ONE SELECTED SYNTHETIC MOMENTUM AND LEGACY FUSION CACHE; NO INIT OR START",
    "signing": "DISCLOSED PUBLIC 0x51 TEST SEED ONLY; REPLAY SIGNS ZERO TIMES",
    "work": "FIXED PUBLIC VALID NONCE ON THE FIRST CAP CONTROL; NO ENTROPY OR WALLET CALL",
    "uncommitted_cap": "ACTUAL SOURCE 500; NEVER LOWERED OR FORCED",
    "competing_forks": "FOUR SOURCE-VALID LEGACY RATIO AND SMALLEST-HASH CONTROLS ABOVE A COMMON HEIGHT ONE",
    "patches": "INDEPENDENT ORDERED DELTA REPLAY AND COMPLETE LOGICAL CHECKPOINT READBACK",
    "wire": "INDEPENDENT SELECTED PROTOBUF ENCODING AND HASH; SOURCE OUTER SIGNATURE AND POW VERIFICATION",
    "view_authority": "PENDING OR HISTORICAL VIEWS ARE NOT CURRENTNESS OR RECOVERY PERMISSION",
    "dependent_receive_eviction": "NOT_PERFORMED", "dynamic_plasma": "NOT_SELECTED; LEGACY INACTIVE VIEW",
    "momentum_admission": "NOT_PERFORMED", "complete_admission": "UNFILLED",
    "application_signing": "NOT_PERFORMED", "journal_composition": "NOT_PERFORMED",
    "source_authentication": "UNFILLED", "canonicality": "UNFILLED", "finality": "UNFILLED",
    "original_custody": "UNFILLED", "restore_fence": "UNFILLED", "independent_assessment": "UNFILLED",
    "construction_security": "NOT ESTABLISHED BY SYNTHETIC POOL OR PUBLIC RECOVERY TESTS",
}


def corpus(records):
    if type(records) is not dict or set(records) != set(CASES):
        raise ValueError("complete separate source control selection required")
    return {"schema": "zenon-nom-pool-forks-corpus-v1", "profile": PROFILE, "core_commit": CORE_COMMIT,
            "research_baseline_commit": BASE, "records": records, "boundary": BOUNDARY}
