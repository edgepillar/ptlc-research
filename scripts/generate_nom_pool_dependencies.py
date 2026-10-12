#!/usr/bin/env python3
"""Select separate plain-account dependency controls without replacing swaps."""

from offline_session.pr138 import CORE_COMMIT

PROFILE = "zenon-pr138-pool-dependencies-v1"
BASE = "38fc1cb13e80f2583ab17b61004402ead25d95a1"
FIXTURE = "compatibility/fixtures/nom_pool_dependencies_v1.json"
CASES = ("included-send", "included-send-without-suffix", "empty-inclusion-control")
KEYS = {
    "sender": ("af06a3e3291714e4f356c19c9b15cd1951ec6e6662aa77be07547f289383341d", "00fbc668f303e1dea4d64e449c5951fbdf4e7c5d"),
    "recipient": ("2df04125f0015afb47ce853aef8772094ff9498c14cb1b9e12973c2927da0fa6", "0004ccf256791690cb0f92e80459e9687784b9bb"),
    "unrelated": ("a7f6dfaf8f38b89ba8ce649b594f91e4d01fdc57f9c9493df43b5e50a9987367", "001a5e2854c17c73b180bee4527ec07d0e8fc1e1"),
}
BOUNDARY = {
    "application": "NO-GO", "core": "NO-GO", "recovery_action": "NONE",
    "subject": "SEPARATE ZERO-AMOUNT USER CONTROLS; ALL OLD SWAP ORIGINALS AND INNER WITNESSES PRESERVED",
    "execution": "ACTUAL SUPERVISOR GENERATE AND EXACT APPLY, NORMAL POOL ADD, INSERT AND DELETE EVENT CALLBACKS",
    "stable": "EXPLICIT CALLER-SELECTED PROMOTION AND ROLLBACK OF ONE SOURCE-GENERATED SEND; NOT A COMMITTED CHAIN",
    "ledger": "EXPLICIT SYNTHETIC MOMENTUM, SEND LOOKUP, CONFIRMATION AND ACTUAL MAILBOX RECONSTITUTION",
    "signing": "DISCLOSED PUBLIC 0x61, 0x62 AND 0x63 TEST SEEDS ONLY; EXACT APPLY AND CALLBACKS SIGN ZERO TIMES",
    "dependent_receive_eviction": "TWO NONEMPTY SEND CALLBACKS REMOVE THE COMPLETE RECIPIENT MANAGER INCLUDING ITS PREFIX",
    "empty_callback": "DELIBERATELY INCOMPLETE NEGATIVE CONTROL; HEIGHT TRUNCATION RETAINS THE RECIPIENT PREFIX",
    "unrelated_manager": "TWO EARLIER ACKNOWLEDGED ORIGINALS RETAINED; STALE THIRD BLOCK REMOVED",
    "patches": "INDEPENDENT DELTA, ORDERED FRONTIER AUGMENTATION, REBUILD AND COMPLETE LOGICAL READBACK",
    "wire": "INDEPENDENT SELECTED PROTOBUF ENCODING AND HASH; SOURCE OUTER SIGNATURE VERIFICATION",
    "post_callback_action": "READBACK ONLY; NO REPLAY, GENERATION OR RECOVERY",
    "view_authority": "PENDING OR HISTORICAL VIEWS ARE NOT CURRENTNESS OR RECOVERY PERMISSION",
    "atomicity": "NOT_PERFORMED; SINGLE-THREADED RECONSTITUTION THEN CALLBACK, NO INTERMEDIATE POOL READ",
    "dynamic_plasma": "NOT_SELECTED; LEGACY INACTIVE VIEW", "momentum_admission": "NOT_PERFORMED",
    "complete_admission": "UNFILLED", "application_signing": "NOT_PERFORMED", "journal_composition": "NOT_PERFORMED",
    "source_authentication": "UNFILLED", "canonicality": "UNFILLED", "finality": "UNFILLED",
    "original_custody": "UNFILLED", "restore_fence": "UNFILLED", "independent_assessment": "UNFILLED",
    "construction_security": "NOT ESTABLISHED BY SYNTHETIC POOL OR PUBLIC RECOVERY TESTS",
}


def corpus(records):
    if type(records) is not dict or set(records) != set(CASES):
        raise ValueError("complete separate dependency control selection required")
    return {"schema": "zenon-nom-pool-dependencies-corpus-v1", "profile": PROFILE, "core_commit": CORE_COMMIT,
            "research_baseline_commit": BASE, "records": records, "boundary": BOUNDARY}
