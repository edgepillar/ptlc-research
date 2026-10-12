#!/usr/bin/env python3
"""Select a property corpus for actual default-cap, complete-batch content."""

from offline_session.pr138 import CORE_COMMIT

PROFILE = "zenon-pr138-content-cap-v1"
BASE = "2299c1e378ed815f2a6c76ca221f28d1d6f264f7"
FIXTURE = "compatibility/fixtures/nom_content_cap_v1.json"
CASE = "preserved-batch-default-cap"
WINDOWS = (98, 99, 100, 101)
READS = 16
BOUNDARY = {
    "application": "NO-GO", "core": "NO-GO", "recovery_action": "NONE",
    "subject": "EXACT PRESERVED PTLC PARENT AND CHILD; SEPARATE PUBLIC-SYNTHETIC USER PREFIX",
    "execution": "ACTUAL SUPERVISOR GENERATE AND EXACT APPLY; NORMAL PUBLIC ACCOUNT POOL ADD; ACTUAL PUBLIC CONTENT GETTERS",
    "content_cap": "ACTUAL UNMODIFIED PROCESS DEFAULT 100; CHILDREN COUNT; COMPLETE BATCHES ONLY",
    "ordering": "ACCOUNT-MANAGER MAP ORDER IS UNSPECIFIED; EACH GETTER IS CHECKED INDEPENDENTLY AGAINST ALL ADMISSIBLE ORDERS",
    "coverage": "64 ACTUAL SELECTION READS; 64 ACTUAL ALL-PENDING READS; BOTH ORDER VARIANTS ARE ADMISSIBLE BUT NOT REQUIRED TO APPEAR",
    "corpus": "DETERMINISTIC PROPERTY PROJECTION AFTER COMPLETE RAW-OBSERVATION VALIDATION; ORIGINAL STREAMS UNCHANGED",
    "preservation": "ALL ORIGINAL FUNDING, INNER WITNESS, PARENT, CHILD AND PRIOR PROFILE INPUTS UNCHANGED",
    "anchor": "SELECTED SYNTHETIC GLOBAL STATE AND MOMENTUM; NOT AN AUTHENTICATED CHAIN",
    "fusion": "DISCLOSED SYNTHETIC 500000000000 FUSION AMOUNT FOR THE SEPARATE USER; LEGACY BUDGET 10500000",
    "signing": "DISCLOSED PUBLIC 0x61 TEST SEED ONLY; 101 GENERATED USER CONTROLS; EXACT APPLY AND GETTERS SIGN ZERO TIMES",
    "sporks": "SELECTED PTLC ACCOUNT CACHE; ACTUAL EMPTY SPORK STORE; NO NODE OR NETWORK ACTIVATION",
    "dynamic_plasma": "NOT_SELECTED; LEGACY INACTIVE PRICING",
    "momentum_application": "NOT_PERFORMED IN THIS PROFILE; PREVIOUS PROFILE IS PRESERVED AND FRESHLY RERUN",
    "persistent_manager": "NOT_SELECTED", "atomicity": "NOT_PERFORMED; SINGLE-THREADED MEMORY CONTROLS",
    "network_node_admission": "NOT_PERFORMED", "application_signing": "NOT_PERFORMED",
    "journal_composition": "NOT_PERFORMED", "source_authentication": "UNFILLED", "canonicality": "UNFILLED",
    "finality": "UNFILLED", "original_custody": "UNFILLED", "restore_fence": "UNFILLED",
    "independent_assessment": "UNFILLED", "construction_security": "NOT ESTABLISHED BY PUBLIC MEMORY CONTROLS",
}


def corpus(records):
    return {"schema": "zenon-nom-content-cap-corpus-v1", "profile": PROFILE,
            "core_commit": CORE_COMMIT, "research_baseline_commit": BASE, "records": records, **BOUNDARY}
