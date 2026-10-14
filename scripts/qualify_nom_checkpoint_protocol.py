#!/usr/bin/env python3
"""Qualify a selected reference retention protocol without service or worker entry."""
import copy
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from offline_session import enrollment_contract as codec, nom_recovery as recovery  # noqa: E402
from offline_session import nom_checkpoint_protocol as protocol  # noqa: E402
from scripts import qualify_nom_source_checkpoint as prior  # noqa: E402
from scripts.nom_cut_capture import sha  # noqa: E402

PROFILE = "ptlc-nom-checkpoint-protocol-qualification-v1"
BASE = "af39c1911ffe4a8cc6cb535d4b75bad95b35ac34"
MANIFEST = "compatibility/nom_checkpoint_protocol_manifest.json"
FIXTURE = "compatibility/fixtures/nom_checkpoint_protocol_v1.json"
KEY_FIXTURE = "qualification/fixtures/enrollment_signature.json"
SELECTED = ("offline_session/nom_checkpoint_protocol.py", "scripts/qualify_nom_checkpoint_protocol.py",
    "tests/test_nom_checkpoint_protocol.py", FIXTURE, KEY_FIXTURE)
BOUNDARY = dict(application="NO-GO", core="NO-GO", recovery_action="NONE",
    protocol_worker_calls=0, signature_mathematics="NOT_PERFORMED BY THIS PROFILE",
    reply_authentication="UNSIGNED REFERENCE FRAMING ONLY", source_currentness="UNFILLED",
    root_provisioning="UNFILLED", service_nonrollback="INDEPENDENT CALLER PREMISE; NOT_IMPLEMENTED",
    checkpoint_storage="NOT_IMPLEMENTED", atomic_service_cas="NOT_IMPLEMENTED", atomic_work_entry="NOT_IMPLEMENTED",
    native_query_pairing="NOT_COMPOSED", preserved_core_source_outcomes=342, new_core_source_outcomes=0)


def corpus():
    return dict(schema=PROFILE, research_baseline_commit=BASE,
        synthetic_notice="Reference transitions over a retained public fixture; no source truth or nonrollback service",
        relation_controls=["matching", "local_ahead", "local_behind", "unavailable_source", "source_rotations", "new_challenge"],
        refusal_controls=["stale_compare_and_advance", "regressed_journal", "diverged_journal", "old_reply",
            "new_service_query", "numeric_alias", "missing_original", "exhausted_reference"],
        unsafe_controls=["coherent_restore", "fresh_bootstrap_from_old_local", "fork_from_old_reference", "unsigned_reply_forgery"],
        expected_checkpoint_selection="EXACT INDEPENDENT EXPECTATION; NO MINIMUM-TO-NEW-HEAD DISCOVERY",
        boundary=BOUNDARY)


def inputs(root=ROOT):
    _, preserved = prior.inputs(root)
    selected = {name: sha((root/name).read_bytes()) for name in SELECTED}
    expected = dict(schema="ptlc-nom-checkpoint-protocol-manifest-v1", profile=PROFILE,
        research_baseline_commit=BASE, input_sha256=selected, preserved_file_sha256=preserved, boundary=BOUNDARY)
    if json.loads((root/FIXTURE).read_text("ascii")) != corpus():
        raise ValueError("selected checkpoint protocol corpus changed")
    if json.loads((root/MANIFEST).read_text("ascii")) != expected:
        raise ValueError("selected checkpoint protocol inputs changed")
    return expected, {**preserved, **selected, MANIFEST:sha((root/MANIFEST).read_bytes())}


def rewrite_reference(retained, events):
    """Synthetic event selection, not a new admission or worker execution receipt."""
    previous = "00"*32
    rows = []
    for sequence, event in enumerate(events, 1):
        row = dict(schema="ptlc-nom-recovery-log-v1", sequence=sequence, previous_hash_hex=previous, event=event)
        row["hash_hex"] = recovery.digest(b"ptlc-nom-log-v1", row)
        previous = row["hash_hex"]
        rows.append(recovery.canonical(row)+b"\n")
    return prior.prior.prior.from_journal(b"".join(rows), challenge_hex="a1"*32)


def fixture_contexts(root=ROOT):
    unsigned, retained = prior.retained_fixture(root)
    events = [json.loads(line)["event"] for line in retained.journal_bytes.splitlines()]
    extended = rewrite_reference(retained, events+[dict(kind="recovery-admitted")])
    divergent = rewrite_reference(retained, events+[copy.deepcopy(events[4])])
    contexts = prior.fixture_expectations(root)
    contexts.update(extended=prior.select_context(extended, root=root), divergent=prior.select_context(divergent, root=root))
    key = json.loads((root/KEY_FIXTURE).read_text("ascii"))["intent"]["owner_auth_key_hex"]
    policy = protocol.select_service(contexts["primary"], service_id_hex="c1"*32,
        service_epoch=1, checkpoint_key_hex=key)
    return policy, contexts, retained


def qualify(root=ROOT):
    _, measured = inputs(root)
    policy, contexts, retained = fixture_contexts(root)
    initial = protocol.bootstrap_reference(policy, contexts["primary"])
    latest = protocol.advance_reference(initial, contexts["extended"], expected_current_digest_hex=initial.digest_hex)
    alternate = protocol.advance_reference(initial, contexts["divergent"], expected_current_digest_hex=initial.digest_hex)
    results = {}
    def compare(name, local, current, challenge="d1"*32):
        query = protocol.checkpoint_query(current, challenge_hex=challenge)
        reply = protocol.reference_reply(current, query)
        result = protocol.compare_reference_reply(local, current, query, reply)
        assert result["state"] == "HOLD" and result["recovery_action"] == "NONE" and result["worker_calls"] == 0
        assert not result["new_work_allowed"] and not result["replenish_work"] and not result["automatic_retry"]
        results[name] = result
        return result
    compare("matching", contexts["primary"], initial)
    compare("local_ahead", contexts["extended"], initial)
    compare("local_behind", contexts["primary"], latest)
    compare("unavailable_source", contexts["unavailable"], latest)
    for name in ("root_rotation", "source_rotation", "checkpoint_rotation", "new_epoch", "new_challenge"):
        assert protocol.advance_reference(initial, contexts[name], expected_current_digest_hex=initial.digest_hex) is initial
        compare(name, contexts[name], latest)
    refusals = []
    def refuse(name, operation):
        try: operation()
        except ValueError: refusals.append(name)
        else: raise AssertionError("expected checkpoint refusal missing")
    refuse("stale_compare_and_advance", lambda:protocol.advance_reference(latest, contexts["divergent"], expected_current_digest_hex=initial.digest_hex))
    refuse("regressed_journal", lambda:protocol.advance_reference(latest, contexts["primary"], expected_current_digest_hex=latest.digest_hex))
    refuse("diverged_journal", lambda:protocol.advance_reference(latest, contexts["divergent"], expected_current_digest_hex=latest.digest_hex))
    query = protocol.checkpoint_query(latest, challenge_hex="d1"*32)
    old_query = protocol.checkpoint_query(initial, challenge_hex="d1"*32)
    refuse("old_reply", lambda:protocol.compare_reference_reply(contexts["primary"], latest, query, protocol.reference_reply(initial, old_query)))
    other_policy = protocol.select_service(contexts["primary"], service_id_hex="c2"*32, service_epoch=1, checkpoint_key_hex=policy.as_dict()["checkpoint_key_hex"])
    other = protocol.bootstrap_reference(other_policy, contexts["primary"])
    refuse("new_service_query", lambda:protocol.reference_reply(other, old_query))
    bad = dict(old_query, expected_sequence=1.0)
    refuse("numeric_alias", lambda:protocol.reference_reply(initial, bad))
    partial = prior.prior.prior.from_journal(b"".join(retained.journal_bytes.splitlines(keepends=True)[:7]), challenge_hex="a1"*32)
    refuse("missing_original", lambda:prior.select_context(partial, root=root))
    limited_policy = protocol.select_service(contexts["primary"], service_id_hex="c3"*32, service_epoch=1,
        checkpoint_key_hex=policy.as_dict()["checkpoint_key_hex"], max_snapshots=1)
    limited = protocol.bootstrap_reference(limited_policy, contexts["primary"])
    refuse("exhausted_reference", lambda:protocol.advance_reference(limited, contexts["extended"], expected_current_digest_hex=limited.digest_hex))
    unsafe = {}
    unsafe["coherent_restore"] = compare("coherent_restore", contexts["primary"], initial)
    reboot = protocol.bootstrap_reference(policy, contexts["primary"])
    unsafe["fresh_bootstrap_from_old_local"] = compare("fresh_bootstrap_from_old_local", contexts["primary"], reboot)
    unsafe["fork_from_old_reference"] = dict(first=latest.digest_hex, sibling=alternate.digest_hex,
        same_sequence=latest.as_dict()["sequence"]==alternate.as_dict()["sequence"], different_heads=latest.digest_hex!=alternate.digest_hex,
        atomic_service_cas="NOT_IMPLEMENTED; SELECTING OLD CURRENT STATE CAN FORK")
    forged = codec._canonical(json.loads(protocol.reference_reply(initial, old_query)))
    unsafe["unsigned_reply_forgery"] = protocol.compare_reference_reply(contexts["primary"], initial, old_query, forged)
    return dict(schema="ptlc-nom-checkpoint-protocol-result-v1", profile=PROFILE, outcome="PASS", input_sha256=measured,
        retained_reference_journal_sha256=retained.projection()["journal_sha256"],
        synthetic_extensions="CANONICAL REFERENCE EVENTS ONLY; ZERO NEW WORKER EXECUTION OR ADMISSION RECEIPTS",
        initial_checkpoint=initial.as_dict(), latest_checkpoint=latest.as_dict(), comparison_results=results,
        refusal_controls=refusals, unsafe_controls=unsafe, boundary=BOUNDARY)


def check_cases(value, root=ROOT):
    expected = qualify(root)
    if codec._canonical(value) != codec._canonical(expected):
        raise ValueError("checkpoint protocol result changed")


def main():
    try: value = qualify()
    except (ValueError, TypeError, OSError, KeyError):
        print("selected NoM checkpoint protocol qualification refused", file=sys.stderr)
        return 1
    print(json.dumps(value, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
