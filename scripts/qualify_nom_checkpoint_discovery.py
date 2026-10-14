#!/usr/bin/env python3
"""Qualify minimum-bound candidate discovery without authenticated current reads."""
import copy
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from offline_session import enrollment_contract as codec  # noqa: E402
from offline_session import nom_checkpoint_discovery as discovery  # noqa: E402
from offline_session import nom_checkpoint_protocol as protocol  # noqa: E402
from scripts import qualify_nom_checkpoint_protocol as prior  # noqa: E402
from scripts.nom_cut_capture import sha  # noqa: E402

PROFILE = "ptlc-nom-checkpoint-discovery-qualification-v1"
BASE = "8f9f4afde9a6949b6f7377f7f03549c41a49e2f7"
MANIFEST = "compatibility/nom_checkpoint_discovery_manifest.json"
FIXTURE = "compatibility/fixtures/nom_checkpoint_discovery_v1.json"
SELECTED = ("offline_session/nom_checkpoint_discovery.py", "scripts/qualify_nom_checkpoint_discovery.py",
    "tests/test_nom_checkpoint_discovery.py", FIXTURE)
BOUNDARY = dict(application="NO-GO", core="NO-GO", recovery_action="NONE", discovery_worker_calls=0,
    response_authentication="UNSIGNED REFERENCE CANDIDATE ONLY", signature_mathematics="NOT_PERFORMED",
    current_service_read="NOT_IMPLEMENTED", candidate_latest="NOT_ESTABLISHED", source_currentness="UNFILLED",
    root_provisioning="UNFILLED", service_nonrollback="NOT_IMPLEMENTED", checkpoint_storage="NOT_IMPLEMENTED",
    atomic_service_cas="NOT_IMPLEMENTED", atomic_work_entry="NOT_IMPLEMENTED", native_query_pairing="NOT_COMPOSED",
    preserved_core_source_outcomes=342, new_core_source_outcomes=0,
    complete_openings="ACTUAL RETAINED ORIGINALS REQUIRED; NEVER RECONSTRUCTED FROM HEADERS")


def corpus():
    return dict(schema=PROFILE, research_baseline_commit=BASE,
        synthetic_notice="Public reference lineage selections, not service currentness or new execution receipts",
        relation_controls=["minimum_candidate", "newer_candidate", "later_minimum", "local_ahead",
            "extension_without_new_charge", "unavailable_source", "unavailable_service"],
        refusal_controls=["missing_opening", "below_minimum", "sibling_after_minimum", "changed_service",
            "old_challenge_reply", "lineage_gap", "numeric_alias", "missing_original",
            "changed_minimum_source_view", "oversized_reply"],
        unsafe_controls=["fresh_challenge_old_candidate", "coherent_restore",
            "sibling_candidates_after_same_minimum", "unsigned_candidate_forgery"],
        known_minimum="COMPLETE INDEPENDENT HISTORY AND SERVICE SELECTION; NOT SELECTED FROM CANDIDATE",
        message_preimage="NEW DOMAIN OVER COMPLETE QUERY AND REPLY; NO SIGNER OR AUTHORITY CONSTRUCTION",
        boundary=BOUNDARY)


def inputs(root=ROOT):
    _, preserved = prior.inputs(root)
    selected = {name: sha((root/name).read_bytes()) for name in SELECTED}
    expected = dict(schema="ptlc-nom-checkpoint-discovery-manifest-v1", profile=PROFILE,
        research_baseline_commit=BASE, input_sha256=selected, preserved_file_sha256=preserved, boundary=BOUNDARY)
    if json.loads((root/FIXTURE).read_text("ascii")) != corpus():
        raise ValueError("selected checkpoint discovery corpus changed")
    if json.loads((root/MANIFEST).read_text("ascii")) != expected:
        raise ValueError("selected checkpoint discovery inputs changed")
    return expected, {**preserved, **selected, MANIFEST: sha((root/MANIFEST).read_bytes())}


def fixture_contexts(root=ROOT):
    policy, contexts, retained = prior.fixture_contexts(root)
    initial = protocol.bootstrap_reference(policy, contexts["primary"])
    latest = protocol.advance_reference(initial, contexts["extended"], expected_current_digest_hex=initial.digest_hex)
    sibling = protocol.advance_reference(initial, contexts["divergent"], expected_current_digest_hex=initial.digest_hex)
    extended = contexts["extended"]._binding._capsule
    events = [json.loads(line)["event"] for line in extended.journal_bytes.splitlines()]
    contexts["third"] = prior.prior.select_context(prior.rewrite_reference(extended,
        events+[dict(kind="recovery-admitted")]), root=root)
    contexts["uncharged_extension"] = prior.prior.select_context(prior.rewrite_reference(extended,
        events+[copy.deepcopy(events[4])]), root=root)
    tail = protocol.advance_reference(latest, contexts["third"], expected_current_digest_hex=latest.digest_hex)
    uncharged = protocol.advance_reference(latest, contexts["uncharged_extension"], expected_current_digest_hex=latest.digest_hex)
    return policy, contexts, retained, dict(initial=initial, latest=latest, tail=tail, sibling=sibling, uncharged=uncharged)


def qualify(root=ROOT):
    _, measured = inputs(root)
    policy, contexts, retained, refs = fixture_contexts(root)
    read = discovery.checkpoint_read(refs["initial"], challenge_hex="d1"*32)
    later = discovery.checkpoint_read(refs["latest"], challenge_hex="d1"*32)
    openings = {name: discovery.checkpoint_opening(value) for name, value in refs.items()}
    results = {}

    def inspect(name, local, selection, opening):
        wire = discovery.unavailable_reply(selection) if opening is None else discovery.discovery_reply(selection, opening)
        result = discovery.inspect_discovery(local, selection, wire, opening)
        assert result["state"] == "HOLD" and result["recovery_action"] == "NONE" and result["worker_calls"] == 0
        assert not any(result[key] for key in ("new_work_allowed", "automatic_retry", "replenish_work", "automatic_bootstrap"))
        assert result["candidate_latest"] == "NOT_ESTABLISHED"
        assert result["response_message_digest_hex"] == discovery.response_message_digest(selection, wire, opening)
        results[name] = result
        return result

    inspect("minimum_candidate", contexts["primary"], read, openings["initial"])
    inspect("newer_candidate", contexts["primary"], read, openings["latest"])
    inspect("later_minimum", contexts["primary"], later, openings["tail"])
    inspect("local_ahead", contexts["third"], read, openings["latest"])
    inspect("extension_without_new_charge", contexts["primary"], later, openings["uncharged"])
    inspect("unavailable_source", contexts["unavailable"], read, openings["latest"])
    inspect("unavailable_service", contexts["primary"], later, None)
    refusals = []

    def refuse(name, operation):
        try:
            operation()
        except ValueError:
            refusals.append(name)
        else:
            raise AssertionError("expected checkpoint discovery refusal missing")

    wire = discovery.discovery_reply(read, openings["latest"])
    refuse("missing_opening", lambda: discovery.inspect_discovery(contexts["primary"], read, wire))
    refuse("below_minimum", lambda: discovery.discovery_reply(later, openings["initial"]))
    refuse("sibling_after_minimum", lambda: discovery.discovery_reply(later, openings["sibling"]))
    other_policy = protocol.select_service(contexts["primary"], service_id_hex="c2"*32,
        service_epoch=1, checkpoint_key_hex=policy.as_dict()["checkpoint_key_hex"])
    other = discovery.checkpoint_opening(protocol.bootstrap_reference(other_policy, contexts["primary"]))
    refuse("changed_service", lambda: discovery.discovery_reply(read, other))
    fresh = discovery.checkpoint_read(refs["initial"], challenge_hex="d2"*32)
    refuse("old_challenge_reply", lambda: discovery.inspect_discovery(contexts["primary"], fresh, wire, openings["latest"]))
    changed = json.loads(wire)
    changed["checkpoint_lineage"] = changed["checkpoint_lineage"][1:]
    refuse("lineage_gap", lambda: discovery.inspect_discovery(contexts["primary"], read, codec._canonical(changed), openings["latest"]))
    changed = json.loads(wire)
    changed["checkpoint_head"]["sequence"] = 2.0
    refuse("numeric_alias", lambda: discovery.inspect_discovery(contexts["primary"], read, codec._canonical(changed), openings["latest"]))
    partial = prior.prior.prior.prior.from_journal(b"".join(retained.journal_bytes.splitlines(keepends=True)[:7]), challenge_hex="a1"*32)
    refuse("missing_original", lambda: prior.prior.select_context(partial, root=root))
    view = discovery.checkpoint_opening(protocol.bootstrap_reference(policy, contexts["source_rotation"]))
    refuse("changed_minimum_source_view", lambda: discovery.discovery_reply(read, view))
    refuse("oversized_reply", lambda: discovery.inspect_discovery(contexts["primary"], read, b"x"*(discovery.MAX_WIRE_BYTES+1), openings["latest"]))
    unsafe = {}
    unsafe["fresh_challenge_old_candidate"] = inspect("fresh_challenge_old_candidate", contexts["primary"], fresh, openings["initial"])
    restored = discovery.checkpoint_read(refs["initial"], challenge_hex="d3"*32)
    unsafe["coherent_restore"] = inspect("coherent_restore", contexts["primary"], restored, openings["initial"])
    first = inspect("sibling_first", contexts["primary"], read, openings["latest"])
    second = inspect("sibling_second", contexts["primary"], read, openings["sibling"])
    unsafe["sibling_candidates_after_same_minimum"] = dict(first=first["candidate_checkpoint_digest_hex"],
        second=second["candidate_checkpoint_digest_hex"], same_sequence=first["candidate_sequence"]==second["candidate_sequence"],
        different_heads=first["candidate_checkpoint_digest_hex"]!=second["candidate_checkpoint_digest_hex"],
        unique_current_head="NOT_ESTABLISHED")
    forged = codec._canonical(json.loads(wire))
    unsafe["unsigned_candidate_forgery"] = discovery.inspect_discovery(contexts["primary"], read, forged, openings["latest"])
    return dict(schema="ptlc-nom-checkpoint-discovery-result-v1", profile=PROFILE, outcome="PASS", input_sha256=measured,
        retained_reference_journal_sha256=retained.projection()["journal_sha256"],
        synthetic_extensions="CANONICAL REFERENCE EVENTS ONLY; ZERO NEW EXECUTION OR ADMISSION RECEIPTS",
        initial_query=read.as_dict(), later_minimum_query=later.as_dict(), comparison_results=results,
        refusal_controls=refusals, unsafe_controls=unsafe, boundary=BOUNDARY)


def check_cases(value, root=ROOT):
    if codec._canonical(value) != codec._canonical(qualify(root)):
        raise ValueError("checkpoint discovery result changed")


def main():
    try:
        result = qualify()
    except (ValueError, TypeError, OSError, KeyError):
        print("selected NoM checkpoint discovery qualification refused", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
