"""Complete synthetic openings qualify consistency, never authenticated truth."""

import ast
import copy
from dataclasses import FrozenInstanceError, replace
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from offline_session import current_authority_contract as current
from qualification import original_read_contract as reads, original_read_response as responses
from qualification import original_read_snapshot as snapshots, policy_effect_store as local
from qualification import source_read_ordering as ordering
from original_snapshot_vectors import INPUT, OUTPUT, canonical, primary_root, root_from, scenario
import original_snapshot_opening as opening


def fixtures():
    return json.loads(INPUT.read_text("ascii")), json.loads(OUTPUT.read_text("ascii"))


def wire(material):
    return canonical(dict(schema=opening.SCHEMA, purpose=opening.PURPOSE, record_material=material))


def reselected_query(query, material):
    """Test adversarial self-selection only, not an authenticated head provider."""
    source = material["source"]
    policy = dict(root_declaration=material["root_declaration"], revision=source["revision"],
        profile_hex=source["profile_hex"], active=source["active"], mode=source["mode"])
    return reads.original_read_query(query._root, query._original,
        checkpoint=current.PolicyCheckpoint(source["revision"],
            hashlib.sha256(opening.POLICY_DOMAIN+canonical(policy)).hexdigest()),
        record_checkpoint=reads.RecordCheckpoint(len(material["events"]),
            hashlib.sha256(opening.RECORD_DOMAIN+canonical(material)).hexdigest()),
        challenge_hex=query.as_dict()["challenge_hex"])


def dictionary_paths(value, prefix=()):
    if isinstance(value, dict):
        for key, child in value.items():
            yield prefix, key
            yield from dictionary_paths(child, prefix+(key,))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from dictionary_paths(child, prefix+(index,))


def at(value, path):
    for part in path:
        value = value[part]
    return value


class OriginalSnapshotOpeningTests(unittest.TestCase):
    def test_nine_live_openings_derive_exact_existing_claims_without_incoming_claims(self):
        inputs, public = fixtures()
        for name, vector in inputs["positive_vectors"].items():
            if name == "unavailable_pending":
                continue
            with self.subTest(name=name), scenario(name) as actual:
                before = actual.path.read_bytes(), actual.store.local_view()
                material, query = actual.material(), actual.query()
                self.assertEqual(material, vector["record_material"])
                claim = opening.derive_claim(query, wire(material))
                self.assertEqual(claim.as_dict(), vector["response"]["claim"])
                derived = responses.original_read_response(actual.root, query, claim)
                self.assertEqual(derived.as_dict(), public["positive_vectors"][name]["response"])
                self.assertEqual(derived.message_digest_hex, vector["message_digest_hex"])
                self.assertEqual((actual.path.read_bytes(), actual.store.local_view()), before)

    def test_unavailable_is_null_state_and_refuses_a_full_history_opening(self):
        with scenario("unavailable_pending") as actual:
            query, material = actual.query(), actual.material()
            actual_claim = actual.response(query).as_dict()["claim"]
            self.assertEqual(actual_claim["observation"], "unavailable")
            self.assertTrue(all(actual_claim[field] is None for field in
                ("claimed_checkpoint", "claimed_record_checkpoint", "head_policy", "original_record")))
            before = actual.path.read_bytes(), actual.store.local_view()
            with self.assertRaises(opening.OpeningRefused):
                opening.derive_claim(query, wire(material))
            self.assertEqual((actual.path.read_bytes(), actual.store.local_view()), before)
            self.assertEqual(actual.store.local_view().charged_operations, 1)

    def test_three_signed_false_state_claims_disagree_with_opened_retained_material(self):
        inputs, public = fixtures()
        for name in ("false_absence_at_pending_head", "false_completion_at_two_charge_head",
                     "false_active_at_revoked_head"):
            vector = public["counterclaim_vectors"][name]
            with self.subTest(name=name), scenario(vector["actual_scenario"]) as actual:
                query = actual.query()
                self.assertEqual(query.as_dict(), vector["response"]["query"])
                derived = opening.derive_claim(query, wire(actual.material()))
                expected = responses.original_read_response(actual.root, query, derived)
                self.assertNotEqual(derived.as_dict(), vector["response"]["claim"])
                self.assertTrue(vector["result"]["root_signature_valid"])
                self.assertTrue(vector["result"]["response_signature_valid"])
                self.assertEqual(inputs["counterclaim_vectors"][name]["response"], vector["response"])
                with self.assertRaises(responses.OriginalResponseError):
                    responses.request(expected, canonical(vector["envelope"]))

    def test_same_id_proposal_and_historical_profile_collisions_refuse_even_with_open_heads(self):
        _, public = fixtures()
        for name in ("same_id_other_proposal", "same_id_other_historical_profile"):
            vector = public["counterclaim_vectors"][name]
            with self.subTest(name=name), scenario(vector["actual_scenario"]) as actual:
                original = vector["response"]["query"]["original_operation"]
                request = local.OriginalRequest(original["operation_id_hex"], original["expected_revision"],
                    canonical(original["governor_profile"]), original["proposal_digest_hex"])
                query = actual.query(original=request)
                self.assertEqual(query.as_dict(), vector["response"]["query"])
                with self.assertRaises(opening.OpeningRefused):
                    opening.derive_claim(query, wire(actual.material()))
                with self.assertRaises(local.StoreRefused):
                    snapshots.sample_original(actual.store, actual.root, query)

    def test_fresh_challenge_over_old_absence_opens_history_but_not_the_changed_current_heads(self):
        _, public = fixtures()
        vector = public["counterclaim_vectors"]["fresh_challenge_over_initial_absence"]
        with scenario("initial_absent") as actual:
            old_wire, old_query = wire(actual.material()), actual.query(challenge="07")
            derived = opening.derive_claim(old_query, old_wire)
            self.assertEqual(derived.as_dict(), vector["response"]["claim"])
            actual.store.allocate_synthetic(actual.original)
            self.assertEqual(opening.derive_claim(old_query, old_wire).as_dict(), derived.as_dict())
            with self.assertRaises(opening.OpeningRefused):
                opening.derive_claim(actual.query(challenge="07"), old_wire)
            with self.assertRaises(local.StoreRefused):
                snapshots.sample_original(actual.store, actual.root, old_query)
            self.assertEqual(actual.store.local_view().charged_operations, 1)

    def test_historical_profile_is_checked_even_for_an_absent_different_original(self):
        with scenario("replaced_completed") as actual:
            old = json.loads(actual.profile)
            other = replace(actual.original, operation_id_hex="10"*32)
            claim = opening.derive_claim(actual.query(original=other), wire(actual.material()))
            self.assertEqual(claim.as_dict()["observation"], "absent")
            old["authority_epoch"] += 1
            query = actual.query(original=replace(other, profile_wire=canonical(old)))
            with self.assertRaises(opening.OpeningRefused):
                opening.derive_claim(query, wire(actual.material()))

    def test_complete_original_retains_old_owner_and_profile_after_current_replacement(self):
        with scenario("replaced_completed") as actual:
            claim = opening.derive_claim(actual.query(), wire(actual.material())).as_dict()
            old = claim["original_record"]["original_operation"]["governor_profile"]
            new = claim["head_policy"]["governor_profile"]
            self.assertNotEqual(old["owner_auth_key_hex"], new["owner_auth_key_hex"])
            self.assertEqual(old, json.loads(actual.profile))
            self.assertFalse(claim["head_policy"]["active"])

    def test_cap_reduction_preserves_earlier_two_charges_without_authorizing_a_third(self):
        with scenario("reduced_pending_two_charges") as actual:
            query, material = actual.query(), actual.material()
            claim = opening.derive_claim(query, wire(material)).as_dict()
            self.assertEqual(len(material["operations"]), 2)
            self.assertEqual(claim["head_policy"]["governor_profile"]["max_attempt_limit"], 1)
            self.assertEqual(claim["observation"], "pending")
            profile = claim["head_policy"]["governor_profile"]
            original = reads.original_operation(operation_id_hex="10"*32, expected_revision=1,
                profile_wire=canonical(profile), proposal_digest_hex="11"*32).as_dict()
            material["operations"].append(dict(original_operation=original, charge_sequence=4, effect_sequence=None))
            material["events"].append(dict(event_sequence=4, kind="charge", revision=1,
                operation_id_hex="10"*32, detail=""))
            with self.assertRaises(opening.OpeningRefused):
                opening.derive_claim(reselected_query(query, material), wire(material))

    def test_mode_round_trip_keeps_policy_digest_but_changes_complete_record_commitment(self):
        with scenario("pending") as actual:
            old_query, old_wire = actual.query(), wire(actual.material())
            actual.store.set_local_source_mode("unavailable")
            actual.store.set_local_source_mode("live")
            new_query = actual.query()
            self.assertEqual(old_query.as_dict()["expected_checkpoint"], new_query.as_dict()["expected_checkpoint"])
            self.assertNotEqual(old_query.as_dict()["expected_record_checkpoint"], new_query.as_dict()["expected_record_checkpoint"])
            with self.assertRaises(opening.OpeningRefused):
                opening.derive_claim(new_query, old_wire)
            self.assertEqual(opening.derive_claim(old_query, old_wire).as_dict()["observation"], "pending")

    def test_bad_digest_bytes_and_coherently_rehashed_new_material_refuse_independent_old_heads(self):
        with scenario("pending") as actual:
            query, material = actual.query(), actual.material()
            changed = copy.deepcopy(material)
            changed["operations"][0]["original_operation"]["proposal_digest_hex"] = "11"*32
            with self.assertRaises(opening.OpeningRefused):
                opening.derive_claim(query, wire(changed))
            with self.assertRaises(opening.OpeningRefused):
                opening.derive_claim(reselected_query(query, changed), wire(changed))
            selected = query.as_dict()
            for field, key in (("expected_checkpoint", "policy_state_digest_hex"),
                               ("expected_record_checkpoint", "record_lineage_digest_hex")):
                with self.subTest(head=field):
                    altered = copy.deepcopy(selected)
                    altered[field][key] = "00"*32
                    prepared = responses._prepared(actual.root.as_dict(), altered)
                    with self.assertRaises(opening.OpeningRefused):
                        opening.derive_claim(prepared, wire(material))

    def test_complete_root_changes_cannot_follow_independently_selected_root(self):
        with scenario("pending") as actual:
            query, material = actual.query(), actual.material()
            for field in ("declaration_revision", "delegated_keys", "source_context"):
                changed = copy.deepcopy(material)
                if field == "declaration_revision":
                    changed["root_declaration"][field] += 1
                elif field == "delegated_keys":
                    changed["root_declaration"][field]["source_response_key_hex"] = "11"*32
                else:
                    changed["root_declaration"][field]["source_incarnation_hex"] = "11"*32
                with self.subTest(field=field), self.assertRaises(opening.OpeningRefused):
                    opening.derive_claim(reselected_query(query, changed), wire(changed))

    def test_every_nested_object_rejects_missing_and_additional_fields(self):
        with scenario("completed") as actual:
            query = actual.query()
            packet = json.loads(wire(actual.material()))
            for path, key in dictionary_paths(packet):
                for operation in ("missing", "additional"):
                    changed = copy.deepcopy(packet)
                    target = at(changed, path)
                    if operation == "missing":
                        del target[key]
                    else:
                        target["unexpected_permission"] = True
                    with self.subTest(path=path, key=key, operation=operation), self.assertRaises(opening.OpeningRefused):
                        opening.derive_claim(query, canonical(changed))

    def test_numeric_boolean_aliases_and_exact_field_types_refuse(self):
        with scenario("completed") as actual:
            query = actual.query()
            packet = json.loads(wire(actual.material()))
            paths = (("record_material", "root_declaration", "declaration_revision"),
                ("record_material", "source", "revision"), ("record_material", "source", "active"),
                ("record_material", "policies", 0, "revision"), ("record_material", "policies", 0, "active"),
                ("record_material", "operations", 0, "charge_sequence"),
                ("record_material", "operations", 0, "effect_sequence"),
                ("record_material", "operations", 0, "original_operation", "expected_revision"),
                ("record_material", "effects", 0, "event_sequence"),
                ("record_material", "events", 0, "event_sequence"))
            for path in paths:
                old = at(packet, path)
                aliases = (int(old), "1", None) if type(old) is bool else (bool(old), float(old), "1", -1)
                for alias in aliases:
                    changed = copy.deepcopy(packet)
                    at(changed, path[:-1])[path[-1]] = alias
                    with self.subTest(path=path, alias=alias), self.assertRaises(opening.OpeningRefused):
                        opening.derive_claim(query, canonical(changed))

    def test_duplicate_unordered_and_nonsequential_retained_lists_refuse(self):
        with scenario("reduced_pending_two_charges") as actual:
            query, material = actual.query(), actual.material()
            for key in ("policies", "operations", "events"):
                for operation in ("duplicate", "reverse", "remove"):
                    changed = copy.deepcopy(material)
                    if operation == "duplicate":
                        changed[key].append(copy.deepcopy(changed[key][0]))
                    elif operation == "reverse":
                        changed[key].reverse()
                    else:
                        changed[key].pop(0)
                    with self.subTest(key=key, operation=operation), self.assertRaises(opening.OpeningRefused):
                        opening.derive_claim(reselected_query(query, changed), wire(changed))
        with scenario("completed") as actual:
            material = actual.material()
            material["effects"].append(copy.deepcopy(material["effects"][0]))
            with self.assertRaises(opening.OpeningRefused):
                opening.derive_claim(reselected_query(actual.query(), material), wire(material))

    def test_record_charge_effect_and_event_correspondence_refuse_rehashed_inconsistency(self):
        with scenario("completed") as actual:
            query, material = actual.query(), actual.material()
            mutations = (("operations", 0, "charge_sequence", 2), ("operations", 0, "effect_sequence", None),
                ("operations", 0, "effect_sequence", 1), ("effects", 0, "event_sequence", 1),
                ("effects", 0, "payload", "other-effect"), ("events", 0, "operation_id_hex", "11"*32),
                ("events", 1, "kind", "charge"), ("events", 1, "detail", "unexpected"),
                ("events", 1, "revision", 1))
            for table, index, key, value in mutations:
                changed = copy.deepcopy(material)
                changed[table][index][key] = value
                with self.subTest(table=table, key=key, value=value), self.assertRaises(opening.OpeningRefused):
                    opening.derive_claim(reselected_query(query, changed), wire(changed))
            for table in ("operations", "effects", "events"):
                changed = copy.deepcopy(material)
                changed[table] = []
                with self.subTest(empty=table), self.assertRaises(opening.OpeningRefused):
                    opening.derive_claim(reselected_query(query, changed), wire(changed))

    def test_policy_history_and_current_source_must_match_each_ordered_event(self):
        with scenario("revoked_pending") as actual:
            query, material = actual.query(), actual.material()
            mutations = (("policies", 0, "active", False), ("policies", 0, "event_sequence", 1),
                ("policies", 1, "event_sequence", 1), ("policies", 1, "revision", 0),
                ("policies", 1, "active", True), ("events", 1, "revision", 0),
                ("events", 1, "operation_id_hex", "01"*32))
            for table, index, key, value in mutations:
                changed = copy.deepcopy(material)
                changed[table][index][key] = value
                with self.subTest(table=table, key=key), self.assertRaises(opening.OpeningRefused):
                    opening.derive_claim(reselected_query(query, changed), wire(changed))

    def test_charge_or_effect_requires_live_active_matching_policy_at_its_event(self):
        with scenario("completed") as actual:
            query, material = actual.query(), actual.material()
            for mode in ("unavailable", "ambiguous", "compromise-detected"):
                changed = copy.deepcopy(material)
                changed["events"].insert(1, dict(event_sequence=2, kind="mode", revision=0,
                    operation_id_hex=None, detail=mode))
                changed["events"][2]["event_sequence"] = 3
                changed["operations"][0]["effect_sequence"] = 3
                changed["effects"][0]["event_sequence"] = 3
                changed["source"]["mode"] = mode
                with self.subTest(mode=mode), self.assertRaises(opening.OpeningRefused):
                    opening.derive_claim(reselected_query(query, changed), wire(changed))
            changed = copy.deepcopy(material)
            changed["policies"].append(dict(revision=1, profile_hex=changed["source"]["profile_hex"],
                active=False, event_sequence=2))
            changed["source"].update(revision=1, active=False)
            changed["events"].insert(1, dict(event_sequence=2, kind="policy", revision=1,
                operation_id_hex=None, detail=""))
            changed["events"][2].update(event_sequence=3, revision=1)
            changed["operations"][0]["effect_sequence"] = 3
            changed["effects"][0]["event_sequence"] = 3
            with self.assertRaises(opening.OpeningRefused):
                opening.derive_claim(reselected_query(query, changed), wire(changed))

    def test_mode_events_require_a_real_transition_and_matching_final_source(self):
        with scenario("mode_round_trip_pending") as actual:
            query, material = actual.query(), actual.material()
            for index, key, value in ((1, "detail", "live"), (2, "detail", "unavailable"),
                                      (1, "operation_id_hex", "01"*32), (1, "revision", 1)):
                changed = copy.deepcopy(material)
                changed["events"][index][key] = value
                with self.subTest(index=index, key=key), self.assertRaises(opening.OpeningRefused):
                    opening.derive_claim(reselected_query(query, changed), wire(changed))

    def test_profile_hex_requires_canonical_complete_namespace_bound_historical_profiles(self):
        with scenario("replaced_completed") as actual:
            query, material = actual.query(), actual.material()
            profile = json.loads(bytes.fromhex(material["policies"][0]["profile_hex"]))
            variants = (material["policies"][0]["profile_hex"].upper(), "00", "f", "gg",
                json.dumps(profile, indent=2).encode("ascii").hex())
            for value in variants:
                changed = copy.deepcopy(material)
                changed["policies"][0]["profile_hex"] = value
                with self.subTest(value=value[:20]), self.assertRaises(opening.OpeningRefused):
                    opening.derive_claim(reselected_query(query, changed), wire(changed))
            profile["authority_id_hex"] = "ff"*32
            changed = copy.deepcopy(material)
            changed["policies"][0]["profile_hex"] = canonical(profile).hex()
            with self.assertRaises(opening.OpeningRefused):
                opening.derive_claim(reselected_query(query, changed), wire(changed))

    def test_wire_aliases_duplicate_keys_deep_values_and_oversized_inputs_refuse(self):
        with scenario("pending") as actual:
            query, good = actual.query(), wire(actual.material())
            variants = (good+b"\n", b" "+good, good.replace(b'"purpose":', b'"purpose":"x","purpose":', 1),
                good.replace(b'"revision":0', b'"revision":0.0', 1),
                good.replace(b'"revision":0', b'"revision":-0', 1),
                good.replace(b'"revision":0', b'"revision":9007199254740992', 1),
                good.replace(b'"revision":0', b'"revision":'+b"9"*5000, 1),
                b'{"schema":NaN}', b'{"schema":Infinity}', b'{"schema":"\xff"}',
                b"["*1000+b"0"+b"]"*1000, b" "*(opening.MAX_WIRE_BYTES+1), b"", bytearray(good))
            for index, value in enumerate(variants):
                with self.subTest(index=index), self.assertRaises(opening.OpeningRefused):
                    opening.derive_claim(query, value)
            deep = 0
            for _ in range(opening.MAX_DEPTH+1):
                deep = [deep]
            with self.assertRaises(opening.OpeningRefused):
                opening.derive_claim(query, canonical(deep))

    def test_finite_store_bounds_and_retention_schema_refuse(self):
        with scenario("pending") as actual:
            query, material = actual.query(), actual.material()
            for table, maximum in (("policies", 33), ("operations", 64), ("events", 256)):
                changed = copy.deepcopy(material)
                changed[table] = [copy.deepcopy(changed[table][0]) for _ in range(maximum+1)]
                with self.subTest(table=table), self.assertRaises(opening.OpeningRefused):
                    opening.derive_claim(query, wire(changed))
            changed = copy.deepcopy(material)
            changed["source"]["revision"] = 33
            with self.assertRaises(opening.OpeningRefused):
                opening.derive_claim(query, wire(changed))
            changed = copy.deepcopy(material)
            changed["retention_rule"] = "selectively-retained"
            with self.assertRaises(opening.OpeningRefused):
                opening.derive_claim(query, wire(changed))
            packet = json.loads(wire(material))
            packet["schema"] = "ptlc-original-read-snapshot-response-public-vectors-v1"
            with self.assertRaises(opening.OpeningRefused):
                opening.derive_claim(query, canonical(packet))

    def test_actual_maximum_revision_history_opens_without_current_owner_reinterpretation(self):
        with scenario("pending") as actual:
            for revision in range(opening.MAX_REVISION):
                actual.store.replace_local_policy(revision, actual.profile, active=True)
            material, query = actual.material(), actual.query()
            self.assertEqual(material["source"]["revision"], 32)
            self.assertEqual(len(material["policies"]), 33)
            claim = opening.derive_claim(query, wire(material)).as_dict()
            self.assertEqual(claim["original_record"]["original_operation"]["expected_revision"], 0)
            self.assertEqual(claim["observation"], "pending")

    def test_actual_maximum_records_and_events_open_under_separate_byte_bound(self):
        declaration = primary_root().as_dict()
        declaration["governor_profile"].update(max_attempt_limit=64, max_target_limit=64)
        root = root_from(declaration)
        source = declaration["source_context"]
        labels = local.SourceLabels(source["source_id_hex"], source["source_incarnation_hex"],
            source["authority_id_hex"], source["resource_digest_hex"])
        profile = canonical(declaration["governor_profile"])
        with tempfile.TemporaryDirectory(prefix="synthetic-opening-bounds-") as directory:
            with local.OfflinePolicyEffectStore(str(Path(directory)/"policy.sqlite3"), labels, initial_profile=profile) as store:
                originals = [local.OriginalRequest(format(index, "064x"), 0, profile, "11"*32) for index in range(1, 65)]
                for original in originals:
                    store.allocate_synthetic(original)
                    store.apply_synthetic_effect(original)
                for _ in range(64):
                    store.set_local_source_mode("unavailable")
                    store.set_local_source_mode("live")
                # The unchanged sampler, not the test parser, selects both local heads.
                heads = snapshots.local_checkpoints(store, root)
                original = originals[0]
                operation = reads.original_operation(operation_id_hex=original.operation_id_hex, expected_revision=0,
                    profile_wire=profile, proposal_digest_hex=original.proposal_digest_hex)
                query = reads.original_read_query(root, operation, checkpoint=heads.policy_checkpoint,
                    record_checkpoint=heads.record_checkpoint, challenge_hex="12"*32)
                from original_snapshot_vectors import Scenario
                holder = object.__new__(Scenario)
                holder.store, holder.root = store, root
                material = holder.material()
                self.assertEqual(tuple(len(material[key]) for key in ("operations", "effects", "events")), (64, 64, 256))
                self.assertLess(len(wire(material)), opening.MAX_WIRE_BYTES)
                derived = opening.derive_claim(query, wire(material))
                self.assertEqual(derived.as_dict(), snapshots.sample_original(store, root, query).as_dict())
                material["effects"].append(copy.deepcopy(material["effects"][0]))
                with self.assertRaises(opening.OpeningRefused):
                    opening.derive_claim(query, wire(material))

    def test_old_correct_opening_remains_replayable_after_revocation_without_source_mutation(self):
        with scenario("pending") as actual:
            query, retained = actual.query(), wire(actual.material())
            claim = opening.derive_claim(query, retained)
            actual.store.replace_local_policy(0, actual.profile, active=False)
            before = actual.path.read_bytes(), actual.store.local_view()
            self.assertEqual(opening.derive_claim(query, retained).as_dict(), claim.as_dict())
            self.assertTrue(claim.as_dict()["head_policy"]["active"])
            with self.assertRaises(opening.OpeningRefused):
                opening.derive_claim(actual.query(), retained)
            with self.assertRaises(local.StoreRefused):
                actual.store.apply_synthetic_effect(actual.original)
            self.assertEqual((actual.path.read_bytes(), actual.store.local_view()), before)

    def test_self_selected_truncated_history_opens_absence_without_proving_retention_or_currentness(self):
        with scenario("pending") as actual:
            query, material = actual.query(), actual.material()
            material.update(operations=[], effects=[], events=[])
            with self.assertRaises(opening.OpeningRefused):
                opening.derive_claim(query, wire(material))
            # A coherent alleged past opens under attacker-selected diagnostic heads.
            # This is precisely why external head/retention provenance stays a gate.
            selected_past = reselected_query(query, material)
            claim = opening.derive_claim(selected_past, wire(material)).as_dict()
            self.assertEqual(claim["observation"], "absent")
            self.assertEqual(actual.store.local_view().charged_operations, 1)
            self.assertEqual(snapshots.sample_original(actual.store, actual.root, query).as_dict()["observation"], "pending")
            with self.assertRaises(local.StoreRefused):
                snapshots.sample_original(actual.store, actual.root, selected_past)

    def test_coherent_restore_reproduces_opening_and_can_repeat_separate_synthetic_effect(self):
        with scenario("pending") as actual:
            query, retained = actual.query(), wire(actual.material())
            claim = opening.derive_claim(query, retained)
            actual.store.close()
            saved = actual.path.read_bytes()
            effects = []
            for _ in range(2):
                actual.path.write_bytes(saved)
                with local.OfflinePolicyEffectStore(str(actual.path), actual.labels) as restored:
                    self.assertEqual(snapshots.local_checkpoints(restored, actual.root).as_dict(),
                        dict(policy_checkpoint=query.as_dict()["expected_checkpoint"],
                            record_checkpoint=query.as_dict()["expected_record_checkpoint"]))
                    self.assertEqual(opening.derive_claim(query, retained).as_dict(), claim.as_dict())
                    effects.append(restored.apply_synthetic_effect(actual.original).effect_sequence)
            self.assertEqual(effects, [2, 2])

    def test_detached_frozen_unsigned_result_and_invalid_exact_selections(self):
        with scenario("pending") as actual:
            query, retained = actual.query(), wire(actual.material())
            claim = opening.derive_claim(query, retained)
            changed = claim.as_dict()
            changed["head_policy"]["active"] = False
            self.assertTrue(claim.as_dict()["head_policy"]["active"])
            with self.assertRaises(FrozenInstanceError):
                claim._wire = b"changed"
            class QueryHook(reads.OriginalReadQuery):
                def as_dict(self):
                    raise AssertionError("subclass hook must not run")
            class WireHook(bytes):
                def __len__(self):
                    raise AssertionError("subclass hook must not run")
            for bad in (None, query.as_dict(), object.__new__(QueryHook), object.__new__(reads.OriginalReadQuery)):
                with self.assertRaises(opening.OpeningRefused):
                    opening.derive_claim(bad, retained)
            with self.assertRaises(opening.OpeningRefused):
                opening.derive_claim(query, WireHook(retained))

    def test_fixed_public_fixtures_domains_and_test_only_no_io_dependencies_are_preserved(self):
        for path, pin in ((INPUT, "0f0bdf4d916c5371f35eb7c2afee03dbcdef4a319999c01955f4b052d9d8fd01"),
                          (OUTPUT, "2d461a54413ef156df62db26c88ac6f789ed8ea27322f3b8b12800b74f8de1bb")):
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), pin)
        self.assertEqual(opening.POLICY_DOMAIN, ordering.STATE_DOMAIN)
        self.assertEqual(opening.RECORD_DOMAIN, snapshots.LINEAGE_DOMAIN)
        self.assertEqual((opening.MAX_REVISION, opening.MAX_EVENTS), (local.MAX_REVISION, local.MAX_EVENTS))
        tree = ast.parse(Path("tests/original_snapshot_opening.py").read_text("ascii"))
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.add(node.module)
        self.assertEqual(imports, {"hashlib", "json", "re", "offline_session", "qualification"})
        calls = {node.func.id for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
        self.assertFalse(calls & {"open", "eval", "exec", "__import__"})


if __name__ == "__main__":
    unittest.main()
