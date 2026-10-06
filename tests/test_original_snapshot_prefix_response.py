"""Framing regressions use callback controls, not application cryptography.

Actual historical signature mathematics runs separately in the post-build
qualifier. These tests do not label arbitrary callback flags as mathematics.
"""

import ast
import copy
from dataclasses import FrozenInstanceError, replace
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from qualification import original_read_contract as reads, original_read_response as response
from original_snapshot_vectors import INPUT, OUTPUT, canonical, scenario
from scripts import qualify_original_snapshot_prefix_response as harness
import original_snapshot_opening as opening
import original_snapshot_prefix as prefix
import original_snapshot_prefix_response as composition


def callback_control(packet):
    """Intentionally forge both flags; supplies no signature mathematics."""
    return response.expected_result(response.request_digest(packet))


class OriginalSnapshotPrefixResponseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = json.loads(OUTPUT.read_text("ascii"))

    def positive(self, name):
        return self.fixture["positive_vectors"][name]

    def arguments(self, earlier, later, old_vector, new_vector):
        return (*earlier, canonical(old_vector["envelope"]), *later, canonical(new_vector["envelope"]))

    def refuse_before_check(self, args):
        calls = []
        def check(packet):
            calls.append(packet)
            return callback_control(packet)
        with self.assertRaises(composition.PrefixResponseRefused):
            composition.compare_public_responses(*args, verifier=check)
        self.assertEqual(calls, [])

    def test_nine_live_framings_derive_complete_expected_requests_before_callback_controls(self):
        for name, vector in self.fixture["positive_vectors"].items():
            if name == "unavailable_pending":
                continue
            with self.subTest(name=name), scenario(name) as actual:
                pair = harness.capture(actual)
                before = actual.path.read_bytes(), actual.store.local_view()
                calls = []
                def check(packet):
                    calls.append(copy.deepcopy(packet))
                    return callback_control(packet)
                result = composition.compare_public_responses(*self.arguments(pair, pair, vector, vector), verifier=check)
                self.assertEqual(calls, [vector["request"], vector["request"]])
                self.assertEqual(result, prefix.compare_openings(*pair, *pair))
                self.assertEqual((actual.path.read_bytes(), actual.store.local_view()), before)

    def test_chain_keeps_two_complete_requests_ordered_and_reverse_refuses_before_callbacks(self):
        with scenario("initial_absent") as actual:
            absent = harness.capture(actual)
            actual.store.allocate_synthetic(actual.original)
            pending = harness.capture(actual)
            actual.store.apply_synthetic_effect(actual.original)
            completed = harness.capture(actual)
            for earlier, later, old, new in ((absent, pending, "initial_absent", "pending"),
                    (pending, completed, "pending", "completed"), (absent, completed, "initial_absent", "completed")):
                with self.subTest(transition=(old, new)):
                    calls = []
                    def check(packet):
                        calls.append(copy.deepcopy(packet))
                        return callback_control(packet)
                    result = harness.compare(earlier, later, self.positive(old), self.positive(new), verifier=check)
                    self.assertEqual(calls, [self.positive(old)["request"], self.positive(new)["request"]])
                    self.assertEqual(result.relation, "retained-extension")
                    self.refuse_before_check(self.arguments(later, earlier, self.positive(new), self.positive(old)))

    def test_two_fixture_futures_extend_pending_but_each_other_refuse_before_callbacks(self):
        with scenario("pending") as old, scenario("completed") as completed, scenario("revoked_pending") as revoked:
            pending, done, stopped = map(harness.capture, (old, completed, revoked))
            for later, name in ((done, "completed"), (stopped, "revoked_pending")):
                result = harness.compare(pending, later, self.positive("pending"), self.positive(name), verifier=callback_control)
                self.assertEqual(result.relation, "retained-extension")
            self.refuse_before_check(self.arguments(done, stopped, self.positive("completed"), self.positive("revoked_pending")))
            self.refuse_before_check(self.arguments(stopped, done, self.positive("revoked_pending"), self.positive("completed")))

    def test_signed_fixture_false_states_on_either_side_do_not_supply_expectations(self):
        for name, vector in self.fixture["counterclaim_vectors"].items():
            if not name.startswith("false_"):
                continue
            with self.subTest(name=name), scenario(vector["actual_scenario"]) as actual:
                pair = harness.counter_query(actual, name)
                valid = self.positive(vector["actual_scenario"])
                self.assertNotEqual(opening.derive_claim(*pair).as_dict(), vector["response"]["claim"])
                for earlier, later in ((valid, vector), (vector, valid)):
                    self.refuse_before_check(self.arguments(pair, pair, earlier, later))

    def test_independent_tuple_collision_queries_refuse_even_self_consistent_packets(self):
        for name in ("same_id_other_proposal", "same_id_other_historical_profile"):
            vector = self.fixture["counterclaim_vectors"][name]
            with self.subTest(name=name), scenario(vector["actual_scenario"]) as actual:
                pair = harness.counter_query(actual, name)
                self.assertEqual(pair[0].as_dict(), vector["response"]["query"])
                self.refuse_before_check(self.arguments(pair, pair, vector, vector))

    def test_fresh_challenge_changes_request_but_old_opening_still_compares_after_charge(self):
        with scenario("initial_absent") as actual:
            old, fresh = harness.capture(actual), harness.capture(actual, challenge="07")
            old_vector = self.positive("initial_absent")
            fresh_vector = self.fixture["counterclaim_vectors"]["fresh_challenge_over_initial_absence"]
            args = self.arguments(old, fresh, old_vector, fresh_vector)
            result = composition.compare_public_responses(*args, verifier=callback_control)
            actual.store.allocate_synthetic(actual.original)
            self.assertEqual(composition.compare_public_responses(*args, verifier=callback_control), result)
            self.assertEqual(result.relation, "same-history")
            self.assertNotEqual(result.earlier_query_digest_hex, result.later_query_digest_hex)
            pending = harness.capture(actual)
            self.refuse_before_check(self.arguments(pending, fresh, self.positive("pending"), fresh_vector))

    def test_unavailable_null_claims_cannot_replace_live_complete_openings(self):
        with scenario("pending") as actual:
            live = harness.capture(actual)
            actual.store.set_local_source_mode("unavailable")
            unavailable = harness.capture(actual)
            vector = self.positive("unavailable_pending")
            self.assertTrue(all(vector["response"]["claim"][field] is None for field in
                ("claimed_checkpoint", "claimed_record_checkpoint", "head_policy", "original_record")))
            self.refuse_before_check(self.arguments(live, unavailable, self.positive("pending"), vector))
            self.refuse_before_check(self.arguments(unavailable, live, vector, self.positive("pending")))

    def test_malformed_later_packet_cannot_trigger_even_earlier_callback(self):
        with scenario("pending") as actual:
            pair, vector = harness.capture(actual), self.positive("pending")
            variants = []
            for field in ("schema", "response_signature_hex"):
                v = copy.deepcopy(vector)
                v["envelope"][field] = "synthetic-invalid"
                variants.append(v)
            for object_name in ("envelope", "response", "root"):
                v = copy.deepcopy(vector)
                target = v["envelope"]
                if object_name == "response":
                    target = target["response"]
                elif object_name == "root":
                    target = target["root_envelope"]["declaration"]
                target["current_permission"] = True
                variants.append(v)
            v = copy.deepcopy(vector)
            v["envelope"]["response"]["claim"]["original_record"]["charge_sequence"] = 2
            variants.append(v)
            v = copy.deepcopy(vector)
            v["envelope"]["response"]["query"]["challenge_hex"] = "07"*32
            variants.append(v)
            for v in variants:
                self.refuse_before_check(self.arguments(pair, pair, vector, v))

    def test_packets_for_other_selected_heads_cannot_replace_opened_expectations(self):
        with scenario("initial_absent") as actual:
            absent = harness.capture(actual)
            actual.store.allocate_synthetic(actual.original)
            pending = harness.capture(actual)
            for old_name, new_name in (("pending", "pending"), ("initial_absent", "initial_absent")):
                self.refuse_before_check(self.arguments(absent, pending, self.positive(old_name), self.positive(new_name)))

    def test_exact_query_and_all_four_byte_types_refuse_subclass_hooks_before_opening(self):
        class QuerySubclass(reads.OriginalReadQuery):
            def as_dict(self):
                raise AssertionError("query hook must not run")
        class BytesSubclass(bytes):
            def decode(self, *args, **kwargs):
                raise AssertionError("byte hook must not run")
        with scenario("pending") as actual:
            pair, vector = harness.capture(actual), self.positive("pending")
            good = self.arguments(pair, pair, vector, vector)
            for index in range(6):
                args = list(good)
                args[index] = object.__new__(QuerySubclass) if index in (0, 3) else BytesSubclass(good[index])
                with self.subTest(index=index), patch.object(prefix, "compare_openings") as opened:
                    self.refuse_before_check(args)
                    opened.assert_not_called()

    def test_noncallable_checker_refuses_before_any_opening(self):
        with scenario("pending") as actual:
            pair, vector = harness.capture(actual), self.positive("pending")
            with patch.object(prefix, "compare_openings") as opened:
                for verifier in (None, True, {}, "synthetic-checker"):
                    with self.assertRaises(composition.PrefixResponseRefused):
                        composition.compare_public_responses(*self.arguments(pair, pair, vector, vector), verifier=verifier)
                opened.assert_not_called()

    def test_noncanonical_duplicate_bounded_and_invalid_wires_refuse_before_callbacks(self):
        with scenario("pending") as actual:
            pair, vector = harness.capture(actual), self.positive("pending")
            good = self.arguments(pair, pair, vector, vector)
            for index in (1, 2, 4, 5):
                limit = opening.MAX_WIRE_BYTES if index in (1, 4) else response.MAX_WIRE_BYTES
                variants = (b"", b"{}", b"[]", good[index]+b"\n",
                    json.dumps(json.loads(good[index].decode("ascii"))).encode("ascii"),
                    b'{"schema":"x","schema":"x"}', b"x"*(limit+1))
                for invalid in variants:
                    with self.subTest(index=index, length=len(invalid)):
                        args = list(good)
                        args[index] = invalid
                        self.refuse_before_check(args)

    def test_wrong_digest_flags_types_and_extra_result_fields_refuse_at_either_check(self):
        with scenario("initial_absent") as actual:
            earlier = harness.capture(actual)
            actual.store.allocate_synthetic(actual.original)
            later = harness.capture(actual)
            args = self.arguments(earlier, later, self.positive("initial_absent"), self.positive("pending"))
            for position in (1, 2):
                for mutation in ("cached", "wrong-digest", "integer-flag", "missing", "permission", "not-dict"):
                    calls = []
                    def check(packet):
                        calls.append(packet)
                        result = callback_control(packet)
                        if len(calls) == position:
                            if mutation == "cached":
                                return self.positive("completed")["result"]
                            if mutation == "wrong-digest":
                                result["request_digest_hex"] = "00"*32
                            elif mutation == "integer-flag":
                                result["response_signature_valid"] = 1
                            elif mutation == "missing":
                                result.pop("root_signature_valid")
                            elif mutation == "permission":
                                result["current_permission"] = True
                            else:
                                return []
                        return result
                    with self.subTest(position=position, mutation=mutation), self.assertRaises(composition.PrefixResponseRefused):
                        composition.compare_public_responses(*args, verifier=check)
                    self.assertEqual(len(calls), position)

    def test_checker_exceptions_refuse_quietly_without_returning_partial_description(self):
        with scenario("pending") as actual:
            pair, vector = harness.capture(actual), self.positive("pending")
            for position in (1, 2):
                calls = []
                def check(packet):
                    calls.append(packet)
                    if len(calls) == position:
                        raise OSError("synthetic untrusted checker diagnostic")
                    return callback_control(packet)
                with self.assertRaises(composition.PrefixResponseRefused) as caught:
                    composition.compare_public_responses(*self.arguments(pair, pair, vector, vector), verifier=check)
                self.assertEqual(str(caught.exception), "synthetic public-response prefix comparison refused")
                self.assertTrue(caught.exception.__suppress_context__)
                self.assertEqual(len(calls), position)

    def test_mutating_checker_packet_cannot_change_the_independent_request_digest(self):
        with scenario("pending") as actual:
            pair, vector = harness.capture(actual), self.positive("pending")
            original_bytes = canonical(vector["envelope"])
            def check(packet):
                packet["response"]["query"]["challenge_hex"] = "07"*32
                packet["response"]["claim"]["challenge_hex"] = "07"*32
                return dict(vector["result"], request_digest_hex="00"*32)
            with self.assertRaises(composition.PrefixResponseRefused):
                composition.compare_public_responses(*self.arguments(pair, pair, vector, vector), verifier=check)
            self.assertEqual(canonical(vector["envelope"]), original_bytes)
            self.assertEqual(opening.derive_claim(*pair).as_dict(), vector["response"]["claim"])

    def test_returned_unsigned_description_is_frozen_defensive_and_has_no_permission_flags(self):
        with scenario("pending") as actual:
            pair, vector = harness.capture(actual), self.positive("pending")
            result = harness.compare(pair, pair, vector, vector, verifier=callback_control)
            self.assertIs(type(result), prefix.PrefixDescription)
            with self.assertRaises(FrozenInstanceError):
                result.relation = "current"
            view = result.as_dict()
            view["later"]["observation"] = "completed"
            self.assertEqual(result.as_dict()["later"]["observation"], "pending")
            self.assertEqual(set(result.as_dict()), {"purpose", "relation", "earlier", "later",
                "retained_originals", "appended_originals", "retained_effects", "appended_effects"})
            self.assertFalse(any(type(value) is bool for value in result.__dict__.values()))

    def test_complete_root_and_original_tuple_boundaries_refuse_before_callbacks(self):
        with scenario("completed") as old, scenario("replaced_completed") as replaced:
            earlier, later = harness.capture(old), harness.capture(replaced)
            opening.derive_claim(*earlier)
            opening.derive_claim(*later)
            self.refuse_before_check(self.arguments(earlier, later, self.positive("completed"), self.positive("replaced_completed")))
        with scenario("initial_absent") as actual:
            earlier = harness.capture(actual)
            later = harness.capture(actual, original=replace(actual.original, operation_id_hex="04"*32))
            self.assertEqual(opening.derive_claim(*later).as_dict()["observation"], "absent")
            self.refuse_before_check(self.arguments(earlier, later, self.positive("initial_absent"), self.positive("initial_absent")))

    def test_test_only_composition_imports_no_io_or_arithmetic_and_preserves_existing_fixture_pins(self):
        source = Path("tests/original_snapshot_prefix_response.py").read_text("ascii")
        tree = ast.parse(source)
        modules = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                modules.append(node.module)
        self.assertEqual(modules, ["qualification", "qualification", "original_snapshot_opening", "original_snapshot_prefix"])
        self.assertFalse(any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id in ("open", "eval", "exec", "compile", "__import__") for node in ast.walk(tree)))
        pins = ((INPUT, "0f0bdf4d916c5371f35eb7c2afee03dbcdef4a319999c01955f4b052d9d8fd01"),
            (OUTPUT, "2d461a54413ef156df62db26c88ac6f789ed8ea27322f3b8b12800b74f8de1bb"),
            (Path("tests/original_snapshot_opening.py"), "e1e8cdd3f868bce2117c56f1eb2eab90bef8626b7687793b62214f0884805ff6"),
            (Path("tests/original_snapshot_prefix.py"), "20b7e00c5aef3ec28184d385d7e10098f289a6e476373ab93527deaa7664a622"),
            (Path("qualification/examples/verify_original_read_response.rs"), "e96a8219e500cd0f79716796c146f64ce22e5f95bd3af26ccd2ad8a208c4834e"))
        for path, expected in pins:
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), expected)


if __name__ == "__main__":
    unittest.main()
