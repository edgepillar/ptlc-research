import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import compare_nom_dev_rebase as reader


class NoMDevRebaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.selected = reader.selection()
        cls.old_pool = reader.pool.inputs(reader.ROOT)[1]["records"]
        cls.old_dependencies = reader.dependencies.inputs(reader.ROOT)[1]["records"]
        cls.current_pool = copy.deepcopy(cls.old_pool)
        # Literal positions independently selected from the retained native run.
        for name, positions in {"complete": (6, 10), "old-inner-before-valid": (8, 12)}.items():
            for position in positions:
                cls.current_pool[name]["post_rollback_views"][position].update(
                    present=False, patch_present=False, patch_hex="", frontier=None, state_dump_hex="")
        cls.current_dependencies = copy.deepcopy(cls.old_dependencies)
        for name, positions in {"empty-inclusion-control": (2, 5, 6), "included-send": (5, 6),
                                "included-send-without-suffix": (4, 5)}.items():
            record = cls.current_dependencies[name]
            for position in positions:
                view = record["views"][position]
                view["patch_hex"] = next(step["retained_patch_hex"] for step in record["trace"]
                                         if step["label"] == view["label"])

    def stream(self, kind="account-pool", records=None):
        module, filename, _ = reader.MODULES[kind]
        records = records if records is not None else self.current_pool
        events = []
        for name in module.CASES:
            events.append(dict(Action="output", Package=module.PACKAGE, Test=module.TEST + "/" + name,
                Output="    " + filename + ":1: " + module.PREFIX + json.dumps(records[name]) + "\n"))
        events += [dict(Action="pass", Package=module.PACKAGE, Test=name)
                   for name in sorted(module.expected_tests()[module.PACKAGE])]
        events.append(dict(Action="pass", Package=module.PACKAGE))
        return b"\n".join(json.dumps(event).encode("ascii") for event in events) + b"\n"

    def test_explicit_immutable_selection(self):
        self.assertEqual(len(self.selected["source_index"]), 441)
        self.assertEqual(len(self.selected["profile_inputs"]), 133)
        self.assertEqual(self.selected["expected_delta"]["total_changed_fields"], 23)

    def test_pool_literal_native_delta_matches(self):
        before = reader.canonical(self.old_pool)
        result = reader.compare_records("account-pool", self.current_pool)
        self.assertEqual(result["cases"], 2)
        self.assertEqual(result["recovery_action"], "NONE")
        self.assertEqual(reader.canonical(self.old_pool), before)
        self.assertIsNotNone(self.old_pool["complete"]["post_rollback_views"][6]["frontier"])

    def test_dependencies_keep_actual_admitted_patches(self):
        before = reader.canonical(self.old_dependencies)
        self.assertEqual(reader.compare_records("pool-dependencies", self.current_dependencies)["cases"], 3)
        self.assertEqual(reader.canonical(self.old_dependencies), before)

    def test_historical_child_aliases_are_not_current(self):
        with self.assertRaises(ValueError):
            reader.compare_records("account-pool", self.old_pool)

    def test_historical_duplicate_frontiers_are_not_current(self):
        with self.assertRaises(ValueError):
            reader.compare_records("pool-dependencies", self.old_dependencies)

    def test_retained_parent_cannot_disappear(self):
        changed = copy.deepcopy(self.current_pool)
        view = changed["complete"]["post_rollback_views"][0]
        self.assertTrue(view["present"])
        view.update(present=False, patch_present=False, patch_hex="", frontier=None, state_dump_hex="")
        with self.assertRaises(ValueError):
            reader.compare_records("account-pool", changed)

    def test_requested_child_identity_is_exact(self):
        changed = copy.deepcopy(self.current_pool)
        changed["complete"]["post_rollback_views"][6]["requested_identifier"]["height"] = "999"
        with self.assertRaises(ValueError):
            reader.compare_records("account-pool", changed)

    def test_original_wire_cannot_be_replaced(self):
        changed = copy.deepcopy(self.current_pool)
        wires = next(values for values in changed["complete"]["remaining_pending_wires"].values() if values)
        raw = bytes.fromhex(wires[0])
        wires[0] = (bytes([raw[0] ^ 1]) + raw[1:]).hex()
        with self.assertRaises(ValueError):
            reader.compare_records("account-pool", changed)

    def test_logical_state_cannot_be_omitted(self):
        changed = copy.deepcopy(self.current_dependencies)
        changed["included-send"]["checkpoints"]["after-callback"]["unrelated"]["state_dump_hex"] = ""
        with self.assertRaises(ValueError):
            reader.compare_records("pool-dependencies", changed)

    def test_original_patch_cannot_be_truncated(self):
        changed = copy.deepcopy(self.current_dependencies)
        changed["included-send"]["views"][5]["patch_hex"] = changed["included-send"]["views"][5]["patch_hex"][:-2]
        with self.assertRaises(ValueError):
            reader.compare_records("pool-dependencies", changed)

    def test_false_is_not_integer_zero(self):
        changed = copy.deepcopy(self.current_pool)
        changed["complete"]["post_rollback_views"][6]["present"] = 0
        with self.assertRaises(ValueError):
            reader.compare_records("account-pool", changed)

    def test_missing_and_extra_members_refuse(self):
        for mode in ("missing-case", "extra-field", "missing-view"):
            with self.subTest(mode=mode):
                changed = copy.deepcopy(self.current_pool)
                if mode == "missing-case":
                    changed.pop("complete")
                elif mode == "extra-field":
                    changed["complete"]["permission"] = "synthetic"
                else:
                    changed["complete"]["post_rollback_views"].pop()
                with self.assertRaises(ValueError):
                    reader.compare_records("account-pool", changed)

    def test_selected_stream_framing_is_separate_from_execution(self):
        records = reader.native_records("account-pool", self.stream())
        self.assertEqual(reader.compare_records("account-pool", records)["cases"], 2)
        records = reader.native_records("pool-dependencies", self.stream("pool-dependencies", self.current_dependencies))
        self.assertEqual(reader.compare_records("pool-dependencies", records)["cases"], 3)

    def test_pass_labels_without_records_refuse(self):
        events = [event for event in map(json.loads, self.stream().splitlines()) if event["Action"] == "pass"]
        with self.assertRaises(ValueError):
            reader.native_records("account-pool", b"\n".join(map(lambda e: json.dumps(e).encode("ascii"), events)))

    def test_duplicate_native_record_refuses(self):
        lines = self.stream().splitlines()
        with self.assertRaises(ValueError):
            reader.native_records("account-pool", b"\n".join([lines[0], *lines]))

    def test_skipped_source_claim_refuses(self):
        events = list(map(json.loads, self.stream().splitlines()))
        events[-2]["Action"] = "skip"
        with self.assertRaises(ValueError):
            reader.native_records("account-pool", b"\n".join(json.dumps(e).encode("ascii") for e in events))

    def test_wrong_package_refuses(self):
        events = list(map(json.loads, self.stream().splitlines()))
        events[0]["Package"] = "synthetic/unselected"
        with self.assertRaises(ValueError):
            reader.native_records("account-pool", b"\n".join(json.dumps(e).encode("ascii") for e in events))

    def test_nonfinite_and_duplicate_record_keys_refuse(self):
        for mode in ("nonfinite", "duplicate-key"):
            with self.subTest(mode=mode):
                events = list(map(json.loads, self.stream().splitlines()))
                original = events[0]["Output"]
                prefix, payload = original.split(reader.pool.PREFIX, 1)
                if mode == "duplicate-key":
                    payload = '{"id":"complete",' + payload[1:]
                else:
                    value = json.loads(payload)
                    value["signing_calls"] = float("nan")
                    payload = json.dumps(value) + "\n"
                events[0]["Output"] = prefix + reader.pool.PREFIX + payload
                with self.assertRaises(ValueError):
                    reader.native_records("account-pool", b"\n".join(json.dumps(e).encode("ascii") for e in events))

    def test_interleaved_record_fragments_refuse(self):
        events = list(map(json.loads, self.stream().splitlines()))
        first = events[0]
        cut = len(first["Output"]) // 2
        end = {**first, "Output": first["Output"][cut:]}
        first["Output"] = first["Output"][:cut]
        events.insert(2, end)
        with self.assertRaises(ValueError):
            reader.native_records("account-pool", b"\n".join(json.dumps(e).encode("ascii") for e in events))

    def test_source_and_profile_inventory_substitution_refuse(self):
        for field in ("source_index", "profile_inputs"):
            with self.subTest(field=field):
                selected = copy.deepcopy(self.selected)
                selected[field].pop(next(iter(selected[field])))
                with patch.object(reader, "regular_bytes", return_value=reader.canonical(selected)):
                    with self.assertRaisesRegex(ValueError, "complete selected inventory"):
                        reader.selection()

    def test_partial_source_cannot_claim_the_pinned_commit(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "complete pinned source selection"):
                reader.compare_source(Path(temporary), {**self.selected, "source_index": {}})

    def test_missing_extra_and_changed_source_refuse(self):
        for mode in ("missing", "extra", "changed"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                source = Path(temporary)
                if mode != "missing":
                    (source / ("unselected.txt" if mode == "extra" else "go.mod")).write_bytes(b"public synthetic bytes\n")
                with self.assertRaises(ValueError):
                    reader.compare_source(source, self.selected)

    def test_source_links_refuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            link = root / "alias"
            link.symlink_to(source, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "regular source directory"):
                reader.compare_source(link, self.selected)
            (source / "go.mod").symlink_to(root / "absent")
            with self.assertRaises((OSError, ValueError)):
                reader.compare_source(source, self.selected)


if __name__ == "__main__":
    unittest.main()
