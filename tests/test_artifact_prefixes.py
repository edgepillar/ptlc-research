"""Synthetic read-only artifact observations; no privacy/provenance authority."""

from copy import deepcopy
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts import check_artifact_prefixes as check


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def selections():
    return {name: {role: ("synthetic-"+name+"-"+role).encode("ascii") for role in check.ROLES}
            for name in check.SELECTIONS}


def wire(prefixes):
    return check.encoded(dict(schema=check.SCHEMA, **{
        name: {role: value.hex() for role, value in prefixes[name].items()} for name in check.SELECTIONS}))


class ArtifactPrefixTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.first, self.second = self.root/"first-artifact", self.root/"second-artifact"
        self.prefixes = selections()
        self.left = b"synthetic artifact before\x00"+self.prefixes["first"][check.ROLES[0]]+b"\x00after"
        self.right = b"synthetic artifact before\x00"+self.prefixes["second"][check.ROLES[1]]+b"\x00after"
        self.first.write_bytes(self.left)
        self.second.write_bytes(self.right)
        self.private = self.root/"private-selection.json"
        self.private.write_bytes(wire(self.prefixes))
        self.private.chmod(0o600)

    def inspect(self, **changes):
        args = dict(first=self.first, first_sha256=digest(self.left), first_bytes=len(self.left),
                    second=self.second, second_sha256=digest(self.right), second_bytes=len(self.right),
                    prefixes=self.prefixes)
        args.update(changes)
        return check.inspect(**args)

    def refuses(self, **changes):
        with self.assertRaises(check.InputError) as caught:
            self.inspect(**changes)
        self.assertEqual(str(caught.exception), check.REFUSAL)

    def test_distinct_artifacts_return_only_fixed_roles_and_measured_streams(self):
        report = self.inspect()
        self.assertEqual(report["byte_relation"], "DIFFER")
        for name, raw, present in (("first", self.left, check.ROLES[0]), ("second", self.right, check.ROLES[1])):
            row = report["artifacts"][name]
            self.assertEqual(set(row), {"sha256", "bytes", "selected_prefix_presence", "present_role_count"})
            self.assertEqual(row["sha256"], digest(raw))
            self.assertEqual(row["bytes"], len(raw))
            self.assertEqual(row["selected_prefix_presence"], {role: role == present for role in check.ROLES})
            self.assertEqual(row["present_role_count"], 1)
        self.assertEqual(set(report), {"schema", "artifacts", "byte_relation", "byte_comparison", "outcome",
            "selection_origin", "prefix_scope", "artifact_publication", "independent_privacy_assessment",
            "reproducibility", "source_to_worker", "filesystem", "application_and_core"})

    def test_equal_bytes_in_distinct_copies_do_not_prove_independent_builds(self):
        self.right = self.left
        self.second.write_bytes(self.right)
        report = self.inspect()
        self.assertEqual(report["byte_relation"], "MATCH")
        self.assertEqual(report["reproducibility"], "NOT VERIFIED")
        self.assertEqual(report["source_to_worker"], "NOT VERIFIED")
        self.assertEqual(report["selection_origin"], "CALLER SELECTED; NOT AUTHENTICATED")
        self.assertEqual(report["application_and_core"], "NO-GO")

    def test_zero_selected_matches_keep_both_artifacts_private_and_unassessed(self):
        self.left, self.right = b"\x00unselected identity remains\xff", b"another unselected location remains"
        self.first.write_bytes(self.left); self.second.write_bytes(self.right)
        report = self.inspect()
        self.assertTrue(all(row["present_role_count"] == 0 for row in report["artifacts"].values()))
        self.assertEqual(report["artifact_publication"], "KEEP BOTH ARTIFACTS PRIVATE")
        self.assertEqual(report["independent_privacy_assessment"], "NOT ASSESSED")

    def test_reports_emit_no_private_strings_encodings_lengths_fingerprints_or_context(self):
        raw = check.encoded(self.inspect()).decode("ascii")
        for row in self.prefixes.values():
            for value in row.values():
                for forbidden in (value.decode("ascii"), value.hex(), digest(value)):
                    self.assertNotIn(forbidden, raw)
        for forbidden in (str(self.root), "synthetic artifact", "offset", "position", "context", "occurrence_count",
                          "prefix_length", digest(wire(self.prefixes))):
            self.assertNotIn(forbidden, raw)

    def test_prefix_crossings_at_every_split_and_selected_maximum_length(self):
        for length in (8, 9, check.MAX_PREFIX_BYTES):
            prefix = b"Q"+b"r"*(length-2)+b"S"
            self.prefixes["first"][check.ROLES[0]] = prefix
            splits = range(1, length) if length < 10 else (1, 2048, length-1)
            for split in splits:
                with self.subTest(length=length, split=split):
                    self.left = b"\x00"*(check.CHUNK_BYTES-split)+prefix+b"tail"
                    self.first.write_bytes(self.left)
                    self.assertTrue(self.inspect()["artifacts"]["first"]["selected_prefix_presence"][check.ROLES[0]])

    def test_overlapping_nested_prefixes_and_repeated_occurrences_are_presence_only(self):
        self.prefixes["first"] = {role: b"a"*(8+i) for i, role in enumerate(check.ROLES)}
        self.left = b"\x00"*(check.CHUNK_BYTES-5)+b"a"*20+b"\x00"+b"a"*20
        self.first.write_bytes(self.left)
        row = self.inspect()["artifacts"]["first"]
        self.assertEqual(row["present_role_count"], 4)
        self.assertTrue(all(row["selected_prefix_presence"].values()))
        self.assertNotIn("occurrence_count", row)

    def test_stream_is_fully_compared_after_all_prefixes_have_been_found(self):
        self.prefixes["second"] = self.prefixes["first"].copy()
        start = b"\x00".join(self.prefixes["first"].values())
        self.left = start+b"\x00"*(2*check.CHUNK_BYTES)+b"A"
        self.right = self.left[:-1]+b"B"
        self.first.write_bytes(self.left); self.second.write_bytes(self.right)
        report = self.inspect()
        self.assertEqual(report["byte_relation"], "DIFFER")
        self.assertEqual([row["present_role_count"] for row in report["artifacts"].values()], [4, 4])

    def test_unequal_lengths_and_an_exact_stream_prefix_are_different(self):
        self.right = self.left+b"additional tail"
        self.second.write_bytes(self.right)
        self.assertEqual(self.inspect()["byte_relation"], "DIFFER")

    def test_byte_relation_is_not_inferred_from_equal_hash_claims(self):
        class SyntheticCollision:
            def update(self, _): pass
            def hexdigest(self): return "0"*64
        with patch.object(check.hashlib, "sha256", return_value=SyntheticCollision()):
            report = self.inspect(first_sha256="0"*64, second_sha256="0"*64)
        self.assertEqual(report["byte_relation"], "DIFFER")

    def test_short_nonempty_artifacts_and_exact_selected_bound_can_match(self):
        self.left = self.right = b"x"
        self.first.write_bytes(self.left); self.second.write_bytes(self.right)
        with patch.object(check, "MAX_ARTIFACT_BYTES", 1):
            self.assertEqual(self.inspect()["byte_relation"], "MATCH")

    def test_each_changed_pin_refuses_without_echoing_expected_values(self):
        for name in ("first", "second"):
            for value in ("0"*64, True, "private unexpected value", "A"*64, "0"*63):
                self.refuses(**{"{}_sha256".format(name): value})

    def test_size_aliases_mismatches_zero_and_over_bound_refuse(self):
        for name in ("first", "second"):
            for value in (True, False, 0, -1, 1.0, "1", check.MAX_ARTIFACT_BYTES+1, 1):
                self.refuses(**{"{}_bytes".format(name): value})

    def test_empty_and_oversized_sparse_files_refuse_before_streaming(self):
        for path in (self.first, self.second):
            with path.open("wb") as handle: handle.truncate(check.MAX_ARTIFACT_BYTES+1)
            with patch.object(check._Scan, "feed", side_effect=AssertionError("stream must not start")):
                self.refuses()
            path.write_bytes(b"")
            self.refuses()
            path.write_bytes(self.left if path == self.first else self.right)

    def test_same_path_and_hard_link_aliases_refuse(self):
        self.refuses(second=self.first, second_sha256=digest(self.left), second_bytes=len(self.left))
        self.second.unlink(); os.link(self.first, self.second)
        self.refuses(second_sha256=digest(self.left), second_bytes=len(self.left))

    def test_direct_symlinks_directories_missing_files_and_linked_immediate_parents_refuse(self):
        missing = self.root/"missing-private-artifact"
        linked = self.root/"linked-artifact"; linked.symlink_to(self.first)
        parent = self.root/"linked-parent"; parent.symlink_to(self.root, target_is_directory=True)
        for path in (missing, linked, self.root, parent/self.first.name):
            self.refuses(first=path)

    def test_trusted_higher_ancestor_links_remain_outside_selected_fence(self):
        nested = self.root/"real"/"child"; nested.mkdir(parents=True)
        path = nested/"artifact"; path.write_bytes(self.left)
        alias = self.root/"higher-alias"; alias.symlink_to(nested.parent, target_is_directory=True)
        report = self.inspect(first=alias/"child"/"artifact")
        self.assertIn("TRUSTED ANCESTORS", report["filesystem"])

    def test_unowned_selection_refuses_without_relying_on_an_untrusted_label(self):
        with patch.object(check.os, "geteuid", return_value=os.geteuid()+1):
            self.refuses()
            with self.assertRaises(check.InputError): check.load_prefixes(self.private)

    def test_missing_extra_unknown_and_foreign_role_labels_refuse_before_file_io(self):
        variants = []
        for name in check.SELECTIONS:
            absent = deepcopy(self.prefixes); absent.pop(name); variants.append(absent)
            for role in check.ROLES:
                absent = deepcopy(self.prefixes); absent[name].pop(role); variants.append(absent)
            extra = deepcopy(self.prefixes); extra[name]["private caller label"] = b"abcdefgh"; variants.append(extra)
        extra = deepcopy(self.prefixes); extra["third"] = extra["first"]; variants.append(extra)
        with patch.object(check, "owned_file", side_effect=AssertionError("selection must refuse first")):
            for value in variants: self.refuses(prefixes=value)

    def test_duplicate_prefix_values_refuse_but_shared_values_across_selections_are_allowed(self):
        for name in check.SELECTIONS:
            value = deepcopy(self.prefixes); value[name][check.ROLES[1]] = value[name][check.ROLES[0]]
            self.refuses(prefixes=value)
        self.prefixes["second"] = self.prefixes["first"].copy()
        self.assertEqual(self.inspect()["artifacts"]["second"]["present_role_count"], 0)

    def test_prefix_lengths_exact_types_and_hostile_subclasses_refuse_without_hooks(self):
        class ForeignBytes(bytes):
            def __len__(self): raise AssertionError("foreign hook")
            def __hash__(self): raise AssertionError("foreign hook")
        class ForeignDict(dict):
            def __iter__(self): raise AssertionError("foreign hook")
        for bad in (b"", b"a"*7, b"a"*(check.MAX_PREFIX_BYTES+1), "abcdefgh", bytearray(b"abcdefgh"),
                    memoryview(b"abcdefgh"), True, ForeignBytes(b"abcdefgh")):
            value = deepcopy(self.prefixes); value["first"][check.ROLES[0]] = bad
            self.refuses(prefixes=value)
        self.refuses(prefixes=ForeignDict(self.prefixes))
        value = deepcopy(self.prefixes); value["first"] = ForeignDict(value["first"]); self.refuses(prefixes=value)
        value = deepcopy(self.prefixes); value["first"][1] = b"abcdefgh"
        self.refuses(prefixes=value)
        # Install a string subclass key with the ordinary hash; comparison must not call its hooks.
        class Key(str):
            def __eq__(self, _): raise AssertionError("foreign hook")
            __hash__ = str.__hash__
        value = deepcopy(self.prefixes); value[Key("foreign-role")] = value["first"]
        self.refuses(prefixes=value)

    def test_changing_prefix_selection_changes_observation_without_attesting_selection_origin(self):
        before = self.inspect()
        changed = deepcopy(self.prefixes); changed["first"][check.ROLES[0]] = b"unobserved-private-prefix"
        after = self.inspect(prefixes=changed)
        self.assertEqual(before["artifacts"]["first"]["sha256"], after["artifacts"]["first"]["sha256"])
        self.assertEqual(before["byte_relation"], after["byte_relation"])
        self.assertEqual(after["artifacts"]["first"]["present_role_count"], 0)
        self.assertEqual(after["selection_origin"], "CALLER SELECTED; NOT AUTHENTICATED")

    def test_appending_truncating_or_replacing_either_artifact_during_read_refuses(self):
        original = check._Scan.feed
        for selected in (self.first, self.second):
            for mutation in ("append", "truncate", "replace"):
                self.first.write_bytes(self.left); self.second.write_bytes(self.right)
                changed = [False]
                def feed(scan, chunk):
                    original(scan, chunk)
                    if not changed[0]:
                        changed[0] = True
                        if mutation == "append":
                            with selected.open("ab") as handle: handle.write(b"changed")
                        elif mutation == "truncate": selected.write_bytes(b"x")
                        else:
                            substitute = self.root/"substitute"
                            substitute.write_bytes(self.left if selected == self.first else self.right)
                            substitute.replace(selected)
                with patch.object(check._Scan, "feed", feed): self.refuses()

    def test_same_size_rewrite_with_restored_mtime_still_refuses(self):
        original = check._Scan.feed; before = self.first.stat(); changed = [False]
        def feed(scan, chunk):
            original(scan, chunk)
            if not changed[0]:
                changed[0] = True
                self.first.write_bytes(b"X"*len(self.left))
                os.utime(self.first, ns=(before.st_atime_ns, before.st_mtime_ns))
        with patch.object(check._Scan, "feed", feed): self.refuses()

    def test_read_errors_are_sanitized_and_cancellation_propagates_without_report(self):
        for failure in (OSError("synthetic private path detail"), ValueError("synthetic private value")):
            with patch.object(check._Scan, "feed", side_effect=failure): self.refuses()
        for failure in (KeyboardInterrupt(), SystemExit(7)):
            with patch.object(check._Scan, "feed", side_effect=failure):
                with self.assertRaises(type(failure)): self.inspect()

    def test_private_json_decodes_only_exact_role_hex_bytes(self):
        self.assertEqual(check.decode_prefixes(wire(self.prefixes)), self.prefixes)
        self.assertEqual(check.load_prefixes(self.private), self.prefixes)

    def test_private_json_duplicate_keys_extra_fields_schema_and_alias_values_refuse(self):
        valid = json.loads(wire(self.prefixes))
        variants = [b'{"schema":"x","schema":"x"}', b'[]', b'true']
        for field, bad in (("schema", "other"), ("schema", True), ("third", {}), ("first", [])):
            value = deepcopy(valid); value[field] = bad; variants.append(check.encoded(value))
        for bad in ("AB"*8, "ab cd ef 01 23 45 67 89", "a"*17, True, 1, 1.0, None, [], "a"*14,
                    "a"*(2*check.MAX_PREFIX_BYTES+2)):
            value = deepcopy(valid); value["first"][check.ROLES[0]] = bad; variants.append(check.encoded(value))
        for bad in (b'NaN', b'Infinity', b'-1', b'1e3'):
            variants.append(wire(self.prefixes).replace(b'"'+self.prefixes["first"][check.ROLES[0]].hex().encode()+b'"', bad, 1))
        variants.append(wire(self.prefixes).replace(b'"first": {', b'"first": {"selected-source-location":"6162636465666768",', 1))
        for raw in variants:
            with self.assertRaises(check.InputError): check.decode_prefixes(raw)

    def test_private_json_wire_bounds_depth_nonascii_and_subclasses_refuse_before_decoder(self):
        class ForeignBytes(bytes):
            def isascii(self): raise AssertionError("foreign hook")
        for raw in (b"", b" "*(check.MAX_SELECTION_BYTES+1), b"[[[[[0]]]]]", b'"\xff"', ForeignBytes(b"{}")):
            with patch.object(check.json, "loads", side_effect=AssertionError("decoder must not start")):
                with self.assertRaises(check.InputError): check.decode_prefixes(raw)
        for raw in (b'{{}', b'"unterminated', wire(self.prefixes)+b' trailing', b'}', b'{"schema":"\\u0000"}'):
            with self.assertRaises(check.InputError): check.decode_prefixes(raw)

    def test_private_selection_permissions_and_direct_file_parent_aliases_refuse(self):
        for mode in (0o644, 0o620, 0o601):
            self.private.chmod(mode)
            with self.assertRaises(check.InputError) as caught: check.load_prefixes(self.private)
            self.assertEqual(str(caught.exception), check.REFUSAL)
        self.private.chmod(0o600)
        alias = self.root/"private-alias"; alias.symlink_to(self.private)
        parent = self.root/"private-parent-alias"; parent.symlink_to(self.root, target_is_directory=True)
        for path in (alias, parent/self.private.name, self.root, self.root/"missing"):
            with self.assertRaises(check.InputError): check.load_prefixes(path)

    def test_private_selection_change_during_decode_refuses_without_echoing_prefixes(self):
        original = check.decode_prefixes
        def changed(raw):
            value = original(raw)
            self.private.write_bytes(raw+b" ")
            return value
        with patch.object(check, "decode_prefixes", changed):
            with self.assertRaises(check.InputError) as caught: check.load_prefixes(self.private)
        self.assertEqual(str(caught.exception), check.REFUSAL)

    def command(self):
        return [sys.executable, "-B", "scripts/check_artifact_prefixes.py",
                "--first", str(self.first), "--expect-first-sha256", digest(self.left),
                "--expect-first-bytes", str(len(self.left)), "--second", str(self.second),
                "--expect-second-sha256", digest(self.right), "--expect-second-bytes", str(len(self.right)),
                "--private-prefixes", str(self.private)]

    def test_cli_success_emits_one_logical_report_and_does_not_modify_any_input(self):
        before = {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in (self.first, self.second, self.private)}
        result = subprocess.run(self.command(), capture_output=True, timeout=10, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, b"")
        self.assertEqual(json.loads(result.stdout), self.inspect())
        self.assertEqual(before, {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in before})
        self.assertEqual(set(self.root.iterdir()), set(before))

    def test_cli_invalid_arguments_and_missing_input_have_no_private_text_or_partial_report(self):
        for command in (self.command()+["--unknown-private-argument", "private detail"],
                        self.command()[:-1]+[str(self.root/"private-missing-selection")],
                        self.command()[:3]):
            result = subprocess.run(command, capture_output=True, timeout=10, check=False)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, b"")
            self.assertEqual(result.stderr, ("FAIL: "+check.REFUSAL+"\n").encode("ascii"))

    def test_cli_never_invokes_native_tools_or_network_interfaces(self):
        output = io.BytesIO()
        class Output:
            buffer = output
        with patch.object(sys, "argv", self.command()[2:]), patch.object(sys, "stdout", Output()), \
                patch.object(subprocess, "run", side_effect=AssertionError("no native invocation")), \
                patch.object(subprocess, "check_output", side_effect=AssertionError("no native invocation")), \
                patch.object(check.contents.inputs.source, "_git", side_effect=AssertionError("no Git")):
            self.assertEqual(check.main(), 0)
        self.assertEqual(json.loads(output.getvalue()), self.inspect())


if __name__ == "__main__":
    unittest.main()
