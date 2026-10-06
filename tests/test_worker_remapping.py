"""Synthetic driver control is not native execution or complete artifact privacy."""

from contextlib import ExitStack
from copy import deepcopy
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts import qualify_worker_remapping as qualification


class RemappingFixture:
    def __init__(self, parent):
        self.root = parent/"synthetic-repository"
        self.root.mkdir(mode=0o700)
        self.home = self.root/"synthetic-cache"
        self.home.mkdir(mode=0o700)
        self.platform = qualification.original.native_platform()
        self.pairs = {}
        for name in qualification.scanner.SELECTIONS:
            pair = tuple(self.root/(name+"-"+role) for role in ("source", "build"))
            for path in pair:
                path.mkdir(mode=0o700)
            self.pairs[name] = pair
        self.tools = {}
        for role in qualification.check.NATIVE_ROLES:
            path = self.root/("synthetic-"+role)
            path.write_bytes(b"Synthetic selected tool; never executed.\n"+role.encode())
            path.chmod(0o700)
            self.tools[role] = path
        self.contents = {"synthetic": "contents"}
        self.resolution = {"synthetic": "resolution"}
        self.contents_sha = hashlib.sha256(qualification.check.encoded(self.contents)).hexdigest()
        self.resolution_sha = hashlib.sha256(qualification.check.encoded(self.resolution)).hexdigest()
        self.calls = []
        self.payload = {name: b"Equal synthetic artifact bytes; no selected prefixes.\n"
                        for name in qualification.scanner.SELECTIONS}
        self.after_build = lambda name: None
        self.report_change = lambda report, name: None

    def locations(self, name="first"):
        return qualification.selected_locations(self.root, *self.pairs[name], self.home)

    def validate(self):
        return qualification.validate_pair(self.root, self.pairs, self.home, self.platform, self.tools)

    def worker(self, name):
        return self.pairs[name][1]/self.platform/"debug/examples"/qualification.check.WORKER

    def run(self, command, request, **bounds):
        self.calls.append((command[:], dict(os.environ), Path.cwd(), request, bounds.copy()))
        if command[1] == "build":
            build = Path(command[command.index("--target-dir")+1])
            name = next(name for name, pair in self.pairs.items() if pair[1] == build)
            worker = self.worker(name)
            worker.parent.mkdir(parents=True)
            worker.write_bytes(self.payload[name])
            worker.chmod(0o700)
            self.after_build(name)
        return b"{}\n"

    def report(self, root, commit, manifest_sha, baseline_sha, workspace, metadata, home,
               platform, build, messages, exit_status, native, worker_sha):
        name = next(name for name, pair in self.pairs.items() if pair[1] == build)
        report = dict(source_commit=commit, witness_manifest_sha256=manifest_sha,
                      resolution_baseline_sha256=baseline_sha, platform=platform,
                      prepared_source_files=55, resolution_sha256=self.resolution_sha,
                      selected_contents_sha256=self.contents_sha,
                      claims=dict(selected_root=dict(profile=deepcopy(qualification.check.ROOT_PROFILE),
                                  features=[], executable_relative_path=platform+"/debug/examples/"+qualification.check.WORKER)),
                      measured_inputs={role: qualification.check.inputs.measure(*native[role],
                                       qualification.check.inputs.MAX_NATIVE_BYTES) for role in native})
        report["measured_inputs"]["original-response-worker"] = qualification.check.inputs.measure(
            self.worker(name), worker_sha, qualification.check.inputs.MAX_NATIVE_BYTES)
        self.report_change(report, name)
        return report

    def gates(self):
        context = ExitStack()
        context.enter_context(patch.object(qualification.original, "prepare", return_value=55))
        context.enter_context(patch.object(qualification.check.inputs, "selected_source",
                                          return_value=("synthetic", [], {"qualification/Cargo.lock": b"synthetic"})))
        context.enter_context(patch.object(qualification.check.inputs, "cargo_records", return_value=[]))
        context.enter_context(patch.object(qualification.check.resolution.caches, "one_directory",
                                          side_effect=lambda path: path/"same-synthetic-namespace"))
        context.enter_context(patch.object(qualification.check.resolution.caches, "select_checkouts", return_value={}))
        context.enter_context(patch.object(qualification.check.resolution.content, "inspect_cargo", return_value=self.contents))
        context.enter_context(patch.object(qualification.check.resolution, "inspect", return_value=dict(
            resolution=self.resolution, selected_contents_sha256=self.contents_sha)))
        context.enter_context(patch.object(qualification.check, "inspect", side_effect=self.report))
        context.enter_context(patch.object(qualification.original, "_run", side_effect=self.run))
        context.enter_context(patch("subprocess.Popen", side_effect=AssertionError("unselected native launch")))
        return context

    def qualify(self):
        with self.gates():
            return qualification.qualify(self.root, self.pairs, self.home, self.platform, self.tools)


class WorkerRemappingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.fixture = RemappingFixture(Path(self.temporary.name))

    def test_nested_rules_select_specific_roles_and_leave_sibling_text_outside_directory_scope(self):
        locations = self.fixture.locations()
        flags = qualification.encoded_flags(locations).split("\x1f")
        rules = [flag.removeprefix("--remap-path-prefix=").split("=") for flag in flags]
        self.assertEqual(len(rules), 4)
        for role in qualification.scanner.ROLES:
            text = locations[role].decode()+"/synthetic.rs"
            matches = [destination+text[len(source):] for source, destination in rules if text.startswith(source)]
            self.assertEqual(matches[-1], qualification.DESTINATIONS[role]+"synthetic.rs")
        sibling = locations["selected-cache-location"].decode()+"-sibling/synthetic.rs"
        self.assertFalse(any(sibling.startswith(source) and destination == "/ptlc/cache/" for source, destination in rules))

    def test_bare_directory_and_relative_spelling_are_explicit_uncovered_forms(self):
        source = self.fixture.locations()["selected-source-location"].decode()
        rules = [value.removeprefix("--remap-path-prefix=").split("=")
                 for value in qualification.encoded_flags(self.fixture.locations()).split("\x1f")]
        self.assertFalse(any(source.startswith(a) and b == "/ptlc/source/" for a, b in rules))
        self.assertFalse(any(("./synthetic.rs").startswith(a) for a, _ in rules))

    def test_space_in_private_path_remains_one_encoded_argument(self):
        source, build = self.fixture.pairs["first"]
        replacement = source.with_name("source with synthetic spaces")
        source.rename(replacement)
        self.fixture.pairs["first"] = replacement, build
        flags = qualification.encoded_flags(self.fixture.locations()).split("\x1f")
        self.assertEqual(len(flags), 4)
        self.assertIn("--remap-path-prefix="+str(replacement)+"/=/ptlc/source/", flags)

    def test_control_nonascii_equals_relative_and_unsupported_prefixes_refuse(self):
        locations = self.fixture.locations()
        for value in (b"/synthetic/path\x1fextra", b"/synthetic/equals=extra", b"/synthetic/../escape",
                      b"synthetic-relative", b"/synthetic/back\\slash", b"/synthetic/colon:extra", b"/synthetic/\xff"):
            changed = dict(locations, **{"selected-source-location": value})
            with self.subTest(value=value), self.assertRaises(qualification.InputError):
                qualification.encoded_flags(changed)

    def test_exact_mapping_bytes_roles_and_aliases_refuse_without_foreign_hooks(self):
        class Foreign(dict):
            def items(self):
                raise AssertionError("foreign hook")
        locations = self.fixture.locations()
        for value in (Foreign(locations), [], {**locations, "unselected": b"synthetic"},
                      {**locations, "selected-source-location": locations["selected-build-location"]},
                      {**locations, "selected-source-location": bytearray(b"synthetic")},
                      {**locations, "selected-source-location": b"tiny"}):
            with self.assertRaises(qualification.InputError):
                qualification.encoded_flags(value)

    def test_nonempty_second_selection_refuses_before_any_copy_or_launch(self):
        (self.fixture.pairs["second"][1]/"synthetic-content").write_bytes(b"occupied")
        with patch.object(qualification, "_build", side_effect=AssertionError("early build")), self.assertRaises(qualification.InputError):
            self.fixture.qualify()
        self.assertEqual(self.fixture.calls, [])

    def test_all_four_private_owned_roots_and_direct_links_are_checked_before_build(self):
        source, _ = self.fixture.pairs["first"]
        source.chmod(0o755)
        with self.assertRaises(qualification.InputError):
            self.fixture.validate()
        source.chmod(0o700)
        destination = source.with_name("synthetic-real-source")
        source.rename(destination)
        source.symlink_to(destination, target_is_directory=True)
        with self.assertRaises(qualification.InputError):
            self.fixture.validate()

    def test_foreign_owner_refuses_before_measurement_or_native_launch(self):
        with patch.object(qualification.os, "geteuid", return_value=os.geteuid()+1), self.assertRaises(qualification.InputError):
            self.fixture.qualify()
        self.assertEqual(self.fixture.calls, [])

    def test_same_pair_directory_and_higher_ancestor_aliases_refuse(self):
        first = self.fixture.pairs["first"]
        self.fixture.pairs["second"] = first
        with self.assertRaises(qualification.InputError):
            self.fixture.validate()
        alias = self.fixture.root.parent/"synthetic-alias"
        alias.symlink_to(self.fixture.root, target_is_directory=True)
        self.fixture.pairs["second"] = tuple(alias/path.name for path in first)
        with self.assertRaises(qualification.InputError):
            self.fixture.validate()

    def test_cross_pair_nesting_and_source_cache_overlap_refuse(self):
        nested = self.fixture.pairs["first"][0]/"nested-source"
        nested.mkdir(mode=0o700)
        self.fixture.pairs["second"] = nested, self.fixture.pairs["second"][1]
        with self.assertRaises(qualification.InputError):
            self.fixture.validate()
        self.fixture.home = self.fixture.pairs["first"][0]
        with self.assertRaises(qualification.InputError):
            self.fixture.locations()

    def test_cross_compilation_incomplete_tools_and_pair_shapes_refuse(self):
        other = next(platform for platform in qualification.check.resolution.PLATFORMS if platform != self.fixture.platform)
        self.fixture.platform = other
        with self.assertRaises(qualification.InputError):
            self.fixture.qualify()
        self.fixture.platform = qualification.original.native_platform()
        for selections in ({"first": self.fixture.pairs["first"]},
                           {**self.fixture.pairs, "first": list(self.fixture.pairs["first"])},
                           {**self.fixture.pairs, "second": (str(self.fixture.pairs["second"][0]), self.fixture.pairs["second"][1])}):
            with self.assertRaises(qualification.InputError):
                qualification.validate_pair(self.fixture.root, selections, self.fixture.home, self.fixture.platform, self.fixture.tools)
        tools = {role: value for role, value in self.fixture.tools.items() if role != "cargo"}
        with self.assertRaises(qualification.InputError):
            qualification.validate_pair(self.fixture.root, self.fixture.pairs, self.fixture.home, self.fixture.platform, tools)
        self.assertEqual(self.fixture.calls, [])

    def test_logical_profile_exposes_no_private_mapping_or_full_coverage_claim(self):
        profile = qualification.selected_profile()
        self.assertEqual(profile["option_count"], 4)
        self.assertEqual(profile["root_claim_profile"], qualification.check.ROOT_PROFILE)
        self.assertIn("NOT COVERED", profile["host_rust_coverage"])
        self.assertIn("NOT FULLY ASSESSED", profile["c_linker_and_support_inputs"])
        encoded = qualification.check.encoded(profile)
        for value in self.fixture.locations().values():
            self.assertNotIn(value, encoded)
            self.assertNotIn(value.hex().encode(), encoded)
            self.assertNotIn(hashlib.sha256(value).hexdigest().encode(), encoded)
        profile["destinations"].clear()
        profile["root_claim_profile"]["test"] = True
        self.assertEqual(len(qualification.selected_profile()["destinations"]), 4)
        self.assertFalse(qualification.selected_profile()["root_claim_profile"]["test"])

    def test_selected_environment_replaces_extra_flags_preserves_unassessed_c_flags_and_restores(self):
        token = self.fixture.platform.upper().replace("-", "_")
        inherited = {"RUSTFLAGS": "synthetic-old", "CARGO_ENCODED_RUSTFLAGS": "synthetic-old",
                     "RUSTC_WRAPPER": "synthetic-old", "RUSTC_WORKSPACE_WRAPPER": "synthetic-old",
                     "CARGO_BUILD_TARGET": "synthetic-old", "CARGO_BUILD_RUSTC": "synthetic-old",
                     "CARGO_TARGET_"+token+"_RUSTFLAGS": "synthetic-old", "CFLAGS": "synthetic-unassessed"}
        with patch.dict(os.environ, inherited):
            before, directory = dict(os.environ), Path.cwd()
            flags = qualification.encoded_flags(self.fixture.locations())
            with qualification._environment(self.fixture.tools, self.fixture.home, self.fixture.pairs["first"][0], self.fixture.platform, flags):
                self.assertEqual(os.environ["CARGO_ENCODED_RUSTFLAGS"], flags)
                self.assertEqual(os.environ["CFLAGS"], "synthetic-unassessed")
                self.assertEqual(os.environ["CARGO_NET_OFFLINE"], "true")
                for key in inherited:
                    if key not in ("CFLAGS", "CARGO_ENCODED_RUSTFLAGS"):
                        self.assertNotIn(key, os.environ)
            self.assertEqual(dict(os.environ), before)
            self.assertEqual(Path.cwd(), directory)

    def test_environment_failure_and_cancellation_restore_without_positive_return(self):
        for exception in (qualification.InputError("synthetic-private"), KeyboardInterrupt(), SystemExit(9)):
            before, directory = dict(os.environ), Path.cwd()
            with self.subTest(exception=type(exception).__name__), self.assertRaises(type(exception)):
                with qualification._environment(self.fixture.tools, self.fixture.home, self.fixture.pairs["first"][0], self.fixture.platform,
                                                qualification.encoded_flags(self.fixture.locations())):
                    os.environ["SYNTHETIC_TRANSIENT"] = "private"
                    raise exception
            self.assertEqual(dict(os.environ), before)
            self.assertEqual(Path.cwd(), directory)

    def test_two_bounded_offline_native_command_selections_use_separate_builds_and_exact_flags(self):
        report = self.fixture.qualify()
        self.assertEqual([call[0][1] for call in self.fixture.calls], ["metadata", "build", "metadata", "build"])
        for i, (command, environment, directory, request, bounds) in enumerate(self.fixture.calls):
            name = "first" if i < 2 else "second"
            self.assertEqual(command[0], str(self.fixture.tools["cargo"]))
            self.assertTrue({"--locked", "--offline"} <= set(command))
            self.assertEqual(request, b"")
            self.assertTrue(directory.samefile(self.fixture.pairs[name][0]))
            self.assertEqual(environment["CARGO_ENCODED_RUSTFLAGS"], qualification.encoded_flags(self.fixture.locations(name)))
            if command[1] == "build":
                self.assertEqual(command[command.index("--target")+1], self.fixture.platform)
                self.assertEqual(command[command.index("--example")+1], qualification.check.WORKER)
                self.assertEqual(bounds, dict(timeout=240, max_output_bytes=qualification.check.MAX_STREAM_BYTES))
            else:
                self.assertEqual(bounds, dict(timeout=30, max_output_bytes=qualification.check.resolution.MAX_JSON_BYTES))
        self.assertEqual(report["comparison"]["byte_relation"], "MATCH")

    def test_zero_scan_and_equal_synthetic_bytes_do_not_authenticate_builds_or_allow_release(self):
        report = self.fixture.qualify()
        self.assertEqual([row["present_role_count"] for row in report["comparison"]["artifacts"].values()], [0, 0])
        self.assertEqual(report["artifact_publication"], "KEEP BOTH ARTIFACTS PRIVATE")
        self.assertEqual(report["reproducibility"], "NOT VERIFIED")
        self.assertEqual(report["source_to_worker"], "NOT VERIFIED")
        self.assertEqual(report["application_and_core"], "NO-GO")

    def test_positive_prefixes_and_different_bytes_are_measurements_not_qualification_failures(self):
        for name in qualification.scanner.SELECTIONS:
            self.fixture.payload[name] = b"\n".join(self.fixture.locations(name).values())
        report = self.fixture.qualify()
        self.assertEqual(report["comparison"]["byte_relation"], "DIFFER")
        self.assertEqual([row["present_role_count"] for row in report["comparison"]["artifacts"].values()], [4, 4])
        self.assertEqual(report["independent_privacy_assessment"], "NOT ASSESSED")
        raw = qualification.check.encoded(report)
        for name in qualification.scanner.SELECTIONS:
            for value in self.fixture.locations(name).values():
                self.assertNotIn(value, raw)
                self.assertNotIn(value.hex().encode(), raw)

    def test_private_raw_streams_have_restricted_modes_and_are_never_part_of_report(self):
        report = self.fixture.qualify()
        for source, _ in self.fixture.pairs.values():
            for name in ("metadata.json", "build-messages.jsonl"):
                path = source/name
                self.assertEqual(path.stat().st_mode & 0o077, 0)
                self.assertEqual(path.read_bytes(), b"{}\n")
        self.assertNotIn(b"build-messages.jsonl", qualification.check.encoded(report))

    def test_metadata_failure_restores_process_state_and_performs_no_build_or_retry(self):
        before, directory = dict(os.environ), Path.cwd()
        with self.fixture.gates(), patch.object(qualification.original, "_run", side_effect=qualification.original.WorkerError("synthetic-private")) as launch:
            with self.assertRaises(qualification.InputError) as caught:
                qualification.qualify(self.fixture.root, self.fixture.pairs, self.fixture.home, self.fixture.platform, self.fixture.tools)
        self.assertEqual(str(caught.exception), qualification.REFUSAL)
        self.assertEqual(launch.call_count, 1)
        self.assertEqual(dict(os.environ), before)
        self.assertEqual(Path.cwd(), directory)
        self.assertFalse((self.fixture.pairs["first"][0]/"build-messages.jsonl").exists())

    def test_prebuild_content_change_refuses_before_build_and_keeps_private_metadata(self):
        with self.fixture.gates(), patch.object(qualification.check.resolution, "inspect", return_value=dict(
                resolution=self.fixture.resolution, selected_contents_sha256="0"*64)), self.assertRaises(qualification.InputError):
            qualification.qualify(self.fixture.root, self.fixture.pairs, self.fixture.home, self.fixture.platform, self.fixture.tools)
        self.assertEqual([call[0][1] for call in self.fixture.calls], ["metadata"])

    def test_postbuild_source_or_resolution_change_refuses_before_second_build(self):
        self.fixture.report_change = lambda report, name: report.update(prepared_source_files=54)
        with self.assertRaises(qualification.InputError):
            self.fixture.qualify()
        self.assertEqual([call[0][1] for call in self.fixture.calls], ["metadata", "build"])

    def test_changed_selected_tool_after_build_refuses_without_reselecting_expected_digest(self):
        self.fixture.after_build = lambda name: self.fixture.tools["cargo"].write_bytes(b"Changed synthetic tool.\n")
        with self.assertRaises(qualification.InputError):
            self.fixture.qualify()
        self.assertEqual(len(self.fixture.calls), 2)

    def test_cross_pair_native_measurement_substitution_refuses_before_scan(self):
        def change(report, name):
            if name == "second":
                report["measured_inputs"]["rustc"]["selected_sha256"] = "0"*64
        self.fixture.report_change = change
        with patch.object(qualification.scanner, "inspect", side_effect=AssertionError("scan too early")), self.assertRaises(qualification.InputError):
            self.fixture.qualify()

    def test_changed_first_output_during_second_build_refuses_against_retained_expectation(self):
        def change(name):
            if name == "second":
                self.fixture.worker("first").write_bytes(b"Changed old artifact.\n")
        self.fixture.after_build = change
        with self.assertRaises(qualification.InputError):
            self.fixture.qualify()
        self.assertEqual(len(self.fixture.calls), 4)

    def test_native_cancellation_restores_state_leaves_selections_and_propagates(self):
        before, directory = dict(os.environ), Path.cwd()
        with self.fixture.gates(), patch.object(qualification.original, "_run", side_effect=KeyboardInterrupt()) as launch:
            with self.assertRaises(KeyboardInterrupt):
                qualification.qualify(self.fixture.root, self.fixture.pairs, self.fixture.home, self.fixture.platform, self.fixture.tools)
        self.assertEqual(launch.call_count, 1)
        self.assertEqual(dict(os.environ), before)
        self.assertEqual(Path.cwd(), directory)
        self.assertTrue(all(path.is_dir() for pair in self.fixture.pairs.values() for path in pair))

    def test_build_transport_failure_retains_metadata_restores_state_and_does_not_retry(self):
        before, directory = dict(os.environ), Path.cwd()
        def fail_build(command, request, **bounds):
            if command[1] == "build":
                raise qualification.original.WorkerError("synthetic-private-output")
            return self.fixture.run(command, request, **bounds)
        with self.fixture.gates(), patch.object(qualification.original, "_run", side_effect=fail_build) as launch:
            with self.assertRaises(qualification.InputError) as caught:
                qualification.qualify(self.fixture.root, self.fixture.pairs, self.fixture.home, self.fixture.platform, self.fixture.tools)
        self.assertEqual(str(caught.exception), qualification.REFUSAL)
        self.assertEqual(launch.call_count, 2)
        self.assertEqual(dict(os.environ), before)
        self.assertEqual(Path.cwd(), directory)
        source = self.fixture.pairs["first"][0]
        self.assertEqual((source/"metadata.json").read_bytes(), b"{}\n")
        self.assertFalse((source/"build-messages.jsonl").exists())

    def test_environment_is_restored_even_if_operating_system_refuses_cwd_restoration(self):
        before, directory = dict(os.environ), Path.cwd()
        actual_chdir = os.chdir
        def refuse_restore(path):
            if path == directory:
                raise OSError("synthetic restoration refusal")
            actual_chdir(path)
        try:
            with patch.object(qualification.os, "chdir", side_effect=refuse_restore), self.assertRaises(OSError):
                with qualification._environment(self.fixture.tools, self.fixture.home, self.fixture.pairs["first"][0], self.fixture.platform,
                                                qualification.encoded_flags(self.fixture.locations())):
                    os.environ["SYNTHETIC_TRANSIENT"] = "private"
            self.assertEqual(dict(os.environ), before)
        finally:
            actual_chdir(directory)

    def test_actual_cli_missing_selections_refuses_quietly_without_path_disclosure(self):
        root = Path(__file__).resolve().parents[1]
        environment = dict(os.environ)
        environment.pop("PYTHONPATH", None)
        result = subprocess.run([sys.executable, "-B", str(root/"scripts/qualify_worker_remapping.py"),
                                 "--unselected-private-value"], cwd=root, capture_output=True, timeout=10, env=environment)
        self.assertEqual((result.returncode, result.stdout), (1, b""))
        self.assertEqual(result.stderr, ("FAIL: "+qualification.REFUSAL+"\n").encode())
        self.assertNotIn(str(root).encode(), result.stderr)


if __name__ == "__main__":
    unittest.main()
