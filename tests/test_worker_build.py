"""Synthetic build claims and bytes do not authenticate compilation or a release."""

from contextlib import ExitStack
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from test_cargo_resolution import Fixture
from scripts import check_worker_build as check
from scripts import qualify_worker_build as qualification


class BuildFixture:
    def __init__(self, parent):
        self.source = Fixture(parent)
        self.source.workspace.chmod(0o700)
        self.build = parent/"build"
        self.build.mkdir(mode=0o700)
        self.source.value["target_directory"] = str(self.source.workspace/"metadata-target")
        package = self.source.package("bitcoin")
        path = Path(package["manifest_path"]).parent/"build.rs"
        path.write_bytes(b"// Synthetic build source.\n")
        target = deepcopy(package["targets"][0])
        target.update(name="build-script-build", kind=["custom-build"], crate_types=["bin"], src_path=str(path))
        package["targets"].append(target)
        self.source.baseline = self.source.normalize()
        self.source.save()
        self.worker = self.build/self.source.platform/"debug/examples"/check.WORKER
        self.worker.parent.mkdir(parents=True)
        self.worker.write_bytes(b"# Synthetic executable bytes; never executed.\n")
        self.worker.chmod(0o700)
        self.worker_sha = hashlib.sha256(self.worker.read_bytes()).hexdigest()
        self.native = {}
        for role in check.NATIVE_ROLES:
            path = parent/role
            path.write_bytes(b"# Synthetic selected native input.\n"+role.encode()+b"\n")
            self.native[role] = (path, hashlib.sha256(path.read_bytes()).hexdigest())
        self.root = self.artifact("ptlc-primitive-qualification")
        self.other = self.artifact("bitcoin")
        self.script = dict(reason="build-script-executed", package_id=self.source.ids["bitcoin"],
                           linked_libs=["synthetic"], linked_paths=["native=/synthetic-private-path"],
                           cfgs=["synthetic"], env=[["SYNTHETIC_ENV", "private synthetic value"]],
                           out_dir=str(self.build/"debug/build/synthetic/out"))
        self.diagnostic = dict(reason="compiler-message", package_id=self.source.ids["bitcoin"],
                               manifest_path=self.source.package("bitcoin")["manifest_path"],
                               target=deepcopy(self.source.package("bitcoin")["targets"][0]),
                               message=dict(level="warning", message="private synthetic diagnostic", children=[]))
        self.terminal = dict(reason="build-finished", success=True)
        self.rows = [self.other, self.script, self.diagnostic, self.root, self.terminal]
        self.messages = self.source.workspace/"build-messages.jsonl"
        self.save()

    def artifact(self, name):
        package = self.source.package(name)
        local = name == "ptlc-primitive-qualification"
        return dict(reason="compiler-artifact", package_id=package["id"], manifest_path=package["manifest_path"],
                    target=deepcopy(package["targets"][0]), profile=deepcopy(check.ROOT_PROFILE),
                    features=[] if local else ["default"], filenames=[str(self.worker if local else self.build/"debug/libsynthetic.rlib")],
                    executable=str(self.worker) if local else None, fresh=False)

    def raw(self, rows=None):
        return b"".join(json.dumps(r, ensure_ascii=False).encode("utf-8")+b"\n" for r in (self.rows if rows is None else rows))

    def save(self):
        self.messages.write_bytes(self.raw())

    def compare(self, rows=None, raw=None, status=0):
        return check.compare(self.raw(rows) if raw is None else raw, self.source.value, self.source.baseline,
                             self.source.workspace, self.build, self.source.platform, status)

    def gates(self):
        context = ExitStack()
        context.enter_context(patch.object(check.resolution, "inspect", return_value=dict(
            resolution=self.source.baseline, prepared_source_files=55, selected_contents_sha256="6"*64)))
        context.enter_context(patch.object(check.inputs, "selected_source", return_value=("7"*40, [], {"qualification/Cargo.lock": b"synthetic"})))
        context.enter_context(patch.object(check.inputs, "cargo_records", return_value=self.source.packages))
        context.enter_context(patch.object(check.resolution.caches, "one_directory", return_value=self.source.registry))
        context.enter_context(patch.object(check.resolution.caches, "select_checkouts", return_value=self.source.checkouts))
        return context

    def inspect(self):
        with self.gates():
            return check.inspect(self.source.root, self.source.commit, self.source.manifest, self.source.digest,
                                 self.source.workspace, self.source.metadata_file, self.source.home, self.source.platform,
                                 self.build, self.messages, 0, self.native, self.worker_sha)


class BuildClaimTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.fixture = BuildFixture(Path(self.temporary.name))

    def refuses(self, change):
        rows = deepcopy(self.fixture.rows)
        change(rows)
        with self.assertRaises(check.InputError):
            self.fixture.compare(rows)

    def test_selected_root_and_private_auxiliary_records_return_only_logical_claims(self):
        report = self.fixture.compare()
        self.assertEqual(report["records"], {"compiler-artifact":2, "build-script-executed":1, "compiler-message":1, "build-finished":1})
        raw = check.encoded(report).decode()
        for value in (str(self.fixture.build), "private synthetic", "SYNTHETIC_ENV", "native=/"):
            self.assertNotIn(value, raw)
        self.assertEqual(report["selected_root"]["target"]["source_path"], "examples/verify_original_read_response.rs")

    def test_omitted_dependency_and_script_records_can_match_without_complete_unit_closure(self):
        report = self.fixture.compare([self.fixture.root, self.fixture.terminal])
        self.assertEqual(report["record_count"], 2)
        self.assertEqual(report["other_artifact_claims"], 0)

    def test_fixed_local_library_artifact_does_not_replace_selected_example(self):
        package=self.fixture.source.package("ptlc-primitive-qualification")
        target=deepcopy(package["targets"][0]);path=Path(package["manifest_path"]).parent/"src/lib.rs"
        path.parent.mkdir();path.write_bytes(b"// Synthetic local library.\n")
        target.update(name="ptlc_primitive_qualification",kind=["lib"],crate_types=["lib"],src_path=str(path))
        package["targets"].append(target);self.fixture.source.baseline=self.fixture.source.normalize()
        rows=deepcopy(self.fixture.rows);library=deepcopy(rows[3])
        library.update(target=target,executable=None,filenames=[str(self.fixture.build/"debug/liblocal.rlib")])
        rows.insert(0,library)
        self.assertEqual(self.fixture.compare(rows)["selected_root"]["target"]["name"],check.WORKER)
        self.assertEqual(self.fixture.compare(rows)["other_artifact_claims"],2)

    def test_coherent_opaque_ids_change_without_selecting_generator_authority(self):
        old = self.fixture.source.ids["ptlc-primitive-qualification"]
        package = self.fixture.source.package("ptlc-primitive-qualification")
        package["id"] = "opaque-alternate-root"
        self.fixture.source.value["resolve"]["root"] = package["id"]
        rows = deepcopy(self.fixture.rows)
        for row in rows:
            if row.get("package_id") == old: row["package_id"] = package["id"]
        self.assertEqual(self.fixture.compare(rows)["selected_root"]["package"], self.fixture.source.baseline["root"])

    def test_unknown_and_unsupported_package_ids_refuse_each_reported_kind(self):
        for index in range(4):
            for value in ("unknown-selected-package", "", True, [], "bad\npackage"):
                self.refuses(lambda rows,i=index,v=value: rows[i].update(package_id=v))

    def test_manifest_substitution_and_path_aliases_refuse(self):
        for index in (0,2,3):
            for value in ("/synthetic/substitute.toml", True, self.fixture.rows[index]["manifest_path"]+"/../Cargo.toml"):
                self.refuses(lambda rows,i=index,v=value: rows[i].update(manifest_path=v))

    def test_every_target_field_substitution_and_boolean_integer_alias_refuses(self):
        for field,value in (("name","replacement"), ("kind",["bin"]), ("crate_types",["lib"]),
                            ("src_path","/synthetic/substitute.rs"), ("edition","2018"), ("doc",1),
                            ("doctest",0), ("test",1)):
            self.refuses(lambda rows,f=field,v=value: rows[3]["target"].update({f:v}))

    def test_missing_extra_and_inexact_record_envelopes_refuse(self):
        for index in range(5):
            self.refuses(lambda rows,i=index: rows[i].pop("reason"))
            self.refuses(lambda rows,i=index: rows[i].update(unreviewed=True))
        self.refuses(lambda rows: rows[3].update(target=[]))

    def test_root_profile_every_field_and_unknown_field_refuse(self):
        for field,value in (("opt_level","3"), ("debuginfo",0), ("debug_assertions",False),
                            ("overflow_checks",False), ("test",True), ("unreviewed",True)):
            self.refuses(lambda rows,f=field,v=value: rows[3]["profile"].update({f:v}))

    def test_nonroot_profile_bounds_and_exact_types_refuse(self):
        for field,value in (("opt_level",0), ("opt_level","9"), ("debuginfo",True), ("debuginfo",3),
                            ("debug_assertions",1), ("overflow_checks",0), ("test",0)):
            self.refuses(lambda rows,f=field,v=value: rows[0]["profile"].update({f:v}))

    def test_unselected_root_features_unknown_dependency_features_and_duplicates_refuse(self):
        self.refuses(lambda rows: rows[3].update(features=["default"]))
        for value in (["unknown"], ["default","default"], True, [1]):
            self.refuses(lambda rows,v=value: rows[0].update(features=v))

    def test_every_cached_artifact_and_freshness_alias_refuses(self):
        for index in (0,3):
            for value in (True, 0, 1, None, "false"):
                self.refuses(lambda rows,i=index,v=value: rows[i].update(fresh=v))

    def test_duplicate_root_with_different_output_claim_is_ambiguous(self):
        self.refuses(lambda rows: rows.insert(3,deepcopy(rows[3])))
        def duplicate(rows):
            row = deepcopy(rows[3]); row["filenames"].append(str(self.fixture.build/"additional-output")); rows.insert(3,row)
        self.refuses(duplicate)

    def test_duplicate_nonroot_operative_artifact_refuses_but_distinct_unit_paths_are_not_closure(self):
        self.refuses(lambda rows: rows.insert(0,deepcopy(rows[0])))
        rows = deepcopy(self.fixture.rows)
        extra = deepcopy(rows[0]); extra["filenames"] = [str(self.fixture.build/"another-unit.rlib")]; rows.insert(0,extra)
        self.assertEqual(self.fixture.compare(rows)["other_artifact_claims"], 2)

    def test_missing_selected_root_and_nonterminal_stream_refuse(self):
        self.refuses(lambda rows: rows.pop(3))
        self.refuses(lambda rows: rows.pop())

    def test_exact_zero_exit_status_is_a_separate_required_operator_claim(self):
        for status in (1, -1, True, False, None, "0"):
            with self.assertRaises(check.InputError): self.fixture.compare(status=status)

    def test_false_duplicate_alias_and_followed_terminal_records_refuse(self):
        for value in (False, 1, "true", None):
            self.refuses(lambda rows,v=value: rows[-1].update(success=v))
        self.refuses(lambda rows: rows.append(deepcopy(rows[-1])))
        self.refuses(lambda rows: rows.append(deepcopy(rows[0])))
        self.refuses(lambda rows: rows.insert(0,rows.pop()))

    def test_unknown_reasons_and_nonobject_records_refuse(self):
        self.refuses(lambda rows: rows[0].update(reason="unreviewed"))
        for raw in (b"[]\n", b"true\n", b'{}\n', b'{"reason":[]}\n'):
            with self.assertRaises(check.InputError): self.fixture.compare(raw=raw)

    def test_incomplete_lines_blank_lines_nonjson_stdout_and_carriage_return_refuse(self):
        raw = self.fixture.raw()
        for value in (raw[:-1], raw+b"\n", b"synthetic stdout\n"+raw, raw.replace(b"\n",b"\r\n"), raw[:-4]+b"\n"):
            with self.assertRaises(check.InputError): self.fixture.compare(raw=value)

    def test_duplicate_keys_floats_nonfinite_numbers_and_bad_utf8_refuse(self):
        for raw in (b'{"reason":"build-finished","success":true,"success":true}\n',
                    b'{"reason":"build-finished","success":1.0}\n',
                    b'{"reason":"build-finished","success":NaN}\n', b'\xff\n'):
            with self.assertRaises(check.InputError): self.fixture.compare(raw=raw)

    def test_stream_line_record_and_aggregate_value_bounds_refuse(self):
        for name,value in (("MAX_STREAM_BYTES",10), ("MAX_LINE_BYTES",10), ("MAX_RECORDS",2), ("MAX_VALUES",10)):
            with patch.object(check,name,value), self.assertRaises(check.InputError): self.fixture.compare()

    def test_excessive_depth_and_surrogate_strings_refuse(self):
        for raw in (b'{"reason":"compiler-message","x":'+b'['*33+b'0'+b']'*33+b'}\n',
                    b'{"reason":"compiler-message","x":"\\ud800"}\n'):
            with self.assertRaises(check.InputError): self.fixture.compare(raw=raw)

    def test_foreign_byte_subclass_runs_no_conversion_hook(self):
        class Hostile(bytes):
            def __bytes__(self): raise AssertionError("foreign hook")
        with self.assertRaises(check.InputError): self.fixture.compare(raw=Hostile(self.fixture.raw()))

    def test_output_escape_alias_duplicates_and_output_count_refuse(self):
        for value in (["/synthetic/outside"], [str(self.fixture.build)+"/../outside"],
                      [str(self.fixture.build)+"//alias"], [str(self.fixture.worker)]*2, [], [None],
                      [str(self.fixture.build/str(i)) for i in range(33)]):
            self.refuses(lambda rows,v=value: rows[3].update(filenames=v))

    def test_root_executable_location_missing_output_and_null_refuse(self):
        for value in (None, str(self.fixture.build/"substitute"), str(self.fixture.worker)+"/../substitute", True):
            self.refuses(lambda rows,v=value: rows[3].update(executable=v))
        self.refuses(lambda rows: rows[3].update(filenames=[str(self.fixture.build/"unrelated")]))

    def test_private_diagnostic_values_are_discarded_and_failure_levels_refuse(self):
        rows = deepcopy(self.fixture.rows)
        rows[2]["message"]["message"] = "Synthetic \u2603 private value"
        self.assertNotIn("private value", check.encoded(self.fixture.compare(rows)).decode())
        for value in ("error", "failure-note", "ice", None, True, []):
            self.refuses(lambda rows,v=value: rows[2]["message"].update(level=v))

    def test_private_script_vectors_shapes_and_escaping_output_directory_refuse(self):
        for field,value in (("env",[["one"]]), ("env",[["one",1]]), ("env",True),
                            ("cfgs",["x"*4097]), ("linked_paths",["x\x00y"]),
                            ("linked_libs",[True]), ("out_dir","/synthetic/outside")):
            self.refuses(lambda rows,f=field,v=value: rows[1].update({f:v}))

    def test_script_claim_requires_declared_script_and_repeated_cached_values_do_not_prove_execution(self):
        self.refuses(lambda rows: rows[1].update(package_id=self.fixture.source.ids["ptlc-primitive-qualification"]))
        rows = deepcopy(self.fixture.rows); rows.insert(1,deepcopy(rows[1]))
        self.assertEqual(self.fixture.compare(rows)["records"]["build-script-executed"],2)

    def test_metadata_scratch_directory_and_platform_selection_are_bound(self):
        self.fixture.source.value["target_directory"] = str(self.fixture.build)
        with self.assertRaises(check.InputError): self.fixture.compare()
        self.fixture.source.value["target_directory"] = str(self.fixture.source.workspace/"metadata-target")
        self.fixture.source.platform = "unsupported-platform"
        with self.assertRaises(check.InputError): self.fixture.compare()


class BuildInspectionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.fixture = BuildFixture(Path(self.temporary.name))

    def test_forged_matching_stream_and_arbitrary_selected_bytes_remain_not_authenticated(self):
        report = self.fixture.inspect()
        self.assertEqual(report["measured_inputs"]["original-response-worker"]["measured_sha256"],self.fixture.worker_sha)
        self.assertEqual(report["source_to_worker"],"NOT VERIFIED")
        self.assertEqual(report["generator_origin"],"NOT AUTHENTICATED")
        self.assertEqual(report["compiled_closure"],"NOT DETERMINED")
        self.assertEqual(report["independent_assessment"],"NOT ASSESSED")
        self.assertEqual(report["application_and_core"],"NO-GO")
        self.assertNotIn(str(self.fixture.source.workspace),check.encoded(report).decode())

    def test_read_only_checker_launches_no_cargo_compiler_script_or_worker(self):
        with patch("subprocess.Popen",side_effect=AssertionError("native launch")):
            self.fixture.inspect()

    def test_changed_worker_bytes_missing_worker_and_wrong_digest_refuse(self):
        self.fixture.worker.write_bytes(b"changed synthetic bytes\n")
        with self.assertRaises(check.InputError): self.fixture.inspect()
        self.fixture.worker.unlink()
        with self.assertRaises(check.InputError): self.fixture.inspect()

    def test_worker_symlink_unexecutable_and_linked_parent_refuse(self):
        self.fixture.worker.chmod(0o600)
        with self.assertRaises(check.InputError): self.fixture.inspect()
        self.fixture.worker.chmod(0o700)
        path = self.fixture.worker.with_name("synthetic-original"); self.fixture.worker.rename(path); self.fixture.worker.symlink_to(path)
        with self.assertRaises(check.InputError): self.fixture.inspect()
        self.fixture.worker.unlink(); path.rename(self.fixture.worker)
        directory=self.fixture.worker.parent; destination=directory.with_name("synthetic-parent")
        directory.rename(destination); directory.symlink_to(destination,target_is_directory=True)
        with self.assertRaises(check.InputError): self.fixture.inspect()

    def test_every_native_pin_and_complete_selection_are_required(self):
        for role in check.NATIVE_ROLES:
            old=self.fixture.native[role];self.fixture.native[role]=(old[0],"0"*64)
            with self.assertRaises(check.InputError): self.fixture.inspect()
            self.fixture.native[role]=old
        self.fixture.native.pop("cargo")
        with self.assertRaises(check.InputError): self.fixture.inspect()

    def test_changed_metadata_source_after_resolution_comparison_refuses(self):
        path = Path(self.fixture.source.package("bitcoin")["targets"][0]["src_path"])
        path.write_bytes(b"// Changed synthetic source.\n")
        with self.assertRaises(check.InputError): self.fixture.inspect()

    def test_read_metadata_target_replacement_cannot_follow_verified_resolution(self):
        value=deepcopy(self.fixture.source.value);value["packages"][1]["targets"][0]["name"]="replacement"
        self.fixture.source.metadata_file.write_text(json.dumps(value))
        with self.assertRaises(check.InputError): self.fixture.inspect()

    def test_invalid_message_file_symlink_and_truncated_stream_refuse(self):
        self.fixture.messages.write_bytes(self.fixture.raw()[:-1])
        with self.assertRaises(check.InputError): self.fixture.inspect()
        self.fixture.messages.unlink(); self.fixture.messages.symlink_to(self.fixture.source.metadata_file)
        with self.assertRaises(check.InputError): self.fixture.inspect()

    def test_owned_private_roots_and_separate_nonnested_directories_are_required(self):
        self.fixture.build.chmod(0o755)
        with self.assertRaises(check.InputError): self.fixture.inspect()
        for first,second in ((self.fixture.build,self.fixture.build), (self.fixture.build,self.fixture.build/"child"),
                             (self.fixture.build/"child",self.fixture.build)):
            with self.assertRaises(check.InputError): check.separate_directories(first,second)

    def test_source_or_cache_comparison_refusal_never_produces_a_partial_positive(self):
        with self.fixture.gates(), patch.object(check.resolution,"inspect",side_effect=check.InputError("synthetic refusal")):
            with self.assertRaises(check.InputError):
                check.inspect(self.fixture.source.root,self.fixture.source.commit,self.fixture.source.manifest,self.fixture.source.digest,
                              self.fixture.source.workspace,self.fixture.source.metadata_file,self.fixture.source.home,self.fixture.source.platform,
                              self.fixture.build,self.fixture.messages,0,self.fixture.native,self.fixture.worker_sha)

    def test_native_byte_bound_and_digest_encoding_refuse_before_claims(self):
        with patch.object(check.inputs,"MAX_NATIVE_BYTES",2),self.assertRaises(check.InputError): self.fixture.inspect()
        old=self.fixture.native["cargo"];self.fixture.native["cargo"]=(old[0],True)
        with self.assertRaises(check.InputError): self.fixture.inspect()

    def test_builder_refuses_nonempty_output_before_launch_or_source_copy(self):
        with patch.object(qualification,"_run",side_effect=AssertionError("launch")),patch.object(qualification,"prepare",side_effect=AssertionError("copy")):
            with self.assertRaises(check.InputError):
                qualification.qualify(self.fixture.source.root,self.fixture.source.workspace,self.fixture.build,self.fixture.source.home,
                                      self.fixture.source.platform,{r:s[0] for r,s in self.fixture.native.items()})

    def test_builder_transport_failure_restores_environment_and_directory_without_retry(self):
        work=Path(self.temporary.name)/"empty-source";build=Path(self.temporary.name)/"empty-build"
        work.mkdir(mode=0o700);build.mkdir(mode=0o700)
        old_environment,old_directory=dict(os.environ),Path.cwd()
        with self.fixture.gates(),patch.object(qualification,"prepare",return_value=55), \
                patch.object(qualification,"native_platform",return_value=self.fixture.source.platform), \
                patch.object(check.resolution.content,"inspect_cargo",return_value={}), \
                patch.object(qualification,"_run",side_effect=qualification.WorkerError("synthetic private error")) as launch:
            with self.assertRaises(qualification.WorkerError):
                qualification.qualify(self.fixture.source.root,work,build,self.fixture.source.home,self.fixture.source.platform,
                                      {r:s[0] for r,s in self.fixture.native.items()})
        self.assertEqual(launch.call_count,1)
        self.assertEqual(dict(os.environ),old_environment)
        self.assertEqual(Path.cwd(),old_directory)
        self.assertFalse((work/"build-messages.jsonl").exists())

    def test_builder_refuses_cross_compilation_before_native_launch_or_copy(self):
        other=next(p for p in check.resolution.PLATFORMS if p != qualification.native_platform())
        with patch.object(qualification,"_run",side_effect=AssertionError("launch")),patch.object(qualification,"prepare",side_effect=AssertionError("copy")):
            with self.assertRaises(check.InputError):
                qualification.qualify(self.fixture.source.root,self.fixture.source.workspace,self.fixture.build,self.fixture.source.home,
                                      other,{r:s[0] for r,s in self.fixture.native.items()})

    def test_cli_missing_selections_are_quiet_and_show_no_private_path_or_traceback(self):
        root=Path(__file__).resolve().parents[1]
        environment=dict(os.environ);environment.pop("PYTHONPATH",None)
        for entry in ("check_worker_build.py","qualify_worker_build.py"):
            result=subprocess.run([sys.executable,"-B",str(root/"scripts"/entry),"--unreviewed-private-value"],
                                  cwd=root,capture_output=True,timeout=10,env=environment)
            self.assertEqual(result.returncode,1)
            self.assertEqual(result.stdout,b"")
            self.assertNotIn(b"unreviewed-private-value",result.stderr)
            self.assertNotIn(str(root).encode(),result.stderr)
            self.assertNotIn(b"Traceback",result.stderr)


if __name__ == "__main__":
    unittest.main()
