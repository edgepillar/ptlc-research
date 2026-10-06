"""Synthetic input substitutions and local source records, not build attestation."""

import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts import check_build_inputs as check
from scripts import qualify_build_inputs as qualify
import test_observation_review_subject as fixtures


ROOT = Path(__file__).resolve().parents[1]
ARCHIVE = b"Public synthetic archive bytes; no external code.\n"
DIGEST = hashlib.sha256(ARCHIVE).hexdigest()
GIT_PIN = "1" * 40
LOCK = ('version = 4\n\n[[package]]\nname = "demo"\nversion = "1.0.0"\nsource = "'
        + check.REGISTRY + '"\nchecksum = "' + DIGEST + '"\n'
        '\n[[package]]\nname = "local"\nversion = "0.0.0"\ndependencies = [\n "demo",\n]\n'
        '\n[[package]]\nname = "gitdemo"\nversion = "2.0.0"\n'
        'source = "git+https://github.com/example/public?rev=' + GIT_PIN + '#' + GIT_PIN + '"\n').encode("ascii")
H1 = "h1:" + base64.b64encode(b"a" * 32).decode("ascii")
MOD = b"module example.invalid/synthetic\n\ngo 1.23.2\n\nrequire (\n example.invalid/demo v1.0.0\n)\n"
SUM = ("example.invalid/demo v1.0.0 " + H1 + "\nexample.invalid/demo v1.0.0/go.mod " + H1 + "\n").encode("ascii")


class BuildRecordTests(unittest.TestCase):
    def test_registry_git_local_records_are_not_a_compiled_closure(self):
        records = check.cargo_records(LOCK)
        self.assertEqual({r["kind"] for r in records}, {"registry-archive", "git-record", "local-record"})
        self.assertEqual(len(records), 3)
        self.assertNotIn("compiled", json.dumps(records))

    def test_cargo_duplicate_missing_extra_and_unsupported_fields_refuse(self):
        variants = (LOCK + LOCK.split(b"[[package]]", 1)[1].join([b"[[package]]", b""]),
                    LOCK.replace(b'name = "demo"\n', b"", 1),
                    LOCK.replace(b'name = "demo"\n', b'name = "demo"\nname = "alias"\n', 1),
                    LOCK.replace(b'name = "demo"\n', b'name = "demo"\nextra = "value"\n', 1),
                    LOCK.replace(b"version = 4", b"version = 3", 1))
        for raw in variants:
            with self.subTest(raw=hashlib.sha256(raw).hexdigest()), self.assertRaises(check.InputError):
                check.cargo_records(raw)

    def test_cargo_unpinned_sources_registry_aliases_and_bad_checksums_refuse(self):
        for raw in (LOCK.replace(GIT_PIN.encode() + b'#', b'2' * 40 + b'#'),
                    LOCK.replace(check.REGISTRY.encode(), b'registry+https://example.invalid/index'),
                    LOCK.replace(DIGEST.encode(), DIGEST.upper().encode()),
                    LOCK.replace(b'name = "demo"', b'name = "../demo"'),
                    LOCK.replace(b'version = "1.0.0"', b'version = "1.0"'),
                    LOCK.replace(b'name = "local"', b'checksum = "' + DIGEST.encode() + b'"\nname = "local"')):
            with self.assertRaises(check.InputError):
                check.cargo_records(raw)

    def test_cargo_literal_array_encoding_and_count_bounds_refuse(self):
        variants = (LOCK.replace(b'"demo",', b'"demo",\n "demo",'),
                    LOCK.replace(b'"demo",', b'"demo"'), LOCK[:-2],
                    LOCK.replace(b'name = "demo"', b'name = "de\\u006do"'),
                    LOCK + b'\x00', b'x' * (check.source.MAX_MANIFEST_BYTES + 1))
        for raw in variants:
            with self.assertRaises(check.InputError):
                check.cargo_records(raw)
        with patch.object(check, "MAX_PACKAGES", 2), self.assertRaises(check.InputError):
            check.cargo_records(LOCK)

    def test_go_requirements_and_checksum_history_have_no_content_verification(self):
        old = ("example.invalid/old v0.1.0/go.mod " + H1 + "\n").encode("ascii")
        report = check.go_records(MOD, SUM + old)
        self.assertEqual(len(report["declared_requirements"]), 1)
        self.assertEqual(len(report["checksum_records"]), 3)
        self.assertEqual(report["resolved_closure"], "NOT DETERMINED")
        self.assertTrue(all(r["contents"] == "NOT MEASURED" for r in report["checksum_records"]))

    def test_go_duplicate_missing_noncanonical_and_bad_h1_records_refuse(self):
        for raw in (SUM + SUM, SUM.splitlines(keepends=True)[0],
                    SUM.replace(b'h1:', b'h2:'), SUM.replace(b'=', b'A'),
                    SUM.replace(b' v1.0.0 ', b' v01.0.0 '), SUM + b'\n',
                    SUM.replace(b'example.invalid/demo', b'../demo')):
            with self.assertRaises(check.InputError):
                check.go_records(MOD, raw)

    def test_go_unhandled_directives_aliases_and_incomplete_requirements_refuse(self):
        for raw in (MOD + b'replace example.invalid/demo => ../other\n',
                    MOD.replace(b'go 1.23.2', b'go "1.23.2"'), MOD[:-2],
                    MOD.replace(b'example.invalid/demo v1.0.0', b'example.invalid/demo v1.0.0\n example.invalid/demo v1.0.0'),
                    MOD.replace(b'module example.invalid/synthetic', b'module ../synthetic')):
            with self.assertRaises(check.InputError):
                check.go_records(raw, SUM)

    def test_streamed_measurement_requires_selected_digest_and_regular_bytes(self):
        with tempfile.TemporaryDirectory(prefix="synthetic-measurement-") as directory:
            path = Path(directory) / "input.bin"
            path.write_bytes(ARCHIVE)
            result = check.measure(path, DIGEST, len(ARCHIVE))
            self.assertEqual(result["bytes"], len(ARCHIVE))
            self.assertEqual(result["measured_sha256"], DIGEST)
            self.assertNotIn(str(path), json.dumps(result))
            for pin in (None, "a" * 64, DIGEST.upper()):
                with self.assertRaises(check.InputError):
                    check.measure(path, pin, len(ARCHIVE))
            with self.assertRaises(check.InputError):
                check.measure(path, DIGEST, len(ARCHIVE) - 1)
            path.unlink()
            with self.assertRaises(check.InputError):
                check.measure(path, DIGEST, len(ARCHIVE))

    def test_zero_directory_symlink_and_sparse_oversized_inputs_refuse(self):
        with tempfile.TemporaryDirectory(prefix="synthetic-input-types-") as directory:
            root = Path(directory)
            zero, link, big = root / "zero", root / "link", root / "big"
            zero.touch()
            link.symlink_to(zero)
            with big.open("wb") as handle:
                handle.truncate(1025)
            for path in (root, zero, link, big):
                with self.assertRaises(check.InputError):
                    check.measure(path, DIGEST, 1024)

    def test_native_selection_is_caller_bytes_not_authenticated_toolchain(self):
        with tempfile.TemporaryDirectory(prefix="synthetic-native-selection-") as directory:
            path = Path(directory) / "native.bin"
            path.write_bytes(ARCHIVE)
            self.assertEqual(qualify.select_digest(path), DIGEST)
            with patch.object(check, "MAX_NATIVE_BYTES", 4), self.assertRaises(check.InputError):
                qualify.select_digest(path)


class BuildInputInspectionTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="synthetic-build-inputs-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.fixture = fixtures.ObservationSubjectTests("runTest")
        self.fixture.root = self.root
        self.fixture.environment = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        self.fixture.environment.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
        self.fixture.git("init", "--quiet")
        files = {name: ("100644", b"Public synthetic source.\n") for name in check.SOURCE_PATHS}
        files["qualification/Cargo.lock"] = ("100644", LOCK)
        for name in ("qualification-go", "qualification-bitcoin-go"):
            files[name + "/go.mod"] = ("100644", MOD)
            files[name + "/go.sum"] = ("100644", SUM)
        self.commit = self.fixture.commit(files)
        tree, rows, _ = check.source._inventory(self.root, self.commit)
        for row in rows:
            row["observation_status"] = "added"
        self.manifest = dict(schema="ptlc-witness-review-subject-v1", commit=self.commit,
                             tree=tree, file_count=len(rows), files=rows)
        for name, (_, raw) in files.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            self.fixture.index(name, raw)
        self.write_manifest(self.manifest)
        self.cache = self.root / "external"
        self.cache.mkdir()
        (self.cache / "demo-1.0.0.crate").write_bytes(ARCHIVE)
        self.native_file = self.root / "native.bin"
        self.native_file.write_bytes(ARCHIVE)
        self.native = {role: (self.native_file, DIGEST) for role in check.NATIVE_ROLES}

    def write_manifest(self, value):
        raw = check.encoded(value)
        path = self.root / check.MANIFEST
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        self.fixture.index(check.MANIFEST, raw)
        self.manifest_sha = hashlib.sha256(raw).hexdigest()

    def inspect(self):
        return check.inspect(self.root, self.commit, self.manifest_sha, self.cache, self.native)

    def test_complete_evidence_has_only_logical_names_and_explicit_gaps(self):
        report = self.inspect()
        self.assertEqual(len(report["source_inputs"]), 10)
        self.assertEqual(len(report["measured_registry_archives"]), 1)
        self.assertEqual(len(report["native_inputs"]), 4)
        self.assertEqual(report["boundary"]["source_to_executable_provenance"], "NOT VERIFIED")
        self.assertEqual(report["boundary"]["independent_review"], "NOT ASSESSED")
        self.assertEqual(report["boundary"]["application_and_core"], "NO-GO")
        self.assertNotIn(str(self.root), json.dumps(report))

    def test_independent_source_and_manifest_pins_cannot_be_bootstrapped(self):
        self.manifest_sha = "2" * 64
        with self.assertRaises(check.InputError):
            self.inspect()
        self.manifest_sha = hashlib.sha256(check.encoded(self.manifest)).hexdigest()
        self.commit = "3" * 40
        with self.assertRaises(check.InputError):
            self.inspect()

    def test_complete_manifest_missing_extra_duplicate_and_boolean_rows_refuse(self):
        for action in ("missing", "extra", "duplicate", "boolean", "tree"):
            value = copy.deepcopy(self.manifest)
            if action == "missing": value["files"].pop()
            if action == "extra": value["files"][0]["extra"] = False
            if action == "duplicate": value["files"].append(value["files"][0])
            if action == "boolean": value["file_count"] = True
            if action == "tree": value["tree"] = "0" * 40
            self.write_manifest(value)
            with self.assertRaises(check.InputError):
                self.inspect()

    def test_noncanonical_duplicate_json_and_index_substitution_refuse(self):
        path = self.root / check.MANIFEST
        raw = path.read_bytes()
        for changed in (raw + b"\n", raw.replace(b'{', b'{"commit":"alias",', 1)):
            path.write_bytes(changed)
            self.fixture.index(check.MANIFEST, changed)
            self.manifest_sha = hashlib.sha256(changed).hexdigest()
            with self.assertRaises(check.InputError):
                self.inspect()
        self.write_manifest(self.manifest)
        self.fixture.index(check.MANIFEST, b"{}\n")
        with self.assertRaises(check.InputError):
            self.inspect()

    def test_source_worktree_and_index_changes_refuse_before_native_measurements(self):
        for name in check.SOURCE_PATHS:
            path = self.root / name
            old = path.read_bytes()
            path.write_bytes(old + b"Public change.\n")
            with patch.object(check, "measure", side_effect=AssertionError("unexpected measurement")):
                with self.assertRaises(check.InputError): self.inspect()
            path.write_bytes(old)
            self.fixture.index(name, old + b"Public change.\n")
            with self.assertRaises(check.InputError): self.inspect()
            self.fixture.index(name, old)

    def test_missing_and_modified_registry_archives_refuse_without_fallback(self):
        path = self.cache / "demo-1.0.0.crate"
        path.write_bytes(ARCHIVE + b"change")
        with self.assertRaises(check.InputError): self.inspect()
        path.unlink()
        with self.assertRaises(check.InputError): self.inspect()

    def test_registry_directory_and_archive_links_refuse(self):
        path = self.cache / "demo-1.0.0.crate"
        path.unlink()
        path.symlink_to(self.native_file)
        with self.assertRaises(check.InputError): self.inspect()
        old = self.cache
        self.cache = self.root / "cache-link"
        self.cache.symlink_to(old, target_is_directory=True)
        with self.assertRaises(check.InputError): self.inspect()

    def test_native_missing_extra_role_and_mismatched_bytes_refuse(self):
        for native in ({}, dict(self.native, extra=(self.native_file, DIGEST)),
                       dict(self.native, cargo=(self.native_file, "4" * 64))):
            with self.assertRaises(check.InputError):
                check.inspect(self.root, self.commit, self.manifest_sha, self.cache, native)
        self.native_file.unlink()
        with self.assertRaises(check.InputError): self.inspect()

    def test_aggregate_archive_bound_refuses_complete_positive_report(self):
        with patch.object(check, "MAX_ARCHIVES_BYTES", len(ARCHIVE) - 1), self.assertRaises(check.InputError):
            self.inspect()

    def test_cli_success_and_missing_pin_emit_no_private_input_paths(self):
        args = [sys.executable, "-B", str(ROOT / "scripts/check_build_inputs.py"), "--root", str(self.root),
                "--expect-commit", self.commit, "--expect-manifest-sha256", self.manifest_sha,
                "--registry-cache", str(self.cache)]
        for role in check.NATIVE_ROLES:
            args.extend(["--" + role, str(self.native_file), "--expect-" + role + "-sha256", DIGEST])
        result = subprocess.run(args, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0)
        self.assertNotIn(str(self.root).encode(), result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout)["boundary"]["build_execution"], "NOT PERFORMED BY THIS CHECK")
        result = subprocess.run(args[:-2], capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr, b"FAIL: offline build input inspection rejected\n")

    def test_qualification_refuses_ambiguous_cache_without_selecting_native_files(self):
        home = self.root / "cargo-home"
        for name in ("one", "two"):
            (home / "registry/cache" / name).mkdir(parents=True)
        args = [sys.executable, "-B", str(ROOT / "scripts/qualify_build_inputs.py"), "--cargo-home", str(home)]
        for role in check.NATIVE_ROLES: args.extend(["--" + role, str(self.native_file)])
        result = subprocess.run(args, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b"")
        self.assertNotIn(str(self.root).encode(), result.stderr)
        (home / "registry/cache/two").rmdir()
        loop = self.root / "native-loop"
        loop.symlink_to(loop)
        args[args.index("--cargo") + 1] = str(loop)
        result = subprocess.run(args, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr, b"FAIL: offline build input qualification rejected\n")
        self.assertNotIn(str(self.root).encode(), result.stderr)


class PinnedBuildRecordTests(unittest.TestCase):
    def test_actual_source_records_keep_git_go_and_worker_paths_separate(self):
        _, records, bodies = check.selected_source(ROOT, qualify.COMMIT, qualify.MANIFEST_SHA256)
        self.assertEqual(len(records), 10)
        packages = check.cargo_records(bodies["qualification/Cargo.lock"])
        self.assertEqual(len(packages), 75)
        self.assertEqual([sum(r["kind"] == k for r in packages) for k in
                          ("registry-archive", "git-record", "local-record")], [68, 6, 1])
        for name, requirements, sums in (("qualification-go", 6, 13), ("qualification-bitcoin-go", 9, 119)):
            go = check.go_records(bodies[name + "/go.mod"], bodies[name + "/go.sum"])
            self.assertEqual(len(go["declared_requirements"]), requirements)
            self.assertEqual(len(go["checksum_records"]), sums)
        worker = bodies["qualification/examples/verify_original_read_response.rs"]
        self.assertIn(b"bitcoin::secp256k1", worker)
        self.assertNotIn(b"schnorr_fun::", worker)


if __name__ == "__main__":
    unittest.main()
