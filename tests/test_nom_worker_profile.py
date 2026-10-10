"""Selected NoM build targets and explicit empty-environment controls."""

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from test_worker_build import BuildFixture
from scripts import check_worker_build as build
from scripts import qualify_nom_worker as qualification
from offline_session.nom_recovery import RecoveryError
from offline_session.nom_verifier import NomPublicVerifier, CLEAN_EXECUTION_PROFILE, LEGACY_EXECUTION_PROFILE
from offline_session.public_worker import run_public_worker, run_clean_environment_public_worker


ROOT = Path(__file__).resolve().parents[1]
TERMS = json.loads((ROOT / "compatibility/fixtures/nom_terms_v1.json").read_text("ascii"))
PAIR = json.loads((ROOT / "compatibility/fixtures/nom_completions_v1.json").read_text("ascii"))["pair"]


class NomBuildTargetTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.fixture = BuildFixture(Path(self.temp.name))
        f = self.fixture
        target = f.source.package("ptlc-primitive-qualification")["targets"][0]
        path = Path(target["src_path"]).with_name("verify_nom_swap.rs")
        path.write_bytes(b"// Synthetic NoM target; never compiled.\n")
        target.update(name="verify_nom_swap", src_path=str(path))
        self.selected = build.resolution.normalize(f.source.raw(), f.source.packages, f.source.workspace,
                                                  f.source.registry, f.source.checkouts, worker="verify_nom_swap")
        worker = f.worker.with_name("verify_nom_swap")
        worker.write_bytes(b"Synthetic NoM executable; never launched.\n")
        f.root.update(target=deepcopy(target), filenames=[str(worker)], executable=str(worker))

    def compare(self, rows=None, worker="verify_nom_swap"):
        f = self.fixture
        return build.compare(f.raw(rows), f.source.value, self.selected, f.source.workspace,
                             f.build, f.source.platform, 0, worker=worker)

    def test_separate_nom_target_matches_without_relabeling_legacy_target(self):
        self.assertEqual(self.compare()["selected_root"]["target"]["name"], "verify_nom_swap")
        with self.assertRaises(build.InputError): self.compare(worker=build.WORKER)
        f = self.fixture
        with self.assertRaises(build.InputError):
            build.resolution.normalize(f.source.raw(), f.source.packages, f.source.workspace,
                                       f.source.registry, f.source.checkouts)

    def test_wrong_example_path_and_unknown_selection_are_refused(self):
        f = self.fixture
        target = f.source.package("ptlc-primitive-qualification")["targets"][0]
        target["src_path"] = str(Path(target["src_path"]).with_name("verify_original_read_response.rs"))
        with self.assertRaises(build.InputError):
            build.resolution.normalize(f.source.raw(), f.source.packages, f.source.workspace,
                                       f.source.registry, f.source.checkouts, worker="verify_nom_swap")
        for name in (None, True, "arbitrary-worker"):
            with self.subTest(name=name), self.assertRaises(build.InputError): self.compare(worker=name)

    def test_nom_artifact_cannot_redirect_executable_or_use_cached_claims(self):
        for change in (lambda row: row.update(executable=str(self.fixture.worker)),
                       lambda row: row.update(fresh=True),
                       lambda row: row["profile"].update(test=True)):
            rows = deepcopy(self.fixture.rows)
            change(rows[3])
            with self.assertRaises(build.InputError): self.compare(rows)

    def test_forged_matching_claims_remain_a_provenance_counterexample(self):
        # Both claims are fixture-written; no compiler or mathematical worker ran.
        report = self.compare([self.fixture.root, self.fixture.terminal])
        self.assertEqual(report["record_count"], 2)
        self.assertEqual(report["other_artifact_claims"], 0)

    def test_ambient_cargo_configuration_refuses_instead_of_silently_overriding(self):
        base = Path(self.temp.name)
        hidden = base / ".cargo"
        hidden.mkdir()
        config = hidden / "config.toml"
        config.write_bytes(b"# Synthetic ambient selection.\n")
        with self.assertRaises(build.InputError):
            qualification.refuse_configuration(self.fixture.source.workspace, self.fixture.source.home)
        config.unlink()
        config.symlink_to(hidden / "absent")
        with self.assertRaises(build.InputError):
            qualification.refuse_configuration(self.fixture.source.workspace, self.fixture.source.home)

    def test_apple_sdk_requires_explicit_directory_and_linux_refuses_it(self):
        base = Path(self.temp.name)
        self.assertEqual(qualification.select_sdk("aarch64-apple-darwin", base), base)
        self.assertIsNone(qualification.select_sdk("x86_64-unknown-linux-gnu", None))
        for value in (None, Path("relative"), base / "absent"):
            with self.subTest(value=value), self.assertRaises(build.InputError):
                qualification.select_sdk("aarch64-apple-darwin", value)
        with self.assertRaises(build.InputError):
            qualification.select_sdk("x86_64-unknown-linux-gnu", base)

    def test_selected_build_environment_has_only_explicit_inputs(self):
        base = Path(self.temp.name)
        tools = {role: base / role for role in build.NATIVE_ROLES}
        with patch.dict(os.environ, {"PTLC_PUBLIC_TEST_CANARY": "public-synthetic-only",
                                   "RUSTFLAGS": "synthetic-ambient-selection", "SDKROOT": "ambient"}):
            linux = qualification.environment(tools, base, base, "x86_64-unknown-linux-gnu")
            apple = qualification.environment(tools, base, base, "aarch64-apple-darwin", base)
        for name in ("PTLC_PUBLIC_TEST_CANARY", "RUSTFLAGS", "HOME", "SDKROOT"):
            self.assertNotIn(name, linux)
        self.assertEqual(apple["SDKROOT"], str(base))
        self.assertEqual(linux["RUSTC"], str(tools["rustc"]))


class NomEnvironmentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.worker = Path(self.temp.name) / "worker"

    def executable(self, code):
        self.worker.write_text("#!" + sys.executable + "\n" + code, encoding="ascii")
        self.worker.chmod(0o700)
        return hashlib.sha256(self.worker.read_bytes()).hexdigest()

    def test_actual_pipe_removes_inherited_canary_and_legacy_keeps_its_profile(self):
        self.executable("import os,sys\nsys.stdout.write(os.environ.get('PTLC_PUBLIC_TEST_CANARY','absent'))\n")
        with patch.dict(os.environ, {"PTLC_PUBLIC_TEST_CANARY": "public-synthetic-only"}):
            self.assertEqual(run_clean_environment_public_worker(str(self.worker), b"", timeout=2,
                                                                max_input_bytes=32), b"absent")
            self.assertEqual(run_public_worker(str(self.worker), b"", timeout=2,
                                              max_input_bytes=32), b"public-synthetic-only")

    def test_nom_adapter_explicit_profile_uses_empty_environment_on_actual_exec(self):
        pin = self.executable("import hashlib,json,os,sys\nwire=sys.stdin.buffer.read()\n"
                              "result={'schema':'ptlc-nom-public-verification-result-v1',"
                              "'request_digest_hex':hashlib.sha256(wire).hexdigest(),"
                              "'valid':'PTLC_PUBLIC_TEST_CANARY' not in os.environ,'completed_long_hex':''}\n"
                              "sys.stdout.write(json.dumps(result,sort_keys=True,separators=(',',':')))\n")
        clean = NomPublicVerifier(self.worker, pin, TERMS, PAIR, execution_profile=CLEAN_EXECUTION_PROFILE)
        legacy = NomPublicVerifier(self.worker, pin, TERMS, PAIR)
        self.assertEqual(clean.request("verify-pair"), legacy.request("verify-pair"))
        self.assertEqual(legacy.execution_profile, LEGACY_EXECUTION_PROFILE)
        with patch.dict(os.environ, {"PTLC_PUBLIC_TEST_CANARY": "public-synthetic-only"}):
            self.assertTrue(clean.verify_pair())
            with self.assertRaises(RecoveryError): legacy.verify_pair()
        # A pinned fixture-written positive is still accepted: this is not crypto trust.
        self.assertTrue(clean.verify_pair())

    def test_unknown_profile_refuses_before_executable_selection(self):
        for value in (None, True, 1, {}, "nom-empty-environment-v2"):
            with self.subTest(value=value), self.assertRaises(RecoveryError):
                NomPublicVerifier(None, "00" * 32, TERMS, PAIR, execution_profile=value)


if __name__ == "__main__": unittest.main()
