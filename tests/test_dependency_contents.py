"""Selected content agreement and synthetic cache tampering, not build authority."""

import base64
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile
import warnings
import zlib

from scripts import check_dependency_contents as check
from scripts import qualify_dependency_contents as qualify
import test_build_inputs as source_fixtures
import test_observation_review_subject as git_fixtures


ROOT = Path(__file__).resolve().parents[1]
FILES = {"src/lib.rs": b"Public synthetic source.\n", "LICENSE": b"Synthetic notice.\n", "empty": b""}
GO_FILES = {"public.go": b"package synthetic\n", "LICENSE": b"Synthetic notice.\n"}
MOD = b"module example.invalid/demo\n"


def rows(files):
    return {name: dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), kind="regular")
            for name, raw in files.items()}


def expected_h1(files, prefix):
    # Test-only selections prepared separately from the entry being measured.
    summary = b"".join(hashlib.sha256(raw).hexdigest().encode("ascii") + b"  "
                       + (prefix + name).encode("ascii") + b"\n" for name, raw in sorted(files.items()))
    return "h1:" + base64.b64encode(hashlib.sha256(summary).digest()).decode("ascii")


def tar_bytes(entries):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, kind, body in entries:
            member = tarfile.TarInfo(name)
            member.type = kind
            if kind == tarfile.REGTYPE:
                member.size = len(body)
                archive.addfile(member, io.BytesIO(body))
            else:
                member.linkname = "src/lib.rs" if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE) else ""
                archive.addfile(member)
    return gzip.compress(stream.getvalue(), mtime=0)


def install(path, files):
    path.mkdir(parents=True, exist_ok=True)
    for name, raw in files.items():
        target = path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)


class ContentFixture(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="synthetic-dependency-content-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.cache, self.installed = self.root / "archives", self.root / "sources"
        self.cache.mkdir()
        self.installed.mkdir()
        self.entries = [("demo-1.0.0/" + name, tarfile.REGTYPE, raw) for name, raw in FILES.items()]
        self.package = dict(name="demo", version="1.0.0", kind="registry-archive")
        self.archive = self.cache / "demo-1.0.0.crate"
        self.set_archive(self.entries)
        self.tree = self.installed / "demo-1.0.0"
        install(self.tree, FILES)

    def set_archive(self, entries):
        raw = tar_bytes(entries)
        self.archive.write_bytes(raw)
        self.package["checksum"] = hashlib.sha256(raw).hexdigest()

    def registry(self):
        return check.registry_contents(self.cache, self.installed, [self.package])


class RegistryContentTests(ContentFixture):
    def test_locked_archive_and_full_installed_tree_agree_with_zero_byte_file(self):
        report = self.registry()[0]
        self.assertEqual((report["files"], report["bytes"]), (3, sum(map(len, FILES.values()))))
        self.assertEqual(report["license_notice_named_files"], 1)
        self.assertNotIn(str(self.root), json.dumps(report))
        self.assertIn("MATCH", report["status"])

    def test_changed_archive_cannot_select_its_own_new_checksum(self):
        self.archive.write_bytes(self.archive.read_bytes() + b"changed")
        with self.assertRaises(check.InputError):
            self.registry()

    def test_missing_modified_extra_and_type_changed_source_refuse(self):
        target = self.tree / "LICENSE"
        for action in ("missing", "modified", "extra", "directory", "symlink"):
            with self.subTest(action=action):
                if action == "missing": target.unlink()
                if action == "modified": target.write_bytes(b"changed")
                if action == "extra": (self.tree / "added.rs").touch()
                if action == "directory": target.unlink(); target.mkdir()
                if action == "symlink": target.unlink(); target.symlink_to(self.tree / "empty")
                with self.assertRaises(check.InputError): self.registry()
                if target.is_symlink() or target.is_file(): target.unlink()
                if target.is_dir(): target.rmdir()
                target.write_bytes(FILES["LICENSE"])
                (self.tree / "added.rs").unlink(missing_ok=True)

    def test_fake_cargo_markers_cannot_authorize_changed_source(self):
        (self.tree / ".cargo-ok").write_bytes(b'{"v":1}')
        checksum = {"files": {n: r["sha256"] for n, r in rows(FILES).items()}, "package": self.package["checksum"]}
        (self.tree / ".cargo-checksum.json").write_bytes(check.encoded(checksum))
        self.assertEqual(self.registry()[0]["generated_metadata"], [".cargo-checksum.json", ".cargo-ok"])
        (self.tree / "src/lib.rs").write_bytes(b"paired fake source")
        checksum["files"]["src/lib.rs"] = hashlib.sha256(b"paired fake source").hexdigest()
        (self.tree / ".cargo-checksum.json").write_bytes(check.encoded(checksum))
        with self.assertRaises(check.InputError): self.registry()

    def test_unrecognized_duplicate_and_oversized_generated_metadata_refuse(self):
        marker = self.tree / ".cargo-ok"
        for raw in (b'{"v":2}', b"private marker", b"x" * (check.inputs.source.MAX_MANIFEST_BYTES + 1)):
            marker.write_bytes(raw)
            with self.assertRaises(check.InputError): self.registry()
        marker.unlink()
        (self.tree / ".cargo-checksum.json").write_bytes(b'{"files":{},"files":{},"package":null}')
        with self.assertRaises(check.InputError): self.registry()

    def test_archive_paths_prefixes_duplicates_aliases_and_reserved_names_refuse(self):
        names = ("../escape", "demo-1.0.0/../escape", "other-1.0.0/src/lib.rs",
                 "demo-1.0.0/src\\lib.rs", "demo-1.0.0/.cargo-ok", "demo-1.0.0/.git/config",
                 "demo-1.0.0/src//lib.rs", "demo-1.0.0/name\n", "demo-1.0.0/" + "x" * 513)
        for name in names:
            self.set_archive([(name, tarfile.REGTYPE, b"synthetic")])
            with self.assertRaises(check.InputError): self.registry()
        for extra in (self.entries[0], ("demo-1.0.0/LICENSE", tarfile.REGTYPE, b"alias"),
                      ("demo-1.0.0/SRC/lib.rs", tarfile.REGTYPE, b"case alias")):
            self.set_archive(self.entries + [extra])
            with self.assertRaises(check.InputError): self.registry()

    def test_tar_links_devices_and_unused_directories_refuse_without_extraction(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.FIFOTYPE, tarfile.DIRTYPE):
            self.set_archive(self.entries + [("demo-1.0.0/extra", kind, b"")])
            with self.assertRaises(check.InputError): self.registry()
        self.assertFalse((self.root / "escape").exists())

    def test_directory_headers_are_allowed_only_for_used_source_parents(self):
        self.set_archive([( "demo-1.0.0", tarfile.DIRTYPE, b""),
                          ("demo-1.0.0/src/", tarfile.DIRTYPE, b"")] + self.entries)
        self.registry()
        (self.tree / "unused").mkdir()
        with self.assertRaises(check.InputError): self.registry()

    def test_compressed_decoded_file_package_count_and_aggregate_bounds_refuse(self):
        for field, limit in (("MAX_TAR_BYTES", 8), ("MAX_FILE_BYTES", 2),
                             ("MAX_PACKAGE_BYTES", 10), ("MAX_ENTRIES", 2), ("MAX_TOTAL_BYTES", 10)):
            with patch.object(check, field, limit), self.assertRaises(check.InputError): self.registry()
        with patch.object(check.inputs, "MAX_ARCHIVE_BYTES", 4), self.assertRaises(check.InputError): self.registry()
        with patch.object(check.inputs, "MAX_ARCHIVES_BYTES", 4), self.assertRaises(check.InputError): self.registry()

    def test_archive_and_installed_root_symlinks_and_changed_descriptor_refuse(self):
        with check.regular(self.archive, check.inputs.MAX_ARCHIVE_BYTES) as handle:
            self.assertTrue(handle.read(2))
        with self.assertRaises(check.InputError):
            with check.regular(self.archive, check.inputs.MAX_ARCHIVE_BYTES): self.archive.write_bytes(b"changed")
        self.archive.unlink(); self.archive.symlink_to(self.tree / "LICENSE")
        with self.assertRaises(check.InputError): self.registry()
        with self.assertRaises(check.InputError): check.tree_rows(self.tree / "empty", rows(FILES))


class GitContentTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="synthetic-pinned-git-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.fixture = git_fixtures.ObservationSubjectTests("runTest")
        self.fixture.root = self.root
        self.fixture.environment = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        self.fixture.environment.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
        self.fixture.git("init", "--quiet")
        self.files = {n: ("100644", raw) for n, raw in FILES.items()}
        self.files["README"] = ("120000", b"LICENSE")
        self.commit = self.make_commit(self.files)
        install(self.root, FILES)
        (self.root / "README").symlink_to("LICENSE")
        (self.root / ".cargo-ok").touch()

    def make_commit(self, files):
        commit = self.fixture.commit(files)
        self.fixture.git("update-ref", "HEAD", commit)
        return commit

    def inspect(self):
        packages = [dict(name="synthetic", version="1.0.0", kind="git-record",
                         source="git+https://github.com/example/public?rev=" + self.commit + "#" + self.commit)]
        return check.git_contents({self.commit: self.root}, packages)

    def test_pinned_objects_regular_bytes_and_internal_link_target_match(self):
        report = self.inspect()[0]
        self.assertEqual((report["files"], report["tracked_symlinks"]), (4, 1))
        self.assertEqual(report["commit"], self.commit)
        self.assertNotIn(str(self.root), json.dumps(report))

    def test_other_head_missing_object_and_parent_repository_fallback_refuse(self):
        for root, commit in ((self.root, "a" * 40), (self.root / "src", self.commit)):
            with self.assertRaises(check.InputError): check.git_rows(root, commit)
        self.make_commit({"other": ("100644", b"another tree")})
        with self.assertRaises(check.InputError): self.inspect()

    def test_modified_missing_extra_and_symlink_type_changes_refuse(self):
        target = self.root / "LICENSE"
        target.write_bytes(b"changed")
        with self.assertRaises(check.InputError): self.inspect()
        target.write_bytes(FILES["LICENSE"])
        target.unlink()
        with self.assertRaises(check.InputError): self.inspect()
        target.write_bytes(FILES["LICENSE"])
        extra = self.root / "extra"; extra.touch()
        with self.assertRaises(check.InputError): self.inspect()
        extra.unlink()
        link = self.root / "README"; link.unlink(); link.write_bytes(b"LICENSE")
        with self.assertRaises(check.InputError): self.inspect()

    def test_changed_link_targets_and_untracked_links_are_not_followed(self):
        link = self.root / "README"; link.unlink(); link.symlink_to("empty")
        with self.assertRaises(check.InputError): self.inspect()
        link.unlink(); link.symlink_to("LICENSE")
        (self.root / "added").symlink_to("LICENSE")
        with self.assertRaises(check.InputError): self.inspect()

    def test_git_object_links_outside_tree_missing_targets_and_cycles_refuse(self):
        for target in (b"../outside", b"/outside", b"missing", b"README", b".git/config"):
            files = dict(self.files, README=("120000", target))
            commit = self.make_commit(files)
            with self.assertRaises(check.InputError): check.git_rows(self.root, commit)

    def test_empty_submodule_metadata_alias_and_large_blob_objects_refuse(self):
        for files in ({}, {"sub": ("160000", self.commit.encode("ascii"))},
                      {".cargo-ok": ("100644", b"source marker")},
                      {"a": ("100644", b"a"), "A": ("100644", b"alias")},
                      {"large": ("100644", b"x" * (check.inputs.source.MAX_BLOB_BYTES + 1))}):
            commit = self.make_commit(files)
            with self.assertRaises((check.InputError, ValueError)): check.git_rows(self.root, commit)

    def test_exact_git_selections_and_owned_metadata_directory_are_required(self):
        with self.assertRaises(check.InputError): check.git_contents({}, [{"kind": "git-record", "name": "demo",
            "version": "1.0.0", "source": "git+https://github.com/example/public?rev=" + self.commit + "#" + self.commit}])
        (self.root / ".cargo-ok").write_bytes(b"self-selected metadata")
        with self.assertRaises(check.InputError): self.inspect()

    def test_forged_commit_tree_and_blob_bytes_cannot_hide_under_pinned_object_names(self):
        tree = self.fixture.git("rev-parse", self.commit + "^{tree}").stdout.decode("ascii").strip()
        blob = self.fixture.git("rev-parse", self.commit + ":LICENSE").stdout.decode("ascii").strip()
        replacement = self.fixture.blob(b"paired forged source")
        for kind, oid in (("commit", self.commit), ("tree", tree), ("blob", blob)):
            path = self.root / ".git/objects" / oid[:2] / oid[2:]
            saved = path.read_bytes()
            original_mode = path.stat().st_mode & 0o777
            body = self.fixture.git("cat-file", kind, oid).stdout
            if kind == "commit": changed = body + b"forged context\n"
            elif kind == "tree": changed = body.replace(bytes.fromhex(blob), bytes.fromhex(replacement), 1)
            else: changed = b"paired forged source"
            self.assertNotEqual(changed, body)
            wire = (kind + " " + str(len(changed))).encode("ascii") + b"\0" + changed
            path.chmod(0o600)
            path.write_bytes(zlib.compress(wire))
            if kind != "commit":
                (self.root / "LICENSE").write_bytes(b"paired forged source")
            try:
                with self.assertRaises(check.InputError): self.inspect()
            finally:
                path.write_bytes(saved)
                path.chmod(original_mode)
                (self.root / "LICENSE").write_bytes(FILES["LICENSE"])

    def test_missing_ambiguous_and_bounded_git_cache_selection_refuse(self):
        home = self.root / "cargo"
        candidate = home / "git/checkouts/public/first"
        candidate.parent.mkdir(parents=True)
        candidate.mkdir()
        with self.assertRaises(check.InputError): qualify.select_checkouts(home, [])
        shutil.copytree(self.root / ".git", candidate / ".git")
        package = dict(kind="git-record", source="git+https://github.com/example/public?rev=" + self.commit + "#" + self.commit)
        self.assertEqual(qualify.select_checkouts(home, [package]), {self.commit: candidate})
        second = candidate.with_name("second")
        shutil.copytree(candidate, second)
        with self.assertRaises(check.InputError): qualify.select_checkouts(home, [package])
        shutil.rmtree(second)
        shutil.rmtree(candidate / ".git")
        candidate.rmdir()
        with patch.object(check.inputs, "MAX_PACKAGES", 0), self.assertRaises(check.InputError):
            qualify.select_checkouts(home, [])


class GoContentTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="synthetic-go-content-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.module, self.version = "example.invalid/demo", "v1.0.0"
        self.prefix = self.module + "@" + self.version + "/"
        self.archive = self.root / "cache/download" / self.module / "@v/v1.0.0.zip"
        self.archive.parent.mkdir(parents=True)
        self.install = self.root / (self.module + "@" + self.version)
        install(self.install, GO_FILES)
        self.write_zip([(self.prefix + n, raw) for n, raw in GO_FILES.items()])
        self.archive.with_suffix(".mod").write_bytes(MOD)
        self.records = dict(declared_requirements=[dict(module=self.module, version=self.version)], checksum_records=[
            dict(module=self.module, version=self.version, kind="module-content", recorded_h1=expected_h1(GO_FILES, self.prefix)),
            dict(module=self.module, version=self.version, kind="go.mod", recorded_h1=expected_h1({"go.mod": MOD}, ""))])

    def write_zip(self, entries, compression=zipfile.ZIP_DEFLATED):
        with zipfile.ZipFile(self.archive, "w", compression=compression) as archive:
            for name, raw in entries:
                archive.writestr(name, raw)

    def inspect(self):
        return check.go_contents(self.root, self.records)

    def test_fixed_module_and_mod_sums_bind_zip_and_installed_content(self):
        report = self.inspect()[0]
        self.assertEqual(report["module_h1"], self.records["checksum_records"][0]["recorded_h1"])
        self.assertEqual(report["go_mod_h1"], self.records["checksum_records"][1]["recorded_h1"])
        self.assertEqual(report["license_notice_named_files"], 1)
        self.assertNotIn(str(self.root), json.dumps(report))

    def test_h1_ignores_zip_order_compression_and_timestamps_but_binds_names(self):
        before = self.inspect()
        self.write_zip([(self.prefix + n, raw) for n, raw in reversed(list(GO_FILES.items()))], zipfile.ZIP_STORED)
        self.assertEqual(self.inspect(), before)
        self.write_zip([(self.prefix + "other.go" if n == "public.go" else self.prefix + n, raw)
                        for n, raw in GO_FILES.items()])
        with self.assertRaises(check.InputError): self.inspect()

    def test_local_ziphash_and_paired_changed_tree_cannot_replace_fixed_h1(self):
        changed = dict(GO_FILES, **{"public.go": b"changed"})
        self.write_zip([(self.prefix + n, raw) for n, raw in changed.items()])
        install(self.install, changed)
        self.archive.with_suffix(".ziphash").write_text(expected_h1(changed, self.prefix))
        with self.assertRaises(check.InputError): self.inspect()

    def test_changed_missing_extra_and_nonregular_installed_go_sources_refuse(self):
        target = self.install / "public.go"
        for action in ("changed", "missing", "extra", "symlink"):
            if action == "changed": target.write_bytes(b"changed")
            if action == "missing": target.unlink()
            if action == "extra": (self.install / "added.go").touch()
            if action == "symlink": target.unlink(); target.symlink_to("LICENSE")
            with self.assertRaises(check.InputError): self.inspect()
            if target.exists() or target.is_symlink(): target.unlink()
            target.write_bytes(GO_FILES["public.go"])
            (self.install / "added.go").unlink(missing_ok=True)

    def test_mod_definition_is_separately_bound_and_must_be_present(self):
        path = self.archive.with_suffix(".mod")
        path.write_bytes(MOD + b"changed")
        with self.assertRaises(check.InputError): self.inspect()
        path.unlink()
        with self.assertRaises(OSError): self.inspect()

    def test_zip_prefix_path_alias_duplicate_directory_and_link_entries_refuse(self):
        for name in ("wrong@v1.0.0/a", self.prefix + "../a", self.prefix + "a\\b",
                     self.prefix + "a//b", self.prefix + "dir/", self.prefix + ".git/config"):
            self.write_zip([(name, b"synthetic")])
            with self.assertRaises(check.InputError): check.go_zip(self.archive, self.prefix)
        self.write_zip([(self.prefix + "a", b"a"), (self.prefix + "A", b"alias")])
        with self.assertRaises(check.InputError): check.go_zip(self.archive, self.prefix)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            self.write_zip([(self.prefix + "a", b"a"), (self.prefix + "a", b"duplicate")])
        with self.assertRaises(check.InputError): check.go_zip(self.archive, self.prefix)
        link = zipfile.ZipInfo(self.prefix + "link"); link.create_system = 3; link.external_attr = 0o120777 << 16
        self.write_zip([(link, b"LICENSE")])
        with self.assertRaises(check.InputError): check.go_zip(self.archive, self.prefix)

    def test_zip_file_count_payload_and_package_bounds_refuse(self):
        for field, limit in (("MAX_FILE_BYTES", 2), ("MAX_PACKAGE_BYTES", 3), ("MAX_ENTRIES", 1), ("MAX_TOTAL_BYTES", 2)):
            with patch.object(check, field, limit), self.assertRaises(check.InputError): self.inspect()
        with patch.object(check.inputs, "MAX_ARCHIVE_BYTES", 4), self.assertRaises(check.InputError): self.inspect()

    def test_missing_zip_and_cache_parent_symlink_refuse(self):
        self.archive.unlink()
        with self.assertRaises(OSError): self.inspect()
        self.write_zip([(self.prefix + n, raw) for n, raw in GO_FILES.items()])
        parent = self.archive.parent
        moved = parent.with_name("saved"); parent.rename(moved); parent.symlink_to(moved.name)
        with self.assertRaises(check.InputError): self.inspect()

    def test_truncated_and_corrupt_zip_payloads_refuse(self):
        original = self.archive.read_bytes()
        self.archive.write_bytes(original[:20])
        with self.assertRaises(zipfile.BadZipFile): self.inspect()
        self.write_zip([(self.prefix + n, raw) for n, raw in GO_FILES.items()], zipfile.ZIP_STORED)
        raw = self.archive.read_bytes().replace(GO_FILES["public.go"], b"x" * len(GO_FILES["public.go"]), 1)
        self.archive.write_bytes(raw)
        with self.assertRaises(zipfile.BadZipFile): self.inspect()

    def test_cache_ascii_uppercase_escape_and_unsupported_identity_refuse(self):
        self.assertEqual(check.escaped("example.invalid/Demo"), "example.invalid/!demo")
        for name in ("../demo", "example.invalid/!demo", "example.invalid/demo\n"):
            with self.assertRaises(check.InputError): check.escaped(name)


class ContentEntryTests(unittest.TestCase):
    def setUp(self):
        self.fixture = source_fixtures.BuildInputInspectionTests("runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root
        self.cache = self.root / "empty-go-cache"; self.cache.mkdir()

    def test_selected_source_pin_cannot_be_chosen_from_installed_metadata(self):
        with self.assertRaises(check.InputError):
            check.inspect_go(self.root, self.fixture.commit, "f" * 64, self.cache, "qualification-go")
        with self.assertRaises(check.InputError):
            check.inspect_go(self.root, self.fixture.commit, self.fixture.manifest_sha, self.cache, "other-module")

    def test_complete_go_profile_and_cli_report_only_historical_content_agreement(self):
        sums = ("example.invalid/demo v1.0.0 " + expected_h1(GO_FILES, "example.invalid/demo@v1.0.0/")
                + "\nexample.invalid/demo v1.0.0/go.mod " + expected_h1({"go.mod": MOD}, "") + "\n").encode("ascii")
        files = {name: ("100644", (self.root / name).read_bytes()) for name in check.inputs.SOURCE_PATHS}
        for name in check.GO_MODULES:
            files[name + "/go.sum"] = ("100644", sums)
            (self.root / (name + "/go.sum")).write_bytes(sums)
            self.fixture.fixture.index(name + "/go.sum", sums)
        self.fixture.commit = self.fixture.fixture.commit(files)
        tree, inventory, _ = check.inputs.source._inventory(self.root, self.fixture.commit)
        self.fixture.write_manifest(dict(schema="ptlc-witness-review-subject-v1", commit=self.fixture.commit,
            tree=tree, file_count=len(inventory), files=[dict(row, observation_status="added") for row in inventory]))
        installed = self.cache / "example.invalid/demo@v1.0.0"
        install(installed, GO_FILES)
        base = self.cache / "cache/download/example.invalid/demo/@v"
        base.mkdir(parents=True)
        (base / "v1.0.0.mod").write_bytes(MOD)
        with zipfile.ZipFile(base / "v1.0.0.zip", "w") as archive:
            for name, raw in GO_FILES.items(): archive.writestr("example.invalid/demo@v1.0.0/" + name, raw)
        result = subprocess.run([sys.executable, "-B", str(ROOT / "scripts/check_dependency_contents.py"),
            "--root", str(self.root), "--expect-commit", self.fixture.commit,
            "--expect-manifest-sha256", self.fixture.manifest_sha, "--profile", "go",
            "--go-cache", str(self.cache), "--go-module", "qualification-go"], capture_output=True, check=False, timeout=15)
        self.assertEqual((result.returncode, result.stderr), (0, b""))
        report = json.loads(result.stdout)
        self.assertEqual(result.stdout, check.encoded(report))
        self.assertEqual(len(report["modules"]), 1)
        self.assertEqual(report["boundary"]["application_and_core"], "NO-GO")
        self.assertEqual(report["boundary"]["source_to_executable_provenance"], "NOT VERIFIED")
        self.assertEqual(report["boundary"]["independent_review"], "NOT ASSESSED")
        self.assertNotIn(str(self.root), result.stdout.decode("ascii"))

    def test_entry_source_worktree_and_index_changes_refuse_before_cache_use(self):
        target = self.root / "qualification-go/go.sum"
        target.write_bytes(b"self-selected sum")
        with self.assertRaises(check.InputError):
            check.inspect_go(self.root, self.fixture.commit, self.fixture.manifest_sha, self.cache, "qualification-go")
        target.write_bytes(source_fixtures.SUM)
        self.fixture.fixture.index("qualification-go/go.sum", b"self-selected index")
        with self.assertRaises(check.InputError):
            check.inspect_go(self.root, self.fixture.commit, self.fixture.manifest_sha, self.cache, "qualification-go")

    def test_cli_missing_pins_unavailable_inputs_mixed_profiles_and_loops_are_sanitized(self):
        common = [sys.executable, "-B", str(ROOT / "scripts/check_dependency_contents.py"), "--root", str(self.root)]
        pins = ["--expect-commit", self.fixture.commit, "--expect-manifest-sha256", self.fixture.manifest_sha]
        loop = self.root / "loop"; loop.symlink_to(loop.name)
        variants = [[], pins + ["--profile", "go", "--go-module", "qualification-go", "--go-cache", str(self.cache)],
                    pins + ["--profile", "cargo", "--go-cache", str(self.cache)],
                    pins + ["--profile", "go", "--go-module", "qualification-go", "--go-cache", str(loop)]]
        for args in variants:
            result = subprocess.run(common + args, capture_output=True, check=False, timeout=15)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, b"")
            self.assertEqual(result.stderr, b"FAIL: offline dependency content inspection rejected\n")

    def test_companion_refuses_empty_ambiguous_and_linked_registry_namespaces(self):
        with self.assertRaises(check.InputError): qualify.one_directory(self.cache)
        (self.cache / "one").mkdir()
        self.assertEqual(qualify.one_directory(self.cache).name, "one")
        (self.cache / "two").mkdir()
        with self.assertRaises(check.InputError): qualify.one_directory(self.cache)
        (self.cache / "two").rmdir(); (self.cache / "one").rmdir(); (self.cache / "one").symlink_to(self.root)
        with self.assertRaises(check.InputError): qualify.one_directory(self.cache)

    def test_companion_missing_mixed_and_looped_profiles_emit_no_partial_report(self):
        loop = self.root / "loop"; loop.symlink_to(loop.name)
        for args in ([], ["--cargo-home", str(loop)],
                     ["--cargo-home", str(self.cache), "--go-cache", str(self.cache), "--go-module", "qualification-go"]):
            result = subprocess.run([sys.executable, "-B", str(ROOT / "scripts/qualify_dependency_contents.py")]+args,
                                    capture_output=True, check=False, timeout=15)
            self.assertEqual((result.returncode, result.stdout), (1, b""))
            self.assertEqual(result.stderr, b"FAIL: offline dependency content qualification rejected\n")


if __name__ == "__main__":
    unittest.main()
