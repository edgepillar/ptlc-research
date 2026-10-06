#!/usr/bin/env python3
"""Compare selected offline dependency contents, without executing dependencies.

Only fixed lock/checksum records supply expectations. Cache markers and current
working trees cannot select replacement expectations. This is content evidence,
not source ownership, build provenance, license assessment or application safety.
"""

import base64
from contextlib import contextmanager
import gzip
import hashlib
import io
import os
from pathlib import Path
import posixpath
import stat
import sys
import tarfile
import zipfile
import zlib

if __package__:
    from . import check_build_inputs as inputs
else:
    import check_build_inputs as inputs


InputError = inputs.InputError
encoded = inputs.encoded
MAX_ENTRIES = 8192
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_PACKAGE_BYTES = 64 * 1024 * 1024
MAX_TAR_BYTES = 80 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024
GO_MODULES = ("qualification-go", "qualification-bitcoin-go")
GENERATED = {".cargo-ok", ".cargo-checksum.json"}


def safe_name(name):
    # A deliberately narrow portable path profile for the selected caches.
    if (type(name) is not str or not name or not name.isascii() or len(name) > 512
            or any(ord(c) < 32 or ord(c) == 127 for c in name)
            or any(c in name for c in "\\:") or name.startswith("/")
            or any(p in {"", ".", "..", ".git"} or len(p) > 255 for p in name.split("/"))):
        raise InputError("unsafe dependency member")
    return name


def directory(path):
    try:
        mode = path.lstat().st_mode
    except OSError:
        raise InputError("owned directory unavailable") from None
    if not stat.S_ISDIR(mode):
        raise InputError("owned directory required")


@contextmanager
def regular(path, bound):
    """Hold one descriptor; stability checks assume an owned, quiescent cache."""
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or not 0 <= before.st_size <= bound:
        raise InputError("bounded regular dependency input required")
    with path.open("rb") as handle:
        opened = os.fstat(handle.fileno())
        if (opened.st_dev, opened.st_ino, opened.st_size) != (
                before.st_dev, before.st_ino, before.st_size):
            raise InputError("dependency input changed")
        yield handle
        after = os.fstat(handle.fileno())
        current = path.lstat()
        fields = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if fields(opened) != fields(after) or fields(after) != fields(current):
            raise InputError("dependency input changed")


def digest_stream(handle, bound):
    total, digest = 0, hashlib.sha256()
    while True:
        data = handle.read(min(1024 * 1024, bound + 1 - total))
        if not data:
            return dict(bytes=total, sha256=digest.hexdigest(), kind="regular")
        total += len(data)
        if total > bound:
            raise InputError("dependency content exceeds bound")
        digest.update(data)


def parents(names):
    return {name.rsplit("/", i)[0] for name in names for i in range(1, name.count("/") + 1)}


def add_name(seen, name):
    safe_name(name)
    if name.lower() in seen or len(seen) >= MAX_ENTRIES:
        raise InputError("duplicate, alias or excessive dependency members")
    seen.add(name.lower())


def summarize(rows):
    if not rows or len(rows) > MAX_ENTRIES or sum(r["bytes"] for r in rows.values()) > MAX_PACKAGE_BYTES:
        raise InputError("empty or excessive dependency content")
    return dict(files=len(rows), bytes=sum(r["bytes"] for r in rows.values()),
                inventory_sha256=hashlib.sha256(encoded(rows)).hexdigest(),
                license_notice_named_files=sum(
                    name.rsplit("/", 1)[-1].upper().startswith(("LICENSE", "COPYING", "NOTICE"))
                    for name in rows),
                tracked_symlinks=sum(r["kind"] == "symlink" for r in rows.values()))


def tree_rows(root, expected, metadata=None, git_metadata=False):
    """Refuse extras, omissions and type changes; never follow source symlinks."""
    directory(root)
    metadata = metadata or {}
    wanted_dirs, seen, rows, found_metadata = parents(expected), set(), {}, {}
    pending, count = [(root, "")], 0
    while pending:
        path, prefix = pending.pop()
        with os.scandir(path) as entries:
            for entry in entries:
                count += 1
                if count > MAX_ENTRIES:
                    raise InputError("installed entry count exceeds bound")
                name = prefix + entry.name
                if name == ".git" and git_metadata:
                    if not entry.is_dir(follow_symlinks=False):
                        raise InputError("owned Git metadata directory required")
                    continue
                add_name(seen, name)
                mode = entry.stat(follow_symlinks=False).st_mode
                if stat.S_ISDIR(mode):
                    if name not in wanted_dirs:
                        raise InputError("extra installed directory")
                    pending.append((Path(entry.path), name + "/"))
                elif name in metadata:
                    with regular(Path(entry.path), inputs.source.MAX_MANIFEST_BYTES) as handle:
                        found_metadata[name] = handle.read(inputs.source.MAX_MANIFEST_BYTES + 1)
                elif name in expected and expected[name]["kind"] == "symlink":
                    if not stat.S_ISLNK(mode):
                        raise InputError("tracked symlink type differs")
                    raw = os.readlink(os.fsencode(entry.path))
                    if len(raw) > 512:
                        raise InputError("tracked link target exceeds bound")
                    rows[name] = dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), kind="symlink")
                elif name in expected:
                    with regular(Path(entry.path), MAX_FILE_BYTES) as handle:
                        rows[name] = digest_stream(handle, MAX_FILE_BYTES)
                else:
                    raise InputError("extra installed input")
    if rows != expected:
        raise InputError("installed dependency contents differ")
    summarize(rows)
    return found_metadata


def cargo_archive(path, checksum, prefix):
    inputs.source._hex(checksum, 64)
    safe_name(prefix)
    with regular(path, inputs.MAX_ARCHIVE_BYTES) as handle:
        archive = digest_stream(handle, inputs.MAX_ARCHIVE_BYTES)
        if archive["sha256"] != checksum:
            raise InputError("archive differs from selected lock checksum")
        handle.seek(0)
        # Bound the entire decoded TAR before its header parser sees extensions.
        with gzip.GzipFile(fileobj=handle, mode="rb") as compressed:
            raw = compressed.read(MAX_TAR_BYTES + 1)
            if len(raw) > MAX_TAR_BYTES:
                raise InputError("decoded archive exceeds bound")
        rows, directories, seen, total = {}, set(), set(), 0
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as contents:
            for member in contents:
                full = member.name[:-1] if member.isdir() and member.name.endswith("/") else member.name
                if full == prefix and member.isdir():
                    add_name(seen, full)
                    if member.size != 0:
                        raise InputError("directory payload refused")
                    continue
                if not full.startswith(prefix + "/"):
                    raise InputError("archive prefix differs")
                name = full[len(prefix) + 1:]
                add_name(seen, name)
                if member.isdir() and member.size == 0:
                    directories.add(name)
                    continue
                if not member.isfile() or member.sparse is not None or not 0 <= member.size <= MAX_FILE_BYTES:
                    raise InputError("unsupported archive member type or size")
                total += member.size
                if total > MAX_PACKAGE_BYTES:
                    raise InputError("package payload exceeds bound")
                with contents.extractfile(member) as body:
                    row = digest_stream(body, MAX_FILE_BYTES)
                if row["bytes"] != member.size:
                    raise InputError("archive member truncated")
                rows[name] = row
        if directories - parents(rows) or GENERATED & set(rows):
            raise InputError("unused directories or reserved source metadata")
        summarize(rows)
    return archive, rows


def registry_contents(cache, installed, packages):
    directory(cache)
    directory(installed)
    reports, compressed_total, payload_total = [], 0, 0
    for package in packages:
        if package["kind"] != "registry-archive":
            continue
        prefix = package["name"] + "-" + package["version"]
        archive, rows = cargo_archive(cache / (prefix + ".crate"), package["checksum"], prefix)
        metadata = tree_rows(installed / prefix, rows, {name: True for name in GENERATED})
        if metadata.get(".cargo-ok", b"") not in (b"", b'{"v":1}'):
            raise InputError("unsupported Cargo marker")
        if ".cargo-checksum.json" in metadata:
            value = inputs.source._json(metadata[".cargo-checksum.json"])
            if (type(value) is not dict or set(value) != {"files", "package"}
                    or value["package"] != package["checksum"]
                    or value["files"] != {n: r["sha256"] for n, r in rows.items()}):
                raise InputError("generated checksum metadata differs")
        summary = summarize(rows)
        compressed_total += archive["bytes"]
        payload_total += summary["bytes"]
        if compressed_total > inputs.MAX_ARCHIVES_BYTES or payload_total > MAX_TOTAL_BYTES:
            raise InputError("aggregate registry input exceeds bound")
        reports.append(dict(summary, name=package["name"], version=package["version"],
                            archive_sha256=archive["sha256"], archive_bytes=archive["bytes"],
                            generated_metadata=sorted(metadata), status="LOCKED ARCHIVE AND INSTALLED CONTENT MATCH"))
    if not reports:
        raise InputError("registry selection empty")
    return reports


def git_object(root, oid, kind):
    inputs.source._hex(oid, 40)
    size = int(inputs.source._git(root, "cat-file", "-s", oid))
    if not 0 <= size <= inputs.source.MAX_BLOB_BYTES:
        raise InputError("Git object exceeds bound")
    body = inputs.source._git(root, "cat-file", kind, oid)
    header = (kind + " " + str(len(body))).encode("ascii") + b"\0"
    if len(body) != size or hashlib.sha1(header + body).hexdigest() != oid:
        raise InputError("Git object bytes differ from selected identity")
    return body


def git_rows(root, commit):
    directory(root)
    inputs.source._hex(commit, 40)
    local = inputs.source._git(root, "rev-parse", "--show-toplevel").decode("utf-8").strip()
    if Path(local) != root.resolve() or inputs.source._git(root, "rev-parse", "HEAD").strip().decode("ascii") != commit:
        raise InputError("selected Git checkout identity differs")
    selected = git_object(root, commit, "commit").split(b"\n", 1)[0]
    if not selected.startswith(b"tree ") or len(selected) != 45:
        raise InputError("selected Git commit tree missing")
    tree = inputs.source._hex(selected[5:].decode("ascii"), 40)
    rows, seen, targets, total = {}, set(), {}, 0
    pending = [(tree, "")]
    while pending:
        tree_id, prefix = pending.pop()
        raw = git_object(root, tree_id, "tree")
        offset = 0
        while offset < len(raw):
            end = raw.find(b"\0", offset)
            if end < 0 or end + 21 > len(raw):
                raise InputError("truncated Git tree record")
            mode, basename = raw[offset:end].split(b" ", 1)
            name = prefix + basename.decode("ascii")
            oid = raw[end + 1:end + 21].hex()
            offset = end + 21
            # Git tree names are single components, unlike an ls-tree listing.
            if b"/" in basename:
                raise InputError("invalid Git tree component")
            add_name(seen, name)
            if mode == b"40000":
                pending.append((oid, name + "/"))
                continue
            if mode not in {b"100644", b"100755", b"120000"} or name in GENERATED:
                raise InputError("unsupported Git member")
            body = git_object(root, oid, "blob")
            total += len(body)
            if total > MAX_PACKAGE_BYTES:
                raise InputError("Git package bytes exceed bound")
            rows[name] = dict(bytes=len(body), sha256=hashlib.sha256(body).hexdigest(),
                              kind="symlink" if mode == b"120000" else "regular")
            if mode == b"120000":
                target = body.decode("ascii")
                if (not target or len(target) > 512 or target.startswith("/") or "\\" in target
                        or ":" in target or any(ord(c) < 32 or ord(c) == 127 for c in target)):
                    raise InputError("unsafe tracked link target")
                targets[name] = posixpath.normpath(posixpath.join(posixpath.dirname(name), target))
    for target in targets.values():
        safe_name(target)
        if target not in rows or rows[target]["kind"] != "regular":
            raise InputError("tracked link does not select an internal regular member")
    summarize(rows)
    return tree, rows


def git_contents(checkouts, packages):
    groups = {}
    for row in packages:
        if row["kind"] == "git-record":
            url, commit = row["source"][4:].split("?rev=")
            commit = commit.split("#")[0]
            groups.setdefault((url, commit), []).append(dict(name=row["name"], version=row["version"]))
    if type(checkouts) is not dict or set(checkouts) != {commit for _, commit in groups}:
        raise InputError("exact pinned Git checkout selection required")
    reports, total = [], 0
    for (url, commit), records in sorted(groups.items()):
        root = checkouts[commit]
        tree, rows = git_rows(root, commit)
        metadata = tree_rows(root, rows, {".cargo-ok": True}, git_metadata=True)
        if metadata.get(".cargo-ok", b"") != b"":
            raise InputError("unsupported Git Cargo marker")
        summary = summarize(rows)
        total += summary["bytes"]
        if total > MAX_TOTAL_BYTES:
            raise InputError("aggregate Git content exceeds bound")
        reports.append(dict(summary, repository=url, commit=commit, tree=tree,
                            package_records=records, generated_metadata=sorted(metadata),
                            status="PINNED GIT OBJECTS AND CHECKOUT CONTENT MATCH"))
    return reports


def h1(rows, prefix):
    """Implement the documented Hash1 content-summary format, without Go code."""
    digest = hashlib.sha256()
    for name in sorted(rows):
        safe_name(name)
        row = rows[name]
        if row["kind"] != "regular":
            raise InputError("Go content must be regular")
        digest.update((row["sha256"] + "  " + prefix + name + "\n").encode("ascii"))
    return "h1:" + base64.b64encode(digest.digest()).decode("ascii")


def escaped(name):
    safe_name(name)
    if "!" in name:
        raise InputError("unsupported Go cache identity")
    return "".join("!" + c.lower() if "A" <= c <= "Z" else c for c in name)


def go_zip(path, prefix):
    rows, seen, total = {}, set(), 0
    with regular(path, inputs.MAX_ARCHIVE_BYTES) as handle, zipfile.ZipFile(handle) as archive:
        if not 0 < len(archive.infolist()) <= MAX_ENTRIES:
            raise InputError("Go ZIP member count exceeds bound")
        for member in archive.infolist():
            if not member.filename.startswith(prefix):
                raise InputError("Go ZIP prefix differs")
            name = member.filename[len(prefix):]
            add_name(seen, name)
            mode = stat.S_IFMT(member.external_attr >> 16)
            if (member.is_dir() or mode not in {0, stat.S_IFREG} or member.flag_bits & 1
                    or member.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
                    or not 0 <= member.file_size <= MAX_FILE_BYTES):
                raise InputError("unsupported Go ZIP member")
            total += member.file_size
            if total > MAX_PACKAGE_BYTES:
                raise InputError("Go ZIP payload exceeds bound")
            with archive.open(member) as body:
                row = digest_stream(body, MAX_FILE_BYTES)
            if row["bytes"] != member.file_size:
                raise InputError("Go ZIP member truncated")
            rows[name] = row
        summarize(rows)
    return rows


def go_contents(cache, records):
    directory(cache)
    sums = {(r["module"], r["version"], r["kind"]): r["recorded_h1"] for r in records["checksum_records"]}
    reports, total = [], 0
    for selected in records["declared_requirements"]:
        module, version = selected["module"], selected["version"]
        logical = module + "@" + version
        storage, storage_version = escaped(module), escaped(version)
        archive_base = cache / "cache/download" / storage / "@v" / storage_version
        # Require each selected parent to be a real directory, including cache
        # namespace components. No adjacent .ziphash supplies an expectation.
        for relative in ("cache", "cache/download", "cache/download/" + storage,
                         "cache/download/" + storage + "/@v"):
            path = cache
            for part in relative.split("/"):
                path = path / part
                directory(path)
        rows = go_zip(archive_base.with_name(storage_version + ".zip"), logical + "/")
        measured = h1(rows, logical + "/")
        if measured != sums[(module, version, "module-content")]:
            raise InputError("Go ZIP content differs from selected sum")
        installed = cache
        for part in (storage + "@" + storage_version).split("/"):
            installed = installed / part
            directory(installed)
        tree_rows(installed, rows)
        with regular(archive_base.with_name(storage_version + ".mod"), MAX_FILE_BYTES) as handle:
            mod = digest_stream(handle, MAX_FILE_BYTES)
        mod_h1 = h1({"go.mod": mod}, "")
        if mod_h1 != sums[(module, version, "go.mod")]:
            raise InputError("Go module definition differs from selected sum")
        summary = summarize(rows)
        total += summary["bytes"] + mod["bytes"]
        if total > MAX_TOTAL_BYTES:
            raise InputError("aggregate Go content exceeds bound")
        reports.append(dict(summary, module=module, version=version, module_h1=measured,
                            go_mod_h1=mod_h1, go_mod_bytes=mod["bytes"],
                            status="SELECTED GO SUM, ZIP AND INSTALLED CONTENT MATCH"))
    return reports


def report_base(commit, tree, manifest_sha256, source_records):
    return dict(schema="ptlc-offline-dependency-content-evidence-v1", source_commit=commit,
                source_tree=tree, witness_manifest_sha256=manifest_sha256, source_inputs=source_records,
                outcome="SELECTED CONTENTS MATCH; NOT ASSESSED",
                boundary=dict(expectations="FIXED SOURCE RECORDS; CACHE METADATA IS NOT AUTHORITY",
                    cache="OWNED QUIESCENT CACHE; NO HOSTILE FILESYSTEM SNAPSHOT CLAIM",
                    git_ownership="NOT AUTHENTICATED", minimal_compiled_closure="NOT DETERMINED",
                    build_execution="NOT PERFORMED BY THIS CHECK", source_to_executable_provenance="NOT VERIFIED",
                    runtime_environment="NOT ATTESTED", license_compliance="NOT ASSESSED",
                    reproducible_or_portable_build="NOT ESTABLISHED", independent_review="NOT ASSESSED",
                    application_and_core="NO-GO"))


def inspect_cargo(root, commit, manifest_sha256, cache, installed, checkouts):
    tree, source_records, bodies = inputs.selected_source(root, commit, manifest_sha256)
    packages = inputs.cargo_records(bodies["qualification/Cargo.lock"])
    report = report_base(commit, tree, manifest_sha256, source_records)
    report.update(profile="cargo", registry=registry_contents(cache, installed, packages),
                  git=git_contents(checkouts, packages), local_records="SOURCE IDENTITY ONLY; NOT A COMPILED CLOSURE",
                  go_contents="NOT MEASURED BY THIS PROFILE")
    return report


def inspect_go(root, commit, manifest_sha256, cache, module):
    if module not in GO_MODULES:
        raise InputError("one fixed Go qualification module required")
    tree, source_records, bodies = inputs.selected_source(root, commit, manifest_sha256)
    records = inputs.go_records(bodies[module + "/go.mod"], bodies[module + "/go.sum"])
    report = report_base(commit, tree, manifest_sha256, source_records)
    report.update(profile="go", qualification_module=module, modules=go_contents(cache, records),
                  checksum_records=len(records["checksum_records"]),
                  unmeasured_history_records=len(records["checksum_records"]) - 2 * len(records["declared_requirements"]),
                  checksum_history="OTHER CHECKSUM HISTORY NOT MEASURED; RESOLVED CLOSURE NOT DETERMINED",
                  cargo_contents="NOT MEASURED BY THIS PROFILE")
    return report


def main():
    try:
        parser = inputs.source._Parser(description=__doc__)
        parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
        parser.add_argument("--expect-commit", required=True)
        parser.add_argument("--expect-manifest-sha256", required=True)
        parser.add_argument("--profile", choices=("cargo", "go"), required=True)
        parser.add_argument("--registry-cache", type=Path)
        parser.add_argument("--registry-src", type=Path)
        parser.add_argument("--git-checkout", nargs=2, action="append", default=[])
        parser.add_argument("--go-cache", type=Path)
        parser.add_argument("--go-module", choices=GO_MODULES)
        args = parser.parse_args()
        if args.profile == "cargo":
            if args.registry_cache is None or args.registry_src is None or args.go_cache or args.go_module:
                raise InputError("exact Cargo profile selection required")
            checkouts = {pin: Path(path) for pin, path in args.git_checkout}
            if len(checkouts) != len(args.git_checkout):
                raise InputError("duplicate Git checkout selection")
            report = inspect_cargo(args.root.resolve(), args.expect_commit, args.expect_manifest_sha256,
                                   args.registry_cache, args.registry_src, checkouts)
        else:
            if (args.go_cache is None or args.go_module is None or args.registry_cache
                    or args.registry_src or args.git_checkout):
                raise InputError("exact Go profile selection required")
            report = inspect_go(args.root.resolve(), args.expect_commit, args.expect_manifest_sha256,
                                args.go_cache, args.go_module)
        sys.stdout.buffer.write(encoded(report))
        return 0
    except (InputError, OSError, ValueError, TypeError, KeyError, UnicodeError, RuntimeError,
            EOFError, tarfile.TarError, zipfile.BadZipFile, zlib.error):
        print("FAIL: offline dependency content inspection rejected", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
