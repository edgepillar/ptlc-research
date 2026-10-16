#!/usr/bin/env python3
"""Build one pinned SQLite CLI from an explicitly supplied offline source archive.

Output is a new caller-owned qualification directory. Original command streams
remain there; only the separate sanitized engine record is shareable by default.
No archive download, directory adoption, cleanup, service or application is added.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys
import threading
import time
import zipfile

SCHEMA = "ptlc-nom-sqlite-engine-build-v1"
VERSION = "3.54.0"
SOURCE_ID = "2026-10-09 15:46:58 be8d059e9a49089ab2dce5ed26dd87aaf598fdc5fbe0b107c0dd758464bcd5e3"
SOURCE_URL = "https://www.sqlite.org/2026/sqlite-amalgamation-3540000.zip"
ARCHIVE_BYTES = 2990479
ARCHIVE_SHA256 = "68e913b0fe8ec6b4e5f391c594a28872884e80d6cd042a1e50c957be46b5aa4d"
ARCHIVE_SHA3 = "7b670a62fdfbd672b75fef004cb703c8a3e87d3a5cc7d675b4a08337004a2d93"
C_SHA3 = "8efd453d08a7cfc4c79de5923153036cdc4dcaa254d4f1e617be6a2a98828f9e"
SOURCE_FILES = {
    "shell.c": (1269586, "c444573b69d70516e64df5ab38911f814ed5509020c92cc899bf1f6ffa582e8f"),
    "sqlite3.c": (9580800, "2da161e310ef0aba3465f22a4d12b8a43723236f0942fa76e8aac523c3317243"),
    "sqlite3.h": (695737, "cd20a2877bc82b94e36c1093b727dd87cfa3c1d581aac6e240925535cbd90166"),
    "sqlite3ext.h": (39547, "48963abfefb41ac329ef9d706acb5eadba952a99a748285c9ded6b5e0942721b"),
}
FLAGS = ("-O0", "-g0", "-DSQLITE_THREADSAFE=1", "-DSQLITE_OMIT_LOAD_EXTENSION=1",
         "-DSQLITE_DQS=0", "-DSQLITE_MAX_MMAP_SIZE=0")
LICENSE_SCOPE = "SQLITE DELIVERABLE CODE PUBLIC DOMAIN; NO ENGINE SOURCE VENDORED"
BUILD_SCOPE = "ONE LOCAL TRUSTED COMPILER AND PLATFORM; NOT INDEPENDENT BUILD OR SERVICE QUALIFICATION"


class BuildNotQualified(ValueError):
    """A newly owned build failed; the original output remains associated with it."""

    def __init__(self, record):
        super().__init__("selected new engine build did not qualify")
        self.record = record


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _write(path, raw):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _run(argv, cwd, originals, label, *, environment, timeout, stdout_cap=64*1024, stderr_cap=1024**2):
    """Retain selected command streams with explicit caps and honest launch state."""
    streams = {"stdout": bytearray(), "stderr": bytearray()}
    stop = threading.Event()
    errors = []
    process = None
    result = dict(actual_exit=None, output_complete=False, process_started=False, timed_out=False)

    def read(name, pipe, maximum):
        try:
            while True:
                block = pipe.read1(65536)
                if not block:
                    break
                available = maximum - len(streams[name])
                streams[name].extend(block[:available])
                if len(block) > available:
                    errors.append(name + "_CAP")
                    stop.set()
                    break
        except BaseException as error:
            errors.append(type(error).__name__)
            stop.set()
        finally:
            pipe.close()

    try:
        process = subprocess.Popen(argv, cwd=cwd, env=environment, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
        result["process_started"] = True
        readers = [threading.Thread(target=read, args=("stdout", process.stdout, stdout_cap)),
                   threading.Thread(target=read, args=("stderr", process.stderr, stderr_cap))]
        for reader in readers:
            reader.start()
        deadline = time.monotonic() + timeout
        while process.poll() is None:
            if stop.wait(.01) or time.monotonic() >= deadline:
                result["timed_out"] = time.monotonic() >= deadline
                process.kill()
                break
        process.wait(timeout=5)
        for reader in readers:
            reader.join(timeout=5)
        if any(reader.is_alive() for reader in readers):
            errors.append("STREAM_JOIN_UNKNOWN")
        result["actual_exit"] = process.returncode
        result["output_complete"] = not errors and not result["timed_out"]
    except OSError as error:
        errors.append("LAUNCH_" + type(error).__name__)
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=5)
            result["actual_exit"] = process.returncode
        result["capture_errors"] = errors
        for name, raw in streams.items():
            raw = bytes(raw)
            _write(originals / (label + "." + name), raw)
            result[name] = dict(bytes=len(raw), sha256=_sha(raw))
        _write(originals / (label + ".json"), _json(result))
    if result["actual_exit"] != 0 or not result["output_complete"]:
        raise ValueError("selected engine command did not qualify")
    return bytes(streams["stdout"]), result


def build(source_archive, output_directory, c_compiler):
    if not __debug__:
        raise ValueError("unoptimized qualification runtime required")
    archive = Path(source_archive)
    info = archive.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size != ARCHIVE_BYTES:
        raise ValueError("exact selected SQLite source archive required")
    raw = archive.read_bytes()
    if _sha(raw) != ARCHIVE_SHA256 or hashlib.sha3_256(raw).hexdigest() != ARCHIVE_SHA3:
        raise ValueError("selected SQLite archive digest refused")
    if sys.platform not in ("darwin", "linux") or platform.machine() not in ("arm64", "aarch64", "x86_64"):
        raise ValueError("selected POSIX engine build platform unavailable")
    root = Path(output_directory).absolute()
    if root.exists() or root.is_symlink():
        raise ValueError("a new exclusive engine output is required")
    root.mkdir(mode=0o700)
    source, originals, temporary = root / "source", root / "originals", root / "temporary"
    for path in (source, originals, temporary):
        path.mkdir(mode=0o700)
    environment = dict(PATH="/usr/bin:/bin", LC_ALL="C", TMPDIR=str(temporary))
    record = dict(schema=SCHEMA, outcome="NOT_QUALIFIED", version=VERSION, source_id=SOURCE_ID,
        source_url=SOURCE_URL, archive_bytes=ARCHIVE_BYTES, archive_sha256=ARCHIVE_SHA256,
        archive_sha3_256=ARCHIVE_SHA3, sqlite3_c_sha3_256=C_SHA3, build_flags=list(FLAGS),
        license=LICENSE_SCOPE, source_files={
            name: dict(bytes=value[0], sha256=value[1]) for name, value in SOURCE_FILES.items()},
        platform=sys.platform, architecture=platform.machine(),
        scope=BUILD_SCOPE,
        application="NO-GO", core="NO-GO", recovery_action="NONE", service_gates_unfilled=7)
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as selected:
            members = selected.infolist()
            expected = {"sqlite-amalgamation-3540000/" + name for name in SOURCE_FILES}
            if (len(members) != 5 or {m.filename for m in members if not m.is_dir()} != expected
                    or sum(m.file_size for m in members) != 11585670 or selected.testzip() is not None):
                raise ValueError("selected source archive layout refused")
            for name, (size, pin) in SOURCE_FILES.items():
                value = selected.read("sqlite-amalgamation-3540000/" + name)
                if len(value) != size or _sha(value) != pin:
                    raise ValueError("selected engine source file refused")
                _write(source / name, value)
        if hashlib.sha3_256((source / "sqlite3.c").read_bytes()).hexdigest() != C_SHA3:
            raise ValueError("selected amalgamation digest refused")
        selected_compiler = shutil.which(c_compiler)
        if selected_compiler is None:
            raise ValueError("explicit selected C compiler unavailable")
        compiler = Path(selected_compiler).resolve()
        record["compiler_executable_sha256"] = _sha(compiler.read_bytes())
        arguments = [str(compiler), *FLAGS]
        if sys.platform == "darwin":
            sdk, _ = _run(["/usr/bin/xcrun", "--show-sdk-path"], source, originals, "sdk-path",
                environment=environment, timeout=30)
            sdk_version, _ = _run(["/usr/bin/xcrun", "--show-sdk-version"], source, originals, "sdk-version",
                environment=environment, timeout=30)
            sdk = sdk.decode("utf-8").strip()
            sdk_version = sdk_version.decode("ascii").strip()
            if not sdk or not all(part.isdigit() for part in sdk_version.split(".")):
                raise ValueError("selected SDK description refused")
            arguments[1:1] = ["-isysroot", sdk]
            environment["SDKROOT"] = sdk
            record["sdk_version"] = sdk_version
            record["build_flags"] = ["-isysroot SELECTED_SDK", *FLAGS]
        arguments += ["shell.c", "sqlite3.c", "-lm", "-o", "sqlite3"]
        _, compile_result = _run(arguments, source, originals, "compile", environment=environment, timeout=900)
        record["compile_actual_exit"] = compile_result["actual_exit"]
        record["compile_output_complete"] = compile_result["output_complete"]
        generated = source / "sqlite3"
        payload = generated.read_bytes()
        if not 0 < len(payload) <= 8 * 1024**2:
            raise ValueError("selected engine build size refused")
        binary = root / "sqlite3"
        generated.rename(binary)
        binary.chmod(0o700)
        query = "SELECT sqlite_version(); SELECT sqlite_source_id(); PRAGMA compile_options;"
        probe, probe_result = _run([str(binary), "-init", "/dev/null", "-batch", "-bail", "-noheader", "-list", ":memory:", query],
            source, originals, "identity-probe", environment=environment, timeout=30)
        lines = probe.decode("ascii").splitlines()
        if (lines[:2] != [VERSION, SOURCE_ID]
                or not {"THREADSAFE=1", "OMIT_LOAD_EXTENSION", "DQS=0", "MAX_MMAP_SIZE=0"} <= set(lines[2:])):
            raise ValueError("selected native engine identity refused")
        record.update(outcome="BUILT_AND_IDENTITY_PROBED", binary_sha256=_sha(payload), binary_bytes=len(payload),
            compile_options=lines[2:], probe_actual_exit=probe_result["actual_exit"],
            probe_output_complete=probe_result["output_complete"])
    except BaseException as error:
        record["failure_class"] = type(error).__name__
        record["original_build_output"] = "RETAINED IN THE EXPLICIT PRIVATE OUTPUT; NOT SANITIZED OR RECLASSIFIED"
        _write(root / "engine.json", _json(record))
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise
        raise BuildNotQualified(record) from None
    _write(root / "engine.json", _json(record))
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-archive", type=Path, required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--c-compiler", required=True)
    parser.add_argument("--ci-transcript", action="store_true",
        help="Include only sharing-checked original compile/probe streams in hosted CI output")
    args = parser.parse_args()
    owned_output = False
    try:
        record = build(args.source_archive, args.output_directory, args.c_compiler)
        owned_output = True
    except BuildNotQualified as error:
        record = error.record
        owned_output = True
    except (ValueError, OSError, zipfile.BadZipFile) as error:
        record = dict(schema=SCHEMA, outcome="NOT_QUALIFIED", error_class=type(error).__name__)
    status = 0 if record["outcome"] == "BUILT_AND_IDENTITY_PROBED" else 1
    if args.ci_transcript:
        originals = {}
        selected_streams = ("compile.stdout", "compile.stderr", "compile.json",
                     "identity-probe.stdout", "identity-probe.stderr", "identity-probe.json") if owned_output else ()
        for name in selected_streams:
            path = args.output_directory / "originals" / name
            if not path.exists():
                continue
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 1024**2:
                status = 1
                continue
            raw = path.read_bytes()
            private = re.search(rb"(?<![:/])/(?:[A-Za-z0-9_.-]+/)+[A-Za-z0-9_.-]*|[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+[.][A-Za-z]{2,}", raw)
            if private:
                originals[name] = dict(sha256=_sha(raw), bytes=len(raw), sharing="WITHHELD; ORIGINAL PRIVATE OUTPUT REMAINS")
                status = 1
            else:
                originals[name] = dict(sha256=_sha(raw), bytes=len(raw), original_hex=raw.hex())
        record = dict(engine_record=record, original_compile_and_probe=originals,
            sdk_path_output="PRIVATE; NOT PUBLISHED", qualification_exit=status)
    print(_json(record).decode("ascii"))
    return status


if __name__ == "__main__":
    sys.exit(main())
