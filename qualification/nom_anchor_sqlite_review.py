"""Read-only review of one finite synthetic SQLite evidence graph.

This verifies retained byte relationships and selected native observations. It
does not recreate actual reference custody, authenticate a service or attest a
compiler, host, filesystem, power-loss property or independent assessment.
"""
import hashlib
import json
from pathlib import Path
import re
import stat

from . import nom_anchor_sqlite_evidence as format_profile

SCHEMA = "ptlc-nom-anchor-sqlite-evidence-review-v1"
SHARING_SCOPE = "BOUNDED PATTERN AND SELECTED SYNTHETIC GRAPH REVIEW; NOT AN ANONYMITY GUARANTEE"
_DIGEST = re.compile(r"[0-9a-f]{64}")
_LABEL = re.compile(r"[a-z0-9][a-z0-9._/-]{0,127}")
_PRIVATE = re.compile(
    rb"/(?:Users|home|Volumes|private)/[^\s\x00]+|[A-Za-z]:\\Users\\|"
    # Start at the complete local-part boundary. Retrying inside a megabyte
    # hex field makes an absent email marker cause quadratic backtracking.
    rb"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+[.][A-Za-z]{2,}|"
    rb"-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----|"
    rb"(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16})|"
    rb"\blocalhost\b|\b[A-Za-z0-9_-]+[.]local\b", re.I)


class ReviewRefused(ValueError):
    """Original evidence is incomplete, inconsistent or outside the selected scope."""


def require(condition):
    if not condition:
        raise ReviewRefused("selected original evidence relationship refused")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _pairs(values):
    result = {}
    for key, value in values:
        require(key not in result)
        result[key] = value
    return result


def document(raw):
    require(raw.isascii())
    result = json.loads(raw, object_pairs_hook=_pairs,
        parse_constant=lambda unused: (_ for _ in ()).throw(ReviewRefused("nonfinite JSON refused")))
    require(canonical(result) == raw)
    return result


def reference(value):
    require(type(value) is dict and set(value) == {"sha256", "bytes"})
    require(type(value["sha256"]) is str and _DIGEST.fullmatch(value["sha256"]) is not None)
    require(type(value["bytes"]) is int and 0 <= value["bytes"] <= format_profile.MAX_OBJECT_BYTES)
    return value


def label(value):
    require(type(value) is str and _LABEL.fullmatch(value) is not None)
    require(all(part not in ("", ".", "..") for part in value.split("/")))
    return value


def sharing(raw):
    """Inspect original bytes and bounded hex openings, without rewriting them."""
    remaining = [4 * format_profile.MAX_OBJECT_BYTES]

    def inspect(value, depth=0):
        remaining[0] -= len(value)
        require(depth <= 24 and remaining[0] >= 0 and _PRIVATE.search(value) is None)
        for match in re.finditer(rb"(?<![0-9A-Za-z_])[0-9A-Fa-f]{16,}(?![0-9A-Za-z_])", value):
            encoded = match.group()
            if len(encoded) % 2 == 0:
                inspect(bytes.fromhex(encoded.decode("ascii")), depth + 1)
    inspect(raw)


class OriginalGraph:
    """Load explicit bounded manifest/event references; never adopt or repair."""

    def __init__(self, directory):
        self.root = Path(directory)
        self.objects, self.labels, self.positions = {}, {}, {}
        info = self.root.lstat()
        require(stat.S_ISDIR(info.st_mode))
        self._directories = {self.root: (info.st_dev, info.st_ino)}
        require({p.name for p in self.root.iterdir()} <= {"enrollment.json", "manifest.json", "objects", "events"})
        for name in ("objects", "events"):
            selected = (self.root / name).lstat()
            require(stat.S_ISDIR(selected.st_mode))
            self._directories[self.root / name] = (selected.st_dev, selected.st_ino)
        self.enrollment = document(self._read(self.root / "enrollment.json", 4096))
        require(type(self.enrollment) is dict)
        expected = dict(schema=format_profile.SCHEMA, identifier=self.enrollment.get("identifier"),
            purpose="synthetic-original-sql-output-only", max_object_bytes=format_profile.MAX_OBJECT_BYTES,
            max_total_bytes=format_profile.MAX_TOTAL_BYTES, max_objects=format_profile.MAX_OBJECTS,
            max_events=format_profile.MAX_EVENTS, application="NO-GO", core="NO-GO", recovery_action="NONE")
        require(self.enrollment == expected)
        require(type(expected["identifier"]) is str and re.fullmatch(r"[0-9a-f]{32}", expected["identifier"]) is not None)
        objects = list((self.root / "objects").iterdir())
        require(len(objects) <= format_profile.MAX_OBJECTS)
        total = 0
        for path in objects:
            require(_DIGEST.fullmatch(path.name) is not None)
            raw = self._read(path, format_profile.MAX_OBJECT_BYTES)
            require(digest(raw) == path.name)
            total += len(raw)
            require(total <= format_profile.MAX_TOTAL_BYTES)
            self.objects[path.name] = raw
        paths = sorted((self.root / "events").iterdir())
        require(len(paths) <= format_profile.MAX_EVENTS)
        intents, completed, intent_labels = {}, set(), {}
        latest = None
        for position, path in enumerate(paths, 1):
            require(path.name == "{:04d}.json".format(position))
            event = document(self._read(path, 4096))
            require(type(event) is dict and set(event) == {"schema", "position", "kind", "label", "object"})
            require(event["schema"] == format_profile.SCHEMA and type(event["position"]) is int and event["position"] == position)
            selected_label, selected = label(event["label"]), reference(event["object"])
            require(event["kind"] in ("RETAIN_INTENT", "RETAINED"))
            if event["kind"] == "RETAIN_INTENT":
                require(selected_label not in intent_labels or intent_labels[selected_label] == selected)
                intent_labels[selected_label] = selected
                intents[position] = (selected_label, selected)
                latest = position
            else:
                require(latest is not None and latest == position - 1)
                require(intents[latest] == (selected_label, selected))
                require(selected["sha256"] in self.objects and len(self.objects[selected["sha256"]]) == selected["bytes"])
                require(selected_label not in self.labels or self.labels[selected_label] == selected)
                self.labels[selected_label] = selected
                self.positions[selected_label] = position
                completed.add(latest)
                latest = None
        intended_digests = {row[1]["sha256"] for row in intents.values()}
        require(set(self.objects) <= intended_digests)
        self.incomplete_intents = len(intents) - len(completed)
        self.manifest = None
        if (self.root / "manifest.json").exists() or (self.root / "manifest.json").is_symlink():
            self.manifest = document(self._read(self.root / "manifest.json", 1024**2))
            require(type(self.manifest) is dict)
            expected_objects = {pin: dict(bytes=len(raw)) for pin, raw in self.objects.items()}
            expected_manifest = dict(schema=format_profile.SCHEMA, identifier=expected["identifier"],
                status=self.manifest.get("status"), report=self.labels.get("comparison-report"),
                objects=expected_objects, labels=self.labels, event_count=len(paths), retained_bytes=total,
                application="NO-GO", core="NO-GO", recovery_action="NONE")
            require(self.manifest == expected_manifest and self.manifest["report"] is not None)
            require(self.manifest["status"] in ("COMPLETE_FINITE_COMPARISON", "NOT_QUALIFIED"))
            if self.manifest["status"] == "COMPLETE_FINITE_COMPARISON":
                require(self.incomplete_intents == 0)
        self.event_count = len(paths)
        self.retained_bytes = total
        self._guard_directories()
        require({p.name for p in (self.root / "objects").iterdir()} == {p.name for p in objects})
        require({p.name for p in (self.root / "events").iterdir()} == {p.name for p in paths})

    def _guard_directories(self):
        for path, identity in self._directories.items():
            selected = path.lstat()
            require(stat.S_ISDIR(selected.st_mode) and (selected.st_dev, selected.st_ino) == identity)

    def _read(self, path, maximum):
        self._guard_directories()
        before = path.lstat()
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= maximum)
        with path.open("rb") as stream:
            raw = stream.read(maximum + 1)
        after = path.lstat()
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_nlink)
                == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_nlink))
        require(len(raw) == before.st_size and len(raw) <= maximum)
        self._guard_directories()
        sharing(raw)
        return raw

    def original(self, name):
        return self.objects[self.labels[name]["sha256"]]

    def json(self, name):
        return document(self.original(name))


def _capture(value, sql):
    from . import nom_anchor_sqlite_capture as capture_profile
    require(type(value) is dict and value["schema"] == "ptlc-selected-native-sql-capture-v1")
    require(type(value["actual_exit"]) is int and value["actual_exit"] in (0, 1, -9))
    require(value["output_complete"] is True and value["processes_reaped"] is True)
    require(value["binary_unchanged"] is True and value["timed_out"] is False and value["capture_errors"] == [])
    require(value["numeric_sqlite_error_code"] == "NOT_CAPTURED_BY_CLI" and value["failed_contender_wrapper"] is None)
    require(value["initial_input_sha256"] == digest(sql))
    continuation = bytes.fromhex(value["continuation_hex"])
    require(continuation in (b"", b"COMMIT;\n"))
    require(value["input_sha256"] == digest(sql + continuation) and value["input_bytes"] == len(sql + continuation))
    require(type(value["written_bytes"]) is int and 0 <= value["written_bytes"] <= value["input_bytes"])
    if value["actual_exit"] in (0, -9):
        require(value["written_bytes"] == value["input_bytes"])
    for name, cap in (("stdout", capture_profile.MAX_STDOUT), ("stderr", capture_profile.MAX_STDERR)):
        raw = bytes.fromhex(value[name + "_hex"])
        require(len(raw) <= cap and len(raw) == value[name + "_bytes"] and digest(raw) == value[name + "_sha256"])
        sharing(raw)
    require(type(value["selected_sigkill"]) is bool and value["selected_sigkill"] == (value["actual_exit"] == -9))
    return bytes.fromhex(value["stdout_hex"]), bytes.fromhex(value["stderr_hex"])


def review_complete(graph, root, platform=None):
    from scripts import qualify_nom_anchor_sqlite as profile
    require(graph.manifest is not None and graph.manifest["status"] == "COMPLETE_FINITE_COMPARISON")
    report = graph.json("comparison-report")
    require(report["schema"] == "ptlc-nom-anchor-sqlite-comparison-v1" and report["outcome"] == "PASS_FINITE_LOCAL_COMPARISON_ONLY")
    _, measured = profile.inputs(root)
    require(report["qualification_input_sha256"] == measured and report["qualification_inputs"] == len(measured))
    require(graph.json("selected/qualification-input-index") == measured)
    require(graph.original("selected/capture-source") == (root / "qualification/nom_anchor_sqlite_capture.py").read_bytes())
    require(graph.original("selected/schema") == (root / "qualification/nom_anchor_sqlite_schema.sql").read_bytes())
    engine = profile.selected_engine_description(graph.json("selected/engine-record"))
    require(report["engine"] == engine and (platform is None or engine["platform"] == platform))
    require(report["boundary"] == profile.BOUNDARY)
    for key, expected in (("application", "NO-GO"), ("core", "NO-GO"), ("recovery_action", "NONE"),
                          ("publication_outcome", "UNKNOWN"), ("service_gates_unfilled", 7),
                          ("original_operation_calls", 0), ("signature_requests", 0), ("new_core_outcomes", 0),
                          ("independent_assessment", "UNFILLED"), ("physical_power_loss", "UNQUALIFIED"),
                          ("authenticated_current_lookup", "NOT_IMPLEMENTED"),
                          ("native_error_codes", "CLI EXITS RETAINED; NUMERIC SQLITE ERROR CODES NOT CAPTURED")):
        require(type(report[key]) is type(expected) and report[key] == expected)
    for name, (size, pin) in profile.ANCHORS.items():
        raw = graph.original("material/anchors/" + name)
        require(len(raw) == size and digest(raw) == pin)
    for name, pin in profile.REQUESTS.items():
        require(digest(graph.original("material/requests/" + name)) == pin)
    reference_inputs = graph.json("material/runtime-input-index")
    require(reference_inputs == profile.prior.inputs(root)[1])
    require(report["input_sha256"] == reference_inputs and report["measured_reference_inputs"] == len(reference_inputs))
    require(set(report["selected_cases"]) == set(profile.CASES) and report["case_count"] == 22 and report["unsafe_controls"] == 4)
    require(sum(type(row) is dict and row.get("successful_unsafe") is True
                for row in report["selected_cases"].values()) == 4)
    calls, observations = report["native_calls"], {}
    require(type(calls) is list and len(calls) == report["supervised_command_count"] == 53)
    require(tuple(row["label"] for row in calls) == profile.NATIVE_CALLS)
    for number, row in enumerate(calls, 1):
        name = row["label"]
        require(type(name) is str and re.fullmatch(r"[a-z0-9-]+", name) is not None and name not in observations)
        require(graph.json("records/native-call-" + str(number)) == row)
        sql = graph.original("sql/" + name)
        require(digest(sql) == row["input_object"])
        original = graph.original("native/" + name + "/capture-stdout")
        require(digest(original) == row["original_capture_object"] and len(original) == row["original_capture_bytes"])
        require(graph.original("native/" + name + "/capture-stderr") == b"")
        value = json.loads(original)
        out, err = _capture(value, sql)
        require(row["actual_native_exit"] == value["actual_exit"] and row["native_output_complete"] is True)
        require(row["selected_sigkill"] == value["selected_sigkill"] and type(row["wrapper_actual_exit"]) is int
                and row["wrapper_actual_exit"] == 0)
        contender = value["contender"]
        nested = int(contender is not None)
        require(type(row["nested_native_calls"]) is int and row["nested_native_calls"] == nested)
        if name == "two-contenders":
            require(nested == 1 and value["actual_exit"] == 0 and value["continuation_hex"] == b"COMMIT;\n".hex())
            other = graph.original("sql/two-contenders-contender")
            require(digest(other) == row["contender_input_object"])
            _, refusal = _capture(contender, other)
            require(contender["actual_exit"] == 1 and b"database is locked" in refusal and contender["contender"] is None)
        else:
            require(nested == 0 and row["contender_input_object"] is None and value["continuation_hex"] == "")
        observations[name] = dict(original=value, stdout=out, stderr=err)
    require(sum(1 + row["nested_native_calls"] for row in calls) == report["actual_native_commands"] == 54)
    require("two-contenders" in observations)
    expected_heads = {
        "wrong-configuration-after": ("initial", 0), "native-full-after": ("initial", 0),
        "initial": ("initial", 0), "after-first": ("active", 1), "after-stale": ("active", 1),
        "after-id-conflict": ("active", 1), "after-nonce-conflict": ("active", 1),
        "contention-after": ("active", 1), "capacity-after": ("active", 1),
        "death-before-commit-reopen": ("initial", 0), "death-after-commit-reopen": ("active", 1),
        "old-restore": ("initial", 0), "independent-1": ("active", 1), "independent-2": ("active", 1),
        "reenrollment": ("active", 1), "terminal": ("retired", 4), "terminal-after-refusal": ("retired", 4),
        "pre-retirement-restore": ("after_third", 3)}
    require({key for key in observations if key.endswith("-head")} == {key + "-head" for key in expected_heads})
    for name, (anchor, revision) in expected_heads.items():
        selected = observations[name + "-head"]
        require(selected["original"]["actual_exit"] == 0 and selected["stderr"] == b"")
        rows = [line for line in selected["stdout"].splitlines() if line.startswith(b"HEAD|")]
        phase = "RETIRED" if anchor == "retired" else "ACTIVE"
        require(rows == [("HEAD|" + str(revision) + "|" + phase + "|").encode("ascii")
                         + graph.original("material/anchors/" + anchor).hex().upper().encode("ascii")])
    refusals = {
        "wrong-configuration-refused": b"CHECK constraint failed", "native-full-exact-request": b"database or disk is full",
        "stale-before": b"exact expected state refused", "conflicting-equal-id": b"UNIQUE constraint failed: requests.request_id",
        "reused-nonce": b"UNIQUE constraint failed: requests.nonce", "trim-retained-request": b"retained request cannot be trimmed",
        "capacity-second": b"finite capacity refused", "write-after-retirement": b"terminal enrollment"}
    for name, message in refusals.items():
        require(observations[name]["original"]["actual_exit"] == 1 and message in observations[name]["stderr"])
    require(observations["missing-existing"]["original"]["actual_exit"] == 1)
    expected_nonzero = set(refusals) | {"missing-existing", "death-before-commit", "death-after-commit"}
    require({name for name, row in observations.items() if row["original"]["actual_exit"] != 0} == expected_nonzero)
    for name, row in observations.items():
        if row["original"]["actual_exit"] == 0:
            require(row["stderr"] == b"")
            if name != "limit-new-connection":
                require(row["stdout"].splitlines()[:3] == [b"delete", b"3", b"0"])
                require(row["stdout"].splitlines().count(b"CONFIG|VERIFIED") == 1)
    require(b"LIMIT|4096\n" in observations["limit-selected-connection"]["stdout"])
    later_limit = observations["limit-new-connection"]["stdout"].splitlines()
    require(len(later_limit) == 1 and later_limit[0].startswith(b"LIMIT|"))
    require(int(later_limit[0].split(b"|")[1]) > 4096)
    require(b"MATCH|1\n" in observations["exact-request-lookup"]["stdout"])
    for cut in ("before", "after"):
        require(observations["death-" + cut + "-commit"]["original"]["actual_exit"] == -9)
    groups = report["image_groups"]
    require(type(groups) is list and len(groups) >= 3)
    group_positions = {}
    for number, group in enumerate(groups, 1):
        require(graph.json("records/image-group-" + str(number)) == group)
        require(group["label"] not in group_positions)
        group_positions[group["label"]] = graph.positions["records/image-group-" + str(number)]
        require(group["actual_native_children"] == "REAPED BEFORE THIS READ")
        require(type(group["files"]) is dict and set(group["files"]) <= {"database", "-journal"})
        for suffix, retained in group["files"].items():
            reference(retained)
            selected_label = "images/" + group["label"] + ("-database" if suffix == "database" else suffix)
            require(graph.labels[selected_label] == retained)
    for name, group in (("native-full-after-head", "native-full-before-lookup"),
                        ("death-before-commit-reopen-head", "death-before-commit-before-engine-reopen"),
                        ("death-after-commit-reopen-head", "death-after-commit-before-engine-reopen")):
        require(group_positions[group] < graph.positions["native/" + name + "/capture-stdout"])
    return dict(native_commands=54, supervised_commands=53, selected_cases=22,
        unsafe_controls=4, engine_platform=engine["platform"], engine_binary_sha256=engine["binary_sha256"],
        qualification_inputs=len(measured), original_image_groups=len(groups))


def review(directory, root, *, allow_incomplete=False, platform=None):
    graph = OriginalGraph(directory)
    complete = graph.manifest is not None and graph.manifest["status"] == "COMPLETE_FINITE_COMPARISON"
    details = review_complete(graph, Path(root), platform) if complete else {}
    require(complete or allow_incomplete)
    manifest = None if graph.manifest is None else dict(sha256=digest((graph.root / "manifest.json").read_bytes()),
        bytes=(graph.root / "manifest.json").stat().st_size)
    return dict(schema=SCHEMA, disposition="VERIFIED_FINITE_COMPARISON" if complete else "RETAINABLE_NOT_QUALIFIED",
        evidence_identifier=graph.enrollment["identifier"], manifest=manifest, object_count=len(graph.objects),
        original_event_count=graph.event_count, incomplete_intents=graph.incomplete_intents,
        retained_bytes=graph.retained_bytes, sharing_scope=SHARING_SCOPE, comparison=details,
        application="NO-GO", core="NO-GO", recovery_action="NONE", service_gates_unfilled=7)
