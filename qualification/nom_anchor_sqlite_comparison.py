"""Finite native SQL comparison; no service, authenticated result or work entry.

All actual reference objects are generated from the unchanged synthetic corpus.
The native transport and every original output are separate measured inputs.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile

from scripts import qualify_nom_anchor_transition_journal as prior
from scripts import qualify_nom_anchor_lifecycle as fixtures
from offline_session import nom_anchor_lifecycle as lifecycle
from . import nom_anchor_sqlite_material as material_codec

PROFILE = "ptlc-nom-anchor-sqlite-comparison-v1"
MAX_CAPTURE_BYTES = 20 * 1024**2
MAX_FIXTURE_BYTES = 256 * 1024**2


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def prepare_material(root, evidence):
    _, measured = prior.inputs(root)
    selected = fixtures.fixture_contexts(root)
    anchors, requests = {}, {}
    for name, value in selected["anchors"].items():
        wire = material_codec.anchor_bytes(value)
        anchors[name] = evidence.put("material/anchors/" + name, wire)
    for name, value in selected["requests"].items():
        payload = material_codec.request_material(value)
        stored = {key: value.hex() if type(value) is bytes else value for key, value in payload.items()}
        original = evidence.put("material/requests/" + name, canonical(stored))
        requests[name] = dict(original, object=original["sha256"], request_id=payload["request_id"], kind=payload["kind"])
    if prior.inputs(root)[1] != measured:
        raise ValueError("selected reference source changed during material preparation")
    evidence.put("material/runtime-input-index", canonical(measured))
    return dict(anchors=anchors, requests=requests), measured, selected


settings = 'PRAGMA journal_mode; PRAGMA synchronous=EXTRA; PRAGMA synchronous; PRAGMA busy_timeout=0; PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF; PRAGMA temp_store=MEMORY; PRAGMA max_page_count=8192;\n'
configuration_guard = """CREATE TEMP TABLE selected_configuration_guard(ok INTEGER NOT NULL CHECK(ok=1));
INSERT INTO selected_configuration_guard VALUES (
    (SELECT journal_mode FROM pragma_journal_mode)='delete'
    AND (SELECT synchronous FROM pragma_synchronous)=3
    AND (SELECT timeout FROM pragma_busy_timeout)=0
    AND (SELECT foreign_keys FROM pragma_foreign_keys)=1
    AND (SELECT trusted_schema FROM pragma_trusted_schema)=0
    AND (SELECT temp_store FROM pragma_temp_store)=2
    AND (SELECT max_page_count FROM pragma_max_page_count)=8192
    AND (SELECT page_size FROM pragma_page_size)=4096
);
SELECT 'CONFIG|VERIFIED';
"""
connection = settings + configuration_guard
def blob(raw):
    assert type(raw) is bytes
    return "X'" + raw.hex() + "'"

def insert(value, **replace):
    value = dict(value, **replace)
    for key in ('request_id', 'nonce'):
        assert re.fullmatch('[0-9a-f]{64}', value[key])
    assert value['kind'] in ('ADVANCE', 'RETIRE')
    return ('INSERT INTO requests(position,request_id,nonce,kind,complete_before,exact_request,complete_after) VALUES ('
        + str(value['after_revision']) + ", '" + value['request_id'] + "', '" + value['nonce'] + "', '" + value['kind'] + "', "
        + ','.join(blob(value[key]) for key in ('before', 'request', 'after')) + ');\n')



def require_actual_custody(selected):
    """Descriptors never stand in for the still-retained actual reference objects."""
    if type(selected) is not dict or type(selected.get("anchors")) is not dict or type(selected.get("requests")) is not dict:
        raise ValueError("actual reference custody must remain available separately")
    anchors, requests = selected["anchors"], selected["requests"]
    if (set(anchors) != {"initial", "active", "after_read", "after_third", "retired"}
            or set(requests) != {"first", "read", "third", "retirement"}
            or any(type(value) is not lifecycle.ReferenceAnchorState for value in anchors.values())
            or any(type(value) is not lifecycle.ReferenceAnchorTransition for value in requests.values())):
        raise ValueError("complete actual reference custody required; stored bytes cannot replace it")
    try:
        for value in anchors.values():
            value.as_dict()
        for value in requests.values():
            value.as_dict()
    except (ValueError, TypeError, AttributeError, KeyError, RecursionError, OverflowError):
        raise ValueError("complete actual reference custody refused") from None


def compare_prepared(root, binary, engine, evidence, material, measured, actual_custody):
    """Run the selected finite corpus against one exact caller-selected native build."""
    if not __debug__:
        raise ValueError("unoptimized qualification runtime required")
    require_actual_custody(actual_custody)
    binary = Path(binary).absolute()
    if hashlib.sha256(binary.read_bytes()).hexdigest() != engine["binary_sha256"]:
        raise ValueError("selected native engine bytes changed")
    requests = {}
    for name, row in material["requests"].items():
        value = json.loads(evidence.read(row["object"]))
        requests[name] = {key: bytes.fromhex(value) if key in ("before", "request", "after") else value
                         for key, value in value.items()}
        pending = json.loads(bytes.fromhex(json.loads(requests[name]["request"])["pending_hold_hex"]))
        assert pending["publication_outcome"] == "UNKNOWN" and pending["disclosure_possible"] and not pending["work_permission"]
    initial = evidence.read(material["anchors"]["initial"]["sha256"])
    here = Path(__file__).resolve().parent
    schema = (here / "nom_anchor_sqlite_schema.sql").read_text("ascii")
    native = here / "nom_anchor_sqlite_capture.py"
    capture_pin = hashlib.sha256(native.read_bytes()).hexdigest()
    evidence.put("selected/capture-source", native.read_bytes())
    evidence.put("selected/schema", schema.encode("ascii"))
    workspace = Path(tempfile.mkdtemp(prefix="ptlc-nom-sqlite-"))
    workspace.chmod(0o700)
    workspace_identity = (workspace.stat().st_dev, workspace.stat().st_ino)
    databases, calls, images, checks = [], [], [], {}
    can_clean = True

    def record(label, value):
        return evidence.put("records/" + label, canonical(value))

    def script_alias(label, sql):
        raw = sql.encode("ascii")
        assert 0 < len(raw) <= 16 * 1024**2 and re.fullmatch("[a-z0-9-]+", label)
        selected = evidence.put("sql/" + label, raw)
        return evidence.path(selected["sha256"]), selected["sha256"]

    def fixture_size():
        total = 0
        for selected in workspace.iterdir():
            info = selected.lstat()
            assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1
            total += info.st_size
        assert total <= MAX_FIXTURE_BYTES
        return total

    def call(label, path, sql, *, mode="rw", cut="none", contender_sql=None):
        nonlocal can_clean
        assert len(calls) < 64
        fixture_size()
        assert hashlib.sha256(native.read_bytes()).hexdigest() == capture_pin
        alias, sql_object = script_alias(label, sql)
        argv = [sys.executable, "-B", str(native), str(binary), engine["binary_sha256"], str(path), str(alias), mode, cut]
        contender_object = None
        if contender_sql is not None:
            other, contender_object = script_alias(label + "-contender", contender_sql)
            argv.append(str(other))
        try:
            selected = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90, check=False)
        except subprocess.TimeoutExpired as error:
            can_clean = False
            evidence.put("native/" + label + "/partial-stdout", (error.output or b"")[:MAX_CAPTURE_BYTES])
            evidence.put("native/" + label + "/partial-stderr", (error.stderr or b"")[:64*1024])
            record("timeout-" + label, dict(actual_exit=None, output_complete=False, fixture_disposition="HOLD"))
            raise ValueError("selected native supervision outcome unknown") from None
        output = evidence.put("native/" + label + "/capture-stdout", selected.stdout[:MAX_CAPTURE_BYTES])
        evidence.put("native/" + label + "/capture-stderr", selected.stderr[:64*1024])
        if selected.returncode != 0 or len(selected.stdout) > MAX_CAPTURE_BYTES or selected.stderr:
            can_clean = False
            record("unqualified-" + label, dict(wrapper_exit=selected.returncode,
                complete_outer_stdout=len(selected.stdout) <= MAX_CAPTURE_BYTES, fixture_disposition="HOLD"))
            raise ValueError("selected native capture did not qualify")
        try:
            original = json.loads(selected.stdout)
        except (ValueError, TypeError):
            can_clean = False
            raise ValueError("selected original capture is unavailable") from None
        if (original.get("actual_exit") is None or original.get("processes_reaped") is not True
                or original.get("binary_unchanged") is not True):
            can_clean = False
        row = dict(label=label, input_object=sql_object, contender_input_object=contender_object,
            original_capture_object=output["sha256"], original_capture_bytes=output["bytes"],
            actual_native_exit=original.get("actual_exit"), native_output_complete=original.get("output_complete"),
            selected_sigkill=original.get("selected_sigkill"), wrapper_actual_exit=selected.returncode,
            nested_native_calls=int(original.get("contender") is not None))
        calls.append(row)
        record("native-call-" + str(len(calls)), row)
        assert original["binary_unchanged"] and original["output_complete"] and not original["capture_errors"]
        assert original["processes_reaped"]
        out, err = bytes.fromhex(original["stdout_hex"]), bytes.fromhex(original["stderr_hex"])
        assert hashlib.sha256(out).hexdigest() == original["stdout_sha256"]
        assert hashlib.sha256(err).hexdigest() == original["stderr_sha256"]
        assert hashlib.sha256(native.read_bytes()).hexdigest() == capture_pin
        fixture_size()
        return original, out, err

    def success(label, path, sql, **kwargs):
        result, out, err = call(label, path, connection + sql, **kwargs)
        assert result['actual_exit'] == 0 and not err
        assert result['written_bytes'] == result['input_bytes']
        assert out.decode('ascii').splitlines()[:3] == ['delete', '3', '0']
        assert out.decode('ascii').splitlines().count('CONFIG|VERIFIED') == 1
        return result, out

    def refuse(label, path, sql, expected):
        result, out, err = call(label, path, connection + sql)
        assert result['actual_exit'] != 0 and not result['selected_sigkill'] and expected in err
        return result['actual_exit']

    def new_path(label):
        path = workspace / (label + '.db')
        assert not path.exists()
        databases.append(path)
        return path

    def create(label, *, capacity=16):
        assert 1 <= capacity <= 16
        path = new_path(label)
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        os.close(fd)
        seed = ("BEGIN IMMEDIATE; INSERT INTO enrollment VALUES(1,'ptlc-nom-anchor-sqlite-comparison-v1',"
            + str(capacity) + ',' + blob(initial) + '); INSERT INTO anchor_state VALUES(1,0,\'ACTIVE\','
            + blob(initial) + '); COMMIT;\n')
        success(label + '-create', path, schema + seed)
        return path

    def head(label, path, expected, revision, phase='ACTIVE'):
        _, output = success(label + '-head', path,
            "SELECT 'HEAD|' || revision || '|' || phase || '|' || hex(complete) FROM anchor_state WHERE id=1;\n", mode='ro')
        rows = [line for line in output.decode('ascii').splitlines() if line.startswith('HEAD|')]
        assert len(rows) == 1
        selected = rows[0].split('|')
        assert selected[1:3] == [str(revision), phase] and bytes.fromhex(selected[3]) == expected
        return dict(revision=revision, phase=phase, complete_sha256=hashlib.sha256(expected).hexdigest())

    def save_images(label, path):
        retained = {}
        for suffix in ("", "-journal"):
            selected = Path(str(path) + suffix)
            if not selected.exists():
                continue
            info = selected.lstat()
            assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= 32 * 1024**2
            raw = selected.read_bytes()
            assert selected.stat().st_size == len(raw)
            retained[suffix or "database"] = evidence.put("images/" + label + (suffix or "-database"), raw)
        images.append(dict(label=label, files=retained, actual_native_children="REAPED BEFORE THIS READ",
            copy_scope="EXPLICIT BOUNDED SYNTHETIC BYTE SNAPSHOT; NOT PHYSICAL POWER-LOSS EVIDENCE"))
        record("image-group-" + str(len(images)), images[-1])
        return retained

    def copied(label, original):
        raw = evidence.read(original["database"]["sha256"])
        path = new_path(label)
        current = fixture_size()
        assert current + len(raw) <= MAX_FIXTURE_BYTES
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        assert path.stat().st_nlink == 1
        return path

    try:
        first, read = requests['first'], requests['read']
        probe = create('limit-probe')
        observed, output, error = call('limit-selected-connection', probe,
            connection + "PRAGMA max_page_count=4096; SELECT 'LIMIT|' || max_page_count FROM pragma_max_page_count;\n")
        assert observed['actual_exit'] == 0 and not error and b'LIMIT|4096\n' in output
        observed, output, error = call('limit-new-connection', probe,
            "SELECT 'LIMIT|' || max_page_count FROM pragma_max_page_count;\n", mode='ro')
        assert observed['actual_exit'] == 0 and not error
        limit_rows = [line for line in output.decode('ascii').splitlines() if line.startswith('LIMIT|')]
        assert len(limit_rows) == 1
        later_limit = int(limit_rows[0].split('|')[1])
        assert later_limit > 4096
        checks['page_limit_requires_each_connection'] = dict(first_connection=4096, reopened_connection=later_limit,
            fixed_prefix='SET AND CHECK 8192 ON EACH ORDINARY CONNECTION; NO PERSISTENCE ASSUMPTION')

        wrong = create('wrong-configuration')
        observed, _, error = call('wrong-configuration-refused', wrong,
            settings + 'PRAGMA synchronous=OFF;\n' + configuration_guard
            + 'BEGIN IMMEDIATE;\n' + insert(first) + 'COMMIT;\n')
        assert observed['actual_exit'] != 0 and b'CHECK constraint failed' in error
        checks['wrong_configuration_refused_before_transition'] = dict(actual_native_exit=observed['actual_exit'],
            retained=head('wrong-configuration-after', wrong, initial, 0))

        full = create('native-full')
        _, output = success('native-full-page-count', full,
            "SELECT 'PAGES|' || page_count FROM pragma_page_count;\n", mode='ro')
        page_rows = [line for line in output.decode('ascii').splitlines() if line.startswith('PAGES|')]
        assert len(page_rows) == 1
        pages = int(page_rows[0].split('|')[1])
        assert 0 < pages < 8192
        native_exit = refuse('native-full-exact-request', full, 'PRAGMA max_page_count=' + str(pages)
            + '; BEGIN IMMEDIATE;\n' + insert(first) + 'COMMIT;\n', b'database or disk is full')
        before_lookup = save_images('native-full-before-lookup', full)
        checks['native_full_preserves_original_unknown'] = dict(actual_native_exit=native_exit,
            selected_error='FULL CLASS INFERRED FROM ORIGINAL MESSAGE AND SELECTED LIMIT; NUMERIC SQLITE CODE NOT CAPTURED', selected_max_pages=pages,
            original_images=before_lookup, original_request_object=material['requests']['first']['object'],
            retained=head('native-full-after', full, initial, 0), publication_outcome='UNKNOWN',
            recovery_action='NONE', automatic_retry=False)

        missing = new_path('missing')
        result, _, _ = call('missing-existing', missing, connection + 'SELECT 1;')
        assert result['actual_exit'] != 0 and not missing.exists()
        checks['missing_existing_never_created'] = True

        path = create('ordinary')
        initial_image = save_images('ordinary-initial', path)
        checks['initial_complete_opening'] = head('initial', path, initial, 0)
        success('first-transition', path, 'BEGIN IMMEDIATE;\n' + insert(first) + 'COMMIT;\n')
        checks['exact_complete_after_state'] = head('after-first', path, first['after'], 1)
        refused = refuse('stale-before', path, 'BEGIN IMMEDIATE;\n' + insert(first) + 'COMMIT;\n', b'exact expected state refused')
        checks['stale_expected_state_refused'] = dict(actual_native_exit=refused,
            retained=head('after-stale', path, first['after'], 1))

        refused = refuse('conflicting-equal-id', path, 'BEGIN IMMEDIATE;\n'
            + insert(read, request_id=first['request_id']) + 'COMMIT;\n', b'UNIQUE constraint failed: requests.request_id')
        checks['conflicting_equal_request_id_refused'] = dict(actual_native_exit=refused,
            retained=head('after-id-conflict', path, first['after'], 1))
        refused = refuse('reused-nonce', path, 'BEGIN IMMEDIATE;\n'
            + insert(read, nonce=first['nonce']) + 'COMMIT;\n', b'UNIQUE constraint failed: requests.nonce')
        checks['reused_nonce_refused'] = dict(actual_native_exit=refused,
            retained=head('after-nonce-conflict', path, first['after'], 1))

        _, output = success('exact-request-lookup', path,
            "SELECT 'MATCH|' || count(*) FROM requests WHERE request_id='" + first['request_id']
            + "' AND exact_request=" + blob(first['request']) + ';\n', mode='ro')
        assert b'MATCH|1\n' in output
        checks['exact_lookup_is_observation_only'] = dict(found=1, publication_outcome='UNKNOWN', recovery_action='NONE')
        checks['retained_result_may_age_before_delivery'] = dict(evaluated_revision=0, later_revision=1,
            authenticated_current_at_delivery='NOT_ESTABLISHED')
        refused = refuse('trim-retained-request', path, 'BEGIN IMMEDIATE; DELETE FROM requests; COMMIT;\n', b'retained request cannot be trimmed')
        checks['retained_request_cannot_be_trimmed'] = dict(actual_native_exit=refused)

        contended = create('contention')
        held_sql = connection + 'BEGIN IMMEDIATE;\n' + insert(first) + "SELECT 'PTLC_SQL_SELECTED_CUT';\n"
        result, out, _ = call('two-contenders', contended, held_sql, cut='contend_at_marker',
            contender_sql=connection + 'BEGIN IMMEDIATE;\n' + insert(first) + 'COMMIT;\n')
        contender = result['contender']
        assert result['actual_exit'] == 0 and result['continuation_hex'] == b'COMMIT;\n'.hex()
        assert contender is not None and contender['actual_exit'] != 0 and contender['output_complete']
        assert b'database is locked' in bytes.fromhex(contender['stderr_hex'])
        checks['one_database_two_contenders'] = dict(winner_exit=0, contender_exit=contender['actual_exit'],
            retained=head('contention-after', contended, first['after'], 1), automatic_retry=False)

        limited = create('capacity', capacity=1)
        success('capacity-first', limited, 'BEGIN IMMEDIATE;\n' + insert(first) + 'COMMIT;\n')
        refused = refuse('capacity-second', limited, 'BEGIN IMMEDIATE;\n' + insert(read) + 'COMMIT;\n', b'finite capacity refused')
        checks['capacity_preserves_complete_history'] = dict(actual_native_exit=refused,
            retained=head('capacity-after', limited, first['after'], 1))

        for cut, commit in (('before-commit', ''), ('after-commit', 'COMMIT;\n')):
            selected = create('death-' + cut)
            raw = connection + 'BEGIN IMMEDIATE;\n' + insert(first) + commit + "SELECT 'PTLC_SQL_SELECTED_CUT';\n"
            result, _, _ = call('death-' + cut, selected, raw, cut='kill_at_marker')
            assert result['selected_sigkill'] and result['actual_exit'] == -9
            saved = save_images('death-' + cut + '-before-engine-reopen', selected)
            expected, revision = (initial, 0) if not commit else (first['after'], 1)
            observed = head('death-' + cut + '-reopen', selected, expected, revision)
            checks['lost_reply_' + cut.replace('-', '_')] = dict(actual_native_exit=-9, original_images=saved,
                observed_local_reference=observed, original_request_object=material['requests']['first']['object'],
                publication_outcome='UNKNOWN', recovery_action='NONE', automatic_retry=False)

        restored = copied('old-restore', initial_image)
        checks['unsafe_coherent_old_restore'] = dict(successful_unsafe=True,
            observed=head('old-restore', restored, initial, 0), nonrollback='UNPROTECTED')
        copies = [copied('independent-' + str(number), initial_image) for number in (1, 2)]
        for number, selected in enumerate(copies, 1):
            success('independent-' + str(number) + '-commit', selected, 'BEGIN IMMEDIATE;\n' + insert(first) + 'COMMIT;\n')
            head('independent-' + str(number), selected, first['after'], 1)
        assert copies[0].stat().st_ino != copies[1].stat().st_ino
        checks['unsafe_independent_service_copies'] = dict(successful_unsafe=True, independently_accepted_copies=2)
        reenrolled = create('reenrollment')
        success('reenrollment-commit', reenrolled, 'BEGIN IMMEDIATE;\n' + insert(first) + 'COMMIT;\n')
        checks['unsafe_explicit_reenrollment'] = dict(successful_unsafe=True,
            observed=head('reenrollment', reenrolled, first['after'], 1))

        retired = create('retirement')
        for name in ('first', 'read', 'third'):
            success('retirement-' + name, retired, 'BEGIN IMMEDIATE;\n' + insert(requests[name]) + 'COMMIT;\n')
        before_retirement = save_images('before-retirement', retired)
        success('terminal-retirement', retired, 'BEGIN IMMEDIATE;\n' + insert(requests['retirement']) + 'COMMIT;\n')
        checks['terminal_history_retained'] = head('terminal', retired, requests['retirement']['after'], 4, 'RETIRED')
        refused = refuse('write-after-retirement', retired, 'BEGIN IMMEDIATE;\n' + insert(first) + 'COMMIT;\n', b'terminal enrollment')
        checks['terminal_enrollment_refuses_further_transition'] = dict(actual_native_exit=refused,
            retained=head('terminal-after-refusal', retired, requests['retirement']['after'], 4, 'RETIRED'))
        old_terminal = copied('pre-retirement-restore', before_retirement)
        checks['unsafe_restored_pre_retirement'] = dict(successful_unsafe=True,
            observed=head('pre-retirement-restore', old_terminal, requests['third']['after'], 3))
        assert sum(type(value) is dict and value.get('successful_unsafe') is True for value in checks.values()) == 4
        assert prior.inputs(root)[1] == measured
        require_actual_custody(actual_custody)
    except BaseException as error:
        record('failure-class', dict(error_class=type(error).__name__, diagnostic='FINITE COMPARISON NOT QUALIFIED; ORIGINAL NATIVE OUTPUT RETAINED'))
        record('comparison-failure.json', dict(outcome='FAILURE; NOT QUALIFIED',
            error_type=type(error).__name__, completed_comparison_keys=list(checks),
            actual_native_calls=len(calls), native_supervision_reaped=can_clean,
            application='NO-GO', core='NO-GO', recovery_action='NONE', service_gates_unfilled=7))
        raise
    finally:
        if can_clean:
            actual_identity = (workspace.stat().st_dev, workspace.stat().st_ino)
            assert actual_identity == workspace_identity
            permitted = {selected.name + suffix for selected in databases for suffix in ('', '-journal')}
            assert all(p.name in permitted and p.is_file() and not p.is_symlink() and p.stat().st_nlink == 1 for p in workspace.iterdir())
            for selected in databases:
                if selected.exists():
                    save_images('final-' + selected.stem, selected)
            record('owned-fixture-disposition.json', dict(native_children='ALL SELECTED NATIVE CHILDREN REAPED',
                images_retained_before_cleanup=True, portable_copies='EXPLICIT AND QUOTA ACCOUNTED',
                disposal='ONLY THIS NEW REGENERABLE SYNTHETIC WORKSPACE; ORIGINAL COMMANDS AND IMAGE OBJECTS RETAINED'))
            shutil.rmtree(workspace)
        else:
            record('owned-fixture-disposition.json', dict(disposition='HOLD',
                reason='Native supervision outcome uncertain; keep original paths and do not adopt them for cleanup'))
    result = dict(schema=PROFILE, outcome="PASS_FINITE_LOCAL_COMPARISON_ONLY", engine=engine,
        selected_cases=checks, case_count=len(checks), unsafe_controls=4, supervised_command_count=len(calls),
        actual_native_commands=sum(1 + row["nested_native_calls"] for row in calls), native_calls=calls,
        image_groups=images, measured_reference_inputs=len(measured), input_sha256=measured,
        original_operation_calls=0, signature_requests=0, new_core_outcomes=0,
        native_error_codes="CLI EXITS RETAINED; NUMERIC SQLITE ERROR CODES NOT CAPTURED",
        independent_assessment="UNFILLED", physical_power_loss="UNQUALIFIED",
        authenticated_current_lookup="NOT_IMPLEMENTED", publication_outcome="UNKNOWN",
        application="NO-GO", core="NO-GO", recovery_action="NONE", service_gates_unfilled=7)
    assert result["case_count"] == 22 and result["actual_native_commands"] == 54
    return result
