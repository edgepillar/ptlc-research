#!/usr/bin/env python3
"""Run and retain one bounded Linux comparison of the pinned candidate."""
import argparse
import base64
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from offline_session.public_worker import WorkerError
from qualification import nom_dev_008bdcd_native as selected
from qualification.nom_current_admission import MIB, PREFIX, canonical, decoded, physical, regular, require
from qualification.nom_fee_original_boundary import compare_files
from scripts import nom_18c048a_command as capture
from scripts.check_nom_18c048a_evidence import privacy
from scripts.qualify_nom_18c048a_native import FLOOR, RESERVATION, original, selected_environment, sha, write_new
from scripts.run_offline_ci_profile import source as research_source

VERSION = b'go version go1.23.12 linux/amd64\n'
SCHEMA = 'ptlc-nom-008bdcd-native-v1'
LABELS = ('go-version', 'selected-dependencies', 'module-verify', 'selected-native')
PASS = 'PASS_FINITE_NATIVE_COMPARISON'
FAIL = 'FAILURE_OR_INCOMPLETE'
RESULT = 'candidate-result.json'
BOUNDARY = dict(application='NO-GO', core='NO-GO', journal_source_upgrade='NOT_SELECTED',
    independent_assessment='UNFILLED', recovery_action='NONE',
    compiler_workspaces=1, physical_source_views=1, module_caches=1,
    bootstrap_network='SELECTED_PACKAGE_DEPENDENCY_ACQUISITION_AND_VERIFICATION',
    native_module_network='OFF', os_network_isolation='NOT_CLAIMED', normal_default_vet=True,
    test_result_cache='DISABLED_BY_COUNT_ONE', automatic_retry=False)


def safe(raw, private_paths=()):
    try:
        require(raw.isascii() and all(os.fsencode(path) not in raw for path in private_paths))
        privacy(raw)
    except (UnicodeError, ValueError):
        return False
    return True


def module_sums(raw):
    sums = {}
    require(raw.isascii() and raw.endswith(b'\n'))
    for line in raw.splitlines():
        parts = line.split(b' ')
        require(len(parts) == 3 and all(parts)
            and all(33 <= byte <= 126 for part in parts for byte in part)
            and re.fullmatch(rb'h1:[A-Za-z0-9+/]{43}=', parts[2]) is not None)
        checksum = base64.b64decode(parts[2][3:], validate=True)
        require(len(checksum) == 32 and base64.b64encode(checksum) == parts[2][3:])
        key = tuple(parts[:2])
        require(key not in sums)
        sums[key] = parts[2]
    return sums


def run(archive, workspace, go, expected_go, cc, head):
    require(not sys.flags.optimize and sys.dont_write_bytecode and sys.platform == 'linux')
    archive, workspace, go, cc = map(physical, (archive, workspace, go, cc))
    info = workspace.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
        and stat.S_IMODE(info.st_mode) == 0o700 and not any(workspace.iterdir())
        and all(not item.is_relative_to(workspace) for item in (archive, go, cc, ROOT))
        and not workspace.is_relative_to(ROOT)
        and shutil.disk_usage(workspace).free >= FLOOR + RESERVATION)
    require(re.fullmatch('[0-9a-f]{64}', expected_go) is not None
        and sha(regular(go, 64*MIB)) == expected_go
        and os.access(go, os.X_OK) and os.access(cc, os.X_OK))
    selection, _, paths = selected.selection()
    before = research_source(ROOT, head)
    report = dict(schema=SCHEMA, selection=selection, boundary=BOUNDARY,
        research_source=before, go_executable_sha256=expected_go,
        cc_executable_sha256=sha(regular(cc, 256*MIB)),
        outcome=FAIL, stage='source', commands={})
    evidence, source = workspace / 'commands', workspace / 'source'
    for name in ('commands', 'home', 'gopath', 'modules', 'build', 'temporary', 'bootstrap'):
        (workspace / name).mkdir(mode=0o700)
    environment = selected_environment(workspace, None, cc)
    environment['PTLC_COMPAT_FIXTURE_ROOT'] = str(ROOT / 'compatibility/fixtures')
    private_paths = (ROOT, workspace, archive, go, cc)

    def command(label, arguments, timeout, selected_environment):
        report['stage'] = label
        require(shutil.disk_usage(workspace).free >= FLOOR)
        try:
            capture.run([str(go), *arguments], environment=selected_environment, directory=source,
                        evidence=evidence, label=label, timeout=timeout)
        finally:
            receipt = decoded(regular(evidence / (label + '.receipt.json'), 64*1024), 64*1024)
            report['commands'][label] = summary = {name: receipt[name] for name in (
                'result', 'actual_exit', 'complete', 'cleanup_complete', 'elapsed_seconds')}
            streams = {kind: original(evidence, label, kind, receipt) for kind in ('stdout', 'stderr')}
            summary['streams'] = {kind: dict(bytes=len(raw), sha256=sha(raw),
                export=safe(raw, private_paths)) for kind, raw in streams.items()}
        require(summary['actual_exit'] == 0 and summary['cleanup_complete'] is True
            and summary['complete'] == dict(stdout=True, stderr=True)
            and all(stream['export'] for stream in summary['streams'].values()))
        return streams['stdout']

    try:
        report['source_before'] = selected.prepare(archive, source)
        require(command('go-version', ['version'], 30, environment) == VERSION)
        bootstrap = workspace / 'bootstrap'
        source_inputs = {name: regular(source / name, 2*MIB) for name in ('go.mod', 'go.sum')}
        for name, raw in source_inputs.items():
            with capture.private_create(bootstrap / name) as stream:
                stream.write(raw)
        alternate = '-modfile=' + str(bootstrap / 'go.mod')
        online = dict(environment, GOPROXY='https://proxy.golang.org',
                      GOSUMDB='sum.golang.org', GODEBUG='http2client=0')
        closure = command('selected-dependencies', ['list', '-deps', '-test', '-mod=readonly',
            alternate, '-f', '{{.ImportPath}}', *selected.PACKAGES], 480, online)
        require(all((PREFIX + name).encode('ascii') in closure.splitlines() for name in selected.ROOTS))
        require(command('module-verify', ['mod', 'verify', alternate], 180, online) == b'all modules verified\n')
        require(regular(bootstrap / 'go.mod', 2*MIB) == source_inputs['go.mod'])
        original_sums = module_sums(source_inputs['go.sum'])
        bootstrap_sums = module_sums(regular(bootstrap / 'go.sum', 2*MIB))
        require(all(bootstrap_sums.get(key) == value for key, value in original_sums.items()))
        report['bootstrap_added_checksums'] = len(bootstrap_sums) - len(original_sums)
        require(compare_files(source, paths) == report['source_before'])

        stdout = command('selected-native', selected.TEST_ARGUMENTS, 900, environment)
        report['comparison'] = selected.accept_events(stdout)
        report['source_after'] = compare_files(source, paths)
        require(report['source_before'] == report['source_after']
            and before == research_source(ROOT, head))
        report.update(outcome=PASS, stage='complete')
    except (AssertionError, KeyError, OSError, ValueError, WorkerError, zipfile.BadZipFile) as error:
        report['failure_class'] = type(error).__name__
    write_new(workspace / RESULT, report)
    return report


def inspect(workspace, head):
    """Check available originals and independently compare the native event values."""
    workspace = physical(workspace)
    raw = regular(workspace / RESULT, 2*MIB)
    require(safe(raw))
    report = decoded(raw, 2*MIB)
    selection, _, paths = selected.selection()
    expected = dict(schema=SCHEMA, selection=selection, boundary=BOUNDARY,
                    research_source=research_source(ROOT, head))
    require(canonical({name: report[name] for name in expected}) == canonical(expected))
    require(report['outcome'] in (PASS, FAIL))
    commands = report['commands']
    require(type(commands) is dict and set(commands) == set(LABELS[:len(commands)]))
    files, streams = [RESULT], {}
    for label, summary in commands.items():
        require(set(summary['streams']) == {'stdout', 'stderr'})
        for kind, pin in summary['streams'].items():
            require(type(pin['export']) is bool and type(pin['bytes']) is int
                and 0 <= pin['bytes'] <= (capture.MAX_STDOUT if kind == 'stdout' else capture.MAX_STDERR)
                and re.fullmatch('[0-9a-f]{64}', pin['sha256']) is not None)
            if pin['export']:
                name = 'commands/' + label + '.' + kind
                content = regular(workspace / name, capture.MAX_STDOUT if kind == 'stdout' else capture.MAX_STDERR)
                require(safe(content) and len(content) == pin['bytes'] and sha(content) == pin['sha256'])
                files.append(name)
                streams[label, kind] = content
    if report['outcome'] == PASS:
        require(len(commands) == len(LABELS) and report['stage'] == 'complete' and len(streams) == 2*len(LABELS))
        require(all(summary['result'] == 'RETURNED_ZERO_WITH_COMPLETE_STREAMS'
            and type(summary['actual_exit']) is int and summary['actual_exit'] == 0
            and summary['cleanup_complete'] is True and canonical(summary['complete']) == canonical(dict(stdout=True, stderr=True))
            for summary in commands.values()))
        require(streams['go-version', 'stdout'] == VERSION
            and streams['module-verify', 'stdout'] == b'all modules verified\n')
        snapshot = dict(files=len(paths), sha256=sha(canonical(paths)))
        require(canonical(report['source_before']) == canonical(report['source_after']) == canonical(snapshot))
        require(canonical(report['comparison']) == canonical(selected.accept_events(streams['selected-native', 'stdout'])))
    return report, sorted(files)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', required=True, type=Path)
    parser.add_argument('--head', required=True)
    parser.add_argument('--archive', type=Path)
    parser.add_argument('--go', type=Path)
    parser.add_argument('--expect-go-sha256')
    parser.add_argument('--cc', type=Path)
    parser.add_argument('--artifact-files', action='store_true')
    args = parser.parse_args()
    try:
        if args.artifact_files:
            _, files = inspect(args.workspace, args.head)
            print('\n'.join(files))
            return 0
        report = run(args.archive, args.workspace, args.go, args.expect_go_sha256, args.cc, args.head)
        print(json.dumps(dict(outcome=report['outcome'], stage=report['stage'],
                             comparison=report.get('comparison')), sort_keys=True))
        return 0 if report['outcome'] == PASS else 1
    except (AssertionError, KeyError, OSError, TypeError, ValueError, WorkerError):
        print('Selected 008bdcd native input or original evidence refused', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
