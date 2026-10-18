#!/usr/bin/env python3
"""Qualify pinned transaction helpers and unsigned generic/PTLC RPC quote data.

The compiler and source are trusted, explicitly selected inputs. Collection has
post-collection stream bounds, not a hostile-compiler sandbox or transport quota.
Callers provide separately admitted storage and compiler/module cache ownership.
No network RPC, signer, node activation, journal migration or fee rewrite exists.
"""
import sys
if sys.flags.optimize:
    raise SystemExit('FAIL: RPC quote qualification requires assertions enabled')
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from qualification.nom_rpc_quote_source import (
    CORE, TREE, MANIFEST, LICENSE_SHA256, check_source, inputs, read_json,
    require, sha, unique,
)

GROUPS = ('go-version', 'originals', 'generic', 'ptlc', 'upstream-rpc')
MAX_FILE = 4 * 1024**2
MAX_TOTAL = 32 * 1024**2
RESULT_SCHEMA = 'ptlc-nom-rpc-source-result-v1'
SELECTION_SCHEMA = 'ptlc-nom-rpc-source-selection-v1'
RETENTION_SCHEMA = 'ptlc-nom-rpc-originals-v1'
PACKAGE_RULE = 'EXPLICIT_RELATIVE_FILES_ONLY; NO_ENVIRONMENT_OR_BINARY_BUNDLE'


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def original_names():
    return ('source-selection.json',) + tuple(group + suffix for group in GROUPS for suffix in ('.stdout', '.stderr'))


def private_directory(path, empty=False):
    require(path.is_absolute())
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700)
    if empty:
        require(not any(path.iterdir()))
    return info.st_dev, info.st_ino


def write_original(path, raw):
    require(type(raw) is bytes and len(raw) <= MAX_FILE)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(raw)


def read_original(evidence, name):
    require(name in set(original_names()) | {'qualification-result.json', 'retention-manifest.json'})
    path = evidence / name
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == os.getuid()
        and stat.S_IMODE(before.st_mode) == 0o600 and before.st_size <= MAX_FILE)
    raw = path.read_bytes()
    after = path.lstat()
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
        (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) and len(raw) == before.st_size)
    return raw


def privacy(raw):
    from scripts.check_artifacts import PATTERNS
    text = raw.decode('ascii')
    require(not any(pattern.search(text) for unused, pattern in PATTERNS))
    require(not re.search(r'/(?:Users|Volumes|private)/|localhost|\b[A-Za-z0-9_-]+[.]local\b', text, re.I))


def verify_subject(subject, root=ROOT):
    if subject is None:
        return
    require(type(subject) is str and re.fullmatch('[0-9a-f]{40}', subject))
    selected = dict(inputs(root)[0]['input_sha256'])
    selected[MANIFEST] = sha(root / MANIFEST)
    environment = {name: value for name, value in os.environ.items() if not name.startswith('GIT_')}
    environment.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull, GIT_NO_LAZY_FETCH='1')
    for name, pin in selected.items():
        size = subprocess.run(['git', '--no-replace-objects', 'cat-file', '-s', subject + ':' + name],
            cwd=root, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
        require(size.returncode == 0 and re.fullmatch(b'[0-9]+\n', size.stdout) and 0 < int(size.stdout) <= 16 * 1024**2)
        blob = subprocess.run(['git', '--no-replace-objects', 'cat-file', 'blob', subject + ':' + name],
            cwd=root, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
        require(blob.returncode == 0 and len(blob.stdout) == int(size.stdout) and hashlib.sha256(blob.stdout).hexdigest() == pin)


def upstream_names():
    names = {'TestGetRequiredPoWFusedPlasmaTarget', 'TestGetRequiredPoWFusedOnlyTargetMeetsPrice',
        'TestGetRequiredResultJSONIncludesZeroFusedTarget'}
    names.update('TestGetRequiredPoWFusedPlasmaTarget/' + name for name in (
        'dynamic-floor', 'dynamic-fused-only', 'dynamic-one-byte', 'dynamic-partial-fusion',
        'dynamic-no-fusion', 'before-first-v2', 'before-first-v2-partial',
        'before-enforcement', 'before-enforcement-partial'))
    names.update('TestGetRequiredPoWFusedOnlyTargetMeetsPrice/' + name for name in ('plain-send', 'ceil-not-floor'))
    return names


def compare_streams(payloads, root=ROOT):
    # Input pins are checked before importing the selected readers or fixtures.
    unused, unused_index, generic_fixture, ptlc_fixture = inputs(root)
    from scripts import qualify_nom_signed_originals as benchmark
    from qualification import nom_rpc_quote_generic as generic, nom_rpc_quote_ptlc as ptlc
    unused_old, unused_old_index, frozen = benchmark.inputs(root)
    vm = read_json(root / 'compatibility/fixtures/nom_supervisor_plasma_v1.json')
    terms = read_json(root / 'compatibility/fixtures/nom_supervisor_inputs_v1.json')
    completed = read_json(root / 'compatibility/fixtures/nom_supervisor_completions_v1.json')
    require(re.fullmatch(rb'go version go1\.23\.12 (linux|darwin)/(amd64|arm64)\n', payloads['go-version.stdout']))
    original_result, original_records = benchmark.inspect(payloads['originals.stdout'], vm, terms, completed)
    require(original_records == frozen and original_result['outcomes_with_parent'] == 25)
    generic_result, generic_records = generic.inspect(payloads['generic.stdout'], benchmark.selected_outcome)
    ptlc_result, ptlc_records = ptlc.inspect(payloads['ptlc.stdout'], benchmark.selected_outcome, frozen, vm)
    require(generic_records == generic_fixture and ptlc_records == ptlc_fixture)
    require(benchmark.selected_outcome(payloads['upstream-rpc.stdout'],
        {'github.com/zenon-network/go-zenon/rpc/api/embedded': upstream_names()}) == 14)
    return dict(outcome='PASS_SELECTED_RPC_SOURCE_COMPONENTS', originals=original_result,
        generic=generic_result, ptlc=ptlc_result, selected_upstream_rpc_outcomes=14,
        actual_go_outcomes=71, source_records=54, quote_records=30,
        existing_signed_original_records=24, existing_public_unlock_inputs=2,
        caller_contract_data_binding='EXACT SELECTED PUBLIC ORIGINALS; NO COMPLETE ADMISSION',
        original_fee_rewrite='NOT_PERFORMED', journal_source_upgrade='NOT_SELECTED',
        source_authority='SYNTHETIC STORES; NO CANONICALITY OR FINALITY',
        application='NO-GO', core='NO-GO', independent_assessment='UNFILLED')


def inspect(payloads, report, root=ROOT):
    manifest = inputs(root)[0]
    require(set(payloads) == set(original_names()))
    selection = json.loads(payloads['source-selection.json'], object_pairs_hook=unique)
    expected_selection = dict(schema=SELECTION_SCHEMA, core_commit=CORE, core_tree=TREE,
        subject_commit=report['subject_commit'], input_sha256=manifest['input_sha256'],
        source_index_payload_sha256=manifest['source_index_payload_sha256'],
        go_executable_sha256=report['go_executable_sha256'],
        source_license_sha256=LICENSE_SHA256, upstream_source_files=443, combined_source_files=446,
        application='NO-GO', core='NO-GO', independent_assessment='UNFILLED')
    require(selection == expected_selection and type(report['go_executable_sha256']) is str
        and re.fullmatch('[0-9a-f]{64}', report['go_executable_sha256']))
    require(report['schema'] == RESULT_SCHEMA and report['outcome'] == 'PASS'
        and report['core_commit'] == CORE and report['core_tree'] == TREE
        and report['input_sha256'] == manifest['input_sha256'] and report['source_unchanged'] is True)
    require(report['application'] == report['core'] == 'NO-GO' and report['independent_assessment'] == 'UNFILLED')
    require(report['network_rpc'] == report['original_fee_rewrite'] == report['node_activation'] == 'NOT_PERFORMED'
        and report['signer'] == report['journal_source_upgrade'] == 'NOT_SELECTED')
    require(set(report['native_runs']) == set(GROUPS))
    for group, result in report['native_runs'].items():
        require(type(result['actual_exit']) is int and result['actual_exit'] == 0
            and result['output_complete'] is True and result['timed_out'] is False
            and result['selected_files_retained'] is True and result['retention'] == 'COMPLETE_COLLECTED_STREAMS')
        for suffix in ('stdout', 'stderr'):
            raw = payloads[group + '.' + suffix]
            require(result[suffix + '_bytes'] == len(raw) and type(result[suffix + '_bytes']) is int
                and result[suffix + '_sha256'] == hashlib.sha256(raw).hexdigest()
                and type(result['retained_' + suffix + '_bytes']) is int
                and result['retained_' + suffix + '_bytes'] == len(raw)
                and result['retained_' + suffix + '_sha256'] == hashlib.sha256(raw).hexdigest())
    analysis = compare_streams(payloads, root)
    require(report['comparison'] == analysis and report['default_vet'] == 'NORMAL DEFAULT FOR FOUR TEST COMMANDS')
    return analysis


def capture(command, checkout, environment, evidence, group, timeout):
    process = subprocess.Popen(command, cwd=checkout, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    timed_out = False
    complete = True
    try:
        output, error = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        complete = False
        process.kill()
        try:
            output, error = process.communicate(timeout=5)
        except subprocess.TimeoutExpired as interrupted:
            output, error = interrupted.stdout or b'', interrupted.stderr or b''
    # The trusted compiler is not sandboxed. Bounds after communicate do not
    # establish allocation limits or that every descendant has been reaped.
    within_bounds = len(output) <= MAX_FILE and len(error) <= MAX_FILE
    # Preserve bounded original prefixes on an over-limit result. The report
    # keeps the full observed lengths and marks this capture incomplete.
    retained_output, retained_error = output[:MAX_FILE], error[:MAX_FILE]
    write_original(evidence / (group + '.stdout'), retained_output)
    write_original(evidence / (group + '.stderr'), retained_error)
    return dict(actual_exit=process.returncode, output_complete=complete and within_bounds, timed_out=timed_out,
        stdout_bytes=len(output), stderr_bytes=len(error), stdout_sha256=hashlib.sha256(output).hexdigest(),
        stderr_sha256=hashlib.sha256(error).hexdigest(), selected_files_retained=True,
        retained_stdout_bytes=len(retained_output), retained_stderr_bytes=len(retained_error),
        retained_stdout_sha256=hashlib.sha256(retained_output).hexdigest(),
        retained_stderr_sha256=hashlib.sha256(retained_error).hexdigest(),
        retention='COMPLETE_COLLECTED_STREAMS' if within_bounds else 'BOUNDED_ORIGINAL_PREFIXES_ONLY')


def qualify(checkout, go, expected_go, evidence, subject=None, root=ROOT):
    manifest, index, unused, unused_ptlc = inputs(root)
    verify_subject(subject, root)
    identity = private_directory(evidence, empty=True)
    require(go.is_absolute() and go.is_file() and not go.is_symlink() and go.stat().st_nlink == 1)
    require(type(expected_go) is str and re.fullmatch('[0-9a-f]{64}', expected_go) and sha(go) == expected_go)
    check_source(checkout, index, root)
    selection = dict(schema=SELECTION_SCHEMA, core_commit=CORE, core_tree=TREE, subject_commit=subject,
        input_sha256=manifest['input_sha256'], source_index_payload_sha256=manifest['source_index_payload_sha256'],
        go_executable_sha256=expected_go, source_license_sha256=LICENSE_SHA256,
        upstream_source_files=443, combined_source_files=446,
        application='NO-GO', core='NO-GO', independent_assessment='UNFILLED')
    write_original(evidence / 'source-selection.json', canonical(selection))
    report = dict(schema=RESULT_SCHEMA, outcome='FAILED_OR_INCOMPLETE', subject_commit=subject,
        core_commit=CORE, core_tree=TREE, input_sha256=manifest['input_sha256'], go_executable_sha256=expected_go,
        native_runs={}, source_unchanged=False, default_vet='NORMAL DEFAULT FOR FOUR TEST COMMANDS',
        collection='TRUSTED GO; POST_COLLECTION_BOUNDS; NO HOSTILE-COMPILER OR DESCENDANT-CONTAINMENT CLAIM',
        network_rpc='NOT_PERFORMED', signer='NOT_SELECTED', original_fee_rewrite='NOT_PERFORMED',
        journal_source_upgrade='NOT_SELECTED', node_activation='NOT_PERFORMED',
        application='NO-GO', core='NO-GO', independent_assessment='UNFILLED')
    proxy = os.environ.get('GOPROXY', 'off')
    require(proxy == 'off' or proxy.startswith('file://') and not any(char in proxy for char in ('\n', '\r', ',', '|')))
    environment = dict(os.environ, GOTOOLCHAIN='local', GOWORK='off', GOENV='off', GOFLAGS='', GOTELEMETRY='off',
        GOPROXY=proxy, GOSUMDB='off', GOPRIVATE='', GONOPROXY='none', GONOSUMDB='none', GOVCS='*:off',
        PTLC_NOM_SIGNED_ORIGINAL_FIXTURE=str(root / 'compatibility/fixtures/nom_supervisor_plasma_v1.json'),
        PTLC_NOM_RPC_PTLC_FIXTURE=str(root / 'compatibility/fixtures/nom_signed_originals_v1.json'))
    commands = (
        ('go-version', [str(go), 'version'], 30),
        ('originals', [str(go), 'test', '-json', '-mod=readonly', '-count=1', '-run', '^TestResearchNoMSignedOriginalByteCustody$', './verifier'], 240),
        ('generic', [str(go), 'test', '-json', '-mod=readonly', '-count=1', '-run', '^TestResearchNoMRpcQuoteCorpus$', './rpc/api/embedded'], 240),
        ('ptlc', [str(go), 'test', '-json', '-mod=readonly', '-count=1', '-run', '^TestResearchNoMPtlcRpcQuoteCorpus$', './rpc/api/embedded'], 240),
        ('upstream-rpc', [str(go), 'test', '-json', '-mod=readonly', '-count=1', '-run',
            '^(TestGetRequiredPoWFusedPlasmaTarget|TestGetRequiredPoWFusedOnlyTargetMeetsPrice|TestGetRequiredResultJSONIncludesZeroFusedTarget)$', './rpc/api/embedded'], 240),
    )
    try:
        for group, command, timeout in commands:
            result = capture(command, checkout, environment, evidence, group, timeout)
            report['native_runs'][group] = result
            require(result['actual_exit'] == 0 and result['output_complete'])
            if group == 'go-version':
                require(re.fullmatch(rb'go version go1\.23\.12 (linux|darwin)/(amd64|arm64)\n', read_original(evidence, 'go-version.stdout')))
            check_source(checkout, index, root)
        require(private_directory(evidence) == identity and sha(go) == expected_go)
        require(inputs(root)[0]['input_sha256'] == manifest['input_sha256'])
        payloads = {name: read_original(evidence, name) for name in original_names()}
        report['comparison'] = compare_streams(payloads, root)
        report.update(outcome='PASS', source_unchanged=True)
    except (AssertionError, OSError, ValueError, KeyError, TypeError, RecursionError, subprocess.SubprocessError) as error:
        report['error_type'] = type(error).__name__
    return report


def retain_manifest(evidence, report, root=ROOT):
    private_directory(evidence)
    payloads = {}
    for name in original_names():
        try:
            payloads[name] = read_original(evidence, name)
        except FileNotFoundError:
            continue
    require(sum(map(len, payloads.values())) <= MAX_TOTAL)
    if report['outcome'] == 'PASS':
        inspect(payloads, report, root)
    else:
        require(report['outcome'] == 'FAILED_OR_INCOMPLETE')
    result = canonical(report)
    write_original(evidence / 'qualification-result.json', result)
    payloads['qualification-result.json'] = result
    manifest = dict(schema=RETENTION_SCHEMA, subject_commit=report['subject_commit'],
        qualification_outcome=report['outcome'], originals_complete=report['outcome'] == 'PASS',
        files={name: dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()) for name, raw in payloads.items()},
        package=PACKAGE_RULE, application='NO-GO', core='NO-GO', independent_assessment='UNFILLED')
    encoded = canonical(manifest)
    write_original(evidence / 'retention-manifest.json', encoded)
    return hashlib.sha256(encoded).hexdigest()


def selected_artifact_names(evidence, root=ROOT, allow_incomplete=False):
    require(type(allow_incomplete) is bool)
    inputs(root)
    private_directory(evidence)
    manifest_raw = read_original(evidence, 'retention-manifest.json')
    manifest = json.loads(manifest_raw, object_pairs_hook=unique)
    require(type(manifest) is dict and set(manifest) == {'schema', 'subject_commit', 'qualification_outcome',
        'originals_complete', 'files', 'package', 'application', 'core', 'independent_assessment'})
    require(manifest['schema'] == RETENTION_SCHEMA and manifest['package'] == PACKAGE_RULE
        and manifest['application'] == manifest['core'] == 'NO-GO' and manifest['independent_assessment'] == 'UNFILLED')
    complete = manifest['qualification_outcome'] == 'PASS'
    require(type(manifest['originals_complete']) is bool and manifest['originals_complete'] is complete)
    require(complete or allow_incomplete and manifest['qualification_outcome'] == 'FAILED_OR_INCOMPLETE')
    expected = set(original_names()) | {'qualification-result.json'}
    files = manifest['files']
    require(type(files) is dict and 'qualification-result.json' in files and set(files) <= expected)
    require(not complete or set(files) == expected)
    payloads = {}
    for name, pin in files.items():
        require(type(pin) is dict and set(pin) == {'bytes', 'sha256'} and type(pin['bytes']) is int
            and 0 <= pin['bytes'] <= MAX_FILE and type(pin['sha256']) is str and re.fullmatch('[0-9a-f]{64}', pin['sha256']))
        raw = read_original(evidence, name)
        require(len(raw) == pin['bytes'] and hashlib.sha256(raw).hexdigest() == pin['sha256'])
        privacy(raw)
        payloads[name] = raw
    require(sum(map(len, payloads.values())) <= MAX_TOTAL)
    report = json.loads(payloads.pop('qualification-result.json'), object_pairs_hook=unique)
    require(report['subject_commit'] == manifest['subject_commit'] and report['outcome'] == manifest['qualification_outcome'])
    if complete:
        inspect(payloads, report, root)
    privacy(manifest_raw)
    return sorted(files) + ['retention-manifest.json']


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--checkout', type=Path)
    parser.add_argument('--go', type=Path)
    parser.add_argument('--expect-go-sha256')
    parser.add_argument('--evidence', required=True, type=Path)
    parser.add_argument('--subject-commit')
    parser.add_argument('--artifact-files', action='store_true')
    parser.add_argument('--allow-incomplete-for-retention', action='store_true')
    args = parser.parse_args(argv)
    try:
        inputs(ROOT)
        verify_subject(args.subject_commit)
        if args.artifact_files:
            print('\n'.join(selected_artifact_names(args.evidence, allow_incomplete=args.allow_incomplete_for_retention)))
            return 0
        require(not args.allow_incomplete_for_retention and args.checkout is not None
            and args.go is not None and args.expect_go_sha256 is not None)
        report = qualify(args.checkout, args.go, args.expect_go_sha256, args.evidence, args.subject_commit)
        pin = retain_manifest(args.evidence, report)
    except (AssertionError, OSError, ValueError, KeyError, TypeError, RecursionError, subprocess.SubprocessError):
        print('FAIL: selected RPC source, evidence or retention; preserve every original', file=sys.stderr)
        return 1
    print(json.dumps(dict(report, retention_manifest_sha256=pin), sort_keys=True))
    return 0 if report['outcome'] == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main())
