"""Qualify selected fixture-only write/fsync exceptions and retain originals."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.nom_signed_io_evidence import (MANIFEST, MAX_FILE, MAX_TOTAL,
    canonical, decode, inspect, original_names, profile_inputs, require, sha)


def verify_subject(subject, root=ROOT):
    if subject is None:
        return
    require(type(subject) is str and re.fullmatch('[0-9a-f]{40}', subject))
    pins = dict(profile_inputs(root))
    pins[MANIFEST] = sha((root/MANIFEST).read_bytes())
    environment = dict(os.environ)
    for key in tuple(environment):
        if key.startswith('GIT_'):
            environment.pop(key)
    environment.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull, GIT_NO_LAZY_FETCH='1')
    for name, pin in pins.items():
        size = subprocess.run(['git', '--no-replace-objects', 'cat-file', '-s', subject+':'+name],
            cwd=root, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
        require(size.returncode == 0 and re.fullmatch(b'[0-9]+\n', size.stdout)
            and 0 < int(size.stdout) <= 1024**2)
        result = subprocess.run(['git', '--no-replace-objects', 'cat-file', 'blob', subject+':'+name], cwd=root,
            env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
        require(result.returncode == 0 and len(result.stdout) <= 1024**2 and sha(result.stdout) == pin)


def private_directory(path, empty=False):
    require(path.is_absolute())
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700)
    if empty:
        require(not any(path.iterdir()))
    return info.st_dev, info.st_ino


def read_original(evidence, name):
    path = evidence/name
    if '/' in name:
        private_directory(path.parent)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid()
        and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= MAX_FILE)
    raw = path.read_bytes()
    after = path.lstat()
    require((info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) ==
        (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) and len(raw) == info.st_size)
    return raw


def privacy(raw):
    from scripts.check_artifacts import PATTERNS
    text = raw.decode('ascii')
    require(not any(pattern.search(text) for unused, pattern in PATTERNS))
    require(not re.search(r'/(?:Users|Volumes|private)/|localhost|\b[A-Za-z0-9_-]+[.]local\b', text, re.I))


def write_original(path, raw):
    require(type(raw) is bytes and len(raw) <= MAX_FILE)
    fd = os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)


def retain_manifest(evidence, report, subject, root=ROOT):
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
    for raw in payloads.values():
        privacy(raw)
    result = canonical(report)
    privacy(result)
    write_original(evidence/'qualification-result.json', result)
    payloads['qualification-result.json'] = result
    value = dict(schema='ptlc-nom-signed-io-originals-v1', subject_commit=subject,
        qualification_outcome=report['outcome'], originals_complete=report['outcome'] == 'PASS',
        files={name: dict(bytes=len(raw), sha256=sha(raw)) for name, raw in payloads.items()},
        package='EXPLICIT_RELATIVE_FILES_ONLY; NO_ENVIRONMENT_OR_BINARY_BUNDLE',
        application='NO-GO', core='NO-GO', independent_assessment='UNFILLED')
    manifest = canonical(value)
    write_original(evidence/'retention-manifest.json', manifest)
    return sha(manifest)


def selected_artifact_names(evidence, root=ROOT, allow_incomplete=False):
    require(type(allow_incomplete) is bool)
    private_directory(evidence)
    manifest_raw = read_original(evidence, 'retention-manifest.json')
    manifest = decode(manifest_raw)
    require(type(manifest) is dict and set(manifest) == {'schema', 'subject_commit', 'qualification_outcome',
        'originals_complete', 'files', 'package', 'application', 'core', 'independent_assessment'})
    require(manifest['schema'] == 'ptlc-nom-signed-io-originals-v1')
    require(manifest['application'] == manifest['core'] == 'NO-GO' and manifest['independent_assessment'] == 'UNFILLED')
    require(manifest['package'] == 'EXPLICIT_RELATIVE_FILES_ONLY; NO_ENVIRONMENT_OR_BINARY_BUNDLE')
    complete = manifest['qualification_outcome'] == 'PASS'
    require(type(manifest['originals_complete']) is bool and manifest['originals_complete'] is complete)
    require(complete or allow_incomplete and manifest['qualification_outcome'] == 'FAILED_OR_INCOMPLETE')
    files = manifest['files']
    expected = set(original_names()) | {'qualification-result.json'}
    require(type(files) is dict and 'qualification-result.json' in files and set(files) <= expected)
    require(not complete or set(files) == expected)
    payloads = {}
    for name, pin in files.items():
        require(type(pin) is dict and set(pin) == {'bytes', 'sha256'})
        require(type(pin['bytes']) is int and 0 <= pin['bytes'] <= MAX_FILE)
        require(type(pin['sha256']) is str and re.fullmatch('[0-9a-f]{64}', pin['sha256']))
        raw = read_original(evidence, name)
        require(len(raw) == pin['bytes'] and sha(raw) == pin['sha256'])
        privacy(raw); payloads[name] = raw
    require(sum(map(len, payloads.values())) <= MAX_TOTAL)
    report = decode(payloads.pop('qualification-result.json'))
    require(report['subject_commit'] == manifest['subject_commit'] and report['outcome'] == manifest['qualification_outcome'])
    if complete:
        inspect(payloads, report, root)
    require(profile_inputs(root))
    return sorted(files) + ['retention-manifest.json']


def main(argv=None):
    if sys.flags.optimize:
        print('FAIL: signed I/O fault qualification requires assertions enabled', file=sys.stderr)
        return 1
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', required=True, type=Path)
    parser.add_argument('--subject-commit')
    parser.add_argument('--artifact-files', action='store_true')
    parser.add_argument('--allow-incomplete-for-retention', action='store_true')
    args = parser.parse_args(argv)
    try:
        profile_inputs(ROOT)
        verify_subject(args.subject_commit)
        if args.artifact_files:
            names = selected_artifact_names(args.evidence, allow_incomplete=args.allow_incomplete_for_retention)
            print('\n'.join(names))
            return 0
        require(not args.allow_incomplete_for_retention)
        private_directory(args.evidence, empty=True)
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
        print('FAIL: selected source or new private evidence directory refused', file=sys.stderr)
        return 1
    try:
        from scripts.nom_signed_io_faults import qualify
        report = qualify(ROOT, args.evidence, args.subject_commit)
    except (AssertionError, OSError, ValueError, TypeError, KeyError, RecursionError, subprocess.SubprocessError) as error:
        report = dict(schema='ptlc-nom-signed-io-faults-v1', outcome='FAILED_OR_INCOMPLETE',
            subject_commit=args.subject_commit, error_type=type(error).__name__,
            fixture_case_count='NOT_QUALIFIED', application='NO-GO', core='NO-GO', independent_assessment='UNFILLED')
    try:
        pin = retain_manifest(args.evidence, report, args.subject_commit)
    except (AssertionError, OSError, ValueError, TypeError, KeyError, RecursionError):
        print('FAIL: fault retention incomplete; preserve every original', file=sys.stderr)
        return 1
    print(json.dumps(dict(report, retention_manifest_sha256=pin), sort_keys=True))
    return 0 if report['outcome'] == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main())
