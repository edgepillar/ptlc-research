#!/usr/bin/env python3
"""Execute the finite pinned 5cb comparison once in caller-owned offline storage.

Acquisition, compiler provenance, storage quotas and private evidence custody
remain separate caller obligations. This invokes no node, wallet or RPC client.
"""
import sys
if sys.flags.optimize:
    raise SystemExit('REFUSED: 5cb native qualification requires assertions enabled')
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from qualification import nom_dev_5cb as selected
from qualification import nom_dev_5cb_reproduction as reproduction
from scripts import nom_5cb_command as capture

require = selected.earlier.require
MIB = 1024**2
FLOOR = 10 * 1024**3
RESERVATION = 2 * 1024**3
TOTAL_SECONDS = 2400


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def write_new(path, value):
    raw = json.dumps(value, sort_keys=True, ensure_ascii=True).encode('ascii')
    require(len(raw) <= 2 * MIB)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                         | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as output:
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())
    return dict(bytes=len(raw), sha256=sha(raw))


def original(directory, label, suffix, receipt):
    raw = selected.earlier.regular(directory / (label + '.' + suffix),
        capture.MAX_STDOUT if suffix == 'stdout' else capture.MAX_STDERR)
    require(len(raw) == receipt['bytes'][suffix]
            and sha(raw) == receipt['sha256'][suffix])
    return raw


def selected_environment(workspace, proxy, cc, sdk=None):
    environment = dict(PATH='/usr/bin:/bin:/usr/sbin:/sbin', HOME=str(workspace / 'home'),
        GOTOOLCHAIN='local', GOWORK='off', GOENV='off', GOFLAGS='',
        GOPROXY=proxy.as_uri(), GOSUMDB='off', GOVCS='*:off',
        GOPRIVATE='', GONOPROXY='none', GONOSUMDB='none', GOTELEMETRY='off',
        GOMAXPROCS='4', CGO_ENABLED='1', CC=str(cc),
        GOPATH=str(workspace / 'gopath'), GOMODCACHE=str(workspace / 'modules'),
        GOCACHE=str(workspace / 'build'), GOTMPDIR=str(workspace / 'temporary'),
        TMPDIR=str(workspace / 'temporary'))
    if sdk is not None:
        environment['SDKROOT'] = str(sdk)
    return environment


def bindings(unit, previous, handoffs, root=ROOT):
    """Materialize only declared inputs; previous streams come from this attempt."""
    values = reproduction.input_bindings(unit, previous, root)
    result = {}
    for key, value in values.items():
        require(re.fullmatch('PTLC_NOM_[A-Z_]+|PTLC_COMPAT_FIXTURE_ROOT', key)
                and type(value) is dict and len(value) == 1)
        if 'generated_json' in value:
            path = handoffs / (unit + '-' + key + '.json')
            write_new(path, value['generated_json'])
        else:
            directory = 'repository_directory' in value
            require(set(value) == {'repository_directory' if directory else 'repository_file'})
            name = value['repository_directory' if directory else 'repository_file']
            require(type(name) is str and not Path(name).is_absolute()
                    and all(part not in ('', '.', '..') for part in name.split('/')))
            path = selected.earlier.physical(Path(root) / name)
            if directory:
                require(path.is_dir())
            else:
                selected.earlier.regular(path, 2 * MIB)
        result[key] = str(path)
    return result


def qualify(source, workspace, go, expected_go, proxy, cc, *, root=ROOT, sdk=None):
    require(not sys.flags.optimize and sys.platform in ('linux', 'darwin')
        and type(expected_go) is str and re.fullmatch('[0-9a-f]{64}', expected_go))
    source, workspace, go, proxy, cc = map(selected.earlier.physical,
                                         (source, workspace, go, proxy, cc))
    plan = reproduction.plan(root, 'all')
    source_before = selected.compare_source(source, root, 'all')
    require(source_before['combined_files'] == 502 and len(plan['units']) == 20)
    require(sha(selected.earlier.regular(go, 64 * MIB)) == expected_go
        and os.access(go, os.X_OK) and os.access(cc, os.X_OK) and proxy.is_dir())
    cc_sha256 = sha(selected.earlier.regular(cc, 256 * MIB))
    if sdk is not None:
        require(sys.platform == 'darwin')
        sdk = selected.earlier.physical(sdk)
        require(sdk.is_dir()
            and not workspace.is_relative_to(sdk) and not sdk.is_relative_to(workspace)
            and not source.is_relative_to(sdk) and not sdk.is_relative_to(source))
    require(not workspace.is_relative_to(proxy) and not proxy.is_relative_to(workspace)
        and not source.is_relative_to(proxy) and not proxy.is_relative_to(source))
    info = workspace.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
        and stat.S_IMODE(info.st_mode) == 0o700 and not any(workspace.iterdir())
        and info.st_dev == source.stat().st_dev
        and shutil.disk_usage(workspace).free >= FLOOR + RESERVATION)
    paths = ('home', 'gopath', 'modules', 'build', 'temporary', 'handoffs', 'commands')
    for name in paths:
        (workspace / name).mkdir(mode=0o700)
    evidence = workspace / 'commands'
    environment = selected_environment(workspace, proxy, cc, sdk)
    started = time.monotonic()
    report = dict(schema='ptlc-nom-5cb-native-attempt-v1', outcome='UNKNOWN',
        core_commit=selected.CORE, core_tree=selected.TREE, profile='all',
        source_before=source_before, go_sha256=expected_go, cc_sha256=cc_sha256,
        platform_sdk='NOT_SELECTED' if sdk is None else 'DARWIN_SDKROOT_SELECTED_CONTENT_UNAUTHENTICATED',
        compiler_identity_scope='MEASURED_EXECUTABLES_ONLY; TRANSITIVE_TOOLCHAIN_NOT_AUTHENTICATED',
        compiler_workspaces=1, source_views=1, selected_commands=20,
        free_space_floor=FLOOR, expected_reservation=RESERVATION,
        os_filesystem_quota='NOT_CLAIMED', normal_default_vet=True,
        test_result_cache='DISABLED_BY_COUNT_ONE', commands={},
        automatic_native_retry=False, complete_account_admission='UNFILLED',
        source_build_authentication='UNFILLED', journal_source_upgrade='NOT_SELECTED',
        application='NO-GO', core='NO-GO', independent_assessment='UNFILLED')
    write_new(workspace / 'native-intent.json', report)
    previous, payloads = {}, {}

    def command(label, arguments, extra=None):
        require(time.monotonic() - started < TOTAL_SECONDS
                and shutil.disk_usage(workspace).free >= FLOOR)
        budget = min(1200, TOTAL_SECONDS - (time.monotonic() - started))
        receipt = capture.run([str(go), *arguments],
            environment=dict(environment, **(extra or {})), directory=source,
            evidence=evidence, label=label, timeout=budget)
        require(receipt['actual_exit'] == 0
            and receipt['result'] == 'RETURNED_ZERO_WITH_COMPLETE_STREAMS'
            and receipt['complete'] == {'stdout': True, 'stderr': True}
            and receipt['cleanup_complete'] is True)
        # Exact argv remains in the private command receipt. The public summary
        # carries no absolute paths, compiler diagnostics or environment values.
        report['commands'][label] = {key: receipt[key] for key in (
            'actual_exit', 'result', 'bytes', 'complete', 'sha256', 'elapsed_seconds')}
        return receipt

    try:
        version = command('go-version', ['version'])
        raw = original(evidence, 'go-version', 'stdout', version)
        platform = {'linux': 'linux/amd64', 'darwin': 'darwin/arm64'}[sys.platform]
        require(raw == ('go version go1.23.12 ' + platform + '\n').encode('ascii'))
        require(original(evidence, 'go-version', 'stderr', version) == b'')
        report['go_version'] = raw.decode('ascii').strip()
        packages = sorted({'./' + row['package'] for row in plan['units']})
        command('cold-build', ['test', '-json', '-p', '2', '-mod=readonly',
                              '-count=1', '-run', '^$', *packages])
        for row in plan['units']:
            unit = row['unit']
            require(unit not in report['commands'])
            require(all(name in previous and name.removesuffix('.stdout')
                        in report['commands'] for name in row['prior_streams_required']))
            receipt = command(unit, row['arguments'],
                              bindings(unit, previous, workspace / 'handoffs', root))
            for suffix in ('stdout', 'stderr'):
                payloads[unit + '.' + suffix] = original(evidence, unit, suffix, receipt)
            require(sum(map(len, payloads.values())) <= selected.MAX_TOTAL)
            if unit in ('vm-path', 'account-authorization'):
                previous[unit + '.stdout'] = payloads[unit + '.stdout']
        comparison = selected.compare_payloads(payloads, root, 'all')
        require(comparison['outcome'] == 'PASS_SELECTED_FINITE_VALUES_ONLY')
        command('upstream-definition', ['test', '-json', '-p', '2',
                '-mod=readonly', '-count=1', './vm/embedded/definition'])
        command('module-verify', ['mod', 'verify'])
        require(selected.compare_source(source, root, 'all') == source_before
            and sha(selected.earlier.regular(go, 64 * MIB)) == expected_go
            and sha(selected.earlier.regular(cc, 256 * MIB)) == cc_sha256)
        report['comparison'] = write_new(workspace / 'finite-value-comparison.json', comparison)
        report.update(outcome='PASS_SELECTED_NATIVE_FINITE_COMPARISONS_ONLY',
            complete_profiles=20, selected_parent_and_child_outcomes=479,
            complete_original_profile_streams=40, actual_native_commands=24,
            source_unchanged=True, compiler_unchanged=True,
            elapsed_seconds=round(time.monotonic() - started, 6))
        require(len(report['commands']) == report['actual_native_commands'])
        write_new(workspace / 'native-result.json', report)
        return report
    except BaseException as failure:
        report.update(outcome='FAILURE_OR_INCOMPLETE_PRESERVED',
            exception_type=type(failure).__name__,
            elapsed_seconds=round(time.monotonic() - started, 6))
        write_new(workspace / 'native-failure.json', report)
        raise


def main():
    class QuietParser(argparse.ArgumentParser):
        def error(self, message):
            raise ValueError('selected 5cb native qualification refused')
    parser = QuietParser(description=__doc__)
    for name in ('source', 'workspace', 'go', 'offline-proxy', 'cc'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--sdk-root', type=Path)
    parser.add_argument('--expect-go-sha256', required=True)
    try:
        args = parser.parse_args()
        report = qualify(args.source, args.workspace, args.go,
                         args.expect_go_sha256, args.offline_proxy, args.cc,
                         sdk=args.sdk_root)
    except (AssertionError, OSError, ValueError, KeyError, TypeError, RuntimeError,
            capture.WorkerError):
        print('REFUSED: 5cb native qualification; preserve private originals', file=sys.stderr)
        return 1
    print(json.dumps({key: report[key] for key in (
        'outcome', 'core_commit', 'core_tree', 'complete_profiles',
        'selected_parent_and_child_outcomes', 'complete_original_profile_streams',
        'actual_native_commands', 'compiler_workspaces', 'source_views',
        'source_unchanged', 'normal_default_vet', 'application', 'core')}, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
