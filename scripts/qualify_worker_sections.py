#!/usr/bin/env python3
"""Read retained remapping outputs against a private canonical claim carrier.

No compilation or verification worker is invoked. Carrier agreement does not
authenticate a prior build, source truth, producer identity or future launch.
"""

import json
import os
from pathlib import Path
import sys

if __package__:
    from . import check_worker_sections as sections
    from . import qualify_worker_remapping as remapping
else:
    import check_worker_sections as sections
    import qualify_worker_remapping as remapping


scanner = sections.scanner
InputError = sections.InputError
REFUSAL = "selected retained worker section qualification refused"
MAX_CARRIER_BYTES = 256 * 1024
TERMINAL = b"PASS: selected target-only Rust remapping pair; two builds; complete byte scan; NOT ASSESSED\n"


def decode_carrier(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_CARRIER_BYTES or not raw.isascii():
        raise InputError(REFUSAL)
    depth, quoted, escaped = 0, False, False
    for byte in raw:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (123, 91):
            depth += 1
            if depth > 12:
                raise InputError(REFUSAL)
        elif byte in (125, 93):
            depth -= 1
            if depth < 0:
                raise InputError(REFUSAL)

    def integer(text):
        if len(text) > 10 or text.startswith('-'):
            raise InputError(REFUSAL)
        return int(text)

    def refuse(_):
        raise InputError(REFUSAL)

    try:
        value, _ = json.JSONDecoder(parse_int=integer, parse_float=refuse,
                                   parse_constant=refuse).raw_decode(raw.decode('ascii'))
        if type(value) is not dict or raw != scanner.encoded(value)+TERMINAL:
            raise InputError(REFUSAL)
        return value
    except (ValueError, UnicodeError, RecursionError):
        raise InputError(REFUSAL) from None


def load_carrier(path):
    scanner.owned_file(path, MAX_CARRIER_BYTES, private=True)
    with scanner.contents.regular(path, MAX_CARRIER_BYTES) as handle:
        status = os.fstat(handle.fileno())
        if status.st_uid != os.geteuid() or status.st_mode & 0o077:
            raise InputError(REFUSAL)
        return decode_carrier(handle.read(MAX_CARRIER_BYTES+1))


def qualify(root, selections, home, platform, carrier):
    try:
        if type(platform) is not str or platform not in remapping.check.resolution.PLATFORMS:
            raise InputError(REFUSAL)
        scanner.fields(selections, scanner.SELECTIONS)
        locations, directories, paths = {}, [], {}
        for name in scanner.SELECTIONS:
            pair = selections[name]
            if type(pair) is not tuple or len(pair) != 2:
                raise InputError(REFUSAL)
            locations[name] = remapping.selected_locations(root, pair[0], pair[1], home)
            directories.extend(pair)
            paths[name] = pair[1]/platform/'debug/examples'/remapping.check.WORKER
        identities = []
        for i, path in enumerate(directories):
            status = path.lstat()
            identities.append((status.st_dev, status.st_ino))
            for other in directories[i+1:]:
                remapping.check.separate_directories(path, other)
        if len(set(identities)) != len(directories):
            raise InputError(REFUSAL)
        prefixes = scanner.selected_prefixes(locations)
        claim = load_carrier(carrier)
        if (claim['schema'] != 'ptlc-offline-rust-path-remapping-pair-v1'
                or scanner.encoded(claim['selected_profile']) != scanner.encoded(remapping.selected_profile())
                or claim['artifact_publication'] != 'KEEP BOTH ARTIFACTS PRIVATE'):
            raise InputError(REFUSAL)
        scanner.fields(claim['builds'], scanner.SELECTIONS)
        comparison = claim['comparison']
        if comparison['schema'] != 'ptlc-offline-selected-artifact-prefix-evidence-v1':
            raise InputError(REFUSAL)
        scanner.fields(comparison['artifacts'], scanner.SELECTIONS)
        arguments = []
        for name in scanner.SELECTIONS:
            build, row = claim['builds'][name], comparison['artifacts'][name]
            if (build['schema'] != 'ptlc-offline-selected-worker-build-evidence-v1'
                    or build['source_commit'] != remapping.original.COMMIT
                    or build['witness_manifest_sha256'] != remapping.original.MANIFEST_SHA256
                    or build['resolution_baseline_sha256'] != remapping.original.BASELINE_SHA256
                    or build['platform'] != platform):
                raise InputError(REFUSAL)
            scanner.fields(row, ('sha256', 'bytes', 'selected_prefix_presence', 'present_role_count'))
            scanner.pin(row['sha256'], row['bytes'])
            scanner.fields(row['selected_prefix_presence'], scanner.ROLES)
            if (any(type(value) is not bool for value in row['selected_prefix_presence'].values())
                    or type(row['present_role_count']) is not int
                    or row['present_role_count'] != sum(row['selected_prefix_presence'].values())):
                raise InputError(REFUSAL)
            measured = build['measured_inputs']['original-response-worker']
            if (type(measured['bytes']) is not int or measured['bytes'] != row['bytes']
                    or measured['selected_sha256'] != row['sha256']
                    or measured['measured_sha256'] != row['sha256']):
                raise InputError(REFUSAL)
            arguments.extend((paths[name], row['sha256'], row['bytes']))
        if any(claim['builds']['first'][field] != claim['builds']['second'][field]
               for field in remapping.PAIR_FIELDS):
            raise InputError(REFUSAL)
        result = sections.inspect(*arguments, prefixes)
        if (any(result['artifacts'][name]['measured'] != comparison['artifacts'][name]
                for name in scanner.SELECTIONS)
                or type(comparison['byte_relation']) is not str
                or result['byte_relation'] != comparison['byte_relation']):
            raise InputError(REFUSAL)
        result.update(carrier_binding='CANONICAL SELECTED CARRIER MATCH; DRIVER AND BUILD ORIGIN NOT ATTESTED',
                      previous_math_launch_binding='NOT ATTESTED; NO WORKER IS LAUNCHED OR REQUALIFIED')
        return result
    except (InputError, OSError, ValueError, TypeError, KeyError, RuntimeError):
        raise InputError(REFUSAL) from None


def main():
    try:
        parser = scanner.contents.inputs.source._Parser(description=__doc__)
        parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
        for name in scanner.SELECTIONS:
            parser.add_argument('--'+name+'-workspace', type=Path, required=True)
            parser.add_argument('--'+name+'-build-directory', type=Path, required=True)
        parser.add_argument('--cargo-home', type=Path, required=True)
        parser.add_argument('--platform', choices=remapping.check.resolution.PLATFORMS, required=True)
        parser.add_argument('--private-pair-report', type=Path, required=True)
        args = parser.parse_args()
        pairs = {name: (getattr(args, name+'_workspace').absolute(),
                        getattr(args, name+'_build_directory').absolute()) for name in scanner.SELECTIONS}
        report = qualify(args.root.absolute(), pairs, args.cargo_home.absolute(), args.platform,
                         args.private_pair_report.absolute())
        sys.stdout.buffer.write(scanner.encoded(report))
        print('PASS: bounded retained worker sections; two complete selected streams; NOT ASSESSED')
        return 0
    except (InputError, OSError, ValueError, TypeError, KeyError, RuntimeError):
        print('FAIL: '+REFUSAL, file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
