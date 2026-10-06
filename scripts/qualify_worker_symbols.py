#!/usr/bin/env python3
"""Revalidate a private remapping carrier, then read bounded symbol references.

Two preceding section acquisitions and two new symbol acquisitions remain
separate; no native worker, compiler or analysis executable is launched.
"""

from pathlib import Path
import sys

if __package__:
    from . import check_worker_symbols as symbols
    from . import qualify_worker_sections as previous
else:
    import check_worker_symbols as symbols
    import qualify_worker_sections as previous


scanner = symbols.scanner
InputError = symbols.InputError
REFUSAL = 'selected retained worker symbol qualification refused'


def qualify(root, selections, home, platform, carrier):
    try:
        earlier = previous.qualify(root, selections, home, platform, carrier)
        locations = {name: previous.remapping.selected_locations(root, selections[name][0], selections[name][1], home)
                     for name in scanner.SELECTIONS}
        arguments = []
        for name in scanner.SELECTIONS:
            row = earlier['artifacts'][name]['measured']
            path = selections[name][1]/platform/'debug/examples'/previous.remapping.check.WORKER
            arguments.extend((path, row['sha256'], row['bytes']))
        report = symbols.inspect(*arguments, scanner.selected_prefixes(locations))
        if (report['byte_relation'] != earlier['byte_relation']
                or any(report['artifacts'][name]['measured'] != earlier['artifacts'][name]['measured']
                       or report['artifacts'][name]['format'] != earlier['artifacts'][name]['format']
                       for name in scanner.SELECTIONS)):
            raise InputError(REFUSAL)
        report.update(carrier_binding='CANONICAL SELECTED CARRIER MATCH; DRIVER AND BUILD ORIGIN NOT ATTESTED',
                      section_agreement='MATCHED PRECEDING SELECTED SECTION OBSERVATION; SEPARATE READS, NO ATOMIC SNAPSHOT',
                      previous_math_launch_binding='NOT ATTESTED; NO WORKER IS LAUNCHED OR REQUALIFIED')
        return report
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
        parser.add_argument('--platform', choices=previous.remapping.check.resolution.PLATFORMS, required=True)
        parser.add_argument('--private-pair-report', type=Path, required=True)
        args = parser.parse_args()
        pairs = {name: (getattr(args, name+'_workspace').absolute(), getattr(args, name+'_build_directory').absolute())
                 for name in scanner.SELECTIONS}
        report = qualify(args.root.absolute(), pairs, args.cargo_home.absolute(), args.platform, args.private_pair_report.absolute())
        sys.stdout.buffer.write(scanner.encoded(report))
        print('PASS: bounded retained worker symbol references; two selected streams; NOT ASSESSED')
        return 0
    except (InputError, OSError, ValueError, TypeError, KeyError, RuntimeError):
        print('FAIL: '+REFUSAL, file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
