#!/usr/bin/env python3
"""Select two private Mach-O builds with one explicit linker object prefix.

The preceding target-only Rust and C debug profiles remain separate. Selected
tools, build scripts and the host are trusted; workers are not launched here.
"""

import os
from pathlib import Path
import re
import sys

if __package__:
    from . import qualify_worker_c_debug as c
    from . import check_worker_symbols as symbols
else:
    import qualify_worker_c_debug as c
    import check_worker_symbols as symbols


rust = c.rust
check = c.check
scanner = c.scanner
InputError = check.InputError
PLATFORM = "aarch64-apple-darwin"
REFUSAL = "selected Mach-O object-prefix qualification refused"
TERMINAL = "PASS: selected Mach-O object-prefix pair; two builds; two symbol reads; NOT ASSESSED"


def object_prefix(value):
    """Require a caller-selected literal directory, preserving its final slash."""
    if (type(value) is not str or not scanner.MIN_PREFIX_BYTES <= len(value) <= scanner.MAX_PREFIX_BYTES
            or re.fullmatch(r"[A-Za-z0-9_./-]+/", value) is None):
        raise InputError(REFUSAL)
    check.resolution.absolute(value[:-1])
    directory = Path(value[:-1])
    check.resolution.content.directory(directory)
    if directory.lstat().st_uid != os.geteuid():
        raise InputError(REFUSAL)
    return value


def encoded_flags(locations, prefix):
    # One comma-joined linker-driver argument follows the four unchanged rules.
    return rust.encoded_flags(locations)+"\x1f-Clink-arg=-Wl,-oso_prefix,"+object_prefix(prefix)


def selected_profile():
    return dict(schema="ptlc-offline-macho-object-prefix-profile-v1",
                preceding_profile=c.selected_profile(), platform=PLATFORM,
                linker_option="-oso_prefix", linker_option_count=1,
                linker_transport="ONE -Clink-arg=-Wl,-oso_prefix,PREFIX/ TOKEN; CARGO_ENCODED_RUSTFLAGS UNIT SEPARATOR",
                prefix_scope="ONE EXPLICIT OWNED ABSOLUTE DIRECTORY WITH TRAILING SLASH; NO INFERENCE OR DOT SHORTHAND",
                prefix_alphabet="ASCII LETTERS, DIGITS, UNDERSCORE, DOT, SLASH AND HYPHEN ONLY",
                target_scope="EXPLICIT NATIVE APPLE TARGET ONLY; SELECTED C COMPILER IS LINKER DRIVER",
                host_and_support_coverage="NOT COMPLETE; NO ADDITIONAL HOST RUST OR SUPPORT REMAPPING",
                stripping_or_rewriting="NONE", profile_origin="FIXED DRIVER SELECTION; NOT ARGUMENT-CONSUMPTION ATTESTATION")


def qualify(root, selections, home, platform, tools, prefix):
    try:
        if type(platform) is not str or platform != PLATFORM:
            raise InputError(REFUSAL)
        pairs, locations = rust.validate_pair(root, selections, home, platform, tools)
        tools = {role: tools[role] for role in check.NATIVE_ROLES}
        prefix = object_prefix(prefix)
        c_flags = {name: c.c_flags(locations[name]) for name in scanner.SELECTIONS}
        flags = {name: encoded_flags(locations[name], prefix) for name in scanner.SELECTIONS}
        builds = {}
        for name in scanner.SELECTIONS:
            with c._c_environment(c_flags[name]):
                builds[name] = rust._build(root, *pairs[name], home, platform, tools, flags[name])
        first, second = (builds[name] for name in scanner.SELECTIONS)
        if (any(first[field] != second[field] for field in rust.PAIR_FIELDS)
                or first["claims"]["selected_root"] != second["claims"]["selected_root"]
                or any(first["measured_inputs"][role] != second["measured_inputs"][role] for role in check.NATIVE_ROLES)):
            raise InputError(REFUSAL)
        arguments = []
        for name in scanner.SELECTIONS:
            worker = pairs[name][1]/platform/"debug/examples"/check.WORKER
            measured = builds[name]["measured_inputs"]["original-response-worker"]
            arguments.extend((worker, measured["selected_sha256"], measured["bytes"]))
        comparison = scanner.inspect(*arguments, locations)
        referenced = symbols.inspect(*arguments, locations)
        if (comparison["byte_relation"] != referenced["byte_relation"]
                or any(referenced["artifacts"][name]["format"] != "THIN MACH-O64 LITTLE ENDIAN"
                       or comparison["artifacts"][name] != referenced["artifacts"][name]["measured"]
                       for name in scanner.SELECTIONS)):
            raise InputError(REFUSAL)
        return dict(schema="ptlc-offline-macho-object-prefix-pair-v1", selected_profile=selected_profile(),
                    builds=builds, comparison=comparison, symbols=referenced,
                    pair_selection="TWO FRESH BUILDS; SAME COMBINED LOGICAL PROFILE, EXPLICIT OBJECT PREFIX AND SELECTED NATIVE BYTES",
                    historical_comparison="EARLIER RUST AND C PAIRS REMAIN SEPARATE; NO ISOLATED CAUSAL CONTROL",
                    execution_origin="TRUSTED DRIVER, HOST, BUILD SCRIPTS AND TOOLS; NOT ATTESTED",
                    producer_attribution="NOT DETERMINED", artifact_publication="KEEP BOTH ARTIFACTS PRIVATE",
                    reproducibility="NOT VERIFIED", source_to_worker="NOT VERIFIED",
                    independent_privacy_assessment="NOT ASSESSED", application_and_core="NO-GO")
    except (InputError, rust.original.WorkerError, OSError, ValueError, TypeError, KeyError, UnicodeError, RuntimeError,
            EOFError, check.resolution.content.tarfile.TarError, check.resolution.content.zipfile.BadZipFile,
            check.resolution.content.zlib.error):
        raise InputError(REFUSAL) from None


def main():
    try:
        parser = check.inputs.source._Parser(description=__doc__)
        parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
        for name in scanner.SELECTIONS:
            parser.add_argument("--"+name+"-workspace", type=Path, required=True)
            parser.add_argument("--"+name+"-build-directory", type=Path, required=True)
        for name in ("cargo-home",)+check.NATIVE_ROLES:
            parser.add_argument("--"+name, type=Path, required=True)
        parser.add_argument("--platform", choices=(PLATFORM,), required=True)
        parser.add_argument("--object-prefix", required=True)
        args = parser.parse_args()
        pairs = {name: (getattr(args, name+"_workspace").absolute(),
                        getattr(args, name+"_build_directory").absolute()) for name in scanner.SELECTIONS}
        tools = {role: getattr(args, role.replace("-", "_")).resolve() for role in check.NATIVE_ROLES}
        report = qualify(args.root.resolve(), pairs, args.cargo_home.absolute(), args.platform, tools, args.object_prefix)
        sys.stdout.buffer.write(check.encoded(report))
        print(TERMINAL)
        return 0
    except (InputError, rust.original.WorkerError, OSError, ValueError, TypeError, KeyError, UnicodeError, RuntimeError,
            EOFError, check.resolution.content.tarfile.TarError, check.resolution.content.zipfile.BadZipFile,
            check.resolution.content.zlib.error):
        print("FAIL: "+REFUSAL, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
