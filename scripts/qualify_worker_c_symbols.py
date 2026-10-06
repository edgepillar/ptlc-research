#!/usr/bin/env python3
"""Bind a canonical private C-pair claim to two retained symbol observations.

Existing section, symbol and debug grammars run in memory from two new streams.
Carrier agreement is not build attestation or permission to release artifacts.
"""

import json
import os
from pathlib import Path
import struct
import sys

if __package__:
    from . import qualify_worker_c_debug as driver
else:
    import qualify_worker_c_debug as driver


names = driver.names
symbols = names.symbols
scanner = driver.scanner
InputError = scanner.InputError
REFUSAL = "selected retained C-worker symbol qualification refused"
MAX_CARRIER_BYTES = 256 * 1024
TERMINAL = b"PASS: selected C debug-prefix pair; two builds; two debug-name reads; NOT ASSESSED\n"
PAIR_DECLARATIONS = dict(
    schema="ptlc-offline-c-debug-prefix-pair-v1",
    pair_selection="TWO FRESH BUILDS; SAME COMBINED LOGICAL PROFILE AND SELECTED NATIVE BYTES",
    historical_comparison="EARLIER RUST-ONLY BUILDS REMAIN SEPARATE; NO ISOLATED CAUSAL CONTROL",
    execution_origin="TRUSTED DRIVER, HOST, BUILD SCRIPTS AND TOOLS; NOT ATTESTED",
    producer_attribution="NOT DETERMINED", artifact_publication="KEEP BOTH ARTIFACTS PRIVATE",
    reproducibility="NOT VERIFIED", source_to_worker="NOT VERIFIED",
    independent_privacy_assessment="NOT ASSESSED", application_and_core="NO-GO")
COMMON = dict(byte_comparison="COMPLETE SELECTED STREAMS",
              selection_origin="CALLER SELECTED; NOT AUTHENTICATED",
              artifact_publication="KEEP BOTH ARTIFACTS PRIVATE",
              independent_privacy_assessment="NOT ASSESSED", reproducibility="NOT VERIFIED",
              source_to_worker="NOT VERIFIED",
              filesystem="OWNED QUIESCENT INPUTS AND TRUSTED ANCESTORS; NO ATOMIC SNAPSHOT",
              application_and_core="NO-GO")
COMPARISON = dict(COMMON, schema="ptlc-offline-selected-artifact-prefix-evidence-v1",
                  outcome="SELECTED BYTE OBSERVATIONS ONLY; NOT ASSESSED",
                  prefix_scope="FOUR EXACT CALLER-SELECTED BYTE STRINGS PER ARTIFACT")
DEBUG = dict(COMMON, schema="ptlc-offline-worker-debug-name-evidence-v1",
             producer_attribution="NOT DETERMINED",
             pool_validation="TWO SELECTED NUL-DELIMITED ELF POOLS ONLY; NO DWARF REFERENCES/FORMS/VERSION VALIDATION",
             symbol_agreement="PRECEDING SYMBOL GRAMMAR IN MEMORY FROM THE SAME STREAMS; NO EXTRA SYMBOL ACQUISITIONS",
             name_semantics="DECLARED TYPE/TERMINATION ONLY; NO TEXT, PATH, STAB SEQUENCE OR SOURCE VALIDATION")


def _same(actual, expected):
    if scanner.encoded(actual) != scanner.encoded(expected):
        raise InputError(REFUSAL)


def decode_carrier(raw):
    if (type(raw) is not bytes or not 0 < len(raw) <= MAX_CARRIER_BYTES
            or not raw.isascii() or not raw.endswith(TERMINAL)):
        raise InputError(REFUSAL)
    body = raw[:-len(TERMINAL)]
    depth, quoted, escaped = 0, False, False
    for byte in body:
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

    def number(text):
        if len(text) > 10 or text.startswith("-"):
            raise InputError(REFUSAL)
        return int(text)

    def refused(_):
        raise InputError(REFUSAL)

    try:
        value = json.loads(body.decode("ascii"), parse_int=number,
                           parse_float=refused, parse_constant=refused)
        if type(value) is not dict or body != scanner.encoded(value):
            raise InputError(REFUSAL)
        return value
    except (ValueError, TypeError, RuntimeError):
        raise InputError(REFUSAL) from None


def load_carrier(path):
    scanner.owned_file(path, MAX_CARRIER_BYTES, private=True)
    with scanner.contents.regular(path, MAX_CARRIER_BYTES) as handle:
        state = os.fstat(handle.fileno())
        if state.st_uid != os.geteuid() or state.st_mode & 0o077:
            raise InputError(REFUSAL)
        return decode_carrier(handle.read(MAX_CARRIER_BYTES+1))


def _fixed(value, declarations, variable):
    scanner.fields(value, (*declarations, *variable))
    _same({key: value[key] for key in declarations}, declarations)


def _measured(row):
    scanner.fields(row, ("sha256", "bytes", "selected_prefix_presence", "present_role_count"))
    scanner.pin(row["sha256"], row["bytes"])
    scanner.fields(row["selected_prefix_presence"], scanner.ROLES)
    if (row["bytes"] > symbols.sections.MAX_BYTES
            or any(type(value) is not bool for value in row["selected_prefix_presence"].values())
            or type(row["present_role_count"]) is not int
            or row["present_role_count"] != sum(row["selected_prefix_presence"].values())):
        raise InputError(REFUSAL)


def _input_measurement(row, bound):
    scanner.fields(row, ("status", "bytes", "selected_sha256", "measured_sha256"))
    scanner.pin(row["selected_sha256"], row["bytes"])
    if (row["bytes"] > bound or row["selected_sha256"] != row["measured_sha256"]
            or row["status"] != "SELECTED BYTES MATCH"):
        raise InputError(REFUSAL)


def _claims(claim, platform):
    _fixed(claim, PAIR_DECLARATIONS, ("selected_profile", "builds", "comparison", "debug_names"))
    _same(claim["selected_profile"], driver.selected_profile())
    scanner.fields(claim["builds"], scanner.SELECTIONS)
    comparison, debug = claim["comparison"], claim["debug_names"]
    _fixed(comparison, COMPARISON, ("artifacts", "byte_relation"))
    _fixed(debug, DEBUG, ("artifacts", "byte_relation"))
    if (type(comparison["byte_relation"]) is not str
            or comparison["byte_relation"] not in ("MATCH", "DIFFER")
            or debug["byte_relation"] != comparison["byte_relation"]):
        raise InputError(REFUSAL)
    for report in (comparison, debug):
        scanner.fields(report["artifacts"], scanner.SELECTIONS)
    for name in scanner.SELECTIONS:
        row = comparison["artifacts"][name]
        _measured(row)
        framed = debug["artifacts"][name]
        scanner.fields(framed, ("measured", "format", "group_presence"))
        _same(framed["measured"], row)
        if type(framed["format"]) is not str or framed["format"] not in ("ELF64 LITTLE ENDIAN", "THIN MACH-O64 LITTLE ENDIAN"):
            raise InputError(REFUSAL)
        scanner.fields(framed["group_presence"], scanner.ROLES)
        for role, groups in framed["group_presence"].items():
            scanner.fields(groups, names.GROUPS)
            if (any(type(value) is not bool for value in groups.values())
                    or any(groups.values()) != row["selected_prefix_presence"][role]):
                raise InputError(REFUSAL)
        build = claim["builds"][name]
        required = dict(schema="ptlc-offline-selected-worker-build-evidence-v1",
                        source_commit=driver.rust.original.COMMIT,
                        witness_manifest_sha256=driver.rust.original.MANIFEST_SHA256,
                        resolution_baseline_sha256=driver.rust.original.BASELINE_SHA256,
                        platform=platform, prepared_source_files=55)
        _same({key: build[key] for key in required}, required)
        for field in ("resolution_sha256", "selected_contents_sha256"):
            scanner.pin(build[field], 1)
        root = build["claims"]["selected_root"]
        _same(root["profile"], driver.check.ROOT_PROFILE)
        _same(root["features"], [])
        if (root["fresh"] is not False
                or root["executable_relative_path"] != platform+"/debug/examples/"+driver.check.WORKER):
            raise InputError(REFUSAL)
        measured = build["measured_inputs"]
        worker = measured["original-response-worker"]
        _input_measurement(worker, symbols.sections.MAX_BYTES)
        if worker["selected_sha256"] != row["sha256"] or worker["bytes"] != row["bytes"]:
            raise InputError(REFUSAL)
        for role in driver.check.NATIVE_ROLES:
            _input_measurement(measured[role], driver.check.inputs.MAX_NATIVE_BYTES)
    first, second = (claim["builds"][name] for name in scanner.SELECTIONS)
    for field in driver.rust.PAIR_FIELDS:
        _same(first[field], second[field])
    _same(first["claims"]["selected_root"], second["claims"]["selected_root"])
    for role in driver.check.NATIVE_ROLES:
        _same(first["measured_inputs"][role], second["measured_inputs"][role])


def _agree(symbol, debug):
    if symbol["format"] != debug["format"]:
        raise InputError(REFUSAL)
    if symbol["format"] != "THIN MACH-O64 LITTLE ENDIAN":
        return
    for role in scanner.ROLES:
        s = [symbol["group_presence"][role][group] for group in symbols.GROUPS]
        d = [debug["group_presence"][role][group] for group in names.GROUPS]
        if (s[0] != d[4] or (s[3] or s[5]) and not d[7]
                or (d[5] or d[6]) and not s[4]
                or s[4] and not any(d[5:8]) or d[7] and not any(s[3:6])
                or any(s[3:6]) != any(d[5:8])):
            raise InputError(REFUSAL)


def _observe(paths, prefixes, claim):
    rows = claim["comparison"]["artifacts"]
    for path in paths.values():
        scanner.owned_file(path, symbols.sections.MAX_BYTES)
    with scanner.contents.regular(paths["first"], symbols.sections.MAX_BYTES) as left:
        with scanner.contents.regular(paths["second"], symbols.sections.MAX_BYTES) as right:
            states = [os.fstat(handle.fileno()) for handle in (left, right)]
            if ((states[0].st_dev, states[0].st_ino) == (states[1].st_dev, states[1].st_ino)
                    or any(state.st_uid != os.geteuid() for state in states)
                    or [state.st_size for state in states] != [rows[name]["bytes"] for name in scanner.SELECTIONS]):
                raise InputError(REFUSAL)
            bodies = [handle.read(rows[name]["bytes"]+1) for name, handle in zip(scanner.SELECTIONS, (left, right))]
            artifacts = {}
            for name, raw in zip(scanner.SELECTIONS, bodies):
                row = rows[name]
                scan = scanner._Scan(prefixes[name]); scan.feed(raw)
                measured = scan.report(row["sha256"], row["bytes"])
                _same(measured, row)
                symbol, debug = symbols._localize(raw, prefixes[name]), names._localize(raw, prefixes[name])
                _same(dict(measured=measured, **debug), claim["debug_names"]["artifacts"][name])
                if any(any(symbol["group_presence"][role].values()) != measured["selected_prefix_presence"][role]
                       for role in scanner.ROLES):
                    raise InputError(REFUSAL)
                _agree(symbol, debug)
                artifacts[name] = dict(measured=measured, **symbol)
            relation = "MATCH" if bodies[0] == bodies[1] else "DIFFER"
            if relation != claim["comparison"]["byte_relation"]:
                raise InputError(REFUSAL)
    return dict(COMMON, schema="ptlc-offline-c-worker-symbol-reference-evidence-v1",
                artifacts=artifacts, byte_relation=relation,
                reference_validation="UNCHANGED BOUNDED SYMBOL GRAMMAR; NO FULL SYMBOL/VALUE/LOADER VALIDATION",
                debug_agreement="EXACT CARRIER DEBUG ROWS REVALIDATED IN MEMORY FROM THE SAME TWO STREAMS",
                carrier_binding="CANONICAL C-PAIR CLAIM MATCH; HISTORICAL INPUTS AND EXECUTION NOT REQUALIFIED OR ATTESTED",
                previous_math_launch_binding="NOT ATTESTED; NO WORKER IS LAUNCHED OR REQUALIFIED",
                producer_attribution="NOT DETERMINED", text_and_debug_decoding="NOT PERFORMED")


def qualify(root, selections, home, platform, carrier):
    try:
        if type(platform) is not str or platform not in driver.check.resolution.PLATFORMS:
            raise InputError(REFUSAL)
        scanner.fields(selections, scanner.SELECTIONS)
        locations, paths, directories = {}, {}, []
        for name in scanner.SELECTIONS:
            pair = selections[name]
            if type(pair) is not tuple or len(pair) != 2:
                raise InputError(REFUSAL)
            locations[name] = driver.rust.selected_locations(root, *pair, home)
            driver.c_flags(locations[name])
            directories.extend(pair)
            paths[name] = pair[1]/platform/"debug/examples"/driver.check.WORKER
        for index, path in enumerate(directories):
            for other in directories[index+1:]:
                driver.check.separate_directories(path, other)
                a, b = path.lstat(), other.lstat()
                if (a.st_dev, a.st_ino) == (b.st_dev, b.st_ino):
                    raise InputError(REFUSAL)
        prefixes = scanner.selected_prefixes(locations)
        claim = load_carrier(carrier)
        _claims(claim, platform)
        return _observe(paths, prefixes, claim)
    except (InputError, OSError, ValueError, TypeError, KeyError, RuntimeError, struct.error):
        raise InputError(REFUSAL) from None


def main():
    try:
        parser = driver.check.inputs.source._Parser(description=__doc__)
        parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
        for name in scanner.SELECTIONS:
            parser.add_argument("--"+name+"-workspace", type=Path, required=True)
            parser.add_argument("--"+name+"-build-directory", type=Path, required=True)
        parser.add_argument("--cargo-home", type=Path, required=True)
        parser.add_argument("--platform", choices=driver.check.resolution.PLATFORMS, required=True)
        parser.add_argument("--private-pair-report", type=Path, required=True)
        args = parser.parse_args()
        pairs = {name: (getattr(args, name+"_workspace").absolute(),
                        getattr(args, name+"_build_directory").absolute()) for name in scanner.SELECTIONS}
        report = qualify(args.root.absolute(), pairs, args.cargo_home.absolute(), args.platform,
                         args.private_pair_report.absolute())
        sys.stdout.buffer.write(scanner.encoded(report))
        print("PASS: retained C-worker symbols; two selected streams; NOT ASSESSED")
        return 0
    except (InputError, OSError, ValueError, TypeError, KeyError, RuntimeError):
        print("FAIL: "+REFUSAL, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
