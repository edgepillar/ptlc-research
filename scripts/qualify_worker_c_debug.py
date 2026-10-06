#!/usr/bin/env python3
"""Build two private workers under a separately selected C debug-prefix profile.

The existing target-only Rust rules are retained as one component. Native tools
and build scripts are trusted; fixed class observations do not identify them.
Verification workers are not launched by this driver.
"""

from contextlib import contextmanager
import os
from pathlib import Path
import re
import sys

if __package__:
    from . import qualify_worker_remapping as rust
    from . import check_worker_debug_names as names
else:
    import qualify_worker_remapping as rust
    import check_worker_debug_names as names


scanner = rust.scanner
check = rust.check
InputError = check.InputError
REFUSAL = "selected C debug-prefix qualification refused"
C_CONTROLS = ("CFLAGS", "HOST_CFLAGS", "TARGET_CFLAGS",
              "CC_SHELL_ESCAPED_FLAGS", "CC_ENABLE_DEBUG_OUTPUT")


def c_flags(locations):
    """Select four unquoted private arguments without environment interpolation."""
    copied = scanner.selected_prefixes(dict(first=locations, second=locations))["first"]
    for value in copied.values():
        try:
            text = value.decode("ascii")
        except UnicodeError:
            raise InputError(REFUSAL) from None
        check.resolution.absolute(text)
        if re.fullmatch(r"[A-Za-z0-9_./-]+", text) is None:
            raise InputError(REFUSAL)
    order = sorted(scanner.ROLES, key=lambda role: (len(copied[role]), scanner.ROLES.index(role)))
    return " ".join("-fdebug-prefix-map="+copied[role].decode("ascii")+"/="+rust.DESTINATIONS[role]
                    for role in order)


def selected_profile():
    return dict(schema="ptlc-offline-c-debug-prefix-profile-v1",
                c_option="-fdebug-prefix-map", c_option_count=4,
                c_transport="CFLAGS ONLY; FOUR UNQUOTED ASCII SPACE-SEPARATED ARGUMENTS",
                c_path_alphabet="ASCII LETTERS, DIGITS, UNDERSCORE, DOT, SLASH AND HYPHEN ONLY",
                c_environment="CLEAR SELECTED CFLAGS, HOST/TARGET CFLAGS, SHELL-PARSING AND DEBUG-OUTPUT VARIANTS; RESTORE ALL ENVIRONMENT",
                c_scope="CONSUMERS OF SELECTED CFLAGS; NOT ALL C, HOST RUST, LINKER OR SUPPORT INPUTS",
                destinations=rust.DESTINATIONS.copy(),
                from_scope="FOUR EXPLICIT DIRECTORY PREFIXES WITH TRAILING SLASH",
                ordering="SHORTEST BYTE PREFIX FIRST; FIXED ROLE ORDER BREAKS TIES",
                rust_option="--remap-path-prefix", rust_option_count=4,
                rust_transport="UNCHANGED CARGO_ENCODED_RUSTFLAGS; ASCII UNIT SEPARATOR",
                rust_scope="UNCHANGED EXPLICIT NATIVE TARGET ONLY; HOST BUILD SCRIPTS AND PROC MACROS NOT COVERED",
                root_claim_profile=check.ROOT_PROFILE.copy(), root_features=[],
                stripping_or_rewriting="NONE", profile_origin="FIXED DRIVER SELECTION; NOT EXECUTION ATTESTATION")


@contextmanager
def _c_environment(flags):
    previous = dict(os.environ)
    try:
        for name in list(os.environ):
            if any(name == base or name.startswith(base+"_") for base in C_CONTROLS):
                del os.environ[name]
        os.environ.update(CFLAGS=flags, CC_SHELL_ESCAPED_FLAGS="0")
        yield
    finally:
        os.environ.clear()
        os.environ.update(previous)


def qualify(root, selections, home, platform, tools):
    try:
        pairs, locations = rust.validate_pair(root, selections, home, platform, tools)
        tools = {role: tools[role] for role in check.NATIVE_ROLES}
        c_selection = {name: c_flags(locations[name]) for name in scanner.SELECTIONS}
        rust_selection = {name: rust.encoded_flags(locations[name]) for name in scanner.SELECTIONS}
        builds = {}
        for name in scanner.SELECTIONS:
            with _c_environment(c_selection[name]):
                builds[name] = rust._build(root, *pairs[name], home, platform, tools, rust_selection[name])
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
        debug = names.inspect(*arguments, locations)
        if (comparison["byte_relation"] != debug["byte_relation"]
                or any(comparison["artifacts"][name] != debug["artifacts"][name]["measured"]
                       for name in scanner.SELECTIONS)):
            raise InputError(REFUSAL)
        return dict(schema="ptlc-offline-c-debug-prefix-pair-v1", selected_profile=selected_profile(),
                    builds=builds, comparison=comparison, debug_names=debug,
                    pair_selection="TWO FRESH BUILDS; SAME COMBINED LOGICAL PROFILE AND SELECTED NATIVE BYTES",
                    historical_comparison="EARLIER RUST-ONLY BUILDS REMAIN SEPARATE; NO ISOLATED CAUSAL CONTROL",
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
        parser.add_argument("--platform", choices=check.resolution.PLATFORMS, required=True)
        args = parser.parse_args()
        pairs = {name: (getattr(args, name+"_workspace").absolute(),
                        getattr(args, name+"_build_directory").absolute()) for name in scanner.SELECTIONS}
        tools = {role: getattr(args, role.replace("-", "_")).resolve() for role in check.NATIVE_ROLES}
        report = qualify(args.root.resolve(), pairs, args.cargo_home.absolute(), args.platform, tools)
        sys.stdout.buffer.write(check.encoded(report))
        print("PASS: selected C debug-prefix pair; two builds; two debug-name reads; NOT ASSESSED")
        return 0
    except (InputError, rust.original.WorkerError, OSError, ValueError, TypeError, KeyError, UnicodeError, RuntimeError,
            EOFError, check.resolution.content.tarfile.TarError, check.resolution.content.zipfile.BadZipFile,
            check.resolution.content.zlib.error):
        print("FAIL: "+REFUSAL, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
