#!/usr/bin/env python3
"""Compare bounded Cargo metadata claims with fixed inputs and a selected baseline.

Native Git inspects local immutable objects; no Cargo, compiler, build script,
dependency, signer or worker is invoked. A matching claim is not authenticated
resolution, compiled closure or build provenance.
"""

import hashlib
import json
from pathlib import Path
import re
import sys

if __package__:
    from . import check_dependency_contents as content
    from . import qualify_dependency_contents as caches
else:
    import check_dependency_contents as content
    import qualify_dependency_contents as caches


inputs = content.inputs
InputError = inputs.InputError
encoded = inputs.encoded
BASELINE = "qualification/fixtures/cargo_resolution.json"
PLATFORMS = ("aarch64-apple-darwin", "x86_64-unknown-linux-gnu")
MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_VALUES = 100000
MAX_DEPTH = 32
MAX_EDGES = 8192
MAX_TARGETS = 4096
MAX_SELECTED_FILES = 1024
MAX_SELECTED_FILE_BYTES = 64 * 1024 * 1024
TOKEN = r"[A-Za-z0-9_][A-Za-z0-9_+-]{0,127}"
GIT_MANIFESTS = {
    "musig2": "Cargo.toml", "schnorr_fun": "schnorr_fun/Cargo.toml",
    "secp256kfun": "secp256kfun/Cargo.toml",
    "secp256kfun_arithmetic_macros": "arithmetic_macros/Cargo.toml",
    "sigma_fun": "sigma_fun/Cargo.toml", "vrf_fun": "vrf_fun/Cargo.toml",
}
TOP_FIELDS = {"packages", "workspace_members", "workspace_default_members", "resolve",
              "target_directory", "version", "workspace_root", "metadata"}
PACKAGE_FIELDS = {"name", "version", "id", "license", "license_file", "description", "source",
                  "dependencies", "targets", "features", "manifest_path", "metadata", "publish",
                  "authors", "categories", "default_run", "rust_version", "keywords", "readme",
                  "repository", "homepage", "documentation", "edition", "links"}
TARGET_FIELDS = {"kind", "crate_types", "name", "src_path", "edition", "doc", "doctest", "test"}
KINDS = {"lib", "rlib", "dylib", "cdylib", "staticlib", "proc-macro", "bin", "example",
         "test", "bench", "custom-build"}
ROOT_DEPENDENCIES = {
    "bitcoin": ("=0.32.7", ["std"]), "musig2": ("*", ["secp256k1"]),
    "schnorr_fun": ("*", ["std"]), "serde_json": ("^1.0", ["std"]),
    "sha2": ("=0.10.9", []),
}


def json_claim(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_JSON_BYTES:
        raise InputError("metadata byte bound exceeded")
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
        elif byte in (91, 123):
            depth += 1
            if depth > MAX_DEPTH:
                raise InputError("metadata depth exceeded")
        elif byte in (93, 125):
            depth -= 1
    def pairs(items):
        if len(items) > inputs.MAX_PACKAGES:
            raise InputError("metadata object bound exceeded")
        result = {}
        for key, value in items:
            if key in result:
                raise InputError("duplicate metadata key")
            result[key] = value
        return result
    def integer(text):
        if len(text) > 20:
            raise InputError("metadata integer bound exceeded")
        return int(text)
    def unsupported(_):
        raise InputError("noninteger metadata number refused")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                           parse_int=integer, parse_float=unsupported, parse_constant=unsupported)
    except (ValueError, UnicodeError, RecursionError):
        raise InputError("invalid metadata encoding") from None
    pending, count = [(value, 0)], 0
    while pending:
        item, level = pending.pop()
        count += 1
        if count > MAX_VALUES or level > MAX_DEPTH:
            raise InputError("metadata value bound exceeded")
        if type(item) is dict:
            for key, child in item.items():
                if len(key) > 256:
                    raise InputError("metadata key bound exceeded")
                pending.append((child, level + 1))
        elif type(item) is list:
            pending.extend((child, level + 1) for child in item)
        elif type(item) is str:
            if len(item) > 8192 or any(0xD800 <= ord(c) <= 0xDFFF for c in item):
                raise InputError("metadata string bound exceeded")
        elif item is not None and type(item) not in (int, bool):
            raise InputError("unsupported metadata value")
    return value


def exact(value, fields):
    if type(value) is not dict or set(value) != fields:
        raise InputError("metadata fields differ")


def token(value):
    if type(value) is not str or re.fullmatch(TOKEN, value) is None:
        raise InputError("unsupported metadata symbol")
    return value


def symbols(value, pattern=TOKEN):
    if (type(value) is not list or len(value) > inputs.MAX_PACKAGES
            or any(type(v) is not str or re.fullmatch(pattern, v) is None for v in value)
            or len(value) != len(set(value))):
        raise InputError("metadata symbols differ")
    return sorted(value)


def opaque(value):
    if (type(value) is not str or not 0 < len(value) <= 2048 or not value.isascii()
            or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        raise InputError("invalid opaque package ID")
    return value


def absolute(value):
    if (type(value) is not str or not value.isascii() or len(value) > 2048
            or any(ord(c) < 32 or ord(c) == 127 for c in value)
            or "\\" in value or ":" in value or not value.startswith("/")
            or any(p in {"", ".", ".."} for p in value.split("/")[1:])):
        raise InputError("unsupported metadata path")
    return Path(value)


def relative(value, parent):
    path = absolute(value)
    try:
        name = path.relative_to(parent).as_posix()
    except ValueError:
        raise InputError("metadata source escaped selection") from None
    content.safe_name(name)
    return name


def key(row):
    return row["name"], row["version"], row.get("source")


def identity(row):
    return row["name"] + "@" + row["version"] + " (" + (row.get("source") or "selected-local-source") + ")"


def lock_edges(packages):
    selected = {}
    for row in packages:
        dependencies = set()
        for entry in row.get("dependencies", []):
            parts = entry.split(" ", 2)
            matches = [p for p in packages if p["name"] == parts[0]]
            if len(parts) > 1:
                if re.fullmatch(inputs.VERSION, parts[1]) is None:
                    raise InputError("unsupported lock edge version")
                matches = [p for p in matches if p["version"] == parts[1]]
            if len(parts) > 2:
                if not parts[2].startswith("(") or not parts[2].endswith(")"):
                    raise InputError("unsupported lock edge source")
                matches = [p for p in matches if p.get("source") == parts[2][1:-1]]
            if len(matches) != 1 or key(matches[0]) in dependencies:
                raise InputError("ambiguous or duplicate lock edge")
            dependencies.add(key(matches[0]))
        selected[key(row)] = dependencies
    return selected


def file_digest(path, measured):
    if path not in measured["hashes"]:
        if len(measured["hashes"]) >= MAX_SELECTED_FILES:
            raise InputError("selected source file count exceeded")
        remaining = MAX_SELECTED_FILE_BYTES - measured["bytes"]
        bound = min(content.MAX_FILE_BYTES, remaining)
        with content.regular(path, bound) as handle:
            result = content.digest_stream(handle, bound)
        measured["bytes"] += result["bytes"]
        measured["hashes"][path] = result["sha256"]
    return measured["hashes"][path]


def package_locations(packages, workspace, registry, checkouts):
    result = {}
    for row in packages:
        if row["kind"] == "registry-archive":
            directory = registry / (row["name"] + "-" + row["version"])
            manifest = directory / "Cargo.toml"
        elif row["kind"] == "local-record":
            directory, manifest = workspace / "qualification", workspace / "qualification/Cargo.toml"
        else:
            name = GIT_MANIFESTS.get(row["name"])
            if name is None:
                raise InputError("Git package manifest not selected")
            manifest = checkouts[row["source"].split("#")[1]] / name
            directory = manifest.parent
        result[key(row)] = directory, manifest
    return result


def root_dependencies(value, packages):
    if type(value) is not list or len(value) != len(ROOT_DEPENDENCIES):
        raise InputError("local dependency declarations differ")
    seen = set()
    for row in value:
        exact(row, {"name", "source", "req", "kind", "rename", "optional", "uses_default_features",
                    "features", "target", "registry"})
        name = row["name"]
        if type(name) is not str or name not in ROOT_DEPENDENCIES or name in seen:
            raise InputError("local dependency identity differs")
        seen.add(name)
        requirement, features = ROOT_DEPENDENCIES[name]
        candidates = [p for p in packages if p["name"] == name]
        if len(candidates) != 1:
            raise InputError("local dependency selection differs")
        expected_source = candidates[0].get("source")
        if candidates[0]["kind"] == "git-record":
            expected_source = expected_source.split("#")[0]
        if (row["source"] != expected_source or row["req"] != requirement or row["kind"] != "dev"
                or row["rename"] is not None or row["optional"] is not False
                or row["uses_default_features"] is not False or symbols(row["features"]) != features
                or row["target"] is not None or row["registry"] is not None):
            raise InputError("local dependency declaration differs")


def _normalize(raw, packages, workspace, registry, checkouts):
    value = json_claim(raw)
    exact(value, TOP_FIELDS)
    if type(value["version"]) is not int or value["version"] != 1:
        raise InputError("metadata format version differs")
    root_path = workspace / "qualification"
    if absolute(value["workspace_root"]) != root_path:
        raise InputError("selected workspace differs")
    absolute(value["target_directory"])
    reported = value["packages"]
    if type(reported) is not list or not 0 < len(reported) <= inputs.MAX_PACKAGES:
        raise InputError("metadata package bound exceeded")
    fixed = {key(p): p for p in packages}
    if len(fixed) != len(packages):
        raise InputError("duplicate selected package")
    locations = package_locations(packages, workspace, registry, checkouts)
    allowed_edges = lock_edges(packages)
    measured_files = {"bytes": 0, "hashes": {}}
    normalized, ids, features, observed, targets_count, local_id = {}, {}, {}, set(), 0, None
    for package in reported:
        exact(package, PACKAGE_FIELDS)
        selected_key = key(package)
        if selected_key not in fixed or selected_key in observed:
            raise InputError("reported package differs from selected lock")
        observed.add(selected_key)
        row = fixed[selected_key]
        package_id = opaque(package["id"])
        if package_id in ids:
            raise InputError("duplicate opaque package ID")
        ids[package_id] = selected_key
        directory, manifest = locations[selected_key]
        if absolute(package["manifest_path"]) != manifest:
            raise InputError("selected package manifest differs")
        declarations = package["features"]
        if type(declarations) is not dict or len(declarations) > inputs.MAX_PACKAGES:
            raise InputError("feature declarations exceed bound")
        declarations = {token(n): symbols(v, r"[A-Za-z0-9_][A-Za-z0-9_:?/-]{0,255}")
                        for n, v in declarations.items()}
        features[selected_key] = declarations
        targets = package["targets"]
        if type(targets) is not list or not targets or len(targets) > inputs.MAX_PACKAGES:
            raise InputError("target declarations exceed bound")
        result, seen = [], set()
        for target in targets:
            if (type(target) is not dict or set(target) not in (TARGET_FIELDS, TARGET_FIELDS | {"required-features"})
                    or any(type(target[n]) is not bool for n in ("doc", "doctest", "test"))
                    or target["edition"] not in {"2015", "2018", "2021", "2024"}):
                raise InputError("unsupported target declaration")
            name = token(target["name"])
            kinds, crate_types = symbols(target["kind"]), symbols(target["crate_types"])
            if not kinds or not crate_types or set(kinds + crate_types) - KINDS:
                raise InputError("unsupported target kind")
            source_path = relative(target["src_path"], directory)
            target_key = (name, tuple(kinds), source_path)
            if target_key in seen:
                raise InputError("duplicate declared target")
            seen.add(target_key)
            targets_count += 1
            if targets_count > MAX_TARGETS:
                raise InputError("aggregate targets exceed bound")
            required = symbols(target.get("required-features", []))
            if set(required) - set(declarations):
                raise InputError("unknown required target feature")
            result.append(dict(name=name, kind=kinds, crate_types=crate_types, source_path=source_path,
                               source_sha256=file_digest(directory/source_path, measured_files), edition=target["edition"],
                               doc=target["doc"], doctest=target["doctest"], test=target["test"], required_features=required))
        if row["kind"] == "local-record":
            if local_id is not None or package["name"] != "ptlc-primitive-qualification" or package["version"] != "0.0.0":
                raise InputError("selected local package differs")
            local_id = package_id
            root_dependencies(package["dependencies"], packages)
            worker = [t for t in result if t["name"] == "verify_original_read_response"]
            if (len(worker) != 1 or worker[0]["kind"] != ["example"] or worker[0]["crate_types"] != ["bin"]
                    or worker[0]["source_path"] != "examples/verify_original_read_response.rs"
                    or worker[0]["edition"] != "2024" or worker[0]["required_features"]):
                raise InputError("selected worker target differs")
        normalized[identity(row)] = dict(name=row["name"], version=row["version"], source=row.get("source"),
                                        source_kind=row["kind"], manifest_sha256=file_digest(manifest, measured_files),
                                        declared_feature_names=sorted(declarations),
                                        declared_features_sha256=hashlib.sha256(encoded(declarations)).hexdigest(),
                                        targets=sorted(result, key=lambda r: encoded(r)))
    if local_id is None:
        raise InputError("local package missing")
    for name in ("workspace_members", "workspace_default_members"):
        if value[name] != [local_id]:
            raise InputError("workspace membership differs")
    resolve = value["resolve"]
    exact(resolve, {"nodes", "root"})
    if resolve["root"] != local_id or type(resolve["nodes"]) is not list or len(resolve["nodes"]) != len(ids):
        raise InputError("resolution root or node count differs")
    nodes, node_ids, edge_count = {}, set(), 0
    for node in resolve["nodes"]:
        exact(node, {"id", "dependencies", "deps", "features"})
        node_id = opaque(node["id"])
        if node_id not in ids or node_id in node_ids:
            raise InputError("unknown or duplicate resolution node")
        node_ids.add(node_id)
        selected_key = ids[node_id]
        enabled = symbols(node["features"])
        if set(enabled) - set(features[selected_key]):
            raise InputError("unknown enabled feature")
        dependencies = node["dependencies"]
        if (type(dependencies) is not list or len(dependencies) > inputs.MAX_PACKAGES
                or any(type(v) is not str or v not in ids for v in dependencies)
                or len(dependencies) != len(set(dependencies))):
            raise InputError("dangling or duplicate dependency reference")
        if type(node["deps"]) is not list or len(node["deps"]) > inputs.MAX_PACKAGES:
            raise InputError("dependency edge bound exceeded")
        edges, seen = [], set()
        for edge in node["deps"]:
            exact(edge, {"name", "pkg", "dep_kinds"})
            name, destination = token(edge["name"]), opaque(edge["pkg"])
            if destination not in ids or (name, destination) in seen:
                raise InputError("dangling or duplicate typed edge")
            seen.add((name, destination))
            if ids[destination] not in allowed_edges[selected_key]:
                raise InputError("typed edge absent from selected lock")
            kinds = edge["dep_kinds"]
            if type(kinds) is not list or not 0 < len(kinds) <= inputs.MAX_PACKAGES:
                raise InputError("dependency kind bound exceeded")
            normalized_kinds, kind_keys = [], set()
            for kind in kinds:
                exact(kind, {"kind", "target"})
                if kind["kind"] not in (None, "dev", "build"):
                    raise InputError("unsupported dependency kind")
                target = kind["target"]
                if target is not None and (type(target) is not str or len(target) > 512
                        or re.fullmatch(r'[A-Za-z0-9_ ()=",.-]+', target) is None):
                    raise InputError("unsupported dependency platform")
                pair = kind["kind"], target
                if pair in kind_keys:
                    raise InputError("duplicate dependency kind")
                kind_keys.add(pair)
                normalized_kinds.append(kind)
            edge_count += 1
            if edge_count > MAX_EDGES:
                raise InputError("aggregate edge bound exceeded")
            edges.append(dict(name=name, dependency=identity(fixed[ids[destination]]),
                              kinds=sorted(normalized_kinds, key=lambda r: encoded(r))))
        if set(dependencies) != {e["pkg"] for e in node["deps"]}:
            raise InputError("redundant dependency lists differ")
        nodes[identity(fixed[selected_key])] = dict(features=enabled, edges=sorted(edges, key=lambda r: encoded(r)))
    if node_ids != set(ids):
        raise InputError("package/node inventories differ")
    root_identity = identity(fixed[ids[local_id]])
    pending, reachable = [root_identity], set()
    while pending:
        selected = pending.pop()
        if selected in reachable:
            continue
        reachable.add(selected)
        pending.extend(e["dependency"] for e in nodes[selected]["edges"])
    if reachable != set(nodes):
        raise InputError("unreachable resolution package")
    return dict(root=root_identity, packages=normalized, nodes=nodes, package_count=len(ids),
                node_count=len(nodes), edge_count=edge_count, target_count=targets_count,
                not_reported_lock_packages=sorted(identity(p) for p in packages if key(p) not in observed))


def normalize(raw, packages, workspace, registry, checkouts):
    try:
        return _normalize(raw, packages, workspace, registry, checkouts)
    except InputError:
        raise
    except (OSError, ValueError, TypeError, KeyError, UnicodeError):
        raise InputError("selected metadata normalization refused") from None


def selected_copy(root, commit, workspace):
    content.directory(workspace)
    content.directory(workspace/"qualification")
    _, rows, bodies = inputs.source._inventory(root, commit)
    expected = {}
    for row in rows:
        name = row["path"]
        if not name.startswith("qualification/"):
            continue
        if (inputs.source._regular(root/name, inputs.source.MAX_BLOB_BYTES) != bodies[name]
                or inputs.source._index(root, name) != bodies[name]):
            raise InputError("fixed qualification source differs")
        raw = bodies[name]
        expected[name[len("qualification/"):]] = dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), kind="regular")
    if not expected:
        raise InputError("qualification source unavailable")
    content.tree_rows(workspace/"qualification", expected)
    return len(expected)


def inspect(root, commit, manifest_sha256, workspace, metadata, home, platform, baseline_sha256):
    if platform not in PLATFORMS:
        raise InputError("platform not selected")
    inputs.source._hex(baseline_sha256, 64)
    tree, _, bodies = inputs.selected_source(root, commit, manifest_sha256)
    baseline_raw = inputs.source._regular(root/BASELINE, inputs.source.MAX_MANIFEST_BYTES)
    if (hashlib.sha256(baseline_raw).hexdigest() != baseline_sha256
            or inputs.source._index(root, BASELINE) != baseline_raw):
        raise InputError("selected resolution baseline differs")
    baseline = inputs.source._json(baseline_raw)
    exact(baseline, {"schema", "source_commit", "manifest_sha256", "selection", "profiles"})
    if (baseline_raw != encoded(baseline) or baseline["schema"] != "ptlc-selected-cargo-resolution-baseline-v1"
            or baseline["source_commit"] != commit or baseline["manifest_sha256"] != manifest_sha256
            or baseline["selection"] != "PROJECT SELECTED CARGO 1.90.0 OBSERVATIONS; NOT INDEPENDENT ATTESTATION"
            or type(baseline["profiles"]) is not dict or set(baseline["profiles"]) != set(PLATFORMS)):
        raise InputError("selected resolution baseline fields differ")
    packages = inputs.cargo_records(bodies["qualification/Cargo.lock"])
    cache = caches.one_directory(home/"registry/cache")
    registry = caches.one_directory(home/"registry/src")
    if cache.name != registry.name:
        raise InputError("registry namespaces differ")
    checkouts = caches.select_checkouts(home, packages)
    measured = content.inspect_cargo(root, commit, manifest_sha256, cache, registry, checkouts)
    copy_files = selected_copy(root, commit, workspace)
    with content.regular(metadata, MAX_JSON_BYTES) as handle:
        raw = handle.read(MAX_JSON_BYTES + 1)
    result = normalize(raw, packages, workspace, registry, checkouts)
    if encoded(result) != encoded(baseline["profiles"][platform]):
        raise InputError("reported resolution differs from selected baseline")
    return dict(schema="ptlc-offline-cargo-resolution-evidence-v1", source_commit=commit, source_tree=tree,
                witness_manifest_sha256=manifest_sha256, baseline_sha256=baseline_sha256, platform=platform,
                prepared_source_files=copy_files, selected_lock_packages=len(packages), resolution=result,
                measured_registry_trees=len(measured["registry"]), measured_git_trees=len(measured["git"]),
                selected_contents_sha256=hashlib.sha256(encoded(measured)).hexdigest(),
                outcome="SELECTED RESOLUTION BASELINE MATCH; NOT ASSESSED",
                interpretation="TOOL-REPORTED WORKSPACE RESOLUTION; NOT EXACT WORKER COMPILATION UNITS",
                generator_origin="NOT AUTHENTICATED", compiled_closure="NOT DETERMINED",
                source_to_worker="NOT VERIFIED", independent_assessment="NOT ASSESSED",
                filesystem="OWNED QUIESCENT SELECTIONS AND TRUSTED PARENTS; NO ATOMIC QUERY SNAPSHOT",
                application_and_core="NO-GO")


def main():
    try:
        parser = inputs.source._Parser(description=__doc__)
        parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
        parser.add_argument("--expect-commit", required=True)
        parser.add_argument("--expect-manifest-sha256", required=True)
        parser.add_argument("--expect-baseline-sha256", required=True)
        parser.add_argument("--workspace", type=Path, required=True)
        parser.add_argument("--metadata", type=Path, required=True)
        parser.add_argument("--cargo-home", type=Path, required=True)
        parser.add_argument("--platform", choices=PLATFORMS, required=True)
        args = parser.parse_args()
        report = inspect(args.root.resolve(), args.expect_commit, args.expect_manifest_sha256,
                         args.workspace.absolute(), args.metadata.absolute(), args.cargo_home.absolute(),
                         args.platform, args.expect_baseline_sha256)
        sys.stdout.buffer.write(encoded(report))
        return 0
    except (InputError, OSError, ValueError, TypeError, KeyError, UnicodeError, RuntimeError,
            EOFError, content.tarfile.TarError, content.zipfile.BadZipFile, content.zlib.error):
        print("FAIL: selected Cargo resolution comparison rejected", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
