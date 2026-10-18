"""Pinned source selection for finite unsigned RPC quote research.

This module supplies no RPC transport, block admission, signing, journal source
upgrade, canonicality or current-chain authority.
"""
import hashlib
import json
from pathlib import Path
import re
import stat
import sys

CORE = 'b5f93c20c15b0622bc8ed1a175b613d6917be3b2'
TREE = 'd9083d4b7aa7b13d6dee68b09d82c11b662be1a4'
ARCHIVE_SHA256 = '7cbd6a158653bcf69923ab98bd138b3a3df4e990a90a2ea45c8de85d3a059c2b'
ARCHIVE_BYTES = 1702725
ARCHIVE_PREFIX = 'zenon-network-go-zenon-b5f93c2'
INDEX_PAYLOAD = 'a12148ebf9a765831389226888e6d2e86b00c9319a76b862313a0ae203557013'
GENERIC_PAYLOAD = 'dd0cb85dc930b0fee378345c7be9ef5b7e58ededa4ad1b7eeaf904908ed109c7'
PTLC_PAYLOAD = '21929ac8b0bcd2e7cf13da76e443174b356b793f3f28c09ee88a66c5bb1c0698'
LICENSE_SHA256 = '3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986'
MANIFEST = 'compatibility/nom_rpc_quotes_manifest.json'
SOURCE_INDEX = 'compatibility/nom_rpc_quotes_source_v1.json'
GENERIC_FIXTURE = 'compatibility/fixtures/nom_rpc_quote_v1.json'
PTLC_FIXTURE = 'compatibility/fixtures/nom_rpc_ptlc_quote_v1.json'
PROBES = {
    'verifier/zz_research_nom_signed_original_probe_test.go': 'compatibility/nom_signed_originals_test.go.txt',
    'rpc/api/embedded/zz_research_nom_rpc_quote_probe_test.go': 'compatibility/nom_rpc_quote_test.go.txt',
    'rpc/api/embedded/zz_research_nom_ptlc_rpc_quote_probe_test.go': 'compatibility/nom_rpc_ptlc_quote_test.go.txt',
}
BENCHMARK_INPUTS = (
    'compatibility/nom_signed_originals_source_v1.json',
    'compatibility/fixtures/nom_signed_originals_v1.json',
    'compatibility/nom_signed_originals_test.go.txt',
    'compatibility/fixtures/nom_supervisor_plasma_v1.json',
    'compatibility/fixtures/nom_supervisor_inputs_v1.json',
    'compatibility/fixtures/nom_supervisor_completions_v1.json',
    'offline_session/nom_signed_recovery.py', 'scripts/nom_signed_corpus.py',
    'scripts/qualify_nom_signed_originals.py', 'scripts/qualify_nom_signed_recovery.py',
    'scripts/prepare_nom_signed_originals.py', 'tests/test_nom_signed_recovery.py',
    'tests/nom_signed_fixture_oracle.py', 'tests/test_nom_signed_originals.py',
    'tests/nom_signed_source_frames.py', 'offline_session/nom_recovery.py',
    'offline_session/nom_recovery_snapshot.py', 'offline_session/nom_verifier.py',
    'offline_session/nom_wire.py', 'offline_session/pr138.py',
    'offline_session/public_worker.py', 'scripts/nom_cut_capture.py',
    'scripts/qualify_nom_recovery_cuts.py', 'scripts/qualify_nom_vm_path.py',
    'scripts/qualify_nom_observation_core.py',
)
OWN_INPUTS = (
    SOURCE_INDEX, GENERIC_FIXTURE, PTLC_FIXTURE,
    'compatibility/nom_rpc_quote_test.go.txt', 'compatibility/nom_rpc_ptlc_quote_test.go.txt',
    'qualification/nom_rpc_quote_source.py', 'qualification/nom_rpc_quote_generic.py',
    'qualification/nom_rpc_quote_ptlc.py', 'scripts/prepare_nom_rpc_quotes.py',
    'scripts/qualify_nom_rpc_quotes.py', 'tests/test_nom_rpc_quotes.py',
    'tests/nom_rpc_quote_frames.py', 'compatibility/nom_signed_originals_manifest.json',
    'scripts/check_artifacts.py',
)
SELECTED_INPUTS = tuple(sorted(set(BENCHMARK_INPUTS) | set(OWN_INPUTS)))


def require(condition):
    if not condition:
        raise ValueError('selected unsigned RPC source comparison refused')


def unique(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError('duplicate selected JSON key')
        result[name] = value
    return result


def read_json(path, limit=2 * 1024**2):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= limit)
    return json.loads(path.read_bytes(), object_pairs_hook=unique)


def sha(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for data in iter(lambda: stream.read(65536), b''):
            result.update(data)
    return result.hexdigest()


def payload_pin(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode('ascii')).hexdigest()


def git_tree(index):
    tree = {}
    for name, record in index.items():
        require(type(name) is str and name.isascii() and '\\' not in name)
        parts = name.split('/')
        require(all(part not in ('', '.', '..') for part in parts))
        branch = tree
        for part in parts[:-1]:
            branch = branch.setdefault(part, {})
            require(type(branch) is dict)
        require(parts[-1] not in branch)
        branch[parts[-1]] = (record['mode'], record['git_blob_sha1'])
    def digest(branch):
        raw = b''
        for name, value in sorted(branch.items(), key=lambda row: row[0] + ('/' if type(row[1]) is dict else '')):
            mode, oid = ('40000', digest(value)) if type(value) is dict else value
            raw += (mode + ' ' + name).encode('ascii') + b'\0' + bytes.fromhex(oid)
        return hashlib.sha1(b'tree ' + str(len(raw)).encode('ascii') + b'\0' + raw).hexdigest()
    return digest(tree)


def inputs(root):
    if sys.flags.optimize:
        raise ValueError('RPC source selection requires assertions enabled')
    manifest = read_json(root / MANIFEST)
    require(manifest['schema'] == 'ptlc-nom-rpc-quotes-manifest-v1'
        and manifest['core_commit'] == CORE and manifest['core_tree'] == TREE
        and manifest['archive_sha256'] == ARCHIVE_SHA256 and manifest['archive_bytes'] == ARCHIVE_BYTES
        and manifest['source_index_payload_sha256'] == INDEX_PAYLOAD
        and manifest['generic_payload_sha256'] == GENERIC_PAYLOAD and manifest['ptlc_payload_sha256'] == PTLC_PAYLOAD
        and manifest['source_license_sha256'] == LICENSE_SHA256
        and manifest['application'] == manifest['core'] == 'NO-GO'
        and manifest['independent_assessment'] == 'UNFILLED'
        and manifest['journal_source_upgrade'] == 'NOT_SELECTED')
    require(set(manifest['input_sha256']) == set(SELECTED_INPUTS))
    for name, pin in manifest['input_sha256'].items():
        require(type(pin) is str and re.fullmatch('[0-9a-f]{64}', pin))
        info = (root / name).lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= 16 * 1024**2)
        require(sha(root / name) == pin)
    index = read_json(root / SOURCE_INDEX)
    require(type(index) is dict and len(index) == 443 and payload_pin(index) == INDEX_PAYLOAD)
    for value in index.values():
        require(type(value) is dict and set(value) == {'bytes', 'sha256', 'git_blob_sha1', 'mode'}
            and type(value['bytes']) is int and 0 <= value['bytes'] <= 16 * 1024**2
            and type(value['sha256']) is str and re.fullmatch('[0-9a-f]{64}', value['sha256'])
            and type(value['git_blob_sha1']) is str and re.fullmatch('[0-9a-f]{40}', value['git_blob_sha1'])
            and value['mode'] in ('100644', '100755'))
    require(git_tree(index) == TREE and index['LICENSE']['sha256'] == LICENSE_SHA256)
    benchmark_index = read_json(root / 'compatibility/nom_signed_originals_source_v1.json')
    require(all(index[name] == benchmark_index[name] for name in ('go.mod', 'go.sum')))
    generic, ptlc = read_json(root / GENERIC_FIXTURE), read_json(root / PTLC_FIXTURE)
    require(type(generic) is dict and len(generic) == 14 and payload_pin(generic) == GENERIC_PAYLOAD)
    require(type(ptlc) is dict and len(ptlc) == 16 and payload_pin(ptlc) == PTLC_PAYLOAD)
    return manifest, index, generic, ptlc


def check_source(checkout, index, root):
    if sys.flags.optimize:
        raise ValueError('RPC source comparison requires assertions enabled')
    require(checkout.is_dir() and not checkout.is_symlink())
    expected = dict(index)
    for name, source in PROBES.items():
        require(name not in expected)
        data = (root / source).read_bytes()
        expected[name] = dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
    measured = set()
    for path in checkout.rglob('*'):
        info = path.lstat()
        require(not stat.S_ISLNK(info.st_mode))
        if stat.S_ISDIR(info.st_mode):
            continue
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1)
        name = path.relative_to(checkout).as_posix()
        require(name in expected and name not in measured)
        row = expected[name]
        require(info.st_size == row['bytes'] and sha(path) == row['sha256'])
        measured.add(name)
    require(measured == set(expected) and len(measured) == 446)
