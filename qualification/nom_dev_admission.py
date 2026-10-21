"""Read a separately pinned dev component subject; no execution or recovery authority."""
import sys

if sys.flags.optimize:
    raise SystemExit('dev admission comparison requires assertions enabled')

import hashlib
import json
import os
from pathlib import Path
import re

from qualification import nom_current_admission as earlier

ROOT = earlier.ROOT
CORE = '5e65a0bdb83700aa1d15b17456a17352b7d04ea9'
TREE = '3668425af59cfe9b88d8b8818b4467ce3f527d73'
SOURCE = 'compatibility/nom_dev_admission_source_v1.json'
INDEX_SHA256 = '2f031704a76b772f66736dadd5d9a7c0d5e3e2e07d97a2b2364cf072fe63b298'
MANIFEST = 'compatibility/nom_dev_admission_manifest.json'
SCHEMA = 'ptlc-nom-dev-admission-selection-v1'
VARIANTS = {
    'compatibility/nom_account_context_test.go.txt': (
        'compatibility/nom_dev_account_context_test.go.txt',
        '6e85d0369ea53616229fc951eeb03ce18eea9253150ec637eca85d1c94a00843',
        b'\t\t\t\th := ledger.mailbox.SequencerByHeight(i)\n',
        b'\t\t\t\th, err := ledger.mailbox.SequencerByHeight(i)\n',
    ),
    'compatibility/nom_bilateral_graph_test.go.txt': (
        'compatibility/nom_dev_bilateral_graph_test.go.txt',
        'aaf4dea88d2025654c60f7c2d5be5e835640b15a1d1cf7a7387bb453b2a0d7cb',
        b'\t\t\t\th := c.SequencerFront(ledger.mailbox)\n',
        b'\t\t\t\th, err := c.SequencerFront(ledger.mailbox)\n',
    ),
    'compatibility/nom_supervisor_plasma_test.go.txt': (
        'compatibility/nom_dev_supervisor_plasma_test.go.txt',
        'f207d130a9a599e28ef498e5c6890f4b5cb6e9034763c7b9c2660f8d215a8eac',
        b'\t\t\t\th := ledger.accounts[a].SequencerFront(ledger.mailbox)\n',
        b'\t\t\t\th, err := ledger.accounts[a].SequencerFront(ledger.mailbox)\n',
    ),
}
ERROR_GUARD = (
    b'\t\t\t\tif err != nil {\n'
    b'\t\t\t\t\tt.Fatal("selected memory sequencer lookup failed", err)\n'
    b'\t\t\t\t}\n'
)
OWN_INPUTS = {SOURCE, 'qualification/nom_dev_admission.py',
              'tests/test_nom_dev_admission.py', earlier.MANIFEST}
OWN_INPUTS.update(row[0] for row in VARIANTS.values())


def require(value):
    if not value:
        raise ValueError('dev admission comparison refused')


def producer_variants(root=ROOT):
    """Require only the explicit API adaptation, including hard failure on error."""
    result = {}
    for original, (selected, digest, before, after) in VARIANTS.items():
        old = earlier.regular(Path(root)/original, 8*earlier.MIB)
        new = earlier.regular(Path(root)/selected, 8*earlier.MIB)
        require(hashlib.sha256(old).hexdigest() == digest and old.count(before) == 1)
        require(after not in old and ERROR_GUARD not in old)
        require(new == old.replace(before, after+ERROR_GUARD, 1))
        result[original] = dict(selected=selected, original_sha256=digest,
                                selected_sha256=hashlib.sha256(new).hexdigest())
    return result


def inputs(root=ROOT):
    root = earlier.physical(root)
    manifest = earlier.decoded(earlier.regular(root/MANIFEST, earlier.MIB), earlier.MIB)
    fixed = dict(schema=SCHEMA, core_commit=CORE, core_tree=TREE,
                 source_files=474, source_index_sha256=INDEX_SHA256,
                 project_probe_files=16, api_variant_files=3,
                 earlier_source=earlier.CORE, earlier_value_source=earlier.rebase.CORE_COMMIT,
                 expected_profile_outcomes=earlier.COUNTS, selected_stateful_outcomes=342,
                 wire_outcomes=45, pr138_outcomes=1,
                 application='NO-GO', core='NO-GO', independent_assessment='UNFILLED',
                 combined_admission='UNFILLED', journal_source_upgrade='NOT_SELECTED')
    require(type(manifest) is dict and set(manifest) == set(fixed)|{'input_sha256'})
    earlier.rebase.exact(fixed, {key:manifest[key] for key in fixed})
    pins = manifest['input_sha256']
    require(type(pins) is dict and set(pins) == OWN_INPUTS)
    for name, digest in pins.items():
        require(type(digest) is str and re.fullmatch('[0-9a-f]{64}', digest))
        require(hashlib.sha256(earlier.regular(root/name, 2*earlier.MIB)).hexdigest() == digest)
    unused_manifest, old_index, unused_reference = earlier.inputs(root)
    earlier.profiles(root)
    raw = earlier.regular(root/SOURCE, earlier.MIB)
    require(hashlib.sha256(raw).hexdigest() == INDEX_SHA256)
    index = earlier.decoded(raw, earlier.MIB)
    require(type(index) is dict and len(index) == 474)
    for name, row in index.items():
        require(type(name) is str and name.isascii() and '\\' not in name)
        require(not Path(name).is_absolute() and all(
            part not in ('', '.', '..', '.git') for part in name.split('/')))
        require(type(row) is dict and set(row) == {'bytes', 'sha256', 'git_blob_sha1', 'mode'})
        require(type(row['bytes']) is int and 0 <= row['bytes'] <= 8*earlier.MIB)
        require(type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}', row['sha256']))
        require(type(row['git_blob_sha1']) is str and re.fullmatch('[0-9a-f]{40}', row['git_blob_sha1']))
        require(row['mode'] in ('100644', '100755'))
    require(earlier.git_tree(index) == TREE)
    require(index['LICENSE'] == old_index['LICENSE'])
    require(all(index[name] == old_index[name] for name in ('go.mod', 'go.sum')))
    producer_variants(root)
    return manifest, index


def probes(root=ROOT):
    selected = earlier.probes(root)
    return {destination:VARIANTS[producer][0] if producer in VARIANTS else producer
            for destination, producer in selected.items()}


def compare_source(source, root=ROOT):
    unused_manifest, index = inputs(root)
    source = earlier.physical(source)
    require(source.is_dir())
    expected = {name:dict(row) for name, row in index.items()}
    for name, producer in probes(root).items():
        require(name not in expected)
        raw = earlier.regular(Path(root)/producer, 8*earlier.MIB)
        expected[name] = dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
                             git_blob_sha1=hashlib.sha1(
                                 b'blob '+str(len(raw)).encode('ascii')+b'\0'+raw).hexdigest())
    seen = set()
    total = 0
    for directory, children, names in os.walk(source, followlinks=False):
        parent = Path(directory)
        require(not parent.is_symlink())
        for name in children:
            require(not (parent/name).is_symlink())
        for name in names:
            path = parent/name
            relative = path.relative_to(source).as_posix()
            require(relative in expected and relative not in seen)
            raw = earlier.regular(path, 8*earlier.MIB)
            row = expected[relative]
            total += len(raw)
            require(total <= 48*earlier.MIB and len(raw) == row['bytes'])
            require(hashlib.sha256(raw).hexdigest() == row['sha256'])
            require(hashlib.sha1(b'blob '+str(len(raw)).encode('ascii')+b'\0'+raw).hexdigest() == row['git_blob_sha1'])
            seen.add(relative)
    require(seen == set(expected) and len(seen) == 490)
    return dict(core_commit=CORE, core_tree=TREE, upstream_files=474,
                project_probe_files=16, api_variant_files=3, combined_files=490,
                content='EXACT_SELECTED_CONTENTS', filesystem_mode_equality='NOT_ASSERTED',
                producer_authentication='NOT_ESTABLISHED_BY_THIS_READER')


def compare_payloads(payloads, root=ROOT):
    inputs(root)
    old = earlier.compare_payloads(payloads, root)
    require(old['core_commit'] == earlier.CORE and old['core_tree'] == earlier.TREE)
    return dict(old, schema='ptlc-nom-dev-admission-components-v1',
                core_commit=CORE, core_tree=TREE, earlier_source=earlier.CORE,
                earlier_value_source=earlier.rebase.CORE_COMMIT,
                api_variant_files=3, profile_scope='SAME SIXTEEN FINITE COMPONENTS; NOT ALL DEV CHANGES',
                source_identity='SEPARATE CONTENT SELECTION; EXECUTION ORIGIN UNESTABLISHED',
                native_vectors='SEPARATE UPSTREAM SOURCE TESTS; NOT EXECUTED BY READER')


def main():
    import argparse

    class QuietParser(argparse.ArgumentParser):
        def error(self, message):
            raise ValueError('dev admission comparison refused')

    parser = QuietParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--streams', type=Path, required=True)
    try:
        args = parser.parse_args()
        source = compare_source(args.source)
        result = compare_payloads(earlier.load_payloads(args.streams))
        result['complete_source'] = source
    except (AssertionError, OSError, ValueError, KeyError, TypeError, RecursionError, OverflowError):
        raise SystemExit('REFUSED: dev admission component comparison') from None
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
