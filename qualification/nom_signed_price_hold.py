"""Finite public source-record comparison; no admission or recovery authority."""
import hashlib
import json
from pathlib import Path
import re
import sys

if sys.flags.optimize:
    raise ValueError('finite price comparison requires assertions enabled')

from qualification.nom_rpc_quote_generic import unique
from scripts.qualify_nom_signed_originals import selected_outcome

TEST = 'TestResearchNoMSignedPriceHold'
PACKAGE = 'github.com/zenon-network/go-zenon/dp'
PREFIX = 'PTLC_NOM_SIGNED_PRICE_HOLD_RECORD='
SCHEMA = 'ptlc-nom-signed-price-hold-source-v1'
CORE = '85c39796fa5ab6fb5ca16e61af34b6616f0ceafe'
TREE = 'cdeb5b6276c13447197c829c5855faa72afd86b9'
MAX_STREAM = 2 * 1024**2
CASES = (
    ('minimum', 2, 1000, 1000, None),
    ('work-only-rise', 2, 1000, 1103, None),
    ('fusion-one-above', 2, 1001, 1000, None),
    ('fusion-rise', 2, 1051, 1103, None),
    ('wide-work-price', 2, 1051, 2**64-1, None),
    ('before-first-v2', 1, 1051, 1103, None),
    ('untrusted-zero-base', 2, 1051, 1103, 0),
    ('untrusted-max-base', 2, 1000, 1000, 2**64-1),
)


def inputs(root):
    """Compare declared project bytes; this does not inspect a node checkout."""
    manifest = json.loads((root/'compatibility/nom_signed_price_hold_manifest.json').read_bytes(), object_pairs_hook=unique)
    assert manifest['schema'] == 'ptlc-nom-signed-price-hold-selection-v1'
    assert manifest['core_commit'] == CORE and manifest['core_tree'] == TREE
    assert manifest['source_files'] == 444 and manifest['source_records'] == 16
    assert manifest['source_archive_sha256'] == '54336f7c1f75f84d0f513d3b22da135bebf62d8da84b776e961b0c3f52f8e1c9'
    names = {
        'compatibility/fixtures/nom_signed_originals_v1.json',
        'compatibility/fixtures/nom_signed_price_hold_v1.json',
        'compatibility/nom_signed_price_hold_test.go.txt',
        'qualification/nom_signed_price_hold.py',
        'qualification/nom_rpc_quote_generic.py',
        'scripts/qualify_nom_signed_originals.py',
        'tests/test_nom_signed_price_hold.py',
    }
    assert set(manifest['input_sha256']) == names
    for name in names:
        assert hashlib.sha256((root/name).read_bytes()).hexdigest() == manifest['input_sha256'][name]
    return manifest


def expected_records(root):
    """Declared integer model over two existing fused-only public originals."""
    inputs(root)
    fixture = json.loads((root/'compatibility/fixtures/nom_signed_originals_v1.json').read_bytes(), object_pairs_hook=unique)
    wanted = {}
    for leg in ('long', 'short'):
        original = fixture[leg+'-original']
        assert original['block']['fused_plasma'] == '73500' and original['block']['difficulty'] == '0'
        assert original['base_plasma'] == '73500'
        for name, version, fusion, work, metadata in CASES:
            f, w = (fusion, work) if version >= 2 else (1000, 1000)
            advertised = 73500 if metadata is None else metadata
            # Selected finite price floor, including its integer division order.
            valid = lambda base: (73500*w)*21000 >= (21000*f//1000)*w*base
            identifier = leg+'-'+name
            wanted[identifier] = dict(schema=SCHEMA, id=identifier,
                original_wire_sha256=original['wire_sha256'], original_node_hash_hex=original['hash_hex'],
                version=str(version), fusion_price=str(fusion), work_price=str(work),
                fused_plasma='73500', difficulty='0', advertised_base=str(advertised),
                canonical_base='73500', advertised_accepts=valid(advertised), canonical_accepts=valid(73500),
                diagnostic_metadata_copy=metadata is not None, original_bytes_preserved=True, recovery_action='NONE')
    retained = json.loads((root/'compatibility/fixtures/nom_signed_price_hold_v1.json').read_bytes(), object_pairs_hook=unique)
    assert json.dumps(retained, sort_keys=True) == json.dumps(wanted, sort_keys=True)
    return wanted


def compare_stream(raw, root):
    """Check a Go-shaped transcript. Its origin and source execution are unproven."""
    wanted = expected_records(root)
    identities = {TEST} | {TEST+'/'+name for name in wanted}
    assert type(raw) is bytes and len(raw) <= MAX_STREAM
    assert selected_outcome(raw, {PACKAGE: identities}) == 17
    output = {}
    for line in raw.splitlines():
        assert len(line) <= 32768
        row = json.loads(line, object_pairs_hook=unique)
        text = row.get('Output', '')
        assert type(text) is str
        if row.get('Action') != 'output' or row.get('Test') not in identities:
            assert PREFIX not in text
            continue
        assert row['Package'] == PACKAGE
        name = row['Test']
        output[name] = output.get(name, '') + text
        assert len(output[name].encode('utf8')) <= 16384
    found = {}
    for name, text in output.items():
        for line in text.splitlines(keepends=True):
            if PREFIX not in line: continue
            match = re.fullmatch(r'\s+zz_research_nom_price_hold_test.go:[0-9]+: '+PREFIX+r'(\{.*\})\n', line)
            assert match
            row = json.loads(match.group(1), object_pairs_hook=unique)
            identifier = row['id']
            assert identifier in wanted and identifier not in found and name == TEST+'/'+identifier
            assert set(row) == set(wanted[identifier])
            assert all(type(row[key]) is type(value) for key, value in wanted[identifier].items())
            assert row == wanted[identifier]
            found[identifier] = row
    assert found == wanted
    return dict(outcome='PASS_FINITE_PRICE_RECORD_COMPARISON', source_records=16, go_shaped_outcomes=17,
        execution_origin='NOT_ESTABLISHED_BY_THIS_READER', complete_admission='UNFILLED',
        journal_source_upgrade='NOT_SELECTED', original_replacement='NOT_PERFORMED', recovery_action='NONE',
        independent_assessment='UNFILLED', application='NO-GO', core='NO-GO')


def main():
    import argparse
    parser = argparse.ArgumentParser(description='Compare finite price records; does not execute or authenticate node source')
    parser.add_argument('--stream', required=True, type=Path)
    args = parser.parse_args()
    try:
        with args.stream.open('rb') as selected:
            raw = selected.read(MAX_STREAM+1)
        result = compare_stream(raw, Path(__file__).resolve().parents[1])
    except (AssertionError, OSError, ValueError, KeyError, TypeError, RecursionError, OverflowError):
        raise SystemExit('REFUSED: finite source-price record comparison') from None
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
