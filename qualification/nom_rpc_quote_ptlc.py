"""Finite PTLC Unlock source quotes; no signed-original admission or fee rewrite."""
import hashlib
import json
import re

TEST = 'TestResearchNoMPtlcRpcQuoteCorpus'
PACKAGE = 'github.com/zenon-network/go-zenon/rpc/api/embedded'
PREFIX = 'PTLC_NOM_PTLC_RPC_QUOTE_RECORD='
PROBE_NAME = 'zz_research_nom_ptlc_rpc_quote_probe_test.go'
SCHEMA = 'ptlc-nom-ptlc-rpc-quote-source-record-v1'
CASES = (
    ('dynamic-fused-only', True, 2, 1050, 1100, 40),
    ('dynamic-partial-ceil', True, 2, 1051, 1103, 30),
    ('dynamic-no-fusion', True, 2, 1051, 1103, 0),
    ('before-first-v2-covered', True, 1, 1051, 1103, 40),
    ('before-first-v2-partial', True, 1, 1051, 1103, 30),
    ('legacy-covered', False, 1, 0, 0, 40),
    ('legacy-partial', False, 1, 0, 0, 30),
    ('legacy-no-fusion', False, 1, 0, 0, 0),
)


def unique(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError('duplicate selected JSON key')
        result[name] = value
    return result


def expected_records(originals, vm_fixture):
    records = {}
    for leg in ('long', 'short'):
        original = originals[leg + '-original']
        raw = bytes.fromhex(original['wire_hex'])
        assert 0 < len(raw) <= 2048 and hashlib.sha256(raw).hexdigest() == original['wire_sha256']
        selected = [row for row in vm_fixture['records']['complete']['trace'] if row['label'] == leg + '-unlock-send']
        assert len(selected) == 1
        vm = selected[0]
        assert vm['block']['wire_hex'] == original['wire_hex']
        assert vm['block']['wire_sha256'] == original['wire_sha256']
        base = int(vm['plasma']['canonical_base'])
        assert base == 73500 and vm['plasma']['base'] == str(base)
        block = original['block']
        assert block['block_type'] == '2' and block['data_hex'].startswith('d33791d3')
        for kind, active, version, fusion, work, units in CASES:
            identifier = leg + '-' + kind
            inputs = dict(leg=leg, original_wire_sha256=original['wire_sha256'],
                original_node_hash_hex=original['hash_hex'], caller_hex=block['address_hex'],
                contract_hex=block['to_address_hex'], block_type=block['block_type'], data_hex=block['data_hex'],
                ptlc_spork_enforced=True, dynamic_spork_enforced=active,
                frontier_version=str(version), next_fusion_price=str(fusion), next_work_price=str(work), fusion_units=str(units))
            available = units * 2100
            dynamic = active and version >= 2
            ceil = lambda value: (value + 999) // 1000
            fused = ceil(base * fusion) if dynamic else base
            if available >= fused:
                difficulty = 0
            else:
                effective = available * 1000 // fusion if dynamic else available
                required_work = ceil((base - effective) * work) if dynamic else base - effective
                difficulty = required_work * 1500
            quote = dict(availablePlasma=available, basePlasma=base,
                requiredDifficulty=difficulty, requiredFusedPlasma=fused)
            records[identifier] = dict(schema=SCHEMA, id=identifier, kind='source-ptlc-unlock-rpc', input=inputs,
                typed_result_json_hex=json.dumps(quote, separators=(',', ':')).encode('ascii').hex())
    return records


def inspect(stream, outcome_reader, originals, vm_fixture):
    expected = expected_records(originals, vm_fixture)
    selected = {TEST} | {TEST + '/' + name for name in expected}
    assert type(stream) is bytes and len(stream) <= 4 * 1024**2 and len(expected) == 16
    assert outcome_reader(stream, {PACKAGE: selected}) == 17
    output = {}
    for line in stream.splitlines():
        assert len(line) <= 65536
        event = json.loads(line, object_pairs_hook=unique)
        text = event.get('Output', '')
        assert type(text) is str
        if event.get('Action') != 'output' or event.get('Test') not in selected:
            assert PREFIX not in text
            continue
        assert event['Package'] == PACKAGE
        identity = event['Test']
        output[identity] = output.get(identity, '') + text
        assert len(output[identity].encode('utf-8')) <= 32768
    found = {}
    for identity, text in output.items():
        for line in text.splitlines(keepends=True):
            if PREFIX not in line:
                continue
            match = re.fullmatch(r'\s+' + re.escape(PROBE_NAME) + r':[0-9]+: ' + PREFIX + r'(\{.*\})\n', line)
            assert match
            record = json.loads(match.group(1), object_pairs_hook=unique)
            assert type(record) is dict and set(record) == {'schema', 'id', 'kind', 'input', 'typed_result_json_hex'}
            identifier = record['id']
            assert type(identifier) is str and identifier in expected and identifier not in found
            assert identity == TEST + '/' + identifier
            assert type(record['input']) is dict and set(record['input']) == set(expected[identifier]['input'])
            assert type(record['input']['ptlc_spork_enforced']) is bool
            assert type(record['input']['dynamic_spork_enforced']) is bool
            assert all(type(value) is str for name, value in record['input'].items() if name not in ('ptlc_spork_enforced', 'dynamic_spork_enforced'))
            encoded = record['typed_result_json_hex']
            assert type(encoded) is str and re.fullmatch('[0-9a-f]{2,1024}', encoded) and len(encoded) % 2 == 0
            quote = json.loads(bytes.fromhex(encoded), object_pairs_hook=unique)
            assert type(quote) is dict and set(quote) == {'availablePlasma', 'basePlasma', 'requiredDifficulty', 'requiredFusedPlasma'}
            assert all(type(value) is int and 0 <= value < 2**64 for value in quote.values())
            assert record == expected[identifier]
            found[identifier] = record
    assert found == expected
    return dict(outcome='PASS_FINITE_PTLC_SOURCE_RPC_QUOTE_COMPARISON', source_records=16,
        actual_rpc_source_calls=16, actual_go_outcomes=17, selected_legs=['long', 'short'],
        selected_canonical_vm_base='73500', source_flags='SYNTHETIC PTLC ENABLEMENT AND SELECTED DYNAMIC PRICE CONTEXTS',
        expected_value_oracle='DECLARED FINITE INTEGER MODEL AND FROZEN VM COST BENCHMARK; AUTHOR COMPARISON',
        source_scope='EXISTING PUBLIC UNLOCK CALLER, CONTRACT AND DATA; HYPOTHETICAL UNSIGNED RPC PARAMETERS',
        original_admission='NOT_ESTABLISHED', original_fee_rewrite='NOT_PERFORMED', signer='NOT_SELECTED',
        network_rpc='NOT_PERFORMED', node_activation='NOT_PERFORMED',
        application='NO-GO', core='NO-GO', independent_assessment='UNFILLED'), found
