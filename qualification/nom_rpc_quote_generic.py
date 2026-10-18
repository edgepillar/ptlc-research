"""Finite unsigned RPC source oracle; not a general RPC client or admission rule."""
import json
import re

TEST = 'TestResearchNoMRpcQuoteCorpus'
PACKAGE = 'github.com/zenon-network/go-zenon/rpc/api/embedded'
PREFIX = 'PTLC_NOM_RPC_QUOTE_RECORD='
PROBE_NAME = 'zz_research_nom_rpc_quote_probe_test.go'
SCHEMA = 'ptlc-nom-unsigned-rpc-quote-source-record-v1'
CASES = (
    ('dynamic-floor', True, 2, 1000, 1000, 12, ''),
    ('dynamic-fused-only', True, 2, 1050, 1100, 12, ''),
    ('dynamic-one-byte', True, 2, 1050, 1100, 12, '01'),
    ('dynamic-partial-fusion', True, 2, 1050, 1100, 9, ''),
    ('dynamic-no-fusion', True, 2, 1050, 1100, 0, ''),
    ('before-first-v2', True, 1, 0, 0, 12, ''),
    ('before-first-v2-partial', True, 1, 0, 0, 9, ''),
    ('before-enforcement', False, 1, 0, 0, 12, ''),
    ('before-enforcement-partial', False, 1, 0, 0, 9, ''),
    ('dynamic-ceil-work', True, 2, 1051, 1103, 9, '01'),
    ('dynamic-no-fusion-ceil-work', True, 2, 1051, 1103, 0, '01'),
    ('before-first-v2-nonzero-prices', True, 1, 1051, 1103, 9, '01'),
    ('before-enforcement-v2', False, 2, 1051, 1103, 9, '01'),
)


def unique(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError('duplicate selected JSON key')
        result[name] = value
    return result


def expected_records():
    records = {}
    for identifier, active, version, fusion, work, units, data in CASES:
        selected = dict(dynamic_spork_enforced=active, frontier_version=str(version),
            next_fusion_price=str(fusion), next_work_price=str(work), fusion_units=str(units), data_hex=data)
        # Deliberately finite public inputs: no resource cap, arbitrary stake,
        # frontier authentication or general dynamic-price policy is modeled here.
        assert type(active) is bool and version in (1, 2) and units in (0, 9, 12) and data in ('', '01')
        available = units * 2100
        base = 21000 + 68 * len(bytes.fromhex(data))
        dynamic = active and version >= 2
        ceil = lambda n: (n + 999) // 1000
        fused = ceil(base * fusion) if dynamic else base
        if available >= fused:
            difficulty = 0
        else:
            effective = available * 1000 // fusion if dynamic else available
            work_units = ceil((base - effective) * work) if dynamic else base - effective
            difficulty = work_units * 1500
        quote = dict(availablePlasma=available, basePlasma=base,
            requiredDifficulty=difficulty, requiredFusedPlasma=fused)
        records[identifier] = dict(schema=SCHEMA, id=identifier, kind='source-rpc', input=selected,
            typed_result_json_hex=json.dumps(quote, separators=(',', ':')).encode('ascii').hex())
    zero = dict(availablePlasma=0, basePlasma=0, requiredDifficulty=0, requiredFusedPlasma=0)
    records['typed-zero-json'] = dict(schema=SCHEMA, id='typed-zero-json', kind='typed-zero', input=None,
        typed_result_json_hex=json.dumps(zero, separators=(',', ':')).encode('ascii').hex())
    return records


def inspect(stream, outcome_reader):
    expected = expected_records()
    selected = {TEST} | {TEST + '/' + identifier for identifier in expected}
    assert type(stream) is bytes and len(stream) <= 4 * 1024**2
    assert outcome_reader(stream, {PACKAGE: selected}) == 15
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
        assert len(output[identity].encode('utf-8')) <= 16384
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
            if record['input'] is not None:
                assert type(record['input']) is dict and set(record['input']) == set(expected[identifier]['input'])
                assert type(record['input']['dynamic_spork_enforced']) is bool
                assert all(type(value) is str for name, value in record['input'].items() if name != 'dynamic_spork_enforced')
            encoded = record['typed_result_json_hex']
            assert type(encoded) is str and re.fullmatch('[0-9a-f]{2,1024}', encoded) and len(encoded) % 2 == 0
            quote = json.loads(bytes.fromhex(encoded), object_pairs_hook=unique)
            assert type(quote) is dict and set(quote) == {'availablePlasma', 'basePlasma', 'requiredDifficulty', 'requiredFusedPlasma'}
            assert all(type(value) is int and 0 <= value < 2**64 for value in quote.values())
            assert record == expected[identifier]
            found[identifier] = record
    assert found == expected
    return dict(outcome='PASS_FINITE_SOURCE_RPC_QUOTE_COMPARISON', source_records=14,
        source_rpc_calls=13, separate_typed_zero_case=1, actual_go_outcomes=15,
        expected_value_oracle='DECLARED FINITE INTEGER MODEL; AUTHOR COMPARISON ONLY',
        serialization='GO TYPED RESULT MARSHAL; NOT A CAPTURED NETWORK RESPONSE',
        dynamic_total_fusion_target='ALTERNATIVE TOTAL PAYMENT; NOT EXTRA FUSION ALONGSIDE POW',
        source_authority='SYNTHETIC STORES; NO CANONICALITY OR COMPLETE BLOCK ADMISSION',
        application='NO-GO', core='NO-GO', independent_assessment='UNFILLED'), found
