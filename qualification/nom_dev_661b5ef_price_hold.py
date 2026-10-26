"""Source-specific finite fee refusal; immutable originals confer no authority."""
import copy
import hashlib

from qualification import nom_embedded_argument_pricing as pricing
from qualification import nom_keyless_supervisor as historical

CORE = pricing.CORE
TIER = 73500
SELECTOR = bytes.fromhex('d33791d3')
ERROR = 'ErrNotEnoughTotalPlasma'
TRACE = ['ACCOUNT_PRECHECK_ENTER', 'ACCOUNT_PRECHECK_PASS']


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def derived_wire(entry, required):
    """Change only field 19 on the ephemeral call copy, never the signed input."""
    assert type(entry) is bytes and 0 < len(entry) <= 8192
    assert type(required) is int and TIER < required < (1 << 64)
    at = 0
    out = bytearray()
    seen = set()
    scalars = {}
    while at < len(entry):
        start = at
        tag, at = historical.number(entry, at)
        field, kind = tag >> 3, tag & 7
        assert field > 0 and field not in seen and len(seen) < 48
        seen.add(field)
        if kind == 0:
            value, at = historical.number(entry, at)
            scalars[field] = value
        elif kind == 2:
            size, at = historical.number(entry, at)
            assert size <= 8192 and at + size <= len(entry)
            at += size
        else:
            raise ValueError('selected outer protobuf field required')
        if field == 19:
            assert kind == 0 and value == TIER
            out.extend(historical.uint(tag) + historical.uint(required))
        else:
            out.extend(entry[start:at])
    assert scalars[15] == scalars[19] == scalars[20] == TIER
    assert scalars.get(17, 0) == 0
    return bytes(out)


def expected(baseline, declared, signed):
    """Overlay twelve earlier fee refusals on an unchanged historical oracle."""
    assert declared['selected_core'] == CORE
    assert set(baseline) == set(declared['declared_case_ids']) == historical.CASE_IDS
    result = copy.deepcopy(baseline)
    changed = 0
    for identifier, row in result.items():
        if not row['declared_dynamic_plasma']:
            continue
        original = signed[row['leg'] + '-original']
        selection = declared['originals'][row['leg']]
        original_wire = bytes.fromhex(original['original_wire_hex'])
        data = bytes.fromhex(original['block']['data_hex'])
        signature = bytes.fromhex(original['signature_hex'])
        assert len(original_wire) == 584 and sha(original_wire) == selection['original_wire_sha256']
        assert original['block']['fused_plasma'] == str(TIER)
        assert original['block']['difficulty'] == '0'
        assert len(data) == 164 and data[:4] == SELECTOR
        if row['variant'] == 'trailing_abi_byte':
            data += b'\0'
        elif row['variant'] == 'changed_witness_byte':
            data = data[:-1] + bytes([data[-1] ^ 1])
        elif row['variant'] == 'missing_outer_signature':
            signature = b''
        elif row['variant'] == 'corrupt_outer_signature':
            signature = bytes([signature[0] ^ 1]) + signature[1:]
        entry = historical.replace_bytes(original_wire, 14, data)
        entry = historical.replace_bytes(entry, 23, signature)
        assert sha(entry) == row['entry_wire_sha256']
        required, error = pricing.cost(TIER, len(data))
        assert error == 'NONE' and required > TIER
        post = derived_wire(entry, required)
        row.update(returned_error=ERROR, transaction_present=False,
            verifier_trace=list(TRACE), pack_entered=False, packed_delta_hex='',
            packed_hash_matches=False, packed_data_sha256='', returned_wire_hex='',
            post_call_wire_sha256=sha(post), post_call_data_sha256=sha(data))
        changed += 1
    assert changed == 12
    return result
