"""Decode bounded original shard transport without granting execution authority.

This never executes transported code or accepts cases, a hosted attempt or an
application action. Independent source and workflow selection remain required.
"""
import base64
import binascii
import hashlib
import json
import math
import re

PREFIX = b'PTLC_OFFLINE_PROFILE_'
CHUNK = 16 * 1024
MAX_STREAM = 4 * 1024**2
MAX_TRANSPORT = 48 * 1024**2
KINDS = ('stdout', 'stderr')
AUTHORITY = 'CALLER_DECLARED_RUN; TRUSTED_LOCAL_SOURCE; EXTERNAL_METADATA_ACCEPTANCE_REQUIRED'


class ProfileDecodeRefused(ValueError):
    """Sanitized transport refusal; never a repair, fallback or permission."""


def require(value):
    if not value: raise ProfileDecodeRefused('offline profile transport refused')


def sha(raw): return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def pairs(items):
    value = {}
    for key, item in items:
        require(key not in value); value[key] = item
    return value


def document(raw):
    require(type(raw) is bytes and raw.isascii())
    return json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda unused: (_ for _ in ()).throw(ProfileDecodeRefused('nonfinite JSON refused')))


def hex_value(value, size):
    require(type(value) is str and re.fullmatch('[0-9a-f]{' + str(size) + '}', value) is not None)


def integer(value, minimum, maximum):
    require(type(value) is int and minimum <= value <= maximum)


def context(value):
    require(type(value) is dict and set(value) == {'head', 'source_sha256', 'run_id', 'attempt', 'platform', 'python', 'authority'})
    hex_value(value['head'], 40); hex_value(value['source_sha256'], 64)
    integer(value['run_id'], 1, 2**63 - 1); integer(value['attempt'], 1, 2**31 - 1)
    require(value['platform'] in ('linux', 'darwin') and type(value['platform']) is str)
    require(type(value['python']) is str and re.fullmatch('3[.][0-9]{1,2}', value['python']) is not None)
    require(value['authority'] == AUTHORITY)
    return value


def source(value, selected):
    require(type(value) is dict and set(value) == {'head', 'tree', 'files', 'source_bytes', 'source_sha256'})
    hex_value(value['head'], 40); hex_value(value['tree'], 40); hex_value(value['source_sha256'], 64)
    integer(value['files'], 1, 4096); integer(value['source_bytes'], 1, 40 * 1024**2)
    require(value['head'] == selected['head'] and value['source_sha256'] == selected['source_sha256'])
    return value


def finite(value):
    require(type(value) in (int, float) and math.isfinite(value) and value >= 0)


def pin(value):
    require(type(value) is dict and set(value) == {'sha256', 'bytes'})
    hex_value(value['sha256'], 64); integer(value['bytes'], 0, MAX_STREAM)
    return value


def metadata(value, selected):
    require(canonical(context(value['context'])) == canonical(selected))
    integer(value['shard'], 0, 3); require(type(value['kind']) is str and value['kind'] in KINDS)
    require(value['launched'] is True and value['output_complete'] is True)
    require(type(value['actual_exit']) is int and value['actual_exit'] == 0)
    return {name: value[name] for name in ('context', 'shard', 'kind', 'launched', 'actual_exit', 'output_complete')}


def supervision(value, workers, selected_pins):
    fields = {'schema', 'outcome', 'workers', 'peak_running', 'children', 'stop_reason',
        'held_fixture_shards', 'elapsed_seconds', 'case_acceptance', 'test_result_cache',
        'verifier_replaced', 'automatic_retry', 'application', 'core', 'independent_assessment'}
    require(type(value) is dict and set(value) == fields)
    require(value['schema'] == 'ptlc-offline-shard-supervision-v1' and value['outcome'] == 'PROCESS_EXITS_ZERO')
    integer(value['workers'], 1, 4); require(value['workers'] == workers)
    integer(value['peak_running'], 1, workers); finite(value['elapsed_seconds'])
    require(value['stop_reason'] is None and value['held_fixture_shards'] == [])
    require(value['case_acceptance'] == 'NOT_PERFORMED; VALIDATE EACH ORIGINAL SHARD STREAM')
    for name in ('test_result_cache', 'verifier_replaced', 'automatic_retry'): require(value[name] is False)
    require(value['application'] == value['core'] == 'NO-GO' and value['independent_assessment'] == 'UNFILLED')
    require(type(value['children']) is list and len(value['children']) == 4)
    for i, row in enumerate(value['children']):
        require(type(row) is dict and set(row) == {'shard', 'launched', 'actual_exit', 'output_complete',
            'stdout', 'stderr', 'started_seconds', 'finished_seconds'})
        integer(row['shard'], 0, 3); require(row['shard'] == i)
        require(row['launched'] is True and row['output_complete'] is True)
        require(type(row['actual_exit']) is int and row['actual_exit'] == 0)
        finite(row['started_seconds']); finite(row['finished_seconds'])
        require(row['started_seconds'] <= row['finished_seconds'] <= value['elapsed_seconds'])
        for kind in KINDS:
            item = row[kind]
            require(type(item) is dict and set(item) == {'sha256', 'bytes', 'eof', 'truncated'})
            require(item['eof'] is True and item['truncated'] is False)
            require(canonical(pin({name: item[name] for name in ('sha256', 'bytes')})) ==
                canonical(selected_pins[str(i) + '.' + kind]))


def decode(raw, *, expected_context, expected_source, expected_workers=4, expected_cases):
    """Recover eight exact streams; case verification is an independent next step."""
    try:
        require(type(raw) is bytes and 0 < len(raw) <= MAX_TRANSPORT and raw.isascii())
        require(raw.count(b'\n') <= 16384)
        selected = context(expected_context); boundary = source(expected_source, selected)
        integer(expected_workers, 1, 4); integer(expected_cases, 1, 65536)
        begin, result, frame_count = None, None, 0
        slots = {(i, kind): dict(raw=bytearray(), chunks=0, last_bytes=CHUNK, ended=False,
            metadata=None, pin=None) for i in range(4) for kind in KINDS}
        base_fields = {'context', 'shard', 'kind', 'launched', 'actual_exit', 'output_complete'}
        for line in raw.splitlines():
            if not line.startswith(PREFIX): continue
            require(result is None)
            label, body = line[len(PREFIX):].split(b'=', 1); frame = document(body)
            require(type(frame) is dict); frame_count += 1; require(frame_count <= 2060)
            if label == b'BEGIN':
                require(begin is None and frame_count == 1)
                require(set(frame) == {'context', 'expected_cases', 'logical_shards', 'original_streams', 'workers', 'source'})
                require(canonical(context(frame['context'])) == canonical(selected))
                require(canonical(source(frame['source'], selected)) == canonical(boundary))
                for name, value in [('expected_cases', expected_cases), ('logical_shards', 4),
                        ('original_streams', 8), ('workers', expected_workers)]:
                    require(type(frame[name]) is int and frame[name] == value)
                begin = frame
            elif label in (b'CHUNK', b'STREAM_END'):
                require(begin is not None)
                fields = base_fields | ({'offset', 'data_base64'} if label == b'CHUNK' else {'sha256', 'bytes', 'chunks'})
                require(set(frame) == fields)
                current = metadata(frame, selected); slot = slots[frame['shard'], frame['kind']]
                require(not slot['ended'])
                if slot['metadata'] is None: slot['metadata'] = current
                require(canonical(slot['metadata']) == canonical(current))
                if label == b'CHUNK':
                    require(type(frame['data_base64']) is str and 0 < len(frame['data_base64']) <= 21848)
                    data = base64.b64decode(frame['data_base64'], validate=True)
                    require(base64.b64encode(data).decode('ascii') == frame['data_base64'])
                    require(slot['last_bytes'] == CHUNK and 0 < len(data) <= CHUNK)
                    integer(frame['offset'], 0, MAX_STREAM); require(frame['offset'] == len(slot['raw']))
                    require(len(slot['raw']) + len(data) <= MAX_STREAM)
                    slot['raw'].extend(data); slot['chunks'] += 1; slot['last_bytes'] = len(data)
                else:
                    selected_pin = pin({name: frame[name] for name in ('sha256', 'bytes')})
                    require(selected_pin == dict(sha256=sha(slot['raw']), bytes=len(slot['raw'])))
                    integer(frame['chunks'], 0, 256); require(frame['chunks'] == slot['chunks'])
                    slot['pin'] = selected_pin; slot['ended'] = True
            elif label == b'RESULT':
                require(begin is not None and all(value['ended'] for value in slots.values()))
                fields = {'schema', 'outcome', 'context', 'source_before', 'source_after', 'source_unchanged',
                    'supervision', 'stream_pins', 'shard_reports', 'error_class', 'actual_accepted_cases',
                    'expected_cases', 'actual_counter_sha256', 'complete_counter_sha256', 'case_acceptance',
                    'test_result_cache', 'verifier_replaced', 'automatic_retry', 'fixture_owner', 'source_tree_copies',
                    'application', 'core', 'recovery_action', 'independent_assessment'}
                require(set(frame) == fields and frame['schema'] == 'ptlc-offline-ci-profile-v1' and frame['outcome'] == 'PASS')
                require(canonical(context(frame['context'])) == canonical(selected))
                require(canonical(source(frame['source_before'], selected)) == canonical(boundary))
                require(canonical(source(frame['source_after'], selected)) == canonical(boundary))
                require(frame['source_unchanged'] is True and frame['error_class'] is None)
                pins = {str(i) + '.' + kind: value['pin'] for (i, kind), value in slots.items()}
                require(canonical(frame['stream_pins']) == canonical(pins))
                supervision(frame['supervision'], expected_workers, pins)
                require(type(frame['shard_reports']) is dict and set(frame['shard_reports']) == set('0123'))
                for name in ('actual_accepted_cases', 'expected_cases'):
                    require(type(frame[name]) is int and frame[name] == expected_cases)
                hex_value(frame['actual_counter_sha256'], 64); hex_value(frame['complete_counter_sha256'], 64)
                require(frame['actual_counter_sha256'] == frame['complete_counter_sha256'])
                require(frame['case_acceptance'] == 'PASS_FOUR_COMPLETE_ORIGINAL_STREAMS')
                require(type(frame['source_tree_copies']) is int and frame['source_tree_copies'] == 0)
                for name in ('test_result_cache', 'verifier_replaced', 'automatic_retry'): require(frame[name] is False)
                require(frame['fixture_owner'] == 'CALLER; UNKNOWN_DATA_PRESERVED')
                require(frame['application'] == frame['core'] == 'NO-GO' and frame['recovery_action'] == 'NONE')
                require(frame['independent_assessment'] == 'UNFILLED')
                result = frame
            else: raise ProfileDecodeRefused('unknown profile frame refused')
        require(begin is not None and result is not None)
        return dict(streams={(i, kind): bytes(value['raw']) for (i, kind), value in slots.items()},
            producer_report=result, original_transport_sha256=sha(raw),
            disposition='CONTENT_EQUALITY_ONLY; NO_EXECUTION_AUTHORITY',
            case_acceptance='NOT_PERFORMED_BY_DECODER', hosted_attempt_acceptance='NOT_PERFORMED',
            code_from_transport_executed=False, application='NO-GO', core='NO-GO', recovery_action='NONE')
    except (AssertionError, ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError,
            binascii.Error):
        raise ProfileDecodeRefused('offline profile transport refused') from None
