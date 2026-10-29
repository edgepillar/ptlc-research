"""Read complete selected fast-tier originals; never supply full CI acceptance."""
import argparse
import base64
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import run_offline_ci_profile as profile
from scripts import run_public_client_ci as producer
from scripts import select_public_client_ci as policy

MAX_TRANSPORT = 24 * 1024**2


def require(value):
    if not value:
        raise ValueError('selected public client originals refused')


def decode(raw, *, root, expected_context, expected_source):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_TRANSPORT and raw.isascii())
    require(type(expected_context) is dict and type(expected_source) is dict)
    require(expected_context['authority'] == producer.AUTHORITY
        and expected_context['build_environment'] == producer.BUILD_ENV
        and expected_context['head'] == expected_source['head']
        and expected_context['source_sha256'] == expected_source['source_sha256'])
    begin = result = None
    streams = {(index, kind): bytearray() for index in range(4) for kind in ('stdout', 'stderr')}
    offsets = set()
    prefix = producer.PREFIX.encode('ascii')
    for line in raw.splitlines():
        if not line.startswith(prefix):
            continue
        require(len(line) <= 65536)
        label, payload = line[len(prefix):].split(b'=', 1)
        value = producer.document(payload)
        require(value.get('context') == expected_context)
        if label == b'BEGIN':
            require(begin is None and result is None and not offsets)
            begin = value
        elif label == b'RESULT':
            require(begin is not None and result is None)
            result = value
        elif label == b'STREAM':
            require(begin is not None and result is None)
            require(set(value) == {'context', 'command', 'kind', 'offset', 'data_base64'})
            index, kind, offset = value['command'], value['kind'], value['offset']
            require(type(index) is int and index in range(4) and kind in ('stdout', 'stderr'))
            require(type(offset) is int and offset >= 0 and (index, kind, offset) not in offsets)
            selected = streams[index, kind]
            require(offset == len(selected))
            chunk = base64.b64decode(value['data_base64'], validate=True)
            require(len(chunk) <= 16384 and (chunk or offset == 0))
            selected.extend(chunk)
            require(len(selected) <= producer.MAX_STREAM)
            offsets.add((index, kind, offset))
        else:
            raise ValueError('unknown or unavailable original stream')
    require(begin is not None and result is not None)
    require(begin['source'] == expected_source and result['source_before'] == expected_source
        and result['source_after'] == expected_source and result['source_unchanged'] is True)
    require(result['schema'] == 'ptlc-public-client-fast-result-v1'
        and result['outcome'] == 'PASS_SELECTED_PUBLIC_CLIENT_SCOPE' and result['error_class'] is None)
    require(profile.supervision_good(result['supervision'], 1))
    require(result['automatic_retry'] is False and result['test_result_cache'] is False)
    require(result['application'] == result['core'] == 'NO-GO'
        and result['independent_assessment'] == 'UNFILLED')
    require(result['full_offline_suite'] == result['unrelated_native_jobs'] == 'NOT_EXECUTED')
    require(begin['full_offline_suite'] == begin['unrelated_native_jobs'] == 'NOT_SELECTED')
    require(result['workspace_limit_bytes'] == producer.MAX_WORKSPACE
        and type(result['sampled_workspace_peak_bytes']) is int
        and 0 <= result['sampled_workspace_peak_bytes'] <= producer.MAX_WORKSPACE)
    require(type(result['transient_sample_retries']) is int and result['transient_sample_retries'] >= 0)
    selected = result['scope']
    require(selected == begin['scope'] and selected['mode'] == policy.FAST)
    recomputed = policy.select_source(root, event='pull_request', base=selected['base'],
        head=expected_context['head'], base_ref='main')
    require(selected == recomputed and selected['source_complete'] is True)
    originals = {key: bytes(value) for key, value in streams.items()}
    for key, value in originals.items():
        require((key[0], key[1], 0) in offsets)
        name = str(key[0]) + '.' + key[1]
        require(result['stream_pins'][name] == dict(bytes=len(value), sha256=profile.sha(value)))
        child = result['supervision']['children'][key[0]]
        require(child[key[1]]['bytes'] == len(value) and child[key[1]]['sha256'] == profile.sha(value))
    accepted = producer.accept_streams(root, originals)
    require(accepted == result['accepted'])
    require(accepted['artifact_versions'] == 2 * expected_source['files'])
    return dict(outcome='PASS_SELECTED_PUBLIC_CLIENT_ORIGINALS_ONLY', context=expected_context,
        source=expected_source, accepted=accepted, scope=selected,
        full_offline_suite='NOT_EXECUTED', unrelated_native_jobs='NOT_EXECUTED',
        whole_workflow_acceptance='NOT_PERFORMED; REQUIRE_EXACT_HOSTED_JOB_METADATA',
        new_native_executions=0, application='NO-GO', core='NO-GO', independent_assessment='UNFILLED')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--context', type=Path, required=True)
    parser.add_argument('--expect-head', required=True)
    args = parser.parse_args()
    require(sys.dont_write_bytecode and not sys.flags.optimize)
    raw = profile.regular(args.input, MAX_TRANSPORT)
    context = producer.document(profile.regular(args.context, 65536))
    source = profile.source(ROOT, args.expect_head)
    require(context['head'] == args.expect_head and context['source_sha256'] == source['source_sha256'])
    print(json.dumps(decode(raw, root=ROOT, expected_context=context, expected_source=source), sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError):
        raise SystemExit('selected public client originals refused')
