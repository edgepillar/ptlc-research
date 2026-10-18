"""Synthetic source-output and artifact fixtures; never native execution proof."""
import copy
import hashlib
import json
from scripts import qualify_nom_rpc_quotes as cli
from qualification.nom_rpc_quote_source import CORE, TREE, LICENSE_SHA256, inputs
from qualification import nom_rpc_quote_generic as generic, nom_rpc_quote_ptlc as ptlc
from tests.nom_signed_source_frames import fixture_stream as signed_stream


def stream(records, model, chunk=71):
    events = [dict(Action='run', Package=model.PACKAGE, Test=model.TEST)]
    for identifier, record in sorted(records.items()):
        name = model.TEST + '/' + identifier
        events.append(dict(Action='run', Package=model.PACKAGE, Test=name))
        line = '    ' + model.PROBE_NAME + ':100: ' + model.PREFIX + json.dumps(record, sort_keys=True, separators=(',', ':')) + '\n'
        for offset in range(0, len(line), chunk):
            events.append(dict(Action='output', Package=model.PACKAGE, Test=name, Output=line[offset:offset + chunk]))
        events.append(dict(Action='pass', Package=model.PACKAGE, Test=name))
    events.extend((dict(Action='pass', Package=model.PACKAGE, Test=model.TEST), dict(Action='pass', Package=model.PACKAGE)))
    return b'\n'.join(json.dumps(event, sort_keys=True).encode('ascii') for event in events) + b'\n'


def outcome_stream(package, names):
    events = []
    for parent in sorted(name for name in names if '/' not in name):
        events.append(dict(Action='run', Package=package, Test=parent))
        for name in sorted(name for name in names if name.startswith(parent + '/')):
            events.extend((dict(Action='run', Package=package, Test=name), dict(Action='pass', Package=package, Test=name)))
        events.append(dict(Action='pass', Package=package, Test=parent))
    events.append(dict(Action='pass', Package=package))
    return b'\n'.join(json.dumps(event, sort_keys=True).encode('ascii') for event in events) + b'\n'


def rewrite_record(raw, model, identifier, transform):
    lines = raw.splitlines()
    events = [json.loads(line) for line in lines]
    name = model.TEST + '/' + identifier
    indices = [i for i, event in enumerate(events) if event.get('Action') == 'output' and event.get('Test') == name]
    assert indices
    text = ''.join(events[i]['Output'] for i in indices)
    selected = [line for line in text.splitlines(keepends=True) if model.PREFIX in line]
    assert len(selected) == 1
    line = selected[0]
    prefix, value = line.split(model.PREFIX, 1)
    record = json.loads(value)
    transform(record)
    replacement = prefix + model.PREFIX + json.dumps(record, sort_keys=True, separators=(',', ':')) + '\n'
    changed = dict(events[indices[0]], Output=text.replace(line, replacement, 1))
    omitted = set(indices[1:])
    return b'\n'.join(json.dumps(changed).encode('ascii') if i == indices[0] else line
        for i, line in enumerate(lines) if i not in omitted) + b'\n'


def rewrite_quote(raw, model, identifier, transform):
    def change(record):
        value = json.loads(bytes.fromhex(record['typed_result_json_hex']))
        transform(value)
        record['typed_result_json_hex'] = json.dumps(value, separators=(',', ':')).encode('ascii').hex()
    return rewrite_record(raw, model, identifier, change)


def valid_artifact(root):
    manifest, unused, generic_records, ptlc_records = inputs(root)
    originals = json.loads((root / 'compatibility/fixtures/nom_signed_originals_v1.json').read_bytes())
    executable = 'ab' * 32  # Explicit synthetic unit metadata, never a measured executable.
    selection = dict(schema=cli.SELECTION_SCHEMA, core_commit=CORE, core_tree=TREE, subject_commit=None,
        input_sha256=manifest['input_sha256'], source_index_payload_sha256=manifest['source_index_payload_sha256'],
        go_executable_sha256=executable, source_license_sha256=LICENSE_SHA256,
        upstream_source_files=443, combined_source_files=446,
        application='NO-GO', core='NO-GO', independent_assessment='UNFILLED')
    payloads = {'source-selection.json': cli.canonical(selection), 'go-version.stdout': b'go version go1.23.12 linux/amd64\n',
        'originals.stdout': signed_stream(originals), 'generic.stdout': stream(generic_records, generic),
        'ptlc.stdout': stream(ptlc_records, ptlc),
        'upstream-rpc.stdout': outcome_stream(generic.PACKAGE, cli.upstream_names())}
    for group in cli.GROUPS:
        payloads[group + '.stderr'] = b''
    runs = {}
    for group in cli.GROUPS:
        row = dict(actual_exit=0, output_complete=True, timed_out=False, selected_files_retained=True,
            retention='COMPLETE_COLLECTED_STREAMS')
        for suffix in ('stdout', 'stderr'):
            raw = payloads[group + '.' + suffix]
            row[suffix + '_bytes'] = row['retained_' + suffix + '_bytes'] = len(raw)
            row[suffix + '_sha256'] = row['retained_' + suffix + '_sha256'] = hashlib.sha256(raw).hexdigest()
        runs[group] = row
    report = dict(schema=cli.RESULT_SCHEMA, outcome='PASS', subject_commit=None, core_commit=CORE, core_tree=TREE,
        input_sha256=manifest['input_sha256'], go_executable_sha256=executable, source_unchanged=True,
        native_runs=runs, default_vet='NORMAL DEFAULT FOR FOUR TEST COMMANDS',
        collection='SYNTHETIC UNIT METADATA; NO NATIVE EXECUTION',
        network_rpc='NOT_PERFORMED', signer='NOT_SELECTED', original_fee_rewrite='NOT_PERFORMED',
        journal_source_upgrade='NOT_SELECTED', node_activation='NOT_PERFORMED',
        application='NO-GO', core='NO-GO', independent_assessment='UNFILLED')
    report['comparison'] = cli.compare_streams(payloads, root)
    return payloads, report


def write_artifact(directory, payloads, report, root):
    for name, raw in payloads.items():
        cli.write_original(directory / name, raw)
    cli.retain_manifest(directory, copy.deepcopy(report), root)
