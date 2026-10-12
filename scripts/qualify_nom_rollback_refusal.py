#!/usr/bin/env python3
"""Compare selected source refusal and complete actual rollback prefixes with a separate state model.

Selected memory state is not an authenticated chain or recovery permission.
Every failed native attempt retains original evidence without fixture fallback.
"""

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from offline_session.pr138 import CORE_COMMIT, CONTRACT_HEX
from offline_session import nom_momentum
from offline_session.public_worker import WorkerError
from scripts import qualify_nom_multi_rollback as prior
from scripts import qualify_nom_batched_rollback as batch
momentum = batch.prior
from scripts.generate_nom_rollback_refusal import PROFILE, BASE, FIXTURE, CASES, CONTROLS, BOUNDARY, corpus
from scripts.nom_native_command import private_create, run

MANIFEST = 'compatibility/nom_rollback_refusal_manifest.json'
DRIVER = 'compatibility/nom_rollback_refusal_test.go.txt'
TEST = 'TestResearchNoMRollbackRefusal'
PACKAGE = prior.PACKAGE
PREFIX = 'PTLC_RESEARCH_ROLLBACK_REFUSAL_RECORD '
SELECTED = (FIXTURE, DRIVER, 'scripts/generate_nom_rollback_refusal.py', 'scripts/qualify_nom_rollback_refusal.py', 'tests/test_nom_rollback_refusal.py')
CORE_FILES = {'chain/momentum_pool.go', 'chain/momentum_events.go', 'chain/account_pool.go', 'chain/momentum/momentum.go', 'common/db/interfaces.go', 'common/db/memdb.go', 'common/db/versioned_db.go', 'common/types/hash_height.go', 'common/types/hash.go', 'vm/vm.go'}
COUNTS = {'control_cases': 2, 'exact_preserved_parent_applies': 2, 'generated_public_controls': 6,
          'normal_account_pool_admissions': 8, 'generated_momenta': 4, 'exact_applied_momenta': 4,
          'public_momentum_pool_adds': 4, 'selected_failed_rollbacks': 2, 'actual_successful_pops': 1,
          'actual_pop_calls': 3, 'injected_pre_delegation_refusals': 2, 'captured_listener_callbacks': 10,
          'refused_controls': 10, 'no_op_controls': 2, 'refused_old_receipts': 2,
          'typed_uncertain_results': 1, 'original_error_results': 1, 'pending_originals_retained': 6,
          'automatic_retries': 0, 'rollback_targets_reached': 0,
          'new_tests_including_parent': 15, 'preserved_source_tests_including_parents': 327,
          'total_source_tests_including_parents': 342}
POOL, SUPERVISOR, PB, BLOCK = batch.POOL, batch.SUPERVISOR, batch.PB, batch.BLOCK
RECORD_FIELDS = prior.RECORD_FIELDS | {'failure'}
CANDIDATE_FIELDS = batch.CANDIDATE_FIELDS


def expected_tests():
    return {PACKAGE: {TEST, *(TEST + '/' + case for case in CASES), *(TEST + '/' + case + '/' + n for case in CASES for n in CONTROLS)}}


def logical(model): return POOL.encode_operations(sorted(model.items())).hex()
def read_json(path): return json.loads(path.read_text('ascii'), object_pairs_hook=SUPERVISOR.vm.unique_object)
def header(row): return {'address_hex': row['block']['address_hex'], 'height': row['block']['height'], 'hash_hex': row['hash_hex']}


def selected_inputs(root): return batch.selected_inputs(root)
def candidate(*args, **kwargs): return batch.candidate(*args, **kwargs)
def checkpoint_digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode('ascii')).hexdigest()


def selected_momentum(value, expected):
    if (type(value) is not dict or set(value) != momentum.MOMENTUM_FIELDS or value['momentum'] != expected
            or value['hash_hex'] != nom_momentum.momentum_hash(expected) or value['public_key_hex'] != momentum.PRODUCER_KEY
            or type(value['signature_hex']) is not str or re.fullmatch('[0-9a-f]{128}', value['signature_hex']) is None
            or momentum.momentum_wire(value).hex() != value['wire_hex'] or value['roundtrip_wire_hex'] != value['wire_hex']):
        raise ValueError('complete independent successor hash, selected producer key or protobuf differs')


def validate_record(r, root=ROOT):
    if (type(r) is not dict or set(r) != RECORD_FIELDS or r['schema'] != 'zenon-nom-rollback-refusal-record-v1' or r['id'] not in CASES
            or any(type(r[k]) is not int or r[k] != v for k, v in (('parent_apply_signatures', 0), ('account_signatures', 3), ('momentum_signatures', 2), ('producer_calls', 4), ('snapshot_calls', 11)))):
        raise ValueError('complete exact source batch record required')
    successful = CASES.index(r['id'])
    seed, base, originals, anchor, parent, child = selected_inputs(root)
    if r['snapshot_identifiers'] != [SUPERVISOR.hh(anchor['hash_hex'], '10109301')] * 7 + [SUPERVISOR.hh(r['momentum']['hash_hex'], '10109302')] * 4: raise ValueError('all actual previous snapshots must name the exact selected anchor')
    if r['input'] != seed or r['selection_wires'] != [child['wire_hex'], parent['wire_hex']]: raise ValueError('preserved original selection or independent initial state differs')
    names = ('fresh-dependent-receive', 'fresh-dependent-suffix', 'unrelated-old-ack')
    if (type(r['candidates']) is not dict or set(r['candidates']) != set(names)
            or type(r['pool_patches']) is not dict or set(r['pool_patches']) != {'parent', 'child', *names}
            or type(r['checkpoints']) is not dict or set(r['checkpoints']) != {'initial', 'before-insertion', 'after-insertion', 'before-rollback', 'before-second-insertion', 'after-second-insertion', 'after-refusal', *(['after-first-pop'] if successful else [])}):
        raise ValueError('complete selected account candidates, patches and checkpoints required')
    roles = seed['roles']; pool_models = {}
    for role, address in roles.items():
        prefix = b'\x03' + bytes.fromhex(address); pool_models[role] = {k[len(prefix):]: v for k, v in base.items() if k.startswith(prefix)}
    pending = {role: [] for role in roles}
    ordered = POOL.ordered_patch(seed['parent_delta_hex']) + POOL.frontier_operations(child) + POOL.frontier_operations(parent)
    parent_patch = POOL.encode_operations(ordered).hex()
    if r['pool_patches']['parent'] != parent_patch or r['pool_patches']['child'] != '': raise ValueError('empty child alias or exact augmented parent patch differs')
    model = dict(base); current = anchor

    def check(value, read_pool=True):
        expected = {'global_dump_hex': logical(model), 'momentum': current}
        for role, address in roles.items():
            acc = b'\x03' + bytes.fromhex(address); mail = b'\x04' + bytes.fromhex(address)
            item = {'stable_hex': logical({k[len(acc):]: v for k, v in model.items() if k.startswith(acc)}),
                    'mailbox_hex': logical({k[len(mail):]: v for k, v in model.items() if k.startswith(mail)})}
            if read_pool: item.update(pool_hex=logical(pool_models[role]), pending_wires=pending[role])
            expected[role] = item
        for label, row in (('parent', parent), ('child', child), ('old-receipt', originals['short-receipt']['block'])):
            included = b'\x09' + bytes.fromhex(row['hash_hex']) in model
            expected[label] = {'wire_hex': row['wire_hex'] if included else '', 'confirmation_height': '10109302' if included else '0'}
        if value != expected: raise ValueError('complete stable, pool, mailbox, header or confirmation projection differs')

    check(r['checkpoints']['initial'])
    pool_models['contract'] = SUPERVISOR.replay(pool_models['contract'], ordered); pending['contract'] = r['selection_wires']
    check(r['checkpoints']['before-insertion'])
    acc = b'\x03' + bytes.fromhex(CONTRACT_HEX); delta = {acc + k: v for k, v in ordered}
    delta[b'\x08' + bytes.fromhex(CONTRACT_HEX)] = bytes(32)
    for row in (parent, child):
        h = bytes.fromhex(row['hash_hex']); delta[b'\x09' + h] = momentum.header_wire(header(row)); delta[b'\x05' + h] = momentum.u64(10109302)
    received = bytes.fromhex(parent['block']['from_block_hash_hex'])
    delta[b'\x04' + bytes.fromhex(roles['alice']) + b'\x06' + received] = momentum.header_wire(header(parent))
    delta[b'\x04' + bytes.fromhex(CONTRACT_HEX) + b'\x05' + received] = None
    mail = b'\x04' + bytes.fromhex(roles['alice']); h = bytes.fromhex(child['hash_hex'])
    delta[mail + b'\x04' + h] = momentum.u64(1); delta[mail + b'\x05' + h] = momentum.u64(1)
    wire_delta = POOL.encode_operations(sorted(delta.items())).hex(); current = r['momentum']
    expected_m = {**anchor['momentum'], 'previous_hash_hex': anchor['hash_hex'], 'height': '10109302', 'timestamp': '701',
                  'content': [header(child), header(parent)], 'changes_hash_hex': hashlib.sha3_256(bytes.fromhex(wire_delta)).hexdigest()}
    if (type(current) is not dict or set(current) != momentum.MOMENTUM_FIELDS or current['momentum'] != expected_m
            or current['hash_hex'] != nom_momentum.momentum_hash(expected_m) or current['public_key_hex'] != momentum.PRODUCER_KEY
            or type(current['signature_hex']) is not str or re.fullmatch('[0-9a-f]{128}', current['signature_hex']) is None
            or momentum.momentum_wire(current).hex() != current['wire_hex'] or current['roundtrip_wire_hex'] != current['wire_hex']
            or r['delta_patch_hex'] != wire_delta or r['exact_apply_patch_hex'] != wire_delta
            or r['manager_patch_hex'] != (bytes.fromhex(wire_delta) + POOL.encode_operations(momentum.frontier(current))).hex()):
        raise ValueError('complete independently encoded momentum, exact delta or manager augmentation differs')
    model = SUPERVISOR.replay(model, sorted(delta.items()) + momentum.frontier(current)); pending['contract'] = []
    check(r['checkpoints']['after-insertion'])
    check(r['checkpoints']['before-second-insertion'])
    first = current; first_model = dict(model)
    second = r['second_momentum']
    if type(second) is not dict or set(second) != {'momentum', 'delta_patch_hex', 'exact_apply_patch_hex', 'manager_patch_hex'}:
        raise ValueError('complete empty successor record required')
    expected_second = {**first['momentum'], 'previous_hash_hex': first['hash_hex'], 'height': '10109303', 'timestamp': '702',
                       'content': [], 'changes_hash_hex': hashlib.sha3_256(b'').hexdigest()}
    current = second['momentum']; selected_momentum(current, expected_second)
    if (second['delta_patch_hex'] != '' or second['exact_apply_patch_hex'] != ''
            or second['manager_patch_hex'] != POOL.encode_operations(momentum.frontier(current)).hex()):
        raise ValueError('empty successor requires empty VM delta and only exact manager frontier writes')
    model = SUPERVISOR.replay(model, momentum.frontier(current))
    check(r['checkpoints']['after-second-insertion'])
    rows = {}
    for name, role, ack, from_child in ((names[0], 'alice', first, child), (names[1], 'alice', first, None), (names[2], 'unrelated', anchor, None)):
        state = pool_models[role]
        previous = SUPERVISOR.hh(originals['short-unlock-send']['block']['hash_hex'], '2') if name == names[0] else SUPERVISOR.hh(rows[names[0]]['hash_hex'], '3') if name == names[1] else SUPERVISOR.hh()
        used = int.from_bytes(state.get(b'\x05', bytes(32)), 'big')
        row, ops = candidate(r['candidates'][name], role, previous, used, ack, from_child)
        rows[name] = row; ops += POOL.frontier_operations(row)
        if r['pool_patches'][name] != POOL.encode_operations(ops).hex(): raise ValueError('exact normal fresh pool patch differs')
        pool_models[role] = SUPERVISOR.replay(state, ops); pending[role].append(row['wire_hex'])
    check(r['checkpoints']['before-rollback'])
    if type(r['controls']) is not dict or set(r['controls']) != set(CONTROLS): raise ValueError('all exact refusal controls required')
    errors = {'missing-add-locker': "insertLocker can't be nil", 'missing-rollback-locker': "insertLocker can't be nil",
              'wrong-target-height': "can't rollback momentums. Expected ", 'wrong-target-hash': "can't rollback momentums. Expected ",
              'old-receipt-before-confirmation': "account-block from-block doesn't exist"}
    for name, control in r['controls'].items():
        if name == 'already-at-frontier': continue
        old = name == 'old-receipt-before-confirmation'
        fields = {'error', 'state_unchanged', 'original_wire_hex', 'transaction_present', 'signatures'} if old else {'error', 'state_unchanged', 'callbacks'}
        fields |= {'checkpoint_before_sha256', 'checkpoint_after_sha256'}
        if name in ('missing-rollback-locker', 'wrong-target-height', 'wrong-target-hash'): fields |= {'target', 'locker_present'}
        check_name = 'before-insertion' if name == 'missing-add-locker' else 'after-insertion' if old else 'before-rollback'
        digest = hashlib.sha256(json.dumps(r['checkpoints'][check_name], sort_keys=True, separators=(',', ':')).encode('ascii')).hexdigest()
        if control.get('checkpoint_before_sha256') != digest or control.get('checkpoint_after_sha256') != digest: raise ValueError('each refusal must bind the complete exact stable and pool checkpoint')
        if name in ('missing-rollback-locker', 'wrong-target-height', 'wrong-target-hash'):
            target = SUPERVISOR.hh(anchor['hash_hex'], '10109300' if name == 'wrong-target-height' else '10109301')
            if name == 'wrong-target-hash': target['hash_hex'] = '2a' + anchor['hash_hex'][2:]
            if control.get('target') != target or control.get('locker_present') is not (name != 'missing-rollback-locker'): raise ValueError('exact selected target or insert locker differs')
        if (type(control) is not dict or set(control) != fields or control['state_unchanged'] is not True
                or type(control['error']) is not str or not control['error'].isascii() or not 1 <= len(control['error']) <= 1024
                or not control['error'].startswith(errors[name])): raise ValueError('exact refusal or independent stable isolation differs')
        if old:
            if control['original_wire_hex'] != seed['old_receipt_wire_hex'] or control['transaction_present'] is not False or type(control['signatures']) is not int or control['signatures'] != 0: raise ValueError('old receipt refusal must preserve original and sign zero times')
        elif type(control['callbacks']) is not int or control['callbacks'] != 0: raise ValueError('refused caller must emit no callback')
    no_op = r['controls']['already-at-frontier']; bound = checkpoint_digest(r['checkpoints']['before-rollback'])
    if (type(no_op) is not dict or set(no_op) != {'result', 'callbacks', 'signatures', 'checkpoint_before_sha256', 'checkpoint_after_sha256', 'target'}
            or no_op['result'] != 'NO_OP' or no_op['target'] != SUPERVISOR.hh(current['hash_hex'], '10109303')
            or any(type(no_op[k]) is not int or no_op[k] != 0 for k in ('callbacks', 'signatures'))
            or no_op['checkpoint_before_sha256'] != bound or no_op['checkpoint_after_sha256'] != bound):
        raise ValueError('frontier no-op requires exact target, zero callbacks and signatures and complete unchanged logical state')
    if type(r['events']) is not list or len(r['events']) != 4 + 2 * successful: raise ValueError('both actual insertions and both actual pop callbacks required')
    second_row = current
    for i, event in enumerate(r['events']):
        kind = 'insert' if i < 4 else 'delete'
        phase = kind + ('-before-account-pool' if i % 2 == 0 else '-after-account-pool')
        event_m = first if i in (0, 1, 6, 7) else second_row
        included = r['selection_wires'] if i in (0, 1, 6, 7) else []
        if (type(event) is not dict or set(event) != {'phase', 'momentum_wire_hex', 'included_wires', 'checkpoint'}
                or event['phase'] != phase or event['momentum_wire_hex'] != event_m['wire_hex'] or event['included_wires'] != included):
            raise ValueError('actual prefetch membership, popped momentum or complete callback order differs')
        if i < 4:
            target = r['checkpoints']['after-insertion' if i < 2 else 'after-second-insertion']
            if i % 2 == 0:
                target = {k: ({x: v for x, v in val.items() if x not in ('pool_hex', 'pending_wires')} if k in roles else val) for k, val in target.items()}
            if event['checkpoint'] != target: raise ValueError('actual insertion callback has unselected complete state')
        elif i < 6:
            model = dict(first_model); current = first
            check(event['checkpoint'], i == 5)
            if i == 5: check(r['checkpoints']['after-first-pop'])
    mid = r['intermediate_pending_aliases']
    expected_mid = {name: {'present': True, 'patch_present': True, 'patch_hex': r['pool_patches'][name]} for name in names} if successful else {}
    if (type(mid) is not dict or mid != expected_mid
            or any(type(value) is not dict or set(value) != {'present', 'patch_present', 'patch_hex'}
                   or type(value['present']) is not bool or type(value['patch_present']) is not bool for value in mid.values())):
        raise ValueError('all three original pending aliases and exact patches must survive the first actual pop')
    check(r['checkpoints']['after-refusal'])
    aliases = {name: {'present': True, 'patch_present': True, 'patch_hex': r['pool_patches'][name]} for name in names}
    aliases.update(parent={'present': True, 'patch_present': False, 'patch_hex': ''}, child={'present': False, 'patch_present': False, 'patch_hex': ''})
    if (type(r['post_rollback_aliases']) is not dict or r['post_rollback_aliases'] != aliases
            or any(type(value.get('present')) is not bool or type(value.get('patch_present')) is not bool for value in r['post_rollback_aliases'].values())):
        raise ValueError('complete confirmed and retained pending aliases require exact original patches')
    selected_error = 'selected pre-delegation Pop refusal'
    cause = 'canonical rollback to {' + anchor['hash_hex'] + ' 10109301} stopped after 1 successful pop(s)' if successful else ''
    expected_failure = {
        'error': 'canonical chain state uncertain: operation failed (' + cause + '); recovery failed (' + selected_error + ')' if successful else selected_error,
        'typed_uncertain': bool(successful), 'cause': cause, 'rollback_error': selected_error if successful else '',
        'original_error_identity': not bool(successful), 'unwrap_selected_error': not bool(successful),
        'rollback_error_identity': bool(successful), 'unwrap_cause': bool(successful),
        'pop_calls': 1 + successful, 'successful_pops': successful, 'injected_refusals': 1,
        'public_rollback_calls': 1, 'signatures': 0, 'delete_callbacks': 2 * successful, 'target_reached': False,
        'target': SUPERVISOR.hh(anchor['hash_hex'], '10109301'), 'frontier': SUPERVISOR.hh(current['hash_hex'], current['momentum']['height']),
        'checkpoint_before_sha256': checkpoint_digest(r['checkpoints']['before-rollback']),
        'checkpoint_after_sha256': checkpoint_digest(r['checkpoints']['after-refusal']),
    }
    failure = r['failure']
    if type(failure) is not dict or set(failure) != set(expected_failure): raise ValueError('complete actual source failure and original identity required')
    if any(type(failure[k]) is not type(value) or failure[k] != value for k, value in expected_failure.items()):
        raise ValueError('actual typed source classification, complete prefix, original error identity or zero-retry boundary differs')
    return r


def validate_records(records, root=ROOT):
    if type(records) is not dict or set(records) != set(CASES): raise ValueError('complete selected rollback record required')
    for case in CASES:
        if type(records[case]) is not dict or records[case].get('id') != case: raise ValueError('selected case identity required')
        validate_record(records[case], root)
    return records


def collect_records(wire, root=ROOT):
    records = {}; pending = ''; pending_test = ''
    if type(wire) is not bytes or len(wire) > 16 * 1024 * 1024: raise ValueError('bounded source stream required')
    for raw in wire.splitlines():
        event = json.loads(raw, object_pairs_hook=SUPERVISOR.vm.unique_object); out = event.get('Output', '')
        if PREFIX in out:
            if (pending or event.get('Action') != 'output' or event.get('Package') != PACKAGE or event.get('Test') not in {TEST + '/' + case for case in CASES}
                    or re.match(r'^    zz_research_nom_rollback_refusal_test.go:[0-9]+: ' + PREFIX, out) is None): raise ValueError('ambiguous source rollback framing')
            pending = out.split(PREFIX, 1)[1]; pending_test = event['Test']
        elif pending:
            if event.get('Action') != 'output' or event.get('Package') != PACKAGE or event.get('Test') != pending_test: raise ValueError('incomplete or wrong source rollback stream')
            pending += out
        else: continue
        if len(pending) > 2 * 1024 * 1024: raise ValueError('selected rollback record bound')
        if not pending.endswith('\n'): continue
        record = json.loads(pending.strip(), object_pairs_hook=SUPERVISOR.vm.unique_object); pending = ''
        if record.get('id') in records or pending_test != TEST + '/' + record.get('id', ''): raise ValueError('duplicate or misattributed source refusal record')
        records[record['id']] = validate_record(record, root)
    if pending: raise ValueError('incomplete source rollback record')
    return validate_records(records, root)


def inputs(root):
    manifest = read_json(root / MANIFEST); fixture = read_json(root / FIXTURE)
    old, _, preserved = prior.inputs(root)
    if (set(manifest) != set(old) or manifest['schema'] != 'zenon-nom-rollback-refusal-manifest-v1' or manifest['profile'] != PROFILE
            or manifest['core_commit'] != CORE_COMMIT or manifest['research_baseline_commit'] != BASE or manifest['expected_counts'] != COUNTS
            or any(type(n) is not int for n in manifest['expected_counts'].values())
            or manifest['preserved_file_sha256'] != preserved or set(manifest['input_sha256']) != set(SELECTED)
            or manifest['patch_format_source'] != old['patch_format_source']
            or set(manifest['core_file_sha256']) != (set(old['core_file_sha256']) | CORE_FILES)
            or any(manifest['core_file_sha256'].get(n) != h for n, h in old['core_file_sha256'].items())
            or (manifest['application'], manifest['core'], manifest['assessment']) != ('NO-GO', 'NO-GO', 'UNFILLED')):
        raise ValueError('complete selected and preserved source manifest required')
    if fixture != corpus(validate_records(fixture['records'], root)): raise ValueError('complete source rollback corpus differs')
    measured = {n: SUPERVISOR.vm.digest(root / n) for n in (MANIFEST, *SELECTED, *preserved)}
    if any(measured[n] != h for n, h in {**manifest['input_sha256'], **preserved}.items()): raise ValueError('selected or preserved input changed')
    return manifest, fixture, measured


def execute(checkout, go, root, evidence):
    replacements = {}; sources = {}
    for name, source in (('nom_rollback_refusal', DRIVER), ('nom_multi_rollback', prior.DRIVER), ('nom_batched_rollback', batch.DRIVER), ('nom_momentum_admission', momentum.DRIVER)):
        target = checkout / 'vm' / ('zz_research_' + name + '_test.go')
        if target.exists() or target.is_symlink(): raise ValueError('overlay would replace an existing input')
        snapshot = evidence / (name + '-source.go.txt'); sources[name] = (root / source).read_bytes()
        with private_create(snapshot) as out: out.write(sources[name])
        replacements[str(target)] = str(snapshot)
    selected = (json.dumps(selected_inputs(root)[0], sort_keys=True) + '\n').encode('ascii')
    with private_create(evidence / 'selected-input.json') as out: out.write(selected)
    overlay = (json.dumps({'Replace': replacements}, sort_keys=True) + '\n').encode('ascii')
    with private_create(evidence / 'overlay.json') as out: out.write(overlay)
    wire = run([str(go), 'test', '-json', '-overlay', str(evidence / 'overlay.json'), '-vet=off', '-mod=readonly', '-count=1', '-run', '^' + TEST + '$', './vm'],
               environment=dict(os.environ, PTLC_NOM_REFUSAL_INPUT=str(evidence / 'selected-input.json'), GOTOOLCHAIN='local', GOPROXY='off', GOSUMDB='off'),
               directory=checkout, evidence=evidence, label='core-observation', timeout=240)
    passed = SUPERVISOR.vm.selected_outcome(wire, expected_tests())
    if ((evidence / 'overlay.json').read_bytes() != overlay or (evidence / 'selected-input.json').read_bytes() != selected
            or any((evidence / (n + '-source.go.txt')).read_bytes() != b for n, b in sources.items())):
        raise ValueError('complete original overlay or selected-input custody changed')
    return wire, passed


def qualify(checkout, go, *, root=ROOT, evidence_parent=None):
    root, checkout, go = root.resolve(), checkout.resolve(), go.resolve()
    manifest, fixture, before = inputs(root); SUPERVISOR.vm.core_state(checkout, manifest); tool_hash = SUPERVISOR.vm.digest(go)
    parent = evidence_parent or root / '.research-cache/nom-rollback-refusal-evidence'
    parent.mkdir(mode=0o700, parents=True, exist_ok=True); info = parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700: raise ValueError('private evidence ownership required')
    evidence = Path(tempfile.mkdtemp(prefix='rollback-refusal-', dir=parent))
    result = {'schema': 'zenon-nom-rollback-refusal-result-v1', 'profile': PROFILE, 'core_commit': CORE_COMMIT, 'outcome': 'UNKNOWN', **BOUNDARY,
              'input_sha256': before, 'go_executable_sha256': tool_hash, 'overlay_vet': 'NOT_PERFORMED; synthetic overlay paths are unavailable to Go 1.23 vet',
              'stream_custody': 'Original private streams and all four selected source snapshots; hosted private custody may be ephemeral'}
    try:
        old = prior.qualify(checkout, go, root=root, evidence_parent=evidence / 'preserved-multi-rollback')
        if old['outcome'] != 'PASS' or old['counts'] != prior.COUNTS or old['tests_passed_including_parents'] != 327: raise ValueError('complete preserved momentum qualification required')
        wire, passed = execute(checkout, go, root, evidence)
        if fixture != corpus(collect_records(wire, root)): raise ValueError('fresh actual rollback execution differs from selection')
        SUPERVISOR.vm.core_state(checkout, manifest)
        if before != inputs(root)[2] or tool_hash != SUPERVISOR.vm.digest(go): raise ValueError('selected source changed during qualification')
        result.update(outcome='PASS', counts=COUNTS, source_unchanged=True, source_result=old, new_tests_including_parent=passed,
                      tests_passed_including_parents=passed + 327, current_recovery_permission='NONE; ACTUAL MEMORY CALLBACKS DO NOT AUTHENTICATE A CHAIN')
        return result
    except BaseException:
        result['outcome'] = 'FAILED_OR_INCOMPLETE'; raise
    finally:
        with private_create(evidence / 'outcome.json') as out: out.write((json.dumps(result, sort_keys=True) + '\n').encode('ascii'))


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--checkout', type=Path, required=True); parser.add_argument('--go', type=Path, required=True)
    args = parser.parse_args()
    try: print(json.dumps(qualify(args.checkout, args.go), sort_keys=True)); return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, WorkerError):
        print('FAIL: selected source rollback refusal controls; preserve original private evidence', file=sys.stderr); return 1


if __name__ == '__main__': sys.exit(main())
