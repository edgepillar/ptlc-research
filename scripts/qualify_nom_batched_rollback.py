#!/usr/bin/env python3
"""Compare actual batched insertion and rollback with a separate state model.

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
from scripts import qualify_nom_momentum_admission as prior
from scripts.generate_nom_batched_rollback import PROFILE, BASE, FIXTURE, CASE, CONTROLS, BOUNDARY, corpus
from scripts.nom_native_command import private_create, run

MANIFEST = 'compatibility/nom_batched_rollback_manifest.json'
DRIVER = 'compatibility/nom_batched_rollback_test.go.txt'
TEST = 'TestResearchNoMBatchedRollback'
PACKAGE = prior.PACKAGE
PREFIX = 'PTLC_RESEARCH_BATCH_ROLLBACK_RECORD '
SELECTED = (FIXTURE, DRIVER, 'scripts/generate_nom_batched_rollback.py', 'scripts/qualify_nom_batched_rollback.py', 'tests/test_nom_batched_rollback.py')
CORE_FILES = {'chain/momentum_pool.go', 'chain/momentum_events.go', 'chain/account_pool.go', 'chain/momentum/ledger_store.go', 'vm/vm_context/spork.go', 'consensus/api/pillar_stats.go'}
COUNTS = {'control_cases': 1, 'exact_preserved_parent_applies': 1, 'generated_public_controls': 3,
          'normal_account_pool_admissions': 4, 'generated_momenta': 1, 'exact_applied_momenta': 1,
          'public_momentum_pool_adds': 1, 'public_rollbacks': 1, 'captured_listener_callbacks': 4,
          'refused_controls': 5, 'refused_old_receipts': 1, 'unrelated_originals_retained': 1,
          'dependent_pending_blocks_evicted': 2, 'new_tests_including_parent': 7,
          'preserved_source_tests_including_parents': 306, 'total_source_tests_including_parents': 313}
POOL, SUPERVISOR, PB = prior.POOL, prior.SUPERVISOR, prior.PB
BLOCK = SUPERVISOR.prior
KEYS = {'alice': ('db995fe25169d141cab9bbba92baa01f9f2e1ece7df4cb2ac05190f37fcc1f9d', '0019e9425dcb7b0d14099922e4909cb12afb0500'),
        'unrelated': prior.prior.KEYS['sender']}
RECORD_FIELDS = {'schema', 'id', 'input', 'selection_wires', 'parent_apply_signatures', 'pool_patches', 'candidates', 'momentum',
                 'delta_patch_hex', 'exact_apply_patch_hex', 'manager_patch_hex', 'checkpoints', 'events', 'controls',
                 'post_rollback_aliases', 'account_signatures', 'momentum_signatures', 'producer_calls', 'snapshot_calls', 'snapshot_identifiers'}
CANDIDATE_FIELDS = prior.prior.CANDIDATE_FIELDS


def expected_tests():
    return {PACKAGE: {TEST, TEST + '/' + CASE, *(TEST + '/' + CASE + '/' + n for n in CONTROLS)}}


def logical(model): return POOL.encode_operations(sorted(model.items())).hex()
def read_json(path): return json.loads(path.read_text('ascii'), object_pairs_hook=SUPERVISOR.vm.unique_object)
def header(row): return {'address_hex': row['block']['address_hex'], 'height': row['block']['height'], 'hash_hex': row['hash_hex']}


def selected_inputs(root):
    original = read_json(root / 'compatibility/fixtures/nom_supervisor_plasma_v1.json')['records']['complete']['trace']
    rows = {r['label']: r for r in original}
    parent = rows['short-unlock-receive']['block']; child = parent['children'][0]
    roles = {'alice': rows['long-funding']['block']['block']['address_hex'], 'bob': rows['short-funding']['block']['block']['address_hex'],
             'contract': CONTRACT_HEX, 'unrelated': KEYS['unrelated'][1]}
    model = {}
    for role, label in (('alice', 'short-receipt'), ('bob', 'long-unlock-send'), ('contract', 'short-unlock-receive')):
        account = POOL.state(rows[label]['before_patch_hex']); address = bytes.fromhex(roles[role])
        model.update({b'\x03' + address + k: v for k, v in account.items()})
        model[b'\x08' + address] = bytes(32)
    momenta = []
    for i, at in ((0, 100), (1, 700)):
        m = {'version': '1', 'chain_id': '69', 'previous_hash_hex': '00' * 32, 'height': str(10109300 + i), 'timestamp': str(at),
             'data_hex': '', 'content': [], 'changes_hash_hex': '00' * 32, 'next_fusion_price': '0', 'next_work_price': '0'}
        r = {'hash_hex': hashlib.sha3_256(('public-nom-supervisor-v1:momentum-' + str(i)).encode('ascii')).hexdigest(),
             'public_key_hex': '', 'signature_hex': '', 'momentum': m}
        r['wire_hex'] = prior.momentum_wire(r).hex(); r['roundtrip_wire_hex'] = r['wire_hex']; momenta.append(r)
        model.update(prior.frontier(r))
    for label in ('long-funding', 'short-funding', 'long-create', 'short-create', 'short-unlock-send'):
        r = rows[label]['block']; h = bytes.fromhex(r['hash_hex'])
        model[b'\x09' + h] = prior.header_wire(header(r)); model[b'\x05' + h] = prior.u64(10109301)
    mail = b'\x04' + bytes.fromhex(CONTRACT_HEX)
    for i, label in enumerate(('long-funding', 'short-funding', 'short-unlock-send'), 1):
        r = rows[label]['block']; model[mail + b'\x04' + bytes.fromhex(r['hash_hex'])] = prior.u64(1)
        model[mail + b'\x08' + prior.u64(i)] = prior.header_wire(header(r))
    model[mail + b'\x07'] = prior.u64(3)
    model[mail + b'\x05' + bytes.fromhex(rows['short-unlock-send']['block']['hash_hex'])] = prior.u64(1)
    for role, send, receive in (('alice', 'long-funding', 'long-create'), ('bob', 'short-funding', 'short-create')):
        model[b'\x04' + bytes.fromhex(roles[role]) + b'\x06' + bytes.fromhex(rows[send]['block']['hash_hex'])] = prior.header_wire(header(rows[receive]['block']))
    value = {'root_hex': logical(model), 'parent_wire_hex': parent['wire_hex'], 'parent_delta_hex': rows['short-unlock-receive']['delta_patch_hex'],
             'old_receipt_wire_hex': rows['short-receipt']['block']['wire_hex'], 'roles': roles}
    return value, model, rows, momenta[-1], parent, child


def candidate(c, role, previous, used, ack, child=None):
    if type(c) is not dict or set(c) != CANDIDATE_FIELDS: raise ValueError('complete selected candidate required')
    r = BLOCK.validate_block(c['block']); b = r['block']; pub, address = KEYS[role]
    expected = {'version': '1', 'chain_id': '69', 'block_type': '3' if child else '2', 'address_hex': address,
                'to_address_hex': '00' * 20 if child else '00a307fb31c7585b6ccb5dc3ddc844e22b14b7aa',
                'height': str(int(previous['height']) + 1), 'previous_hash_hex': previous['hash_hex'],
                'momentum_hash_hex': ack['hash_hex'], 'momentum_height': ack['momentum']['height'], 'amount': '0',
                'token_standard_hex': '00' * 10, 'from_block_hash_hex': child['hash_hex'] if child else '00' * 32,
                'descendant_hashes_hex': [], 'data_hex': '', 'fused_plasma': '21000', 'difficulty': '0', 'nonce_hex': '00' * 8}
    if (b != expected or r['public_key_hex'] != pub or r['children'] != []
            or any(type(c[k]) is not int or c[k] != v for k, v in (('generation_signatures', 1), ('apply_signatures', 0)))
            or any(c[k] != '21000' for k in ('base_plasma', 'total_plasma', 'canonical_base'))
            or c['used_before'] != str(used) or c['available_before'] != str(420000 - used)):
        raise ValueError('exact public predecessor, acknowledgement, cost, budget or key differs')
    token = bytes.fromhex(child['block']['token_standard_hex']) if child else bytes(10)
    balance = int(child['block']['amount']) if child else 0
    ops = [(b'\x03' + token, balance.to_bytes(32, 'big')), (b'\x05', (used + 21000).to_bytes(32, 'big'))]
    if child: ops.append((b'\x06' + bytes.fromhex(child['hash_hex']), prior.u64(1)))
    delta = POOL.encode_operations(ops).hex()
    if (c['delta_patch_hex'] != delta or c['applied_delta_hex'] != delta or r['changes_hash_hex'] != hashlib.sha3_256(bytes.fromhex(delta)).hexdigest()
            or c['applied_wire_hex'] != r['wire_hex'] or PB.selected_wire(r, 21000, 21000).hex() != r['wire_hex']):
        raise ValueError('complete independent account delta, hash or protobuf differs')
    return r, ops


def validate_record(r, root=ROOT):
    if (type(r) is not dict or set(r) != RECORD_FIELDS or r['schema'] != 'zenon-nom-batched-rollback-record-v1' or r['id'] != CASE
            or any(type(r[k]) is not int or r[k] != v for k, v in (('parent_apply_signatures', 0), ('account_signatures', 3), ('momentum_signatures', 1), ('producer_calls', 2), ('snapshot_calls', 7)))):
        raise ValueError('complete exact source batch record required')
    seed, base, originals, anchor, parent, child = selected_inputs(root)
    if r['snapshot_identifiers'] != [SUPERVISOR.hh(anchor['hash_hex'], '10109301')] * 7: raise ValueError('all actual previous snapshots must name the exact selected anchor')
    if r['input'] != seed or r['selection_wires'] != [child['wire_hex'], parent['wire_hex']]: raise ValueError('preserved original selection or independent initial state differs')
    names = ('fresh-dependent-receive', 'fresh-dependent-suffix', 'unrelated-old-ack')
    if (type(r['candidates']) is not dict or set(r['candidates']) != set(names)
            or type(r['pool_patches']) is not dict or set(r['pool_patches']) != {'parent', 'child', *names}
            or type(r['checkpoints']) is not dict or set(r['checkpoints']) != {'initial', 'before-insertion', 'after-insertion', 'before-rollback', 'after-rollback'}):
        raise ValueError('complete selected account candidates, patches and checkpoints required')
    roles = seed['roles']; pool_models = {}
    for role, address in roles.items():
        prefix = b'\x03' + bytes.fromhex(address); pool_models[role] = {k[len(prefix):]: v for k, v in base.items() if k.startswith(prefix)}
    base_accounts = copy.deepcopy(pool_models); pending = {role: [] for role in roles}
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
        h = bytes.fromhex(row['hash_hex']); delta[b'\x09' + h] = prior.header_wire(header(row)); delta[b'\x05' + h] = prior.u64(10109302)
    received = bytes.fromhex(parent['block']['from_block_hash_hex'])
    delta[b'\x04' + bytes.fromhex(roles['alice']) + b'\x06' + received] = prior.header_wire(header(parent))
    delta[b'\x04' + bytes.fromhex(CONTRACT_HEX) + b'\x05' + received] = None
    mail = b'\x04' + bytes.fromhex(roles['alice']); h = bytes.fromhex(child['hash_hex'])
    delta[mail + b'\x04' + h] = prior.u64(1); delta[mail + b'\x05' + h] = prior.u64(1)
    wire_delta = POOL.encode_operations(sorted(delta.items())).hex(); current = r['momentum']
    expected_m = {**anchor['momentum'], 'previous_hash_hex': anchor['hash_hex'], 'height': '10109302', 'timestamp': '701',
                  'content': [header(child), header(parent)], 'changes_hash_hex': hashlib.sha3_256(bytes.fromhex(wire_delta)).hexdigest()}
    if (type(current) is not dict or set(current) != prior.MOMENTUM_FIELDS or current['momentum'] != expected_m
            or current['hash_hex'] != nom_momentum.momentum_hash(expected_m) or current['public_key_hex'] != prior.PRODUCER_KEY
            or type(current['signature_hex']) is not str or re.fullmatch('[0-9a-f]{128}', current['signature_hex']) is None
            or prior.momentum_wire(current).hex() != current['wire_hex'] or current['roundtrip_wire_hex'] != current['wire_hex']
            or r['delta_patch_hex'] != wire_delta or r['exact_apply_patch_hex'] != wire_delta
            or r['manager_patch_hex'] != (bytes.fromhex(wire_delta) + POOL.encode_operations(prior.frontier(current))).hex()):
        raise ValueError('complete independently encoded momentum, exact delta or manager augmentation differs')
    model = SUPERVISOR.replay(model, sorted(delta.items()) + prior.frontier(current)); pending['contract'] = []
    check(r['checkpoints']['after-insertion'])
    rows = {}
    for name, role, ack, from_child in ((names[0], 'alice', current, child), (names[1], 'alice', current, None), (names[2], 'unrelated', anchor, None)):
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
    if type(r['events']) is not list or len(r['events']) != 4: raise ValueError('complete actual listener sequence required')
    for i, event in enumerate(r['events']):
        expected_phase = ('insert' if i < 2 else 'delete') + ('-before-account-pool' if i % 2 == 0 else '-after-account-pool')
        if type(event) is not dict or set(event) != {'phase', 'momentum_wire_hex', 'included_wires', 'checkpoint'} or event['phase'] != expected_phase or event['momentum_wire_hex'] != current['wire_hex'] or event['included_wires'] != r['selection_wires']: raise ValueError('actual child and parent prefetch or listener ordering differs')
        if i < 2:
            if event['checkpoint'] != (r['checkpoints']['after-insertion'] if i else {k: ({x: v for x, v in val.items() if x not in ('pool_hex', 'pending_wires')} if k in roles else val) for k, val in r['checkpoints']['after-insertion'].items()}): raise ValueError('insert listener sees unselected state')
        else:
            model = dict(base); current_saved = current; current = anchor
            if i == 2: check(event['checkpoint'], False)
            else:
                pool_models['contract'] = base_accounts['contract']; pool_models['alice'] = base_accounts['alice']; pending['alice'] = []
                check(event['checkpoint']); check(r['checkpoints']['after-rollback'])
            current = current_saved
    aliases = {}
    for name in ('parent', 'child', *names):
        retained = name == names[2]
        patch = r['pool_patches'][name] if retained else ''
        aliases[name] = {'present': retained, 'patch_present': retained, 'patch_hex': patch}
    if (type(r['post_rollback_aliases']) is not dict or set(r['post_rollback_aliases']) != set(aliases)
            or any(type(value) is not dict or set(value) != {'present', 'patch_present', 'patch_hex'}
                   or type(value['present']) is not bool or type(value['patch_present']) is not bool
                   for value in r['post_rollback_aliases'].values())):
        raise ValueError('complete typed historical aliases required')
    if r['post_rollback_aliases'] != aliases: raise ValueError('removed aliases or exact unrelated retained patch differs')
    return r


def validate_records(records, root=ROOT):
    if type(records) is not dict or set(records) != {CASE}: raise ValueError('complete selected rollback record required')
    validate_record(records[CASE], root); return records


def collect_records(wire, root=ROOT):
    records = {}; pending = ''
    if type(wire) is not bytes or len(wire) > 16 * 1024 * 1024: raise ValueError('bounded source stream required')
    for raw in wire.splitlines():
        event = json.loads(raw, object_pairs_hook=SUPERVISOR.vm.unique_object); out = event.get('Output', '')
        if PREFIX in out:
            if (pending or records or event.get('Action') != 'output' or event.get('Package') != PACKAGE or event.get('Test') != TEST + '/' + CASE
                    or re.match(r'^    zz_research_nom_batched_rollback_test.go:[0-9]+: ' + PREFIX, out) is None): raise ValueError('ambiguous source rollback framing')
            pending = out.split(PREFIX, 1)[1]
        elif pending:
            if event.get('Action') != 'output' or event.get('Package') != PACKAGE or event.get('Test') != TEST + '/' + CASE: raise ValueError('incomplete or wrong source rollback stream')
            pending += out
        else: continue
        if len(pending) > 2 * 1024 * 1024: raise ValueError('selected rollback record bound')
        if not pending.endswith('\n'): continue
        record = json.loads(pending.strip(), object_pairs_hook=SUPERVISOR.vm.unique_object); pending = ''; records[record['id']] = validate_record(record, root)
    if pending: raise ValueError('incomplete source rollback record')
    return validate_records(records, root)


def inputs(root):
    manifest = read_json(root / MANIFEST); fixture = read_json(root / FIXTURE)
    old, _, preserved = prior.inputs(root)
    if (set(manifest) != set(old) or manifest['schema'] != 'zenon-nom-batched-rollback-manifest-v1' or manifest['profile'] != PROFILE
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
    for name, source in (('nom_batched_rollback', DRIVER), ('nom_momentum_admission', prior.DRIVER)):
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
               environment=dict(os.environ, PTLC_NOM_BATCH_INPUT=str(evidence / 'selected-input.json'), GOTOOLCHAIN='local', GOPROXY='off', GOSUMDB='off'),
               directory=checkout, evidence=evidence, label='core-observation', timeout=240)
    passed = SUPERVISOR.vm.selected_outcome(wire, expected_tests())
    if ((evidence / 'overlay.json').read_bytes() != overlay or (evidence / 'selected-input.json').read_bytes() != selected
            or any((evidence / (n + '-source.go.txt')).read_bytes() != b for n, b in sources.items())):
        raise ValueError('complete original overlay or selected-input custody changed')
    return wire, passed


def qualify(checkout, go, *, root=ROOT, evidence_parent=None):
    root, checkout, go = root.resolve(), checkout.resolve(), go.resolve()
    manifest, fixture, before = inputs(root); SUPERVISOR.vm.core_state(checkout, manifest); tool_hash = SUPERVISOR.vm.digest(go)
    parent = evidence_parent or root / '.research-cache/nom-batched-rollback-evidence'
    parent.mkdir(mode=0o700, parents=True, exist_ok=True); info = parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700: raise ValueError('private evidence ownership required')
    evidence = Path(tempfile.mkdtemp(prefix='batched-rollback-', dir=parent))
    result = {'schema': 'zenon-nom-batched-rollback-result-v1', 'profile': PROFILE, 'core_commit': CORE_COMMIT, 'outcome': 'UNKNOWN', **BOUNDARY,
              'input_sha256': before, 'go_executable_sha256': tool_hash, 'overlay_vet': 'NOT_PERFORMED; synthetic overlay paths are unavailable to Go 1.23 vet',
              'stream_custody': 'Original private streams and both selected source snapshots; hosted private custody may be ephemeral'}
    try:
        old = prior.qualify(checkout, go, root=root, evidence_parent=evidence / 'preserved-momentum-admission')
        if old['outcome'] != 'PASS' or old['counts'] != prior.COUNTS or old['tests_passed_including_parents'] != 306: raise ValueError('complete preserved momentum qualification required')
        wire, passed = execute(checkout, go, root, evidence)
        if fixture != corpus(collect_records(wire, root)): raise ValueError('fresh actual rollback execution differs from selection')
        SUPERVISOR.vm.core_state(checkout, manifest)
        if before != inputs(root)[2] or tool_hash != SUPERVISOR.vm.digest(go): raise ValueError('selected source changed during qualification')
        result.update(outcome='PASS', counts=COUNTS, source_unchanged=True, source_result=old, new_tests_including_parent=passed,
                      tests_passed_including_parents=passed + 306, current_recovery_permission='NONE; ACTUAL MEMORY CALLBACKS DO NOT AUTHENTICATE A CHAIN')
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
        print('FAIL: actual source batched rollback controls; preserve original private evidence', file=sys.stderr); return 1


if __name__ == '__main__': sys.exit(main())
