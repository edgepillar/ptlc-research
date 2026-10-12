#!/usr/bin/env python3
"""Compare actual default-cap content against independent complete-batch properties.

The deterministic corpus is produced only after all original source observations
pass. No cross-account order or authenticated recovery permission is inferred.
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
from offline_session.public_worker import WorkerError
from scripts import qualify_nom_batched_rollback as prior
from scripts.generate_nom_content_cap import PROFILE, BASE, FIXTURE, CASE, WINDOWS, READS, BOUNDARY, corpus
from scripts.nom_native_command import private_create, run

MANIFEST = 'compatibility/nom_content_cap_manifest.json'
DRIVER = 'compatibility/nom_content_cap_test.go.txt'
TEST = 'TestResearchNoMContentCap'
PACKAGE = prior.PACKAGE
PREFIX = 'PTLC_RESEARCH_CONTENT_CAP_RECORD '
SELECTED = (FIXTURE, DRIVER, 'scripts/generate_nom_content_cap.py', 'scripts/qualify_nom_content_cap.py', 'tests/test_nom_content_cap.py')
CORE_FILES = {'chain/account_pool.go', 'chain/interface.go', 'vm/constants/plasma.go', 'vm/plasma.go'}
COUNTS = {'control_cases': 1, 'capacity_windows': 4, 'actual_default_content_cap': 100,
          'actual_pending_account_cap': 500, 'exact_preserved_parent_applies': 1,
          'generated_public_controls': 101, 'exact_applied_public_controls': 101,
          'normal_account_pool_admissions': 102, 'actual_public_selections': 64,
          'actual_all_pending_reads': 64, 'new_tests_including_parent': 6,
          'preserved_source_tests_including_parents': 313, 'total_source_tests_including_parents': 319}
POOL, SUPERVISOR, PB, BLOCK = prior.POOL, prior.SUPERVISOR, prior.PB, prior.BLOCK
FIELDS = {'schema', 'id', 'input', 'actual_cap', 'actual_pending_cap', 'parent_apply_signatures',
          'account_signatures', 'momentum_signatures', 'candidates', 'pool_patches', 'checkpoints', 'snapshot_identifiers'}


def expected_tests():
    return {PACKAGE: {TEST, TEST + '/' + CASE, *(TEST + '/' + CASE + '/unrelated-' + str(n) for n in WINDOWS)}}


def selected_inputs(root): return prior.selected_inputs(root)
def read_json(path): return prior.read_json(path)
def logical(model): return prior.logical(model)
def checkpoint_digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode('ascii')).hexdigest()


def order_properties(n, checkpoint):
    users = list(range(2, n + 2)); batch = [0, 1]
    full = {'contract-first': batch + users, 'user-first': users + batch}
    # Treat every user header as its own unit and the original batch as one unit.
    selected = {}
    for label, units in (('contract-first', [batch] + [[i] for i in users]),
                         ('user-first', [[i] for i in users] + [batch])):
        out = []
        for unit in units:
            if len(out) + len(unit) > 100: break
            out.extend(unit)
        selected[label] = out
    return {'independent_reads': READS, 'all_admissible_orders': full,
            'selection_admissible_orders': selected, 'checkpoint_sha256': checkpoint_digest(checkpoint),
            'state_unchanged': True, 'getter_signatures': 0, 'observed_both_orders_required': False}


def candidate(c, previous, used, ack, peer, user):
    if type(c) is not dict or set(c) != prior.CANDIDATE_FIELDS: raise ValueError('complete separate public candidate required')
    r = BLOCK.validate_block(c['block']); b = r['block']; pub = prior.KEYS['unrelated'][0]
    expected = {'version': '1', 'chain_id': '69', 'block_type': '2', 'address_hex': user, 'to_address_hex': peer,
                'height': str(int(previous['height']) + 1), 'previous_hash_hex': previous['hash_hex'],
                'momentum_hash_hex': ack['hash_hex'], 'momentum_height': ack['momentum']['height'], 'amount': '0',
                'token_standard_hex': '00' * 10, 'from_block_hash_hex': '00' * 32, 'descendant_hashes_hex': [],
                'data_hex': '', 'fused_plasma': '21000', 'difficulty': '0', 'nonce_hex': '00' * 8}
    if (b != expected or r['public_key_hex'] != pub or r['children'] != []
            or any(type(c[k]) is not int or c[k] != v for k, v in (('generation_signatures', 1), ('apply_signatures', 0)))
            or any(c[k] != '21000' for k in ('base_plasma', 'total_plasma', 'canonical_base'))
            or c['used_before'] != str(used) or c['available_before'] != str(10500000 - used)):
        raise ValueError('exact predecessor, acknowledgement, public key, cost or disclosed budget differs')
    ops = [(b'\x03' + bytes(10), bytes(32)), (b'\x05', (used + 21000).to_bytes(32, 'big'))]
    delta = POOL.encode_operations(ops).hex()
    if (c['delta_patch_hex'] != delta or c['applied_delta_hex'] != delta or r['changes_hash_hex'] != hashlib.sha3_256(bytes.fromhex(delta)).hexdigest()
            or c['applied_wire_hex'] != r['wire_hex'] or PB.selected_wire(r, 21000, 21000).hex() != r['wire_hex']):
        raise ValueError('complete independent delta, exact apply, hash or protobuf differs')
    return r, ops


def validate_record(r, root=ROOT, *, raw=False):
    selected_field = 'observations' if raw else 'observation_properties'
    if type(r) is not dict or set(r) != FIELDS | {selected_field}: raise ValueError('complete selected content record required')
    seed, base, originals, ack, parent, child = selected_inputs(root)
    if r['schema'] != 'zenon-nom-content-cap-record-v1' or r['id'] != CASE or r['input'] != seed:
        raise ValueError('exact original selected input required')
    for k, v in {'actual_cap': 100, 'actual_pending_cap': 500, 'parent_apply_signatures': 0,
                 'account_signatures': 101, 'momentum_signatures': 0}.items():
        if type(r[k]) is not int or r[k] != v: raise ValueError('unchanged measured defaults or signature counts required')
    identifier = SUPERVISOR.hh(ack['hash_hex'], ack['momentum']['height'])
    if r['snapshot_identifiers'] != [identifier] * 3: raise ValueError('all actual contract snapshot queries require exact anchor')
    if type(r['candidates']) is not list or len(r['candidates']) != 101: raise ValueError('all separate public candidates required')
    patch_names = {'parent', 'child', *(str(n) for n in range(1, 102))}
    labels = {'initial', 'parent-admitted', *('unrelated-' + str(n) for n in WINDOWS)}
    if type(r['pool_patches']) is not dict or set(r['pool_patches']) != patch_names or type(r['checkpoints']) is not dict or set(r['checkpoints']) != labels:
        raise ValueError('all exact pool patches and complete checkpoints required')
    contract = bytes.fromhex(CONTRACT_HEX); user = seed['roles']['unrelated']; peer = seed['roles']['bob']
    prefix = b'\x03' + contract
    states = {'contract': {k[len(prefix):]: v for k, v in base.items() if k.startswith(prefix)}, 'unrelated': {}}
    pending = {'contract': [], 'unrelated': []}

    def check(label):
        expected = {'global_hex': logical(base)}
        for role in states:
            framed = b''.join(len(bytes.fromhex(w)).to_bytes(4, 'big') + bytes.fromhex(w) for w in pending[role])
            expected[role] = {'pool_hex': logical(states[role]), 'pending_count': len(pending[role]),
                              'pending_wire_sha256': hashlib.sha256(framed).hexdigest()}
        value = r['checkpoints'][label]
        if value != expected or any(type(value[role].get('pending_count')) is not int for role in states):
            raise ValueError('complete global, frontier pool or pending-wire projection differs')

    check('initial')
    ops = POOL.ordered_patch(seed['parent_delta_hex']) + POOL.frontier_operations(child) + POOL.frontier_operations(parent)
    if r['pool_patches']['parent'] != POOL.encode_operations(ops).hex() or r['pool_patches']['child'] != '':
        raise ValueError('exact preserved parent augmentation or empty child alias differs')
    states['contract'] = SUPERVISOR.replay(states['contract'], ops); pending['contract'] = [child['wire_hex'], parent['wire_hex']]
    check('parent-admitted'); previous = SUPERVISOR.hh()
    for n, c in enumerate(r['candidates'], 1):
        row, delta = candidate(c, previous, (n - 1) * 21000, ack, peer, user)
        delta += POOL.frontier_operations(row)
        if r['pool_patches'][str(n)] != POOL.encode_operations(delta).hex(): raise ValueError('each exact normal pool patch requires original frontier writes')
        states['unrelated'] = SUPERVISOR.replay(states['unrelated'], delta); pending['unrelated'].append(row['wire_hex'])
        previous = SUPERVISOR.hh(row['hash_hex'], str(n))
        if n in WINDOWS: check('unrelated-' + str(n))
    properties = {label: order_properties(n, r['checkpoints'][label]) for n in WINDOWS for label in ('unrelated-' + str(n),)}
    value = r[selected_field]
    if type(value) is not dict or set(value) != set(properties): raise ValueError('all four independent getter windows required')
    if raw:
        for label, rows in value.items():
            if type(rows) is not list or len(rows) != READS: raise ValueError('all original getter observations required')
            prop = properties[label]
            for observation in rows:
                if type(observation) is not dict or set(observation) != {'all_indices', 'selection_indices', 'checkpoint_before_sha256', 'checkpoint_after_sha256', 'signatures'}:
                    raise ValueError('complete original getter observation required')
                for k, admissible in (('all_indices', prop['all_admissible_orders']), ('selection_indices', prop['selection_admissible_orders'])):
                    v = observation[k]
                    if type(v) is not list or any(type(i) is not int for i in v) or v not in admissible.values():
                        raise ValueError('getter violates complete-batch limit, membership, per-account order or admissible cross-account order')
                if any(observation[k] != prop['checkpoint_sha256'] for k in ('checkpoint_before_sha256', 'checkpoint_after_sha256')):
                    raise ValueError('each getter must bind the complete unchanged checkpoint')
                if type(observation['signatures']) is not int or observation['signatures'] != 0: raise ValueError('getters must sign zero times')
    else:
        if value != properties or any(type(p.get('state_unchanged')) is not bool or type(p.get('observed_both_orders_required')) is not bool or type(p.get('independent_reads')) is not int or type(p.get('getter_signatures')) is not int for p in value.values()):
            raise ValueError('deterministic admissible property projection differs')
        if any(type(i) is not int for p in value.values() for k in ('all_admissible_orders', 'selection_admissible_orders') for indices in p[k].values() for i in indices):
            raise ValueError('typed integer catalog references required')
    return {**{k: copy.deepcopy(r[k]) for k in FIELDS}, 'observation_properties': properties}


def validate_records(records, root=ROOT, *, raw=False):
    if type(records) is not dict or set(records) != {CASE}: raise ValueError('complete selected capacity record required')
    return {CASE: validate_record(records[CASE], root, raw=raw)}


def collect_records(wire, root=ROOT):
    records = {}; pending = ''
    if type(wire) is not bytes or len(wire) > 16 * 1024 * 1024: raise ValueError('bounded original source stream required')
    for raw_line in wire.splitlines():
        event = json.loads(raw_line, object_pairs_hook=SUPERVISOR.vm.unique_object); out = event.get('Output', '')
        if PREFIX in out:
            if (pending or records or event.get('Action') != 'output' or event.get('Package') != PACKAGE or event.get('Test') != TEST + '/' + CASE
                    or re.match(r'^    zz_research_nom_content_cap_test.go:[0-9]+: ' + PREFIX, out) is None): raise ValueError('ambiguous content source framing')
            pending = out.split(PREFIX, 1)[1]
        elif pending:
            if event.get('Action') != 'output' or event.get('Package') != PACKAGE or event.get('Test') != TEST + '/' + CASE: raise ValueError('incomplete or wrong content source stream')
            pending += out
        else: continue
        if len(pending) > 2 * 1024 * 1024: raise ValueError('content source record bound')
        if not pending.endswith('\n'): continue
        record = json.loads(pending.strip(), object_pairs_hook=SUPERVISOR.vm.unique_object); pending = ''
        records[record['id']] = validate_record(record, root, raw=True)
    if pending: raise ValueError('incomplete original content record')
    return validate_records(records, root)


def inputs(root):
    manifest = read_json(root / MANIFEST); fixture = read_json(root / FIXTURE)
    old, _, preserved = prior.inputs(root)
    if (set(manifest) != set(old) or manifest['schema'] != 'zenon-nom-content-cap-manifest-v1' or manifest['profile'] != PROFILE
            or manifest['core_commit'] != CORE_COMMIT or manifest['research_baseline_commit'] != BASE or manifest['expected_counts'] != COUNTS
            or any(type(n) is not int for n in manifest['expected_counts'].values())
            or manifest['preserved_file_sha256'] != preserved or set(manifest['input_sha256']) != set(SELECTED)
            or manifest['patch_format_source'] != old['patch_format_source']
            or set(manifest['core_file_sha256']) != set(old['core_file_sha256']) | CORE_FILES
            or any(manifest['core_file_sha256'].get(n) != h for n, h in old['core_file_sha256'].items())
            or (manifest['application'], manifest['core'], manifest['assessment']) != ('NO-GO', 'NO-GO', 'UNFILLED')):
        raise ValueError('complete selected and preserved source manifest required')
    if fixture != corpus(validate_records(fixture['records'], root)): raise ValueError('complete deterministic property corpus differs')
    measured = {n: SUPERVISOR.vm.digest(root / n) for n in (MANIFEST, *SELECTED, *preserved)}
    if any(measured[n] != h for n, h in {**manifest['input_sha256'], **preserved}.items()): raise ValueError('selected or preserved input changed')
    return manifest, fixture, measured


def execute(checkout, go, root, evidence):
    replacements = {}; sources = {}
    for name, source in (('nom_content_cap', DRIVER), ('nom_batched_rollback', prior.DRIVER), ('nom_momentum_admission', prior.prior.DRIVER)):
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
               environment=dict(os.environ, PTLC_NOM_CAP_INPUT=str(evidence / 'selected-input.json'), GOTOOLCHAIN='local', GOPROXY='off', GOSUMDB='off'),
               directory=checkout, evidence=evidence, label='core-observation', timeout=240)
    passed = SUPERVISOR.vm.selected_outcome(wire, expected_tests())
    if ((evidence / 'overlay.json').read_bytes() != overlay or (evidence / 'selected-input.json').read_bytes() != selected
            or any((evidence / (n + '-source.go.txt')).read_bytes() != b for n, b in sources.items())):
        raise ValueError('complete original overlays or selected-input custody changed')
    return wire, passed


def qualify(checkout, go, *, root=ROOT, evidence_parent=None):
    root, checkout, go = root.resolve(), checkout.resolve(), go.resolve()
    manifest, fixture, before = inputs(root); SUPERVISOR.vm.core_state(checkout, manifest); tool_hash = SUPERVISOR.vm.digest(go)
    parent = evidence_parent or root / '.research-cache/nom-content-cap-evidence'
    parent.mkdir(mode=0o700, parents=True, exist_ok=True); info = parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700: raise ValueError('private evidence ownership required')
    evidence = Path(tempfile.mkdtemp(prefix='content-cap-', dir=parent))
    result = {'schema': 'zenon-nom-content-cap-result-v1', 'profile': PROFILE, 'core_commit': CORE_COMMIT, 'outcome': 'UNKNOWN', **BOUNDARY,
              'input_sha256': before, 'go_executable_sha256': tool_hash, 'overlay_vet': 'NOT_PERFORMED; synthetic overlay paths are unavailable to Go 1.23 vet',
              'stream_custody': 'Original private streams and all three selected source snapshots; hosted private custody may be ephemeral'}
    try:
        old = prior.qualify(checkout, go, root=root, evidence_parent=evidence / 'preserved-batched-rollback')
        if old['outcome'] != 'PASS' or old['counts'] != prior.COUNTS or old['tests_passed_including_parents'] != 313: raise ValueError('complete preserved batch qualification required')
        wire, passed = execute(checkout, go, root, evidence)
        if fixture != corpus(collect_records(wire, root)): raise ValueError('fresh actual getter properties differ from selection')
        SUPERVISOR.vm.core_state(checkout, manifest)
        if before != inputs(root)[2] or tool_hash != SUPERVISOR.vm.digest(go): raise ValueError('selected source changed during qualification')
        result.update(outcome='PASS', counts=COUNTS, source_unchanged=True, source_result=old, new_tests_including_parent=passed,
                      tests_passed_including_parents=passed + 313, current_recovery_permission='NONE; CAPACITY PROPERTIES DO NOT AUTHENTICATE A CHAIN')
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
        print('FAIL: actual source content-cap properties; preserve original private evidence', file=sys.stderr); return 1


if __name__ == '__main__': sys.exit(main())
