"""Finite data comparison for fixture-only signed-wire syscall exceptions.

This reader never opens a journal owner or calls its transition implementation.
Source selection and fixture agreement do not authenticate source or an actor.
"""
import hashlib
import json
from pathlib import PurePosixPath
import re

BASE = '176d772265103379b312f1e0481e1a2fdf6e2c71'
PARENT = 'compatibility/nom_signed_process_cuts_manifest.json'
PARENT_SHA = 'fd565108a60e52a73d8fe1dda812f04c8d1eeae4df4ba1b1d7a3013a7589f78f'
MANIFEST = 'compatibility/nom_signed_io_faults_manifest.json'
TARGETS = ('signed-short', 'signed-admitted', 'signed-recovered', 'signed-long', 'signed-attempt')
MODES = ('before-write', 'zero-write', 'partial-write', 'complete-write-error',
         'file-sync-error', 'post-sync-error')
PROFILE_SOURCES = ('scripts/nom_signed_io_faults.py', 'scripts/nom_signed_io_evidence.py',
                   'scripts/qualify_nom_signed_io_faults.py')
MAX_FILE = 128 * 1024
MAX_TOTAL = 8 * 1024**2


def require(value):
    if not value:
        raise ValueError('selected signed-wire I/O fault evidence refused')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
        allow_nan=False).encode('ascii')


def decode(raw):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_FILE)
    def pairs(values):
        result = {}
        for key, value in values:
            require(key not in result)
            result[key] = value
        return result
    value = json.loads(raw.decode('ascii'), object_pairs_hook=pairs)
    require(canonical(value) == raw)
    return value


def profile_inputs(root):
    """Check all declared project inputs before importing the selected actor."""
    parent_raw = (root/PARENT).read_bytes()
    require(len(parent_raw) <= MAX_FILE and sha(parent_raw) == PARENT_SHA)
    parent = json.loads(parent_raw)
    selected_raw = (root/MANIFEST).read_bytes()
    require(len(selected_raw) <= MAX_FILE)
    selected = json.loads(selected_raw)
    require(type(selected) is dict and set(selected) == {'schema', 'source_subject_base_commit',
        'parent_manifest_sha256', 'input_sha256', 'application', 'core', 'independent_assessment'})
    require(selected['schema'] == 'ptlc-nom-signed-io-faults-manifest-v1')
    require(selected['source_subject_base_commit'] == BASE and selected['parent_manifest_sha256'] == PARENT_SHA)
    pins = selected['input_sha256']
    require(type(pins) is dict and set(pins) == set(parent['input_sha256']) | {PARENT} | set(PROFILE_SOURCES))
    require(len(pins) == 32 and pins[PARENT] == PARENT_SHA)
    require(all(pins[name] == pin for name, pin in parent['input_sha256'].items()))
    for name, pin in pins.items():
        path = PurePosixPath(name)
        require(path.as_posix() == name and not path.is_absolute() and '..' not in path.parts and '\\' not in name)
        require(type(pin) is str and re.fullmatch('[0-9a-f]{64}', pin))
        raw = (root/name).read_bytes()
        require(len(raw) <= 1024**2 and sha(raw) == pin)
    require(selected['application'] == selected['core'] == 'NO-GO' and selected['independent_assessment'] == 'UNFILLED')
    return pins


def original_names():
    return ['source-selection.json'] + [target+'--'+mode+'/'+name
        for target in TARGETS for mode in MODES
        for name in ('journal.log', 'before-target.log', 'case-result.json')]


def journal_records(raw):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_FILE and raw.endswith(b'\n'))
    lines = raw[:-1].split(b'\n')
    require(1 <= len(lines) <= 16)
    records = []; previous = '00'*32
    for sequence, line in enumerate(lines, 1):
        row = decode(line)
        require(type(row) is dict and set(row) == {'schema', 'sequence', 'previous_hash_hex', 'event', 'hash_hex'})
        require(row['schema'] == 'ptlc-nom-recovery-log-v1' and type(row['sequence']) is int and row['sequence'] == sequence)
        require(row['previous_hash_hex'] == previous)
        unhashed = {key: value for key, value in row.items() if key != 'hash_hex'}
        require(sha(b'ptlc-nom-log-v1\0'+canonical(unhashed)) == row['hash_hex'])
        records.append(row); previous = row['hash_hex']
    return records


def fixture_model(root):
    """Disclosed finite source lookup and public derivatives, without a journal."""
    from offline_session import nom_recovery as base
    from offline_session.nom_signed_recovery import CONTEXT_SCHEMA
    from scripts.nom_signed_corpus import SourceCorpusAllowlist, signed_observation
    terms = json.loads((root/'compatibility/fixtures/nom_supervisor_inputs_v1.json').read_bytes())['terms']
    completions = json.loads((root/'compatibility/fixtures/nom_supervisor_completions_v1.json').read_bytes())
    corpus = json.loads((root/'compatibility/fixtures/nom_signed_originals_v1.json').read_bytes())
    selection = dict(schema=CONTEXT_SCHEMA, source_commit='137fc528f10ad1ac37ca6d9c4f90ed4b9ee8e598',
        source_tree='1897e82296a7cc0d558a39d00398840495638bfd',
        corpus_sha256=sha(json.dumps(corpus, sort_keys=True).encode('ascii')),
        contract_hex=corpus['long-original']['block']['to_address_hex'])
    lookup = SourceCorpusAllowlist(terms, completions['pair'], selection, corpus)
    originals = {}; facts = {}; derivatives = {}
    for leg in ('short', 'long'):
        raw = bytes.fromhex(corpus[leg+'-original']['wire_hex'])
        facts[leg] = lookup.verify_original(leg, raw)
        originals[leg] = dict(wire_hex=raw.hex(), facts_wire_hex=facts[leg].hex())
        derivatives[leg] = base.synthetic_claim(terms, leg, base.decode(facts[leg])['witness_hex']).hex()
    funded = [signed_observation(terms, completions, lookup, leg, 'funded') for leg in ('long', 'short')]
    confirmed = signed_observation(terms, completions, lookup, 'short', 'unlock-confirmed', bytes.fromhex(originals['short']['wire_hex']))
    events = [dict(kind='init', role='bob', terms=terms, pair=completions['pair']), dict(kind='signed-context', selection=selection)]
    events += [dict(kind='signed-observation', wire_hex=raw.hex()) for raw in funded]
    short_event = dict(kind='signed-original', leg='short', **originals['short'])
    long_event = dict(kind='signed-original', leg='long', **originals['long'])
    admitted = dict(kind='signed-admitted', wire_sha256=sha(bytes.fromhex(originals['short']['wire_hex'])))
    recovered = dict(kind='signed-recovered', wire_sha256=admitted['wire_sha256'], signature_hex=completions['long_signature_hex'])
    attempt = dict(kind='signed-attempt', leg='long', wire_sha256=sha(bytes.fromhex(originals['long']['wire_hex'])))
    append = [short_event, admitted, recovered, long_event, attempt]
    prefixes = [events]
    prefixes.append(events+[short_event, dict(kind='signed-observation', wire_hex=confirmed.hex())])
    prefixes.append(prefixes[-1]+[admitted])
    prefixes.append(prefixes[-1]+[recovered])
    prefixes.append(prefixes[-1]+[long_event])
    return dict(selection=selection, originals=originals, derivatives=derivatives, funded=funded,
        confirmed=confirmed, long_completion=completions['long_signature_hex'], prefixes=prefixes, append=append)


def expected_status(model, index, complete):
    short = index != 0 or complete
    long = index == 4 or index == 3 and complete
    completion = index >= 3 or index == 2 and complete
    charge = int(complete) if index == 1 else int(index >= 2)
    phases = {'short': 'UNLOCK_CONFIRMED'} if index >= 1 else {}
    if long:
        phases['long'] = 'OUTCOME_UNKNOWN' if index == 4 and complete else 'ORIGINAL_RETAINED'
    return dict(signed_context=model['selection'],
        signed_originals={leg: model['originals'][leg] for leg, present in (('short', short), ('long', long)) if present},
        long_completion_hex=model['long_completion'] if completion else None,
        recovery_charges=charge, recovery_outcome='COMPLETE' if completion else 'UNKNOWN' if charge else 'NOT_ENTERED',
        phases=phases, attempts={'long': 1} if index == 4 and complete else {}, funded={'long': True, 'short': True},
        disclosure_possible=short, signed_observations=[raw.hex() for raw in model['funded']+([model['confirmed']] if index >= 1 else [])],
        synthetic_reference_derivatives=dict(owned={'long': model['derivatives']['long']} if long else {},
            remote_short_hex=model['derivatives']['short'] if short else ''),
        application='NO-GO', core='NO-GO', observation_authority='UNFILLED')


def inspect(payloads, report, root):
    pins = profile_inputs(root)
    require(type(payloads) is dict and set(payloads) == set(original_names()) and len(payloads) == 91)
    require(all(type(raw) is bytes and len(raw) <= MAX_FILE for raw in payloads.values()))
    require(sum(map(len, payloads.values())) <= MAX_TOTAL)
    selected = decode(payloads['source-selection.json'])
    require(type(selected) is dict and set(selected) == {'schema', 'input_sha256', 'subject_commit', 'python_sha256', 'fixture_oracle'})
    require(selected['schema'] == 'ptlc-nom-signed-io-selection-v1' and selected['input_sha256'] == pins)
    subject = selected['subject_commit']
    require(subject is None or type(subject) is str and re.fullmatch('[0-9a-f]{40}', subject))
    require(type(selected['python_sha256']) is str and re.fullmatch('[0-9a-f]{64}', selected['python_sha256']))
    require(selected['fixture_oracle'] == 'DISCLOSED_FIXTURE_ORACLE; NO_SIGNATURE_MATHEMATICS')
    model = fixture_model(root)
    for index, target in enumerate(TARGETS):
      for mode in MODES:
        name = target+'--'+mode
        before = payloads[name+'/before-target.log']; after = payloads[name+'/journal.log']
        records = journal_records(before)
        require(canonical([row['event'] for row in records]) == canonical(model['prefixes'][index]))
        next_record = dict(schema='ptlc-nom-recovery-log-v1', sequence=len(records)+1,
            previous_hash_hex=records[-1]['hash_hex'], event=model['append'][index])
        next_record['hash_hex'] = sha(b'ptlc-nom-log-v1\0'+canonical(next_record))
        wire = canonical(next_record)+b'\n'
        complete = mode in ('complete-write-error', 'file-sync-error', 'post-sync-error')
        require(after == before+(wire if complete else wire[:17] if mode == 'partial-write' else b''))
        if mode != 'partial-write':
            require(len(journal_records(after)) == len(records)+int(complete))
        status = None if mode == 'partial-write' else expected_status(model, index, complete)
        retry = status is not None and status['recovery_charges'] > 0 and status['long_completion_hex'] is None
        expected = dict(case=name, target=target, mode=mode, original_operation_returned=False,
            current_owner_poisoned=True, intercepted_write_calls=2 if mode == 'partial-write' else 1,
            actual_written_bytes=len(wire) if complete else 17 if mode == 'partial-write' else 0,
            intercepted_file_sync_calls=int(mode in ('file-sync-error', 'post-sync-error')), completed_file_syncs=int(mode == 'post-sync-error'),
            before_sha256=sha(before), after_sha256=sha(after), before_bytes=len(before), after_bytes=len(after),
            reopen='QUARANTINED_TORN_ORIGINAL' if mode == 'partial-write' else 'COMPLETE_EXISTING_IMAGE_SYNCED',
            recovery_entries_before_operation=int(index >= 3), recovery_entries_after_operation=int(index >= 2),
            recovery_entries_on_reopen=0, explicit_unknown_retry_refused=retry, status=status,
            refusal='reference write outcome is uncertain', worker=selected['fixture_oracle'], physical_power_loss='NOT_TESTED')
        require(canonical(decode(payloads[name+'/case-result.json'])) == canonical(expected))
    expected_report = dict(schema='ptlc-nom-signed-io-faults-v1', outcome='PASS', cases=30,
        complete_image_reopens=25, torn_image_quarantines=5, recovery_entries_on_reopen=0,
        explicit_unknown_retry_refusals=5, native_mathematical_executions=0, external_process_kills=0,
        physical_power_loss='NOT_TESTED', independent_assessment='UNFILLED', application='NO-GO', core='NO-GO',
        input_sha256=pins, subject_commit=subject, python_sha256=selected['python_sha256'])
    require(canonical(report) == canonical(expected_report))
    return dict(outcome='PASS_FINITE_DATA_COMPARISON', original_files=91, cases=30,
        journal_transition_calls=0, native_mathematical_executions=0)
