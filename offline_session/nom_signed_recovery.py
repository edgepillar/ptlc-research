"""Offline candidate for exact public signed-wire custody.

The raw verifier and immutable observation callback are explicitly trusted.
Neither is implemented or authenticated here. Synthetic reference derivatives
remain separate from retained account bytes. No signer, transport, chain
authority, rollback fence, runtime sandbox or production permission is supplied.
"""
import copy
import hashlib
import os
import re

from . import nom_recovery as base
from .nom_recovery_snapshot import SnapshotNomRecovery
from .pr138 import fixed_hex

CONTEXT_SCHEMA = 'ptlc-nom-public-signed-context-v1'
FACT_SCHEMA = 'ptlc-nom-public-signed-original-facts-v1'
OBSERVATION_SCHEMA = 'ptlc-nom-public-signed-observation-v1'
MAX_RAW = 2048
MAX_FACTS = 2048


def _require(value):
    if not value:
        raise base.RecoveryError('selected public signed-wire candidate refused')


def selected_context(terms, pair, selection):
    base.validate_terms(terms); base.validate_pair(pair)
    base.fields(selection, ('schema', 'source_commit', 'source_tree', 'corpus_sha256', 'contract_hex'))
    _require(selection['schema'] == CONTEXT_SCHEMA)
    for name in ('source_commit', 'source_tree'):
        _require(type(selection[name]) is str and re.fullmatch('[0-9a-f]{40}', selection[name]))
    fixed_hex(selection['corpus_sha256'], 32); fixed_hex(selection['contract_hex'], 20)
    wire = base.canonical(selection)
    return base.decode(wire), base.digest(b'ptlc-nom-public-signed-context-v1', {
        'selection': base.decode(wire), 'verification_context_digest_hex': base.verification_context_digest(terms, pair)})


class SignedNomRecoveryCandidate(SnapshotNomRecovery):
    """Actual inherited file journal, with a separate two-phase raw-wire path.

    New event kinds are deliberately incompatible with the historical writer.
    This is no migration and cannot authenticate any old journal or its facts.
    The trusted verifier returns immutable canonical fact bytes for the exact
    raw input; source admission and canonical chain observation remain external.
    """

    @classmethod
    def open(cls, path, terms, pair, *, role, verifier, raw_verifier,
             observation_verifier, selection, hook=None):
        terms = base.decode(base.canonical(base.validate_terms(terms)))
        pair = base.decode(base.canonical(base.validate_pair(pair)))
        selection, selected_digest = selected_context(terms, pair, selection)
        _require(callable(observation_verifier) and callable(getattr(raw_verifier, 'verify_original', None))
            and getattr(raw_verifier, 'context_digest_hex', None) == selected_digest)
        created = []
        def mark(kind):
            if kind == 'init': created.append(True)
            if hook is not None: hook(kind)
        instance = None
        try:
            instance = super().open(path, terms, pair, role=role, verifier=verifier,
                observation_verifier=lambda unused: False, hook=mark)
            instance._signed_busy = False
            instance._raw_verifier = raw_verifier
            instance._signed_observer = observation_verifier
            if instance._state['signed_context'] is None:
                _require(created == [True] and instance._sequence == 1)
                instance._append({'kind': 'signed-context', 'selection': selection})
            _require(instance._state['signed_context'] == selection)
            for leg, original in instance._state['signed_originals'].items():
                raw = bytes.fromhex(original['wire_hex'])
                fresh = instance._foreign(lambda: raw_verifier.verify_original(leg, raw))
                _require(type(fresh) is bytes and fresh.hex() == original['facts_wire_hex'])
                instance._facts(leg, raw, fresh, instance._state)
            completed = instance._state['recovered_long_hex']
            if completed:
                _require(instance._foreign(lambda: verifier.verify_claim('long', completed)) is True)
            # A complete record surviving a lost acknowledgement is synced
            # before this selected reopen returns any local state or output.
            try:
                os.fsync(instance._fd); os.fsync(instance._dir)
            except OSError:
                raise base.Quarantined('signed reopen durability outcome is unknown') from None
            return instance
        except BaseException:
            if instance is not None: instance.close()
            raise

    def _signed_guard(self):
        self._check()
        if self._signed_busy:
            raise base.RecoveryError('signed-wire callback reentry refused')

    def _foreign(self, operation):
        self._signed_guard()
        self._signed_busy = True
        try:
            result = operation()
        finally:
            self._signed_busy = False
        self._check()
        return result

    def _read_image(self):
        self._check_file()
        os.lseek(self._fd, 0, os.SEEK_SET)
        chunks, size = [], 0
        while True:
            raw = os.read(self._fd, min(65536, base.MAX_LOG+1-size))
            if not raw: break
            chunks.append(raw); size += len(raw)
            if size > base.MAX_LOG:
                raise base.Quarantined('signed journal image exceeds its boundary')
        return b''.join(chunks)

    def _load(self):
        try:
            selected = self._read_image()
            base.NomRecovery._load(self)
            if self._read_image() != selected:
                raise base.Quarantined('signed journal changed while opening')
        except (base.RecoveryError, OSError, ValueError, TypeError, KeyError, RecursionError, OverflowError):
            raise base.Quarantined('signed history refused without repair') from None
        self._signed_image = selected

    def _check(self):
        base.NomRecovery._check(self)
        selected = getattr(self, '_signed_image', b'')
        try:
            if self._read_image() != selected:
                raise base.Quarantined('signed journal continuity changed')
        except (OSError, base.RecoveryError):
            self._poisoned = True
            raise base.Quarantined('signed journal continuity changed') from None

    def _append(self, event):
        self._check()
        record = {'schema': 'ptlc-nom-recovery-log-v1', 'sequence': self._sequence+1,
            'previous_hash_hex': self._head, 'event': event}
        record['hash_hex'] = base.digest(b'ptlc-nom-log-v1', record)
        expected = getattr(self, '_signed_image', b'')+base.canonical(record)+b'\n'
        base.NomRecovery._append(self, event)
        try:
            if self._read_image() != expected:
                raise base.Quarantined('signed append image differs')
        except (OSError, base.RecoveryError):
            self._poisoned = True
            raise base.Quarantined('signed append acknowledgement is unknown') from None
        self._signed_image = expected

    def _facts(self, leg, raw, facts_wire, state):
        _require(type(raw) is bytes and 0 < len(raw) <= MAX_RAW
            and type(facts_wire) is bytes and 0 < len(facts_wire) <= MAX_FACTS)
        facts = base.decode(facts_wire)
        base.fields(facts, ('schema', 'leg', 'context_digest_hex', 'wire_sha256', 'node_hash_hex',
            'chain_id', 'entry_id_hex', 'caller_hex', 'contract_hex', 'witness_hex', 'checks'))
        selected, expected = selected_context(self.terms, self.pair, state['signed_context'])
        _require(leg in ('long', 'short') and facts['schema'] == FACT_SCHEMA and facts['leg'] == leg
            and facts['context_digest_hex'] == expected
            and facts['wire_sha256'] == hashlib.sha256(raw).hexdigest()
            and facts['chain_id'] == self.terms['chain_id']
            and facts['entry_id_hex'] == self.terms[leg]['entry_id_hex']
            and facts['caller_hex'] == self.terms[self.terms[leg]['recipient']+'_address_hex']
            and facts['contract_hex'] == selected['contract_hex']
            and facts['checks'] == dict(hash='PASS', signature='PASS', producer='PASS'))
        fixed_hex(facts['node_hash_hex'], 32); fixed_hex(facts['witness_hex'], 64)
        return facts

    def _signed_proof(self, wire, state):
        _require(type(wire) is bytes)
        proof = base.decode(wire)
        base.fields(proof, ('schema', 'context_digest_hex', 'node_hash_hex', 'wire_sha256', 'reference'))
        _require(proof['schema'] == OBSERVATION_SCHEMA and proof['context_digest_hex'] == selected_context(
            self.terms, self.pair, state['signed_context'])[1])
        reference = proof['reference']
        leg, kind = self._validate_observation(reference, state)
        if kind == 'funded':
            # This is an explicit trusted entry claim; no signed funding bytes
            # or authenticated entry proof are inferred by this candidate.
            _require(proof['node_hash_hex'] == self.terms[leg]['entry_id_hex'] and proof['wire_sha256'] == '')
        else:
            _require(leg in state['signed_originals'])
            original = state['signed_originals'][leg]
            facts = self._facts(leg, bytes.fromhex(original['wire_hex']), bytes.fromhex(original['facts_wire_hex']), state)
            _require((proof['node_hash_hex'], proof['wire_sha256']) == (facts['node_hash_hex'], facts['wire_sha256']))
        return proof, leg, kind

    def _apply(self, event):
        kind = event.get('kind') if type(event) is dict else None
        if kind == 'init':
            state = base.NomRecovery._apply(self, event)
            state.update(signed_context=None, signed_originals={}, signed_observations=[])
            return state
        state = copy.deepcopy(self._state)
        if kind == 'signed-context':
            base.fields(event, ('kind', 'selection'))
            _require(state['initialized'] and state['signed_context'] is None and self._sequence == 1)
            state['signed_context'] = selected_context(self.terms, self.pair, event['selection'])[0]
            return state
        _require(state.get('signed_context') is not None)
        if kind == 'signed-original':
            base.fields(event, ('kind', 'leg', 'wire_hex', 'facts_wire_hex'))
            leg = event['leg']
            raw, facts_wire = bytes.fromhex(event['wire_hex']), bytes.fromhex(event['facts_wire_hex'])
            facts = self._facts(leg, raw, facts_wire, state)
            _require(leg not in state['signed_originals'])
            derivative = base.synthetic_claim(self.terms, leg, facts['witness_hex'])
            if leg == 'short' and self.role == 'bob':
                transition = {'kind': 'remote-short', 'leg': 'short', 'wire_hex': derivative.hex()}
            else:
                _require(self._owned(leg))
                transition = {'kind': 'original', 'leg': leg, 'wire_hex': derivative.hex()}
            state = base.NomRecovery._apply(self, transition)
            state['signed_originals'][leg] = {'wire_hex': raw.hex(), 'facts_wire_hex': facts_wire.hex()}
            state['disclosure_possible'] = True
        elif kind == 'signed-observation':
            base.fields(event, ('kind', 'wire_hex'))
            wire = bytes.fromhex(event['wire_hex'])
            proof, leg, unused = self._signed_proof(wire, state)
            state = base.NomRecovery._apply(self, {'kind': 'observation', 'proof': proof['reference']})
            state['signed_observations'].append(wire.hex())
        elif kind in ('signed-admitted', 'signed-recovered', 'signed-attempt'):
            expected = ('kind', 'leg', 'wire_sha256') if kind == 'signed-attempt' else (
                ('kind', 'wire_sha256', 'signature_hex') if kind == 'signed-recovered' else ('kind', 'wire_sha256'))
            base.fields(event, expected)
            leg = event['leg'] if kind == 'signed-attempt' else 'short'
            _require(leg in state['signed_originals'])
            original = state['signed_originals'][leg]
            _require(event['wire_sha256'] == hashlib.sha256(bytes.fromhex(original['wire_hex'])).hexdigest())
            if kind == 'signed-admitted':
                _require(state['recovery_count'] == 0 and not state['recovered_long_hex'])
                transition = {'kind': 'recovery-admitted'}
            elif kind == 'signed-recovered':
                _require(state['recovery_count'] == 1)
                transition = {'kind': 'recovered', 'signature_hex': event['signature_hex']}
            else:
                transition = {'kind': 'attempt', 'leg': leg}
            state = base.NomRecovery._apply(self, transition)
        else:
            raise base.RecoveryError('historical event is not a signed-wire selection')
        return state

    def retain_signed_original(self, leg, raw):
        self._signed_guard()
        _require(leg in ('long', 'short') and type(raw) is bytes and 0 < len(raw) <= MAX_RAW)
        _require(self._owned(leg) or (leg == 'short' and self.role == 'bob'))
        original = self._state['signed_originals'].get(leg)
        if original:
            _require(original['wire_hex'] == raw.hex())
            return base.decode(bytes.fromhex(original['facts_wire_hex']))
        if leg == 'long': _require(bool(self._state['recovered_long_hex']))
        facts_wire = self._foreign(lambda: self._raw_verifier.verify_original(leg, raw))
        facts = self._facts(leg, raw, facts_wire, self._state)
        _require(self._foreign(lambda: self._verifier.verify_claim(leg, facts['witness_hex'])) is True)
        self._append({'kind': 'signed-original', 'leg': leg, 'wire_hex': raw.hex(), 'facts_wire_hex': facts_wire.hex()})
        return base.decode(facts_wire)

    def record_signed_observation(self, wire):
        self._signed_guard()
        proof, leg, unused = self._signed_proof(wire, self._state)
        _require(self._foreign(lambda: self._signed_observer(wire)) is True)
        prior = next((encoded for encoded in reversed(self._state['signed_observations'])
            if base.decode(bytes.fromhex(encoded))['reference']['leg'] == leg), None)
        if prior != wire.hex(): self._append({'kind': 'signed-observation', 'wire_hex': wire.hex()})

    def recover_long_completion(self, original_short, proof_wire):
        self._signed_guard()
        _require(self.role == 'bob' and type(proof_wire) is bytes)
        facts = self.retain_signed_original('short', original_short)
        proof, leg, kind = self._signed_proof(proof_wire, self._state)
        _require(leg == 'short' and kind == 'unlock-confirmed')
        self.record_signed_observation(proof_wire)
        if not self._state['recovered_long_hex']:
            if self._state['recovery_count']:
                raise base.Quarantined('previous public recovery remains unknown; automatic retry refused')
            self._append({'kind': 'signed-admitted', 'wire_sha256': facts['wire_sha256']})
            signature = self._foreign(lambda: self._verifier.recover_long(facts['witness_hex']))
            _require(self._foreign(lambda: self._verifier.verify_claim('long', signature)) is True)
            self._append({'kind': 'signed-recovered', 'wire_sha256': facts['wire_sha256'], 'signature_hex': signature})
        # A public completion is returned, never an outer signed account block.
        return self._state['recovered_long_hex']

    def prepare_signed_attempt(self, leg):
        self._signed_guard()
        _require(leg in self._state['signed_originals'])
        raw = bytes.fromhex(self._state['signed_originals'][leg]['wire_hex'])
        self._append({'kind': 'signed-attempt', 'leg': leg, 'wire_sha256': hashlib.sha256(raw).hexdigest()})
        return raw

    def status(self):
        self._signed_guard()
        state = super().status()
        return dict(signed_context=state['signed_context'], signed_originals=state['signed_originals'],
            long_completion_hex=state['recovered_long_hex'] or None, recovery_charges=state['recovery_count'],
            recovery_outcome=('COMPLETE' if state['recovered_long_hex'] else 'UNKNOWN' if state['recovery_count'] else 'NOT_ENTERED'),
            phases=state['phases'], attempts=state['attempts'], funded=state['funded'],
            disclosure_possible=state['disclosure_possible'], signed_observations=state['signed_observations'],
            synthetic_reference_derivatives=dict(owned=state['originals'], remote_short_hex=state['remote_short_hex']),
            application='NO-GO', core='NO-GO', observation_authority='UNFILLED')

    def record_observation(self, *args, **kwargs):
        raise base.RecoveryError('use the explicit signed observation path')

    def retain_original(self, *args, **kwargs):
        raise base.RecoveryError('use exact signed original retention')

    def prepare_attempt(self, *args, **kwargs):
        raise base.RecoveryError('use exact signed original output')

    def recover_long(self, *args, **kwargs):
        raise base.RecoveryError('select public completion recovery before supplying a signed original')
