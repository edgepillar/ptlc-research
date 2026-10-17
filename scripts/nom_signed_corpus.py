"""Disclosed source-record lookup and synthetic observation builder for qualification.

This is not application cryptography, a general account verifier or chain proof.
"""
import hashlib
import json
from offline_session import nom_recovery as base
from offline_session.nom_wire import account_block_hash, decode_call
from offline_session.nom_signed_recovery import selected_context, FACT_SCHEMA, OBSERVATION_SCHEMA

class SourceCorpusAllowlist:
    """Admit only exact bytes from an explicitly selected source-probe record set.

    The source probe was separately qualified. This lookup is not a fresh node
    execution, a general signature verifier, source authentication or chain proof.
    """
    def __init__(self, terms, pair, selection, records):
        raw = json.dumps(records, sort_keys=True).encode('ascii')
        if hashlib.sha256(raw).hexdigest() != selection['corpus_sha256']:
            raise base.RecoveryError('selected source record set differs')
        self._wire = raw
        self.terms = base.decode(base.canonical(terms))
        self.selection, self.context_digest_hex = selected_context(terms, pair, selection)
        self.calls = 0

    def verify_original(self, leg, raw):
        self.calls += 1
        if type(raw) is not bytes:
            raise base.RecoveryError('exact fixture bytes required')
        rows = [r for r in json.loads(self._wire).values() if r['leg'] == leg
            and r['wire_hex'] == raw.hex() and r['checks'] == dict(hash='PASS', signature='PASS', producer='PASS')]
        if len(rows) != 1:
            raise base.RecoveryError('public source allowlist refused')
        r = rows[0]
        block = r['block']
        call = decode_call(bytes.fromhex(block['data_hex']))
        if (r['computed_hash_hex'] != r['hash_hex'] or account_block_hash(block) != r['hash_hex']
                or call['method'] != 'Unlock' or block['block_type'] != '2' or block['amount'] != '0'):
            raise base.RecoveryError('selected public source projection refused')
        return base.canonical(dict(schema=FACT_SCHEMA, leg=leg, context_digest_hex=self.context_digest_hex,
            wire_sha256=hashlib.sha256(raw).hexdigest(), node_hash_hex=r['hash_hex'], chain_id=block['chain_id'],
            entry_id_hex=call['entry_id_hex'], caller_hex=block['address_hex'], contract_hex=block['to_address_hex'],
            witness_hex=call['witness_hex'], checks=r['checks']))


def signed_observation(terms, completions, allowlist, leg, kind, raw=None):
    """Explicit synthetic observation wrapper; never an authenticated chain fact."""
    values = {}
    node_hash, raw_sha = terms[leg]['entry_id_hex'], ''
    if kind != 'funded':
        facts = base.decode(allowlist.verify_original(leg, raw))
        node_hash, raw_sha = facts['node_hash_hex'], facts['wire_sha256']
        derivative = base.synthetic_claim(terms, leg, facts['witness_hex'])
        values['transaction_hash_hex'] = base.synthetic_transaction_hash(derivative)
        if kind in ('send-confirmed', 'unlock-confirmed'):
            values.update(send_timestamp='900', send_momentum_hash_hex='aa'*32)
        if kind == 'unlock-confirmed':
            values.update(receive_timestamp='1100', receive_momentum_hash_hex='bb'*32)
    return base.canonical(dict(schema=OBSERVATION_SCHEMA, context_digest_hex=allowlist.context_digest_hex,
        node_hash_hex=node_hash, wire_sha256=raw_sha, reference=base.observation(terms, leg, kind, **values)))
