"""Bounded hypothetical traces; no admission, custody or recovery authority."""
import json
from pathlib import Path
import re


SCHEMA = 'ptlc-nom-disclosure-timeout-request-v1'
RESULT = 'ptlc-nom-disclosure-timeout-result-v1'
CORE = '85c39796fa5ab6fb5ca16e61af34b6616f0ceafe'
TREE = 'cdeb5b6276c13447197c829c5855faa72afd86b9'
MAX_REQUEST = 32768
MAX_EVENTS = 32
MAX_TIME = 2**63 - 1
MAX_WORK = 4
LEGS = ('long', 'short')
ORIGINAL_FIELDS = {'wire_sha256', 'node_hash_hex'}
EVENT_FIELDS = {
    'possible-short-disclosure': set(),
    'elapsed': set(),
    'charge-unknown-work': set(),
    'counterparty-unavailable': set(),
    'price-refusal': {'leg'},
    'account-order-refusal': {'leg'},
    'original-unavailable': {'leg', 'part'},
    'custodian-unavailable': {'leg'},
    'observer-unavailable': {'leg'},
    'declared-send-confirmed': {'leg', 'send_timestamp'},
    'model-unlock-receive': {'leg'},
    'model-reclaim-receive': {'leg', 'send_timestamp'},
    'reorg': {'leg'},
}


def require(value):
    if not value:
        raise ValueError('finite disclosure/timeout trace refused')


def fields(value, names):
    require(type(value) is dict and set(value) == set(names))


def integer(value, minimum, maximum):
    require(type(value) is int and minimum <= value <= maximum)
    return value


def unique(pairs):
    result = {}
    for name, value in pairs:
        require(name not in result)
        result[name] = value
    return result


def nonfinite(unused):
    raise ValueError('finite disclosure/timeout trace refused')


def _leg_view(state):
    return dict(state='HOLD', original_reference=dict(state['original_reference']),
        future_price_refusal=state['future_price_refusal'],
        future_order_refusal=state['future_order_refusal'],
        observer_available_in_model=state['observer_available_in_model'],
        custodian_available_in_model=state['custodian_available_in_model'],
        declared_send_timestamp=state['declared_send_timestamp'],
        entry_in_model=state['entry_in_model'])


def evaluate(request):
    """Replay supplied finite assumptions without filling any missing original.

    Receive order is explicitly hypothetical. Its reachability under the core
    scheduler, account authorization and admission is not established here.
    """
    fields(request, {'schema', 'expires_at', 'original_references',
        'unknown_work_charged', 'work_limit', 'events'})
    require(type(request['schema']) is str and request['schema'] == SCHEMA)
    fields(request['expires_at'], LEGS)
    expiries = {leg: integer(request['expires_at'][leg], 1, MAX_TIME) for leg in LEGS}
    require(expiries['long'] > expiries['short'])
    limit = integer(request['work_limit'], 1, MAX_WORK)
    charged = integer(request['unknown_work_charged'], 0, limit)
    fields(request['original_references'], LEGS)
    states = {}
    for leg in LEGS:
        reference = request['original_references'][leg]
        fields(reference, ORIGINAL_FIELDS)
        for value in reference.values():
            require(value is None or type(value) is str and re.fullmatch('[0-9a-f]{64}', value))
        states[leg] = dict(original_reference=dict(reference), future_price_refusal=False,
            future_order_refusal=False, observer_available_in_model=True,
            custodian_available_in_model=True, declared_send_timestamp=None,
            entry_in_model='OPEN')
    events = request['events']
    require(type(events) is list and 0 < len(events) <= MAX_EVENTS)
    disclosed = False
    counterparty = True
    previous_time = 0
    findings = set()
    steps = []
    for event in events:
        require(type(event) is dict and type(event.get('kind')) is str)
        kind = event['kind']
        require(kind in EVENT_FIELDS)
        fields(event, {'kind', 'at'} | EVENT_FIELDS[kind])
        at = integer(event['at'], previous_time, MAX_TIME)
        previous_time = at
        leg = event.get('leg')
        if 'leg' in event:
            require(type(leg) is str and leg in LEGS)
        send = None
        if 'send_timestamp' in event:
            send = integer(event['send_timestamp'], 0, at)
        outcome = 'RECORDED_MODEL_ASSUMPTION_ONLY'
        if kind == 'possible-short-disclosure':
            disclosed = True
        elif kind == 'charge-unknown-work':
            if charged == limit:
                outcome = 'MODEL_WORK_LIMIT_EXHAUSTED'
            else:
                charged += 1
                outcome = 'UNKNOWN_CHARGE_RECORDED_IN_MODEL_ONLY'
        elif kind == 'counterparty-unavailable':
            counterparty = False
        elif kind == 'price-refusal':
            states[leg]['future_price_refusal'] = True
        elif kind == 'account-order-refusal':
            states[leg]['future_order_refusal'] = True
        elif kind == 'original-unavailable':
            part = event['part']
            require(type(part) is str and part in ('wire_sha256', 'node_hash_hex', 'both'))
            for name in ORIGINAL_FIELDS if part == 'both' else (part,):
                states[leg]['original_reference'][name] = None
        elif kind == 'custodian-unavailable':
            states[leg]['custodian_available_in_model'] = False
        elif kind == 'observer-unavailable':
            states[leg]['observer_available_in_model'] = False
        elif kind == 'declared-send-confirmed':
            # This declaration is unauthenticated input, never an observation proof.
            require(states[leg]['declared_send_timestamp'] in (None, send))
            states[leg]['declared_send_timestamp'] = send
            outcome = ('DECLARED_SEND_BEFORE_EXPIRY' if send < expiries[leg]
                else 'DECLARED_SEND_NOT_BEFORE_EXPIRY')
        elif kind == 'model-unlock-receive':
            send = states[leg]['declared_send_timestamp']
            require(send is not None)
            if states[leg]['entry_in_model'] != 'OPEN':
                outcome = 'MODEL_ENTRY_ALREADY_CONSUMED'
                if states[leg]['entry_in_model'] == 'RECLAIMED' and send < expiries[leg]:
                    findings.add('CONDITIONAL_TIMELY_UNLOCK_LOSES_TO_RECLAIM_ORDER')
            elif send >= expiries[leg]:
                outcome = 'MODEL_UNLOCK_EXPIRY_COMPONENT_REFUSES'
            else:
                states[leg]['entry_in_model'] = 'UNLOCKED'
                outcome = 'MODEL_UNLOCK_EXPIRY_COMPONENT_PASSES'
                if at >= expiries[leg]:
                    findings.add('TIMELY_SEND_CAN_HAVE_LATE_MODEL_RECEIVE')
        elif kind == 'model-reclaim-receive':
            if states[leg]['entry_in_model'] != 'OPEN':
                outcome = 'MODEL_ENTRY_ALREADY_CONSUMED'
                if states[leg]['entry_in_model'] == 'UNLOCKED':
                    findings.add('CONDITIONAL_RECLAIM_LOSES_TO_UNLOCK_ORDER')
            elif send < expiries[leg]:
                outcome = 'MODEL_RECLAIM_EXPIRY_COMPONENT_REFUSES'
            else:
                states[leg]['entry_in_model'] = 'RECLAIMED'
                outcome = 'MODEL_RECLAIM_EXPIRY_COMPONENT_PASSES'
        elif kind == 'reorg':
            states[leg]['declared_send_timestamp'] = None
            states[leg]['entry_in_model'] = 'OPEN'
            outcome = 'MODEL_OBSERVATION_INVALIDATED'
            if disclosed or charged:
                findings.add('REORG_CANNOT_UNDISCLOSE_OR_REFUND_UNKNOWN_WORK')
        elif kind == 'elapsed' and charged:
            findings.add('ELAPSED_TIME_DOES_NOT_REFUND_UNKNOWN_WORK')
        if disclosed:
            if not counterparty:
                findings.add('DISCLOSED_WITH_UNAVAILABLE_COUNTERPARTY')
            for name in LEGS:
                state = states[name]
                suffix = name.upper()
                if state['future_price_refusal']:
                    findings.add('DISCLOSED_WITH_PRICE_REFUSAL_' + suffix)
                if state['future_order_refusal']:
                    findings.add('DISCLOSED_WITH_ORDER_REFUSAL_' + suffix)
                if any(value is None for value in state['original_reference'].values()):
                    findings.add('DISCLOSED_WITH_MISSING_REFERENCE_' + suffix)
                if not state['custodian_available_in_model']:
                    findings.add('DISCLOSED_WITH_UNAVAILABLE_CUSTODIAN_' + suffix)
                if not state['observer_available_in_model']:
                    findings.add('DISCLOSED_WITH_UNAVAILABLE_OBSERVER_' + suffix)
            long_send = states['long']['declared_send_timestamp']
            if at >= expiries['long'] and (long_send is None or long_send >= expiries['long']):
                findings.add('NO_TIMELY_LONG_SEND_ESTABLISHED_AFTER_DISCLOSURE')
            if charged == limit and states['long']['entry_in_model'] != 'UNLOCKED':
                findings.add('UNKNOWN_WORK_LIMIT_EXHAUSTED_AFTER_DISCLOSURE')
        steps.append(dict(kind=kind, at=at, model_outcome=outcome, state='HOLD',
            possible_disclosure=disclosed, unknown_work_charged=charged,
            legs={name: _leg_view(states[name]) for name in LEGS}))
    return dict(schema=RESULT, outcome='HOLD_FINITE_HYPOTHETICAL_TRACE_ONLY',
        source_commit=CORE, source_tree=TREE, expires_at=dict(expiries),
        declared_expiry_gap=expiries['long'] - expiries['short'],
        state='HOLD', recovery_action='NONE', actions=[], original_replacements=0,
        possible_disclosure=disclosed, unknown_work_charged=charged, work_limit=limit,
        counterparty_available_in_model=counterparty,
        legs={leg: _leg_view(states[leg]) for leg in LEGS},
        steps=steps, findings=sorted(findings),
        model_reachability='NOT_ESTABLISHED_BY_CORE', full_admission='UNFILLED',
        source_execution='NOT_PERFORMED', original_byte_custody='UNFILLED',
        authenticated_observation='UNFILLED', finality='UNFILLED',
        rollback_protection='UNFILLED', availability='UNFILLED',
        safe_disclosure_or_wait_duration='NOT_SELECTED',
        history_completeness='ASSUMED_INPUT; NOT_AUTHENTICATED',
        service_gates={'AS-' + str(n): 'UNFILLED' for n in range(1, 8)},
        signing='NOT_PERFORMED', journal_write='NOT_PERFORMED',
        original_release='NOT_PERFORMED', transaction_broadcast='NOT_PERFORMED',
        work_replenishment='NOT_PERFORMED', retry='NOT_PERFORMED',
        native_worker_runs=0, new_work_allowed=False,
        journal_source_upgrade='NOT_SELECTED', independent_assessment='UNFILLED',
        application='NO-GO', core='NO-GO')


def evaluate_json(raw):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_REQUEST)
    try:
        request = json.loads(raw.decode('ascii'), object_pairs_hook=unique,
            parse_constant=nonfinite)
        return evaluate(request)
    except (KeyError, TypeError, RecursionError, OverflowError) as error:
        raise ValueError('finite disclosure/timeout trace refused') from error


def main():
    import argparse
    class QuietParser(argparse.ArgumentParser):
        def error(self, message):
            raise ValueError('finite disclosure/timeout trace refused')
    parser = QuietParser(description=__doc__)
    parser.add_argument('--request', required=True, type=Path)
    try:
        arguments = parser.parse_args()
        with arguments.request.open('rb') as selected:
            raw = selected.read(MAX_REQUEST + 1)
        result = evaluate_json(raw)
    except (OSError, ValueError):
        raise SystemExit('REFUSED: finite disclosure/timeout trace') from None
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
