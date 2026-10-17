"""Synthetic structured-output fixtures and adverse parser variants; no node execution."""
import hashlib
import json
from scripts.qualify_nom_signed_originals import PREFIX, TEST, PACKAGE


def _bucket(stream, identifier):
    lines = stream.splitlines()
    events = [json.loads(line) for line in lines]
    indices = [i for i, event in enumerate(events) if event.get('Action') == 'output'
        and event.get('Test') == TEST+'/'+identifier]
    assert indices
    text = ''.join(events[i]['Output'] for i in indices)
    records = [line for line in text.splitlines(keepends=True) if PREFIX in line]
    assert len(records) == 1
    return lines, events, indices, text, records[0]


def _rewrite(stream, identifier, transform):
    lines, events, indices, text, record = _bucket(stream, identifier)
    first = dict(events[indices[0]])
    first['Output'] = transform(text, record)
    omitted = set(indices[1:])
    return b'\n'.join(json.dumps(first).encode('ascii') if i == indices[0] else line
        for i, line in enumerate(lines) if i not in omitted)+b'\n'


def _record(stream, identifier, transform):
    def rewrite(text, line):
        prefix, wire = line.split(PREFIX, 1)
        value = json.loads(wire)
        transform(value)
        replacement = prefix+PREFIX+json.dumps(value, sort_keys=True, separators=(',', ':'))+'\n'
        assert text.count(line) == 1
        return text.replace(line, replacement, 1)
    return _rewrite(stream, identifier, rewrite)


def variants(stream):
    lines, events, indices, text, record = _bucket(stream, 'long-original')
    first_pass = [i for i, event in enumerate(events) if event.get('Action') == 'pass'
        and event.get('Test') == TEST+'/long-original']
    assert len(first_pass) == 1
    missing_pass = b'\n'.join(line for i, line in enumerate(lines) if i != first_pass[0])+b'\n'
    chunks = [i for i in indices if not events[i]['Output'].startswith(('=== RUN', '--- PASS'))]
    assert len(chunks) >= 3 and any(not events[i]['Output'].endswith('\n') for i in chunks)
    crossed = list(lines)
    event = dict(events[chunks[1]]); event['Test'] = TEST+'/short-original'
    crossed[chunks[1]] = json.dumps(event).encode('ascii')
    reordered = list(lines)
    reordered[chunks[1]], reordered[chunks[2]] = reordered[chunks[2]], reordered[chunks[1]]
    cases = [
        ('missing actual Go outcome', missing_pass),
        ('duplicate complete record', _rewrite(stream, 'long-original', lambda text, line:text.replace(line, line+line, 1))),
        ('missing record with complete Go outcomes', _rewrite(stream, 'long-original', lambda text, line:text.replace(line, '', 1))),
        ('normalized original substitution', _record(stream, 'long-unknown-protobuf-field', lambda r:r.update(
            wire_hex=r['reencoded_wire_hex'], wire_sha256=hashlib.sha256(bytes.fromhex(r['reencoded_wire_hex'])).hexdigest()))),
        ('changed node identifier', _record(stream, 'long-original', lambda r:r.update(hash_hex='00'*32))),
        ('changed leg label', _record(stream, 'long-original', lambda r:r.update(leg='short'))),
        ('integer decoded flag', _record(stream, 'long-original', lambda r:r.update(decoded=1))),
        ('positive missing signature claim', _record(stream, 'long-missing-signature', lambda r:r['checks'].update(signature='PASS'))),
        ('fragment assigned to another test', b'\n'.join(crossed)+b'\n'),
        ('reordered same-test fragments', b'\n'.join(reordered)+b'\n'),
        ('unterminated record line', _rewrite(stream, 'long-original', lambda text, line:text.replace(line, line.rstrip('\n'), 1))),
    ]
    return dict(cases)


def fixture_stream(records):
    events=[dict(Action='run',Package=PACKAGE,Test=TEST)]
    for identifier,record in sorted(records.items()):
        name=TEST+'/'+identifier
        events.append(dict(Action='run',Package=PACKAGE,Test=name))
        events.append(dict(Action='output',Package=PACKAGE,Test=name,Output='=== RUN   '+name+'\n'))
        line='    zz_research_nom_signed_original_probe_test.go:180: '+PREFIX+json.dumps(record,sort_keys=True,separators=(',',':'))+'\n'
        for offset in range(0,len(line),1024):
            events.append(dict(Action='output',Package=PACKAGE,Test=name,Output=line[offset:offset+1024]))
        events.append(dict(Action='output',Package=PACKAGE,Test=name,Output='--- PASS: '+name+' (0.00s)\n'))
        events.append(dict(Action='pass',Package=PACKAGE,Test=name))
    events.append(dict(Action='pass',Package=PACKAGE,Test=TEST))
    events.append(dict(Action='pass',Package=PACKAGE))
    return b'\n'.join(json.dumps(value,sort_keys=True).encode('ascii') for value in events)+b'\n'
