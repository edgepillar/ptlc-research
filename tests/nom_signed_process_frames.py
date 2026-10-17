"""Synthetic adverse original frames; no additional process execution."""
import copy
from scripts.nom_signed_process_evidence import decode,canonical,sha


def mutations(payloads,root):
    controls=[]
    def add(label,edit):
        changed=dict(payloads);edit(changed);controls.append((label,changed))
    def edit_json(values,name,edit):
        row=decode(values[name]);edit(row);values[name]=canonical(row)
    def receipt_stream(values,stem,suffix,label):
        raw=values[stem+suffix]
        edit_json(values,stem+'receipt.json',lambda row:row.update({label+'_hex':raw.hex(),label+'_sha256':sha(raw)}))
    def edit_journal(values,cut,edit):
        name=cut+'/journal.log';rows=[decode(line) for line in values[name].splitlines()]
        edit(rows);previous='00'*32;result=[]
        for number,row in enumerate(rows,1):
            row.update(sequence=number,previous_hash_hex=previous);row.pop('hash_hex',None)
            row['hash_hex']=sha(b'ptlc-nom-log-v1\0'+canonical(row));previous=row['hash_hex'];result.append(canonical(row)+b'\n')
        values[name]=b''.join(result)
    add('missing original',lambda p:p.pop('after-public-reply/worker/call-003.stdout'))
    add('unselected original',lambda p:p.update({'extra-original':b''}))
    def duplicate(p):
        name='after-public-reply/worker/call-003.receipt.json'
        p[name]=b'{"exit_code":0,'+p[name][1:]
    add('duplicate receipt JSON key',duplicate)
    add('boolean native exit',lambda p:edit_json(p,'after-public-reply/worker/call-003.receipt.json',lambda r:r.update(exit_code=False)))
    add('boolean native number',lambda p:edit_json(p,'after-signed-short/worker/call-001.receipt.json',lambda r:r.update(number=True)))
    add('changed native phase',lambda p:edit_json(p,'after-public-reply/worker/call-003.receipt.json',lambda r:r.update(phase='after-signed-admitted:write')))
    def changed_request(p):
        stem='after-public-reply/worker/call-003.'
        edit_json(p,stem+'stdin',lambda r:r.update(context_digest_hex='00'*32));receipt_stream(p,stem,'stdin','request')
    add('self-consistent changed public request',changed_request)
    def changed_reply(p):
        stem='after-public-reply/worker/call-003.'
        edit_json(p,stem+'stdout',lambda r:r.update(completed_long_hex='00'*64));receipt_stream(p,stem,'stdout','stdout')
    add('self-consistent changed public completion',changed_reply)
    def changed_marker(p):
        stem='after-signed-short/actor.'
        p[stem+'stdout']=p[stem+'stdout'].replace(b'os._exit(72)',b'SIGKILL')
        receipt_stream(p,stem,'stdout','stdout')
    add('changed actual cut method',changed_marker)
    add('successful actor instead of selected exit72',lambda p:edit_json(p,'after-public-reply/actor.receipt.json',lambda r:r.update(exit_code=0)))
    add('timeout capture instead of complete actor',lambda p:edit_json(p,'after-public-reply/actor.receipt.json',lambda r:r.update(stream_completeness='COMPLETE_AFTER_TIMEOUT')))
    recovered=decode(payloads['after-signed-recovered/journal.log'].splitlines()[-1])
    add('diagnostic public reply promoted to original journal',lambda p:edit_journal(p,'after-public-reply',lambda rows:rows.append(copy.deepcopy(recovered))))
    add('coherent older prefix removes charged work',lambda p:edit_journal(p,'after-public-reply',lambda rows:rows.pop()))
    add('coherent changed journal role',lambda p:edit_journal(p,'after-signed-short',lambda rows:rows[0]['event'].update(role='alice')))
    def boolean_sequence(p):
        name='after-signed-short/journal.log';rows=[decode(line) for line in p[name].splitlines()]
        rows[0]['sequence']=True;previous='00'*32;output=[]
        for row in rows:
            row['previous_hash_hex']=previous;row.pop('hash_hex');row['hash_hex']=sha(b'ptlc-nom-log-v1\0'+canonical(row))
            previous=row['hash_hex'];output.append(canonical(row)+b'\n')
        p[name]=b''.join(output)
    add('boolean journal sequence with coherent self hashes',boolean_sequence)
    from scripts.qualify_nom_signed_originals import inputs
    from scripts.nom_signed_corpus import SourceCorpusAllowlist
    from offline_session.nom_signed_recovery import CONTEXT_SCHEMA
    selected,unused,records=inputs(root)
    terms=decode((root/'compatibility/fixtures/nom_supervisor_inputs_v1.json').read_bytes())['terms']
    pair=decode((root/'compatibility/fixtures/nom_supervisor_completions_v1.json').read_bytes())['pair']
    selection=dict(schema=CONTEXT_SCHEMA,source_commit=selected['core_commit'],source_tree=selected['core_tree'],
        corpus_sha256=selected['record_set_payload_sha256'],contract_hex=records['long-original']['block']['to_address_hex'])
    lookup=SourceCorpusAllowlist(terms,pair,selection,records)
    alias=bytes.fromhex(records['long-unknown-protobuf-field']['wire_hex'])
    facts=lookup.verify_original('long',alias)
    def changed_original(p):
        def change(rows):rows[-1]['event'].update(wire_hex=alias.hex(),facts_wire_hex=facts.hex())
        edit_journal(p,'after-signed-long',change)
    add('same-nodehash different raw original with coherent self hashes',changed_original)
    add('changed source pin before spawn',lambda p:edit_json(p,'after-public-reply/configuration-before-spawn.json',lambda r:r['source_input_sha256'].update({'offline_session/nom_signed_recovery.py':'00'*32})))
    add('changed actor source pin',lambda p:edit_json(p,'after-public-reply/configuration-before-spawn.json',lambda r:r.update(actor_sha256='00'*32)))
    return controls
