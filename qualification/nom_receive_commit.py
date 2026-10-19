"""Compare two finite committed mock cases without granting recovery authority."""
import sys

if sys.flags.optimize:
    raise SystemExit('receive commit comparison requires assertions enabled')

import hashlib
import json
import math
import os
from pathlib import Path

from qualification import nom_current_admission as source_reader

ROOT=Path(__file__).resolve().parents[1]
CORE=source_reader.CORE
TREE=source_reader.TREE
MANIFEST='compatibility/nom_receive_commit_manifest.json'
DRIVER='compatibility/nom_receive_commit_test.go.txt'
DESTINATION='zenon/mock/zz_research_nom_receive_commit_test.go'
LICENSE='licenses/GPL-3.0-go-zenon.txt'
NOTICE='docs/NOM_RECEIVE_COMMIT_NOTICE.md'
SELECTED={DRIVER,LICENSE,NOTICE,source_reader.SOURCE,
    'qualification/nom_receive_commit.py','tests/test_nom_receive_commit.py'}
PACKAGE='github.com/zenon-network/go-zenon/zenon/mock'
TEST='TestResearchNoMReceiveCommit'
CASES={'unlock-first':'unlock','reclaim-first':'reclaim'}
TESTS={TEST,*(TEST+'/'+case for case in CASES)}
MARKER='PTLC_NOM_RECEIVE_COMMIT_RECORD='
MAX_STDOUT=8*1024**2
MAX_STDERR=1024**2
MAX_EVENT=64*1024
MAX_OUTPUT_LINE=8192
decoded=source_reader.decoded
regular=source_reader.regular
canonical=source_reader.canonical


def inputs(root=ROOT):
    root = source_reader.physical(root)
    manifest = decoded(regular(root / MANIFEST, 64 * 1024), 64 * 1024)
    fixed = dict(schema='ptlc-nom-receive-commit-selection-v1', core_commit=CORE,
        core_tree=TREE, upstream_files=444, project_probe_files=1,
        expected_go_outcomes=3, expected_cases=sorted(CASES),
        event_output_fragments='SAME_TEST_LINE_REASSEMBLY', max_output_line_bytes=MAX_OUTPUT_LINE,
        source_index_sha256=source_reader.INDEX_SHA256,
        probe_license='GPL-3.0-only', independent_assessment='UNFILLED',
        application='NO-GO', core='NO-GO')
    require(type(manifest) is dict and set(manifest) == set(fixed) | {'input_sha256'})
    require(canonical({key: manifest[key] for key in fixed}) == canonical(fixed))
    pins = manifest['input_sha256']
    require(type(pins) is dict and set(pins) == SELECTED)
    for name, pin in pins.items():
        require(type(pin) is str and len(pin) == 64 and all(c in '0123456789abcdef' for c in pin))
        require(hashlib.sha256(regular(root / name, 2 * 1024**2)).hexdigest() == pin)
    raw = regular(root / source_reader.SOURCE, 1024**2)
    require(hashlib.sha256(raw).hexdigest() == source_reader.INDEX_SHA256)
    index = decoded(raw, 1024**2)
    require(type(index) is dict and len(index) == 444)
    require(source_reader.git_tree(index) == TREE)
    require(index['LICENSE']['sha256'] == pins[LICENSE])
    return manifest, index


def compare_source(source, root=ROOT):
    manifest, index = inputs(root)
    source = source_reader.physical(source)
    require(source.is_dir())
    expected = {name: row['sha256'] for name, row in index.items()}
    require(DESTINATION not in expected)
    expected[DESTINATION] = manifest['input_sha256'][DRIVER]
    seen = set()
    total = 0
    for directory, children, names in os.walk(source, followlinks=False):
        parent = Path(directory)
        require(not parent.is_symlink())
        require(all(not (parent / name).is_symlink() for name in children))
        for name in names:
            path = parent / name
            relative = path.relative_to(source).as_posix()
            require(relative in expected and relative not in seen)
            raw = regular(path, 8 * 1024**2)
            total += len(raw)
            require(total <= 40 * 1024**2)
            require(hashlib.sha256(raw).hexdigest() == expected[relative])
            seen.add(relative)
    require(seen == set(expected) and len(seen) == 445)
    return dict(upstream_files=444, project_probe_files=1, combined_files=445,
        content='EXACT_SELECTED_CONTENTS', filesystem_mode_equality='NOT_ASSERTED',
        producer_authentication='NOT_ESTABLISHED_BY_THIS_READER')


def require(value,reason='receive commit comparison refused'):
    if not value:raise ValueError(reason)

def pairs(values):
    result={}
    for key,value in values:
        require(key not in result,'duplicate JSON key');result[key]=value
    return result

def nonfinite(value):raise ValueError('nonfinite JSON value')

def decode(raw):
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=nonfinite)

def compare_record(value,case):
    fixed=dict(schema='ptlc-nom-receive-commit-source-v1',case=case,selected_head=case.split('-')[0],
        later_send_refusal='ErrABSequencerNotNext',head_receive_acknowledges_confirmation=True,
        fixed_recipient_or_owner_payout=True,contract_entry_unchanged_after_generation=True,generation_commits=0,
        contract_receives_committed=2,head_committed_payouts=1,later_committed_payouts=0,
        later_method_error='ErrDataNonExistent',later_error_generation_commits=0,
        head_commit_matches_generated=True,later_commit_matches_generated=True,
        contract_entry_absent_after_commits=True,contract_token_balance_after_commits=0,
        recipient_balance_credit='NOT_ASSESSED',queue_liveness='NOT_ASSESSED',source_execution='IN_PROCESS_MOCK_ONLY',
        canonicality='UNFILLED',swap_atomicity='NOT_ASSESSED',safe_disclosure_margin='NOT_SELECTED',
        recovery_action='NONE',application='NO-GO',core='NO-GO')
    heights=('head_confirmation_height','later_confirmation_height','head_receive_confirmation_height','later_receive_confirmation_height')
    times=('expiration','head_confirmation_time','later_confirmation_time','processing_time')
    require(type(value) is dict and set(value)==set(fixed)|set(heights)|set(times),'unselected record fields')
    for name,expected in fixed.items():
        require(type(value[name]) is type(expected) and value[name]==expected,'unselected record '+name)
    for name in heights:
        require(type(value[name]) is int and 0<value[name]<2**64,'invalid confirmation height')
    require(all(value[left]<value[right] for left,right in zip(heights,heights[1:])),'wrong confirmation order')
    for name in times:
        require(type(value[name]) is int and 0<value[name]<2**63,'invalid time')
    require(value['processing_time']>=value['later_confirmation_time']>=value['expiration'],'wrong later expiry relation')
    require(value['head_confirmation_time']<value['later_confirmation_time'],'wrong send time order')
    relation=value['head_confirmation_time']<value['expiration']
    require(relation is (case=='unlock-first'),'wrong head expiry relation')
    return value

def compare_stream(raw):
    require(type(raw) is bytes and 0<len(raw)<=MAX_STDOUT,'unbounded stream')
    require(raw.endswith(b'\n'),'incomplete event stream')
    buffers={};started=False;finished=False;runs=set();passed=set();records={};events=0
    for line in raw.splitlines():
        require(0<len(line)<=MAX_EVENT,'unbounded event')
        event=decode(line);events+=1
        require(type(event) is dict and set(event)<=source_reader.EVENT_FIELDS and not finished,'unselected event fields or data after outcome')
        require('FailedBuild' not in event,'failed build field')
        if 'Time' in event:require(type(event['Time']) is str and 0<len(event['Time'])<=128,'invalid event time')
        if 'Elapsed' in event:
            elapsed=event['Elapsed']
            require(type(elapsed) in (int,float) and math.isfinite(elapsed) and elapsed>=0,'invalid elapsed value')
        if 'Output' in event:require(type(event['Output']) is str and event.get('Action')=='output','invalid output field')
        require(event.get('Package')==PACKAGE,'unselected package')
        action=event.get('Action');require(type(action) is str and action in ('start','run','output','pass'),'failed or unselected action')
        test=event.get('Test')
        if 'Test' in event:require(type(test) is str and test in TESTS,'unselected explicit Test')
        if action=='start':
            require('Test' not in event and not started and not runs and not buffers,'duplicate package start')
            started=True;continue
        require(started,'event before package start')
        if action=='run':
            require('Test' in event and test not in runs,'duplicate test run')
            if test!=TEST:
                require(TEST in runs and TEST not in passed,'child outside parent run')
                require(not (runs-passed-{TEST}),'overlapping finite cases')
            else:require(not runs,'parent after child')
            runs.add(test);continue
        if action=='output':
            output=event.get('Output');require(type(output) is str and len(output.encode('utf-8'))<=MAX_EVENT,'unbounded Output')
            if 'Test' in event:require(test in runs and test not in passed,'output outside test run')
            pending=buffers.get(test,'')+output
            while '\n' in pending:
                text,pending=pending.split('\n',1)
                require(len(text.encode('utf-8'))<=MAX_OUTPUT_LINE,'unbounded output line')
                if MARKER not in text:continue
                require(test in TESTS-{TEST} and text.startswith(MARKER) and text.count(MARKER)==1,'unbound record line')
                case=test.split('/',1)[1]
                require(case not in records,'duplicate case record')
                records[case]=compare_record(decode(text[len(MARKER):]),case)
            require(len(pending.encode('utf-8'))<=MAX_OUTPUT_LINE,'unbounded partial line')
            buffers[test]=pending;continue
        if 'Test' in event:
            require(test in runs and test not in passed and not buffers.get(test,''),'incomplete or duplicate test outcome')
            if test==TEST:require(passed==TESTS-{TEST},'parent before complete children')
            else:require(test.split('/',1)[1] in records,'missing child record')
            passed.add(test)
        else:
            require(passed==runs==TESTS and not any(buffers.values()),'incomplete package outcome')
            finished=True
    require(started and finished and passed==TESTS and set(records)==set(CASES),'missing terminal outcomes')
    return dict(outcome='PASS_TWO_FINITE_COMMITTED_MOCK_VALUES_ONLY',cases=records,
        events=events,passed_including_parent=3,package_passes=1,stdout_sha256=hashlib.sha256(raw).hexdigest(),
        execution='NOT_PERFORMED_BY_READER',producer_authentication='NOT_ESTABLISHED_BY_READER',
        application='NO-GO',core='NO-GO')


record=compare_record


def compare_payloads(stdout,stderr,root=ROOT):
    manifest,unused_index=inputs(root)
    require(type(stderr) is bytes and len(stderr)<=MAX_STDERR)
    checked=compare_stream(stdout)
    return dict(schema='ptlc-nom-receive-commit-comparison-v1',outcome=checked['outcome'],
        core_commit=CORE,core_tree=TREE,probe_sha256=manifest['input_sha256'][DRIVER],
        cases=checked['cases'],passed_including_parent=3,package_passes=1,
        parsed_events=checked['events'],event_output_fragments='SAME_TEST_LINE_REASSEMBLY',
        stdout_sha256=hashlib.sha256(stdout).hexdigest(),stdout_bytes=len(stdout),
        stderr_sha256=hashlib.sha256(stderr).hexdigest(),stderr_bytes=len(stderr),
        actual_command_exit='NOT_ESTABLISHED_BY_THIS_READER',
        producer_authentication='NOT_ESTABLISHED_BY_THIS_READER',
        source_content='SEPARATE_COMPLETE_CONTENT_CHECK_REQUIRED',
        native_execution='NOT_PERFORMED_BY_READER',independent_assessment='UNFILLED',
        canonicality='UNFILLED',finality='UNFILLED',liveness='UNFILLED',
        recipient_balance_credit='NOT_ASSESSED',swap_atomicity='NOT_ASSESSED',
        safe_disclosure_margin='NOT_SELECTED',journal_source_upgrade='NOT_SELECTED',
        journal_write='NOT_PERFORMED',signing='NOT_PERFORMED',transaction_broadcast='NOT_PERFORMED',
        recovery_action='NONE',application='NO-GO',core='NO-GO')


def main():
    import argparse

    class QuietParser(argparse.ArgumentParser):
        def error(self,message):raise ValueError('receive commit comparison refused')

    parser=QuietParser(description=__doc__)
    parser.add_argument('--source',type=Path,required=True)
    parser.add_argument('--stdout',type=Path,required=True)
    parser.add_argument('--stderr',type=Path,required=True)
    try:
        args=parser.parse_args()
        source=compare_source(args.source)
        result=compare_payloads(regular(args.stdout,MAX_STDOUT),regular(args.stderr,MAX_STDERR))
        result['complete_source']=source
    except (AssertionError,ValueError,TypeError,KeyError,OSError,UnicodeError,OverflowError):
        print('receive commit comparison refused',file=sys.stderr)
        return 1
    print(canonical(result).decode('ascii'))
    return 0


if __name__=='__main__':raise SystemExit(main())
