"""Explicit self-exiting actor for offline public-byte recovery qualification."""
import hashlib
import json
import os
from pathlib import Path
import sys
from unittest.mock import patch

def run(root,directory,executable,config):
    if sys.flags.optimize:raise ValueError('actor requires assertions enabled')
    if not root.is_absolute() or not directory.is_absolute() or not executable.is_absolute():
        raise ValueError('explicit selected actor paths required')
    selected=json.loads((root/'compatibility/nom_signed_process_cuts_manifest.json').read_bytes())
    if config['source_input_sha256']!=selected['input_sha256']:
        raise ValueError('selected actor source map differs')
    for name,pin in config['source_input_sha256'].items():
        relative=Path(name)
        if relative.is_absolute() or '..' in relative.parts or hashlib.sha256((root/relative).read_bytes()).hexdigest()!=pin:
            raise ValueError('selected source changed before import')
    sys.path.insert(0,str(root))
    from offline_session import nom_recovery as base
    from offline_session.nom_signed_recovery import SignedNomRecoveryCandidate,CONTEXT_SCHEMA
    from offline_session.nom_verifier import NomPublicVerifier,CLEAN_EXECUTION_PROFILE
    from scripts.nom_cut_capture import OriginalCapture,retain,sha
    from scripts.qualify_nom_recovery_cuts import CountedVerifier
    from scripts.nom_signed_corpus import SourceCorpusAllowlist,signed_observation
    from scripts.qualify_nom_signed_originals import inputs
    assert all(sha((root/name).read_bytes())==pin for name,pin in config['source_input_sha256'].items())
    assert sha(Path(__file__).read_bytes())==config['actor_sha256']
    assert sha(Path(sys.executable).resolve().read_bytes())==config['python_sha256']
    assert sha(executable.read_bytes())==config['worker_sha256']
    manifest,unused,records=inputs(root)
    terms=json.loads((root/'compatibility/fixtures/nom_supervisor_inputs_v1.json').read_bytes())['terms']
    completed=json.loads((root/'compatibility/fixtures/nom_supervisor_completions_v1.json').read_bytes())
    selection=dict(schema=CONTEXT_SCHEMA,source_commit=manifest['core_commit'],source_tree=manifest['core_tree'],
        corpus_sha256=manifest['record_set_payload_sha256'],contract_hex=records['long-original']['block']['to_address_hex'])
    raw_verifier=SourceCorpusAllowlist(terms,completed['pair'],selection,records)
    short=bytes.fromhex(records['short-original']['wire_hex']);long=bytes.fromhex(records['long-original']['wire_hex'])
    funded=[signed_observation(terms,completed,raw_verifier,leg,'funded') for leg in ('long','short')]
    proof=signed_observation(terms,completed,raw_verifier,'short','unlock-confirmed',short)
    allowed=set(funded+[proof]);observed=[];target={}
    capture=OriginalCapture(directory/'worker',executable,config['worker_sha256']);capture.phase=config['cut']+':write'
    public=NomPublicVerifier(executable,config['worker_sha256'],terms,completed['pair'],execution_profile=CLEAN_EXECUTION_PROFILE)
    def die(hook):
        # The inherited append has fsynced and installed its next state before
        # invoking this hook. Reading the public status API inside that append
        # would intentionally fail its image-continuity guard.
        state=target['store']._state
        value=dict(schema='ptlc-nom-signed-process-cut-v1',cut=config['cut'],hook=hook,method='os._exit(72)',
            worker_modes=list(counted.modes),recovery_entries=counted.entries,recovery_returns=counted.returns,
            diagnostic_public_result=counted.returned_result,observer_calls_before_cut=observed,
            charge=state['recovery_count'],retained_completion=state['recovered_long_hex'] or None,
            signed_legs=sorted(state['signed_originals']),attempts=state['attempts'])
        retain(directory/'cut-receipt.json',base.canonical(value))
        sys.stdout.buffer.write(base.canonical(dict(schema='ptlc-nom-signed-process-marker-v1',cut=config['cut'],method='os._exit(72)'))+b'\n')
        sys.stdout.buffer.flush();os._exit(72)
    class DeathVerifier(CountedVerifier):
        def recover_long(self,signature):
            result=super().recover_long(signature)
            if config['cut']=='after-public-reply':die('PUBLIC_REPLY_BEFORE_RECOVERED_APPEND')
            return result
    counted=DeathVerifier(public)
    def observer(wire):observed.append(wire.hex());return wire in allowed
    def hook(kind):
        if config['cut']=='after-signed-admitted' and kind=='signed-admitted':die(kind)
        if config['cut']=='after-signed-recovered' and kind=='signed-recovered':die(kind)
        if kind=='signed-original' and 'store' in target:
            has_long='long' in target['store']._state['signed_originals']
            if config['cut']=='after-signed-short' and not has_long:die('SIGNED_SHORT_RETAINED')
            if config['cut']=='after-signed-long' and has_long:die('SIGNED_LONG_RETAINED')
        if config['cut']=='after-signed-attempt' and kind=='signed-attempt':die(kind)
    with patch('offline_session.nom_verifier.run_clean_environment_public_worker',capture.run):
        with SignedNomRecoveryCandidate.open(directory/'journal.log',terms,completed['pair'],role='bob',
                verifier=counted,raw_verifier=raw_verifier,observation_verifier=observer,selection=selection,hook=hook) as store:
            target['store']=store
            for wire in funded:store.record_signed_observation(wire)
            store.retain_signed_original('short',short)
            store.recover_long_completion(short,proof)
            assert 'long' not in store.status()['signed_originals']
            store.retain_signed_original('long',long)
            store.prepare_signed_attempt('long')
    raise ValueError('selected actor boundary was not reached')

if __name__=='__main__':
    if sys.flags.optimize:
        print('FAIL: signed process-cut actor requires assertions enabled',file=sys.stderr)
        raise SystemExit(1)
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root',type=Path,required=True)
    parser.add_argument('--directory',type=Path,required=True)
    parser.add_argument('--executable',type=Path,required=True)
    parser.add_argument('--configuration',type=Path,required=True)
    args=parser.parse_args()
    try:
        if sys.flags.optimize:raise ValueError('actor requires assertions enabled')
        raw=args.configuration.read_bytes()
        if len(raw)>32768:raise ValueError('selected configuration too large')
        config=json.loads(raw)
        if set(config)!={'schema','cut','source_input_sha256','actor_sha256','python_sha256','worker_sha256'} or config['schema']!='ptlc-nom-signed-process-selection-v1':
            raise ValueError('selected configuration fields refused')
        run(args.source_root,args.directory,args.executable,config)
    except (OSError,ValueError,KeyError,TypeError,AssertionError):
        print('FAIL: signed process-cut actor; preserve all originals',file=sys.stderr)
        raise SystemExit(1)
