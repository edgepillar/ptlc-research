"""Round-trip real synthetic originals and refuse malformed profile transport.

The declared run is synthetic. These controls qualify framing and case-reader
components, and cannot qualify a hosted attempt or a speedup.
"""
import base64
from collections import Counter
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import unittest

CONFIG = None
REFUSALS = []
PINS = None


def sha(raw): return hashlib.sha256(raw).hexdigest()


def load(path, expected):
    path = Path(path); raw = path.read_bytes()
    assert sha(raw) == expected
    name = 'prepared_profile_control_' + expected
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


class OriginalProfileTransportControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        global CONFIG
        if CONFIG is not None:
            cls.initialize()
            return
        import sys
        import test_offline_ci_profile_driver as driver
        from scripts.run_offline_shard import counter_digest
        owner = driver.ProfileDriverControls('test_real_four_children_preserve_every_case_and_original_byte')
        owner.setUp()
        with owner.workspace('chunked') as selected:
            child = owner.execute(selected)
            owner.assertEqual(child.returncode, 0)
            report = owner.result(child)
            root = Path(__file__).resolve().parents[1]
            complete = Counter({'test_profile_fixture_'+str(i)+'.Example.test_'+name:1
                for i in range(4) for name in ('first', 'second')})
            originals = {}
            for i in range(4):
                for kind in ('stdout', 'stderr'):
                    path = selected['streams']/(str(i)+'.'+kind)
                    raw = path.read_bytes()
                    originals[str(i)+'.'+kind] = dict(path=str(path), bytes=len(raw), sha256=sha(raw))
            producer = root/'scripts/run_offline_ci_profile.py'
            decoder = root/'scripts/read_offline_ci_profile.py'
            context = dict(head=selected['head'], source_sha256=selected['source']['source_sha256'],
                run_id=99871, attempt=1, platform=sys.platform,
                python='{}.{}'.format(sys.version_info.major, sys.version_info.minor),
                authority='CALLER_DECLARED_RUN; TRUSTED_LOCAL_SOURCE; EXTERNAL_METADATA_ACCEPTANCE_REQUIRED')
            CONFIG = dict(producer=str(producer), producer_sha256=sha(producer.read_bytes()),
                decoder=str(decoder), decoder_sha256=sha(decoder.read_bytes()),
                originals=originals, synthetic_context=context, expected_source=selected['source'],
                counter=dict(complete), partition_cases={str(i):{
                    'test_profile_fixture_'+str(i)+'.Example.test_'+name:1 for name in ('first','second')}
                    for i in range(4)},
                plans={str(i):report['shard_reports'][str(i)]['plan'] for i in range(4)},
                original_supervision=report['supervision'], complete_counter_sha256=counter_digest(complete))
            cls.initialize()

    @classmethod
    def initialize(cls):
        cls.producer = load(CONFIG['producer'], CONFIG['producer_sha256'])
        cls.decoder = load(CONFIG['decoder'], CONFIG['decoder_sha256'])
        cls.raw = {}
        for name, pin in CONFIG['originals'].items():
            path = Path(pin['path']); data = path.read_bytes()
            assert len(data) == pin['bytes'] and sha(data) == pin['sha256']
            cls.raw[name] = data
        cls.context = CONFIG['synthetic_context']; cls.source = CONFIG['expected_source']
        cls.complete = Counter(CONFIG['counter']); assert sum(cls.complete.values()) == len(cls.complete) == 8
        cls.case_count = 8
        cls.reports = {}
        for i in range(4):
            rows = [line for line in cls.raw[str(i) + '.stdout'].splitlines() if line.startswith(b'PTLC_SHARD_RESULT=')]
            assert len(rows) == 1
            cls.reports[str(i)] = json.loads(rows[0].split(b'=', 1)[1])
        cls.supervision = CONFIG['original_supervision']
        cls.frames = cls.packet(cls.raw)

    @classmethod
    def packet(cls, originals):
        frames = [('BEGIN', dict(context=cls.context, expected_cases=cls.case_count, logical_shards=4,
            original_streams=8, workers=4, source=cls.source))]
        pins = {}; supervision = copy.deepcopy(cls.supervision)
        for i in range(4):
            for kind in ('stdout', 'stderr'):
                raw = originals[str(i) + '.' + kind]
                base = dict(context=cls.context, shard=i, kind=kind, launched=True, actual_exit=0, output_complete=True)
                for offset in range(0, len(raw), 16384):
                    frames.append(('CHUNK', dict(base, offset=offset,
                        data_base64=base64.b64encode(raw[offset:offset + 16384]).decode('ascii'))))
                pin = dict(sha256=sha(raw), bytes=len(raw)); pins[str(i) + '.' + kind] = pin
                supervision['children'][i][kind] = dict(pin, eof=True, truncated=False)
                frames.append(('STREAM_END', dict(base, **pin, chunks=(len(raw) + 16383) // 16384)))
        frames.append(('RESULT', dict(schema='ptlc-offline-ci-profile-v1', outcome='PASS', context=cls.context,
            source_before=cls.source, source_after=cls.source, source_unchanged=True,
            supervision=supervision, stream_pins=pins, shard_reports=cls.reports, error_class=None,
            actual_accepted_cases=cls.case_count, expected_cases=cls.case_count,
            actual_counter_sha256=CONFIG['complete_counter_sha256'],
            complete_counter_sha256=CONFIG['complete_counter_sha256'],
            case_acceptance='PASS_FOUR_COMPLETE_ORIGINAL_STREAMS', test_result_cache=False,
            verifier_replaced=False, automatic_retry=False, fixture_owner='CALLER; UNKNOWN_DATA_PRESERVED',
            source_tree_copies=0, application='NO-GO', core='NO-GO', recovery_action='NONE', independent_assessment='UNFILLED')))
        return frames

    def encode(self, frames):
        return b''.join(b'PTLC_OFFLINE_PROFILE_' + name.encode('ascii') + b'=' +
            json.dumps(value, sort_keys=True, separators=(',', ':')).encode('ascii') + b'\n' for name, value in frames)

    def decode(self, frames):
        return self.decoder.decode(self.encode(frames), expected_context=self.context,
            expected_source=self.source, expected_workers=4, expected_cases=self.case_count)

    def refuses(self, name, frames):
        with self.assertRaises(self.decoder.ProfileDecodeRefused): self.decode(frames)
        REFUSALS.append(name)

    def test_original_eight_streams_roundtrip_without_test_execution(self):
        result = self.decode(self.frames)
        for i in range(4):
            for kind in ('stdout', 'stderr'):
                self.assertEqual(result['streams'][i, kind], self.raw[str(i) + '.' + kind])
        self.assertEqual(result['case_acceptance'], 'NOT_PERFORMED_BY_DECODER')
        self.assertEqual(result['hosted_attempt_acceptance'], 'NOT_PERFORMED')
        self.assertIs(result['code_from_transport_executed'], False)
        self.assertEqual((result['application'], result['core'], result['recovery_action']), ('NO-GO', 'NO-GO', 'NONE'))

    def test_original_case_streams_match_fresh_discovery_inputs(self):
        union = Counter()
        for i in range(4):
            expected = Counter(CONFIG['partition_cases'][str(i)])
            actual, unused = self.producer.accept_streams(self.raw[str(i) + '.stdout'], self.raw[str(i) + '.stderr'],
                expected, CONFIG['plans'][str(i)])
            self.assertFalse(set(union) & set(actual)); union.update(actual)
        self.assertEqual(union, self.complete)

    def test_coherent_context_reselection_cannot_replace_independent_pins(self):
        for field, value in [('head', 'f' * 40), ('source_sha256', 'f' * 64), ('run_id', 99872),
                ('attempt', 2), ('platform', 'linux' if self.context['platform'] == 'darwin' else 'darwin'),
                ('python', '3.11' if self.context['python'] != '3.11' else '3.13'), ('authority', 'synthetic authority')]:
            selected = copy.deepcopy(self.frames)
            for unused, row in selected:
                row['context'][field] = value
            self.refuses('coherent context ' + field, selected)

    def test_numeric_boolean_aliases_have_no_acceptance_path(self):
        for label, mutation in [
            ('attempt', lambda f: f[0][1]['context'].__setitem__('attempt', True)),
            ('shard', lambda f: next(row for name, row in f if name == 'CHUNK').__setitem__('shard', False)),
            ('offset', lambda f: next(row for name, row in f if name == 'CHUNK').__setitem__('offset', False)),
            ('exit', lambda f: next(row for name, row in f if name == 'CHUNK').__setitem__('actual_exit', False)),
            ('source copies', lambda f: f[-1][1].__setitem__('source_tree_copies', False)),
            ('supervisor child', lambda f: f[-1][1]['supervision']['children'][0].__setitem__('actual_exit', False)),
            ('supervisor peak', lambda f: f[-1][1]['supervision'].__setitem__('peak_running', True))]:
            selected = copy.deepcopy(self.frames); mutation(selected); self.refuses('boolean ' + label, selected)

    def test_missing_duplicate_reordered_and_unknown_frames_refuse(self):
        chunk = next(i for i, row in enumerate(self.frames) if row[0] == 'CHUNK')
        end = next(i for i, row in enumerate(self.frames) if row[0] == 'STREAM_END')
        for label, mutation in [
            ('begin absent', lambda f: f.pop(0)), ('begin duplicate', lambda f: f.insert(1, copy.deepcopy(f[0]))),
            ('chunk absent', lambda f: f.pop(chunk)), ('chunk duplicate', lambda f: f.insert(chunk, copy.deepcopy(f[chunk]))),
            ('stream end absent', lambda f: f.pop(end)), ('stream end duplicate', lambda f: f.insert(end, copy.deepcopy(f[end]))),
            ('result absent', lambda f: f.pop()), ('after result', lambda f: f.append(copy.deepcopy(f[0]))),
            ('unknown frame', lambda f: f.insert(1, ('ALLOW_WORK', {})))]:
            selected = copy.deepcopy(self.frames); mutation(selected); self.refuses(label, selected)
        selected = copy.deepcopy(self.frames)
        first = next(i for i, row in enumerate(selected) if row[0] == 'CHUNK')
        selected[first], selected[first + 1] = selected[first + 1], selected[first]
        self.refuses('chunk order', selected)

    def test_chunk_encoding_offsets_hash_size_and_terminal_counts_refuse(self):
        for field, value in [('data_base64', '***'), ('data_base64', ''), ('offset', 1),
                ('output_complete', False), ('actual_exit', -9), ('launched', False)]:
            selected = copy.deepcopy(self.frames)
            next(row for name, row in selected if name == 'CHUNK')[field] = value
            self.refuses('chunk ' + field + ' ' + str(value), selected)
        for field, value in [('sha256', 'f' * 64), ('bytes', -1), ('chunks', -1), ('chunks', True)]:
            selected = copy.deepcopy(self.frames)
            next(row for name, row in selected if name == 'STREAM_END')[field] = value
            self.refuses('end ' + field, selected)

    def test_extra_fields_and_capability_claims_refuse(self):
        for label, mutation in [
            ('begin', lambda f: f[0][1].__setitem__('signing_allowed', True)),
            ('context', lambda f: f[0][1]['context'].__setitem__('new_work_allowed', True)),
            ('chunk', lambda f: next(row for name, row in f if name == 'CHUNK').__setitem__('replacement_allowed', True)),
            ('result', lambda f: f[-1][1].__setitem__('funds_allowed', True)),
            ('application', lambda f: f[-1][1].__setitem__('application', 'GO')),
            ('recovery', lambda f: f[-1][1].__setitem__('recovery_action', 'RETRY'))]:
            selected = copy.deepcopy(self.frames); mutation(selected); self.refuses('extra or authority ' + label, selected)

    def test_source_changes_and_supervisor_incompleteness_refuse(self):
        for label, mutation in [
            ('source after', lambda f: f[-1][1]['source_after'].__setitem__('tree', 'f' * 40)),
            ('source unchanged', lambda f: f[-1][1].__setitem__('source_unchanged', False)),
            ('stop reason', lambda f: f[-1][1]['supervision'].__setitem__('stop_reason', 'TIMEOUT')),
            ('held fixture', lambda f: f[-1][1]['supervision'].__setitem__('held_fixture_shards', [0])),
            ('worker count', lambda f: f[-1][1]['supervision'].__setitem__('workers', 3)),
            ('incomplete child', lambda f: f[-1][1]['supervision']['children'][0].__setitem__('output_complete', False)),
            ('truncated stream', lambda f: f[-1][1]['supervision']['children'][0]['stdout'].__setitem__('truncated', True)),
            ('missing child', lambda f: f[-1][1]['supervision']['children'].pop()),
            ('duplicate child', lambda f: f[-1][1]['supervision']['children'].__setitem__(1, copy.deepcopy(f[-1][1]['supervision']['children'][0])))]:
            selected = copy.deepcopy(self.frames); mutation(selected); self.refuses(label, selected)

    def test_duplicate_json_keys_nonfinite_values_and_data_bounds_refuse(self):
        raw = self.encode(self.frames)
        duplicate = raw.replace(b'PROFILE_BEGIN={', b'PROFILE_BEGIN={"workers":4,', 1)
        with self.assertRaises(self.decoder.ProfileDecodeRefused):
            self.decoder.decode(duplicate, expected_context=self.context, expected_source=self.source,
                expected_workers=4, expected_cases=self.case_count)
        REFUSALS.append('duplicate JSON key')
        selected = copy.deepcopy(self.frames); selected[-1][1]['supervision']['elapsed_seconds'] = float('nan')
        self.refuses('nonfinite time', selected)
        original = self.decoder.MAX_TRANSPORT
        try:
            self.decoder.MAX_TRANSPORT = len(raw) - 1
            with self.assertRaises(self.decoder.ProfileDecodeRefused): self.decode(self.frames)
            REFUSALS.append('transport cap injection only')
        finally: self.decoder.MAX_TRANSPORT = original
        self.assertEqual(original, 48 * 1024**2)

    def test_byte_equality_does_not_establish_case_execution(self):
        original = dict(self.raw); original['0.stdout'] = b''
        result = self.decode(self.packet(original))
        self.assertEqual(result['case_acceptance'], 'NOT_PERFORMED_BY_DECODER')
        with self.assertRaises(self.producer.ProfileRefused):
            self.producer.accept_streams(result['streams'][0, 'stdout'], result['streams'][0, 'stderr'],
                Counter(CONFIG['partition_cases']['0']), CONFIG['plans']['0'])
        REFUSALS.append('manufactured empty case stream rejected by separate case parser')
