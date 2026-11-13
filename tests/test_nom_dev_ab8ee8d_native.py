"""Controls for the exact native selection and its data-only result reader."""
import json
from pathlib import Path
import tempfile
from unittest import mock
import re
import unittest

from qualification import nom_dev_ab8ee8d_native as selected
from qualification.nom_current_admission import PREFIX
from scripts import qualify_nom_ab8ee8d_native as runner


def event_bytes(events):
    return b''.join(json.dumps(event, sort_keys=True).encode('ascii') + b'\n' for event in events)


def synthetic_events():
    events = []
    for package, roots in selected.ROOTS.items():
        package = PREFIX + package
        events.append(dict(Action='start', Package=package))
        for root in roots:
            events.extend(dict(Action=action, Package=package, Test=root) for action in ('run', 'pass'))
        events.append(dict(Action='pass', Package=package))
    return events


class NoMDevAb8ee8dNativeControls(unittest.TestCase):
    def test_plan_uses_one_exact_filter_and_the_original_corpus(self):
        plan, index, combined = selected.selection()
        self.assertEqual((len(index), len(combined), len(selected.ROOTS)), (574, 575, 19))
        self.assertEqual(sum(map(len, selected.ROOTS.values())), 128)
        decode = 'TestAccountBlock_UnmarshalJSON_DescendantDecodeIsLinear'
        self.assertEqual({package for package, roots in selected.ROOTS.items() if decode in roots},
                         {'chain/nom', 'rpc/api'})
        self.assertEqual(combined[selected.PROBE], plan['project_input_sha256'][selected.DRIVER])
        self.assertEqual(len(plan['project_input_sha256']), 5)
        self.assertEqual(tuple(plan['test_arguments'][-19:]), selected.PACKAGES)
        self.assertIn('-count=1', plan['test_arguments'])
        self.assertIn('-mod=readonly', plan['test_arguments'])
        self.assertNotIn('-vet=off', plan['test_arguments'])
        names = [name for roots in selected.ROOTS.values() for name in roots]
        self.assertTrue(all(re.fullmatch(selected.TEST_FILTER, name) for name in names))
        self.assertFalse(any(re.fullmatch(selected.TEST_FILTER, name + 'Other') for name in names))

    def test_baseline_roots_and_new_admission_scope_are_both_selected(self):
        plan, _, _ = selected.selection()
        self.assertEqual((plan['baseline_parents'], plan['added_parents']), (39, 89))
        self.assertEqual(plan['baseline_core'], selected.baseline.upstream.CORE)
        self.assertEqual(plan['core_commit'], selected.upstream.CORE)
        self.assertEqual(plan['selection_scope'], runner.BOUNDARY['selection_scope'])
        self.assertEqual(runner.SCHEMA, 'ptlc-nom-ab8ee8d-native-v2')
        for package, roots in selected.baseline.ROOTS.items():
            with self.subTest(package=package):
                self.assertTrue(set(roots) <= set(selected.ROOTS[package]))
        for package, root in (
            ('chain', 'TestAcknowledgementRequirement_SporkReadFailureIsError'),
            ('node', 'TestHTTPAdmissionCoversGzipClose'),
            ('rpc/server', 'TestHTTPAdmissionRefusalClosesIncompleteBody'),
            ('verifier', 'TestEmbeddedRefundRecoveryHeight_LongStallIsLogarithmic'),
            ('vm/embedded/tests', 'TestEmbeddedRefund_LateActivationRecoversStalledQueue'),
            ('protocol/downloader', 'TestBlockFetchImportFreesCapacityDuringPass'),
        ):
            with self.subTest(package=package):
                self.assertIn(root, selected.ROOTS[package])

    def test_stream_refuses_skipped_missing_and_additional_roots(self):
        original = synthetic_events()
        record = selected.accept_events(event_bytes(original))
        self.assertEqual((record['packages'], record['required_parents']), (19, 128))
        for events in (original[:1] + original[3:],
                       original[:2] + [dict(original[2], Action='skip')] + original[3:],
                       original[:3] + [dict(original[1], Test='TestUnselected')] + original[3:]):
            with self.subTest(events=len(events)), self.assertRaises(ValueError):
                selected.accept_events(event_bytes(events))

    def test_export_checks_original_streams_and_module_checksum_keys(self):
        self.assertTrue(runner.safe(b'go version go1.23.12 linux/amd64\n'))
        self.assertFalse(runner.safe(b'compiler path TOKEN', ('TOKEN',)))
        self.assertFalse(runner.safe(b'line with non-ASCII byte \xff'))
        row = b'example.invalid/module v1.0.0 h1:' + b'A'*43 + b'=\n'
        self.assertEqual(len(runner.module_sums(row)), 1)
        for invalid in (row + row, row.rstrip(), row.replace(b'h1:', b'h0:')):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                runner.module_sums(invalid)


    def projection_fixture(self):
        rows = synthetic_events()
        rows.insert(2, dict(rows[1], Action='output', Output='synthetic'+chr(0xa0)+'output\n'))
        originals = [json.dumps(row, sort_keys=True, ensure_ascii=False).encode('utf-8') + b'\n' for row in rows]
        raw = b''.join(originals)
        content, record, complete = selected.original_event_selection(raw)
        return rows, originals, raw, content, record, complete

    def test_selection_preserves_structural_bytes_and_privacy_refusal(self):
        rows, originals, raw, content, record, complete = self.projection_fixture()
        self.assertFalse(runner.safe(raw))
        self.assertTrue(runner.safe(content))
        self.assertEqual(content, b''.join(line for row, line in zip(rows, originals) if row['Action'] != 'output'))
        self.assertEqual(record['omitted_output_events'], 1)
        self.assertEqual(record['original_stdout'], dict(bytes=len(raw), sha256=runner.sha(raw)))
        checked = selected.accept_selected_events(content, record, record['original_stdout'], complete)
        self.assertEqual((checked['packages'], checked['required_parents']), (19, 128))
        self.assertEqual(checked['full_stdout_acceptance'], 'NOT_CLAIMED')
        self.assertEqual(checked['selection_completeness_by_reader'], 'NOT_ESTABLISHED')
        plain = event_bytes(synthetic_events())
        kept, no_output, full = selected.original_event_selection(plain)
        self.assertEqual(kept, plain)
        self.assertEqual(no_output['omitted_output_events'], 0)
        self.assertEqual(no_output['original_stdout'], no_output['selected_stream'])

    def test_selection_keeps_failed_skipped_missing_and_duplicate_guards(self):
        rows = synthetic_events()
        for changed in (rows[:2] + [dict(rows[2], Action='fail')] + rows[3:],
                        rows[:2] + [dict(rows[2], Action='skip')] + rows[3:],
                        rows[:1] + rows[3:], rows[:3] + [rows[2]] + rows[3:]):
            with self.subTest(events=len(changed)), self.assertRaises(ValueError):
                selected.original_event_selection(event_bytes(changed))

    def test_selection_refuses_malformed_and_out_of_state_output(self):
        rows = synthetic_events()
        invalid = (event_bytes(rows).rstrip(b'\n'),
            b'{"Action":"output","Action":"start"}\n' + event_bytes(rows),
            b'not-json\n' + event_bytes(rows),
            event_bytes(rows[:1] + [dict(rows[1], Action='output', Output='synthetic')] + rows[1:]),
            event_bytes(rows[:1] + [dict(rows[1], Output='synthetic')] + rows[2:]))
        for raw in invalid:
            with self.subTest(bytes=len(raw)), self.assertRaises(ValueError):
                selected.original_event_selection(raw)

    def test_selected_reader_refuses_forged_count_pin_and_custody_claims(self):
        _, _, _, content, original, complete = self.projection_fixture()
        changes = (('original_events', True), ('selected_events', True), ('omitted_output_events', -1),
            ('selected_stream', dict(bytes=len(content), sha256='0'*64)),
            ('original_stdout', dict(bytes=1, sha256='0'*64)),
            ('full_stdout_acceptance', 'ACCEPTED'), ('selection_completeness_by_reader', 'ESTABLISHED'))
        for key, value in changes:
            record = dict(original, **{key: value})
            with self.subTest(field=key), self.assertRaises(ValueError):
                selected.accept_selected_events(content, record, original['original_stdout'], complete)
        record = dict(original, omitted_output_events=0, original_events=original['selected_events'])
        with self.assertRaises(ValueError):
            selected.accept_selected_events(content, record, original['original_stdout'],
                dict(complete, events=record['original_events']))

    def test_selected_reader_refuses_lost_structural_rows_and_added_output(self):
        rows, _, _, content, record, complete = self.projection_fixture()
        kept = content.splitlines(keepends=True)
        extra = json.dumps(dict(rows[1], Action='output', Output='synthetic')).encode('ascii') + b'\n'
        for raw in (b''.join(kept[:2]+kept[3:]), content+extra):
            changed = dict(record, selected_stream=dict(bytes=len(raw), sha256=runner.sha(raw)),
                           selected_events=len(raw.splitlines()))
            changed['original_events'] = changed['selected_events'] + changed['omitted_output_events']
            with self.subTest(bytes=len(raw)), self.assertRaises(ValueError):
                selected.accept_selected_events(raw, changed, changed['original_stdout'],
                    dict(complete, events=changed['original_events']))

    def artifact_fixture(self, workspace):
        _, _, raw, content, selection, complete = self.projection_fixture()
        _, _, paths = selected.selection()
        snapshot = dict(files=len(paths), sha256=runner.sha(runner.canonical(paths)))
        research = dict(head='1'*40, tree='2'*40, files=1, source_bytes=1, source_sha256='3'*64)
        plan, _, _ = selected.selection()
        report = dict(schema=runner.SCHEMA, selection=plan, boundary=runner.BOUNDARY,
            research_source=research, outcome=runner.PASS, stage='complete', commands={},
            source_before=snapshot, source_after=snapshot, comparison=complete, event_selection=selection)
        commands = workspace/'commands'; commands.mkdir()
        for label in runner.LABELS:
            streams = {}
            for kind in ('stdout', 'stderr'):
                value = (runner.VERSION if label=='go-version' else b'all modules verified\n'
                         if label=='module-verify' else raw if label=='selected-native'
                         else b'synthetic dependency\n') if kind=='stdout' else b''
                exported = (label,kind)!=('selected-native','stdout')
                streams[kind] = dict(bytes=len(value),sha256=runner.sha(value),export=exported)
                if exported:(commands/(label+'.'+kind)).write_bytes(value)
            report['commands'][label] = dict(result='RETURNED_ZERO_WITH_COMPLETE_STREAMS',actual_exit=0,
                cleanup_complete=True,complete=dict(stdout=True,stderr=True),elapsed_seconds=0.0,streams=streams)
        (commands/runner.EVENTS).write_bytes(content)
        (workspace/runner.RESULT).write_bytes(runner.canonical(report))
        return report,research

    def test_artifact_reader_selects_original_rows_without_full_stdout_claim(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            _, research = self.artifact_fixture(workspace)
            with mock.patch.object(runner,'research_source',return_value=research):
                report, files = runner.inspect(workspace,research['head'])
            self.assertEqual(len(files),9)
            self.assertIn('commands/'+runner.EVENTS,files)
            self.assertNotIn('commands/selected-native.stdout',files)
            self.assertFalse(report['commands']['selected-native']['streams']['stdout']['export'])
            self.assertEqual(report['event_selection']['full_stdout_acceptance'],'NOT_CLAIMED')

    def test_artifact_reader_refuses_missing_or_relabelled_event_evidence(self):
        for invalid in ('missing-events','full-stdout-export'):
            with self.subTest(invalid=invalid), tempfile.TemporaryDirectory() as directory:
                workspace = Path(directory)
                report, research = self.artifact_fixture(workspace)
                if invalid=='missing-events':(workspace/'commands'/runner.EVENTS).unlink()
                else:
                    report['commands']['selected-native']['streams']['stdout']['export']=True
                    (workspace/runner.RESULT).write_bytes(runner.canonical(report))
                with mock.patch.object(runner,'research_source',return_value=research), self.assertRaises((ValueError,OSError)):
                    runner.inspect(workspace,research['head'])


if __name__ == '__main__':
    unittest.main()
