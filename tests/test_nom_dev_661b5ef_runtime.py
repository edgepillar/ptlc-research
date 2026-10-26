"""Manufactured runtime event controls; no Go, node or observation authority."""
import copy
import json
import unittest
from unittest.mock import patch

from qualification import nom_dev_661b5ef_runtime as reader

REFUSALS = (ValueError,AssertionError,KeyError,TypeError,OSError)


def events(unit, child=False):
    package = reader.common.PREFIX+reader.SPECS[unit][0]
    rows = [dict(Action='start',Package=package)]
    for number,name in enumerate(reader.SPECS[unit][2]):
        rows.append(dict(Action='run',Package=package,Test=name))
        if child and number == 0:
            rows.extend([
                dict(Action='run',Package=package,Test=name+'/selected-child'),
                dict(Action='pass',Package=package,Test=name+'/selected-child',Elapsed=0),
            ])
        rows.append(dict(Action='pass',Package=package,Test=name,Elapsed=0))
    rows.append(dict(Action='pass',Package=package,Elapsed=0))
    return rows


def encoded(rows):
    return b''.join(json.dumps(row,sort_keys=True).encode('ascii')+b'\n' for row in rows)


class CurrentRuntimeTests(unittest.TestCase):
    def test_exact_source_test_set_preserves_limits_and_excludes_node_start(self):
        value = reader.inputs()
        self.assertEqual((value['source_files'],value['profiles'],value['required_top_level_tests']),(518,9,58))
        selected = {name for row in value['units'].values() for name in row['tests']}
        self.assertNotIn(value['excluded_real_node_test'],selected)
        self.assertNotIn('TestNewNodeManager_CLIContextStillWorks',selected)
        self.assertEqual((value['application'],value['core'],value['recovery_action']),('NO-GO','NO-GO','NONE'))
        for row in reader.plan():
            self.assertEqual(row['prior_streams_required'],[])
            self.assertEqual(row['arguments'][:8],['test','-json','-p','2','-mod=readonly','-count=1','-run',row['parent']])
            self.assertNotIn('-vet=off',row['arguments'])

    def test_nine_manufactured_profiles_supply_no_native_execution(self):
        payloads = {unit+suffix:encoded(events(unit)) if suffix == '.stdout' else b''
            for unit in reader.SPECS for suffix in ('.stdout','.stderr')}
        value = reader.compare_payloads(payloads)
        self.assertEqual((value['complete_profiles'],value['required_top_level_tests'],value['original_streams']),(9,58,18))
        self.assertEqual(value['observed_descendants'],0)
        self.assertEqual(value['native_execution'],'NOT_PERFORMED_BY_READER')
        self.assertEqual(value['independent_assessment'],'UNFILLED')

    def test_nested_and_paused_lifecycles_are_closed_without_independent_child_count_claim(self):
        unit = 'runtime-manager-guards'
        rows = events(unit,True)
        row = copy.deepcopy(rows[1]);row['Action']='pause'
        resume = dict(row,Action='cont')
        rows[2:2] = [row,resume]
        value = reader.read(encoded(rows),unit)
        self.assertEqual(value['observed_descendants'],1)
        self.assertIn('NOT AN INDEPENDENT CASE ENUMERATION',value['child_count_scope'])
        self.assertEqual(value['execution_origin'],'NOT_ESTABLISHED_BY_READER')

    def test_missing_reordered_duplicate_failed_skipped_and_foreign_events_refuse(self):
        unit = 'runtime-manager-guards'
        for mode in ('start','run','last-test','package-pass','duplicate-test','duplicate-package',
            'fail','skip','foreign-test','foreign-package','pass-before-run','after-package',
            'pause-without-run','cont-without-pause','output-after-test','parent-before-child'):
            rows = events(unit,True)
            if mode == 'start':rows.pop(0)
            elif mode == 'run':rows.pop(1)
            elif mode == 'last-test':rows = rows[:-3]+rows[-1:]
            elif mode == 'package-pass':rows.pop()
            elif mode == 'duplicate-test':rows.insert(4,copy.deepcopy(rows[3]))
            elif mode == 'duplicate-package':rows.append(copy.deepcopy(rows[-1]))
            elif mode in ('fail','skip'):rows[3]['Action']=mode
            elif mode == 'foreign-test':rows[1]['Test']='TestUnselected'
            elif mode == 'foreign-package':rows[1]['Package']='unselected/package'
            elif mode == 'pass-before-run':rows[1]['Action']='pass'
            elif mode == 'after-package':rows.append(dict(Action='output',Package=rows[0]['Package'],Output='late\n'))
            elif mode == 'pause-without-run':rows[1]['Action']='pause'
            elif mode == 'cont-without-pause':rows[1]['Action']='cont'
            elif mode == 'output-after-test':
                rows.insert(5,dict(Action='output',Package=rows[0]['Package'],Test=rows[1]['Test'],Output='late\n'))
            else:
                rows[3],rows[4] = rows[4],rows[3]
            with self.subTest(mode=mode),self.assertRaises(REFUSALS):
                reader.read(encoded(rows),unit)

    def test_partial_foreign_and_old_profile_selections_refuse(self):
        payloads = {unit+suffix:encoded(events(unit)) if suffix == '.stdout' else b''
            for unit in reader.SPECS for suffix in ('.stdout','.stderr')}
        for mode in ('one-missing','one-extra','foreign-stream','missing-stderr'):
            selected = dict(payloads)
            if mode == 'one-missing':selected.pop('runtime-node-stop.stdout')
            elif mode == 'one-extra':selected['unselected.stdout']=b''
            elif mode == 'foreign-stream':
                selected['runtime-node-stop.stdout']=selected['runtime-manager-guards.stdout']
            else:selected.pop('runtime-manager-close.stderr')
            with self.subTest(mode=mode),self.assertRaises(REFUSALS):
                reader.compare_payloads(selected)

    def test_json_types_duplicate_fields_eof_and_extra_fields_refuse(self):
        unit = 'runtime-spork-tombstone'
        raw = encoded(events(unit))
        bad = [b'',raw[:-1],raw+b'{}\n',raw.replace(b'"Action": "run"',b'"Action":"run","Action":"pass"',1)]
        for field,value in (('Elapsed',True),('Elapsed',float('nan')),('FailedBuild','unselected'),('Authority','GO')):
            rows = events(unit);rows[-1][field]=value;bad.append(encoded(rows))
        for number,value in enumerate(bad):
            with self.subTest(case=number),self.assertRaises(REFUSALS):
                reader.read(value,unit)

    def test_manifest_source_substitution_and_authority_promotions_refuse(self):
        original = reader.common.decoded
        manifest = reader.inputs()
        for field,value in (('core_commit','0'*40),('required_top_level_tests',51),
            ('application','GO'),('independent_assessment','PASS')):
            changed = copy.deepcopy(manifest);changed[field]=value
            def decoded(raw,limit):
                parsed = original(raw,limit)
                return changed if type(parsed) is dict and parsed.get('schema') == manifest['schema'] else parsed
            with self.subTest(field=field),patch.object(reader.common,'decoded',side_effect=decoded),self.assertRaises(REFUSALS):
                reader.inputs()
        changed = copy.deepcopy(manifest)
        changed['units']['runtime-node-stop']['tests'].append(changed['excluded_real_node_test'])
        def decoded(raw,limit):
            parsed = original(raw,limit)
            return changed if type(parsed) is dict and parsed.get('schema') == manifest['schema'] else parsed
        with patch.object(reader.common,'decoded',side_effect=decoded),self.assertRaises(REFUSALS):
            reader.inputs()


    def test_logging_initializers_have_exact_bodies_and_cannot_self_repin(self):
        from pathlib import Path
        selected = reader.probes()
        self.assertEqual(len(selected),3)
        self.assertEqual(set(selected.values()),reader.OWN_INPUTS-{
            'qualification/nom_dev_661b5ef_runtime.py','tests/test_nom_dev_661b5ef_runtime.py'})
        original = reader.common.regular
        for logical,name in selected.items():
            raw = (reader.ROOT/name).read_bytes()
            self.assertIn(b'log15.Root().SetHandler(log15.DiscardHandler())',raw)
            self.assertNotIn(b'TestMain',raw)
            self.assertNotIn(b'os.Stdout',raw)
            def changed(path,limit):
                result = original(path,limit)
                return result+b'\nfunc unselected() {}\n' if Path(path)==reader.ROOT/name else result
            with self.subTest(probe=logical),patch.object(reader.common,'regular',side_effect=changed),self.assertRaises(REFUSALS):
                reader.probes()

    def test_darwin_diagnostic_profile_is_explicit_and_retains_default_codegen_flags(self):
        from pathlib import Path
        import tempfile
        from scripts import qualify_nom_661b5ef_native as native
        root = Path(tempfile.gettempdir())/'synthetic-profile'
        environment = native.selected_environment(root,root/'proxy',root/'cc')
        self.assertNotIn('CGO_CFLAGS',environment)
        self.assertEqual(environment['GOFLAGS'],'-trimpath')
        self.assertEqual(reader.diagnostic_profile(None),'GO_DEFAULT_CGO_FLAGS')
        selected = native.selected_environment(root,root/'proxy',root/'cc',root/'sdk')
        self.assertEqual(selected['CGO_CFLAGS'],'-O2 -g -Wno-deprecated-declarations')
        self.assertEqual(selected['GOFLAGS'],'-trimpath')
        self.assertEqual(selected['GOTOOLCHAIN'],'local')
        self.assertEqual(reader.diagnostic_profile(root/'sdk'),'DARWIN_O2_G_NO_DEPRECATED_DECLARATIONS')


if __name__ == '__main__':
    unittest.main()
