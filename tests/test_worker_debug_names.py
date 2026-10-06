"""Synthetic debug-name framing, privacy and separately acquired carrier checks."""

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts import check_worker_debug_names as check
from scripts import qualify_worker_debug_names as companion
import test_worker_sections as fixtures
import test_worker_symbols as symbol_fixtures


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


class WorkerDebugNameTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory();self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name);self.paths={n:self.root/n for n in check.scanner.SELECTIONS}
        self.selected=fixtures.prefixes()
        self.bodies={'first':fixtures.elf([(b'.debug_str',1,0,self.selected['first'][check.scanner.ROLES[0]]+b'\x00')]),
                     'second':symbol_fixtures.macho(b' '+self.selected['second'][check.scanner.ROLES[2]]+b'\x00',[(1,0x64)])}
        self.save()

    def save(self):
        for n in check.scanner.SELECTIONS:self.paths[n].write_bytes(self.bodies[n])

    def inspect(self, **changes):
        values=dict(first=self.paths['first'],first_sha256=digest(self.bodies['first']),first_bytes=len(self.bodies['first']),
                    second=self.paths['second'],second_sha256=digest(self.bodies['second']),second_bytes=len(self.bodies['second']),prefixes=self.selected)
        values.update(changes);return check.inspect(**values)

    def refuses(self, **changes):
        with self.assertRaises(check.InputError) as caught:self.inspect(**changes)
        self.assertEqual(str(caught.exception),check.REFUSAL)

    def row(self, name='first', role=None):
        return self.inspect()['artifacts'][name]['group_presence'][role or check.scanner.ROLES[0]]

    def present(self, row):
        return [g for g,v in row.items() if v]

    def test_fixed_debug_pool_and_source_stab_classes_and_complete_measurements(self):
        report=self.inspect()
        for n,role,groups in (('first',check.scanner.ROLES[0],(0,1)),('second',check.scanner.ROLES[2],(4,5))):
            row=report['artifacts'][n];self.assertEqual(set(row),{'measured','format','group_presence'})
            self.assertEqual(self.present(row['group_presence'][role]),[check.GROUPS[g] for g in groups])
            self.assertEqual(row['measured']['sha256'],digest(self.bodies[n]))

    def test_line_string_pool_has_separate_raw_and_terminated_classes(self):
        needle=self.selected['first'][check.scanner.ROLES[0]]
        self.bodies['first']=fixtures.elf([(b'.debug_line_str',1,0,needle+b'\x00')]);self.save()
        self.assertEqual(self.present(self.row()),list(check.GROUPS[2:4]))

    def test_both_pools_may_contain_the_same_selected_bytes(self):
        needle=self.selected['first'][check.scanner.ROLES[0]]
        self.bodies['first']=fixtures.elf([(name,1,0,needle+b'\x00') for name in check.POOLS]);self.save()
        self.assertEqual(self.present(self.row()),list(check.GROUPS[:4]))

    def test_only_exact_pool_spellings_are_selected(self):
        needle=self.selected['first'][check.scanner.ROLES[0]]
        for name in (b'.debug_str.dwo',b'.debug_line_str_other',b'.debug_info',b'.other'):
            self.bodies['first']=fixtures.elf([(name,1,0,needle)]);self.save()
            self.assertEqual(self.present(self.row()),[check.GROUPS[8]])

    def test_empty_and_absent_pools_preserve_complete_complement(self):
        needle=self.selected['first'][check.scanner.ROLES[0]]
        for entries in ([],[(b'.debug_str',1,0,b'')],[(b'.debug_str',1,0,b''),(b'.debug_line_str',1,0,b'')]):
            self.bodies['first']=fixtures.elf(entries,tail=needle);self.save()
            self.assertEqual(self.present(self.row()),[check.GROUPS[8]])

    def test_pool_first_byte_need_not_be_zero(self):
        self.assertNotEqual(self.bodies['first'][-2],0)
        self.assertTrue(self.row()[check.GROUPS[1]])

    def test_empty_entries_count_toward_the_entry_bound(self):
        self.bodies['first']=fixtures.elf([(b'.debug_str',1,0,b'\x00\x00')]);self.save()
        with patch.object(check,'MAX_POOL_ENTRIES',2):self.inspect()
        with patch.object(check,'MAX_POOL_ENTRIES',1):self.refuses()

    def test_entry_bound_is_total_across_both_selected_pools(self):
        self.bodies['first']=fixtures.elf([(b'.debug_str',1,0,b'\x00'),(b'.debug_line_str',1,0,b'\x00\x00')]);self.save()
        with patch.object(check,'MAX_POOL_ENTRIES',3):self.inspect()
        with patch.object(check,'MAX_POOL_ENTRIES',2):self.refuses()

    def test_byte_bound_totals_selected_elf_pools_without_counting_macho_table(self):
        self.bodies['first']=fixtures.elf([(b'.debug_str',1,0,b'a\x00'),(b'.debug_line_str',1,0,b'b\x00')]);self.save()
        with patch.object(check,'MAX_POOL_BYTES',4):self.inspect()
        with patch.object(check,'MAX_POOL_BYTES',3):self.refuses()

    def test_exact_entry_length_passes_and_next_byte_refuses(self):
        needle=self.selected['first'][check.scanner.ROLES[0]]
        for size,positive in ((check.MAX_ENTRY_BYTES,True),(check.MAX_ENTRY_BYTES+1,False)):
            self.bodies['first']=fixtures.elf([(b'.debug_str',1,0,needle+b'X'*(size-len(needle))+b'\x00')]);self.save()
            if positive:self.assertTrue(self.row()[check.GROUPS[1]])
            else:self.refuses()

    def test_unterminated_final_pool_entry_refuses(self):
        for name in check.POOLS:
            self.bodies['first']=fixtures.elf([(name,1,0,b'synthetic incomplete')]);self.save();self.refuses()

    def test_termination_after_selected_entry_bound_refuses(self):
        self.bodies['first']=fixtures.elf([(b'.debug_str',1,0,b'synthetic\x00')]);self.save()
        with patch.object(check,'MAX_ENTRY_BYTES',8):self.refuses()

    def test_duplicate_pool_names_refuse_even_with_an_empty_duplicate(self):
        for name in check.POOLS:
            self.bodies['first']=fixtures.elf([(name,1,0,b''),(name,1,0,b'synthetic\x00')]);self.save();self.refuses()

    def test_selected_non_file_backed_or_wrong_section_types_refuse(self):
        for kind in (0,3,8):
            self.bodies['first']=fixtures.elf([(b'.debug_str',kind,0,b'synthetic\x00')]);self.save();self.refuses()

    def test_selected_compression_flags_and_spellings_refuse(self):
        for name,flags in ((b'.debug_str',0x800),(b'.debug_line_str',0x800),(b'.zdebug_str',0),(b'.zdebug_line_str',0)):
            self.bodies['first']=fixtures.elf([(name,1,flags,b'synthetic\x00')]);self.save();self.refuses()

    def test_raw_pool_match_across_internal_zero_is_not_a_terminated_entry_match(self):
        needle=b'synthetic\x00split';self.selected['first'][check.scanner.ROLES[0]]=needle
        self.bodies['first']=fixtures.elf([(b'.debug_str',1,0,needle+b'\x00')]);self.save()
        self.assertEqual(self.present(self.row()),[check.GROUPS[0]])

    def test_pool_complement_boundary_matches_remain_complete(self):
        self.selected['first'][check.scanner.ROLES[0]]=b'boundary\x00synthetic'
        self.bodies['first']=fixtures.elf([(b'.debug_str',1,0,b'boundary\x00')],tail=b'synthetic');self.save()
        self.assertEqual(self.present(self.row()),[check.GROUPS[9]])

    def test_adjacent_selected_pool_boundary_is_reported_without_raw_containment(self):
        self.selected['first'][check.scanner.ROLES[0]]=b'boundary\x00synthetic'
        self.bodies['first']=fixtures.elf([(b'.debug_str',1,0,b'boundary\x00'),(b'.debug_line_str',1,0,b'synthetic\x00')]);self.save()
        self.assertEqual(self.present(self.row()),[check.GROUPS[9]])

    def test_exact_region_boundary_containment_is_not_crossing(self):
        needle=self.selected['first'][check.scanner.ROLES[0]]+b'\x00';self.selected['first'][check.scanner.ROLES[0]]=needle
        self.bodies['first']=fixtures.elf([(b'.debug_str',1,0,needle)]);self.save()
        self.assertEqual(self.present(self.row()),[check.GROUPS[0]])
        self.bodies['first']=fixtures.elf([(b'.debug_str',1,0,b'\x00')],tail=needle);self.save()
        self.assertEqual(self.present(self.row()),[check.GROUPS[8]])

    def test_exact_macho_source_included_source_and_other_types_are_separate(self):
        needle=self.selected['second'][check.scanner.ROLES[0]]
        for flags,group in ((0x64,5),(0x84,6),(0x66,7),(0x65,7),(0x85,7),(0x0e,7),(0xff,7)):
            self.bodies['second']=symbol_fixtures.macho(b' '+needle+b'\x00',[(1,flags)]);self.save()
            self.assertEqual(self.present(self.row('second')),[check.GROUPS[4],check.GROUPS[group]])

    def test_macho_zero_index_has_no_name_even_with_nonzero_first_table_byte(self):
        needle=self.selected['second'][check.scanner.ROLES[0]]
        self.bodies['second']=symbol_fixtures.macho(needle+b'\x00',[(0,0x64),(0,0x84)]);self.save()
        self.assertEqual(self.present(self.row('second')),[check.GROUPS[4]])

    def test_macho_interior_suffixes_and_repeated_cross_class_references(self):
        needle=self.selected['second'][check.scanner.ROLES[0]]
        self.bodies['second']=symbol_fixtures.macho(b' prefix'+needle+b'\x00',[(7,0x64),(7,0x64),(7,0x84),(7,0x66)]);self.save()
        self.assertEqual(self.present(self.row('second')),list(check.GROUPS[4:8]))

    def test_reference_start_after_match_cannot_claim_that_complete_match(self):
        needle=self.selected['second'][check.scanner.ROLES[0]]
        self.bodies['second']=symbol_fixtures.macho(b' '+needle+b'\x00',[(2,0x64)]);self.save()
        self.assertEqual(self.present(self.row('second')),[check.GROUPS[4]])

    def test_unreferenced_macho_table_matches_supply_no_source_reference(self):
        needle=self.selected['second'][check.scanner.ROLES[0]]
        self.bodies['second']=symbol_fixtures.macho(b' '+needle+b'\x00');self.save()
        self.assertEqual(self.present(self.row('second')),[check.GROUPS[4]])

    def test_macho_raw_internal_zero_matches_are_not_reference_matches(self):
        needle=b'synthetic\x00split';self.selected['second'][check.scanner.ROLES[0]]=needle
        self.bodies['second']=symbol_fixtures.macho(b' '+needle+b'\x00',[(1,0x64),(11,0x84)]);self.save()
        self.assertEqual(self.present(self.row('second')),[check.GROUPS[4]])

    def test_macho_section_descriptor_and_value_fields_remain_uninterpreted(self):
        raw=self.bodies['second'];offset=struct.unpack_from('<I',raw,112)[0]
        earlier=self.row('second',check.scanner.ROLES[2])
        for at,fmt,value in ((5,'B',255),(6,'H',65535),(8,'Q',2**64-1)):
            self.bodies['second']=fixtures.replace(raw,offset+at,fmt,value);self.save()
            self.assertEqual(self.row('second',check.scanner.ROLES[2]),earlier)

    def test_preceding_symbol_grammar_refuses_before_new_region_selection(self):
        raw=symbol_fixtures.elf();self.bodies['first']=fixtures.replace(raw,256+56,'Q',16);self.save()
        with patch.object(check,'_regions',side_effect=AssertionError('must refuse first')):self.refuses()

    def test_whole_measurements_and_reference_implications_match_previous_readers(self):
        report=self.inspect();args=[]
        for n in check.scanner.SELECTIONS:args.extend((self.paths[n],digest(self.bodies[n]),len(self.bodies[n])))
        section=check.sections.inspect(*args,self.selected);symbol=check.symbols.inspect(*args,self.selected)
        for n,row in report['artifacts'].items():
            self.assertEqual(row['measured'],section['artifacts'][n]['measured']);self.assertEqual(row['measured'],symbol['artifacts'][n]['measured'])
            for role,groups in row['group_presence'].items():self.assertEqual(any(groups.values()),row['measured']['selected_prefix_presence'][role])

    def test_private_names_prefix_fingerprints_and_entry_positions_are_not_emitted(self):
        raw=check.scanner.encoded(self.inspect()).decode('ascii')
        for values in self.selected.values():
            for value in values.values():
                for forbidden in (value.decode('ascii'),value.hex(),digest(value)):self.assertNotIn(forbidden,raw)
        for forbidden in (str(self.root),'.debug_str','.debug_line_str','entry_count','reference_count','offset','timestamp','prefix_length'):self.assertNotIn(forbidden,raw)

    def test_equal_copied_names_and_types_remain_private_unattested(self):
        self.bodies['first']=self.bodies['second'];self.save();report=self.inspect()
        self.assertEqual(report['byte_relation'],'MATCH');self.assertEqual(report['producer_attribution'],'NOT DETERMINED')
        self.assertEqual(report['artifact_publication'],'KEEP BOTH ARTIFACTS PRIVATE')
        self.assertEqual(report['source_to_worker'],report['reproducibility']);self.assertEqual(report['reproducibility'],'NOT VERIFIED')
        self.assertEqual(report['application_and_core'],'NO-GO')

    def test_bad_complete_pins_sizes_and_role_aliases_refuse_before_parsing(self):
        for changes in ({'first_sha256':'0'*64},{'first_bytes':True},{'first_bytes':check.sections.MAX_BYTES+1},{'prefixes':{}}):
            with patch.object(check,'_localize',side_effect=AssertionError('must refuse first')):self.refuses(**changes)

    def test_symlink_inode_alias_and_foreign_owner_refuse(self):
        linked=self.root/'linked';linked.symlink_to(self.paths['first']);self.refuses(first=linked)
        self.refuses(second=self.paths['first'],second_sha256=digest(self.bodies['first']),second_bytes=len(self.bodies['first']))
        with patch.object(check.os,'geteuid',return_value=os.geteuid()+1):self.refuses()

    def test_named_replacement_during_read_refuses_when_stability_guard_closes(self):
        original=check._localize
        def changed(raw,prefixes):
            value=original(raw,prefixes);replacement=self.root/'replacement';replacement.write_bytes(self.bodies['first']);os.replace(replacement,self.paths['first']);return value
        with patch.object(check,'_localize',side_effect=changed):self.refuses()

    def test_errors_sanitize_and_cancellation_propagates_with_closed_guards(self):
        for error in (OSError('private detail'),ValueError('private detail'),RuntimeError('private detail'),struct.error('private detail')):
            with patch.object(check,'_localize',side_effect=error):self.refuses()
        for error in (KeyboardInterrupt,SystemExit):
            with patch.object(check,'_localize',side_effect=error):
                with self.assertRaises(error):self.inspect()
        self.inspect()

    def test_real_reader_cli_returns_exact_fixed_json_and_sanitized_unknown_option(self):
        selection=self.root/'selection';selection.write_bytes(check.scanner.encoded(dict(schema=check.scanner.SCHEMA,**{
            n:{role:value.hex() for role,value in values.items()} for n,values in self.selected.items()})));selection.chmod(0o600)
        command=[sys.executable,'-B','scripts/check_worker_debug_names.py','--private-prefixes',str(selection)]
        for n in check.scanner.SELECTIONS:command.extend(('--'+n,str(self.paths[n]),'--expect-'+n+'-sha256',digest(self.bodies[n]),'--expect-'+n+'-bytes',str(len(self.bodies[n]))))
        result=subprocess.run(command,capture_output=True,check=False);self.assertEqual(result.returncode,0);self.assertEqual(result.stderr,b'');self.assertEqual(json.loads(result.stdout),self.inspect())
        result=subprocess.run(command+['--unselected-option',str(self.root)],capture_output=True,check=False)
        self.assertEqual(result.returncode,1);self.assertEqual(result.stdout,b'');self.assertNotIn(str(self.root).encode(),result.stderr)


class WorkerDebugNameCarrierTests(unittest.TestCase):
    def setUp(self):
        self.driver=fixtures.WorkerSectionCarrierTests();self.driver.setUp();self.addCleanup(self.driver.doCleanups)
        for n in check.scanner.SELECTIONS:
            needle=self.driver.selected[n][check.scanner.ROLES[2]];raw=symbol_fixtures.macho(b' '+needle+b'\x00',[(1,0x64)])
            self.driver.worker(n).write_bytes(raw);self.driver.raw[n]=raw
            self.driver.claim['builds'][n]['measured_inputs']['original-response-worker'].update(bytes=len(raw),selected_sha256=digest(raw),measured_sha256=digest(raw))
        args=[]
        for n in check.scanner.SELECTIONS:args.extend((self.driver.worker(n),digest(self.driver.raw[n]),len(self.driver.raw[n])))
        self.driver.claim['comparison']=check.scanner.inspect(*args,self.driver.selected);self.driver.save()

    def qualify(self):
        d=self.driver;return companion.qualify(d.root,d.pairs,d.home,d.platform,d.carrier)

    def refuses(self):
        with self.assertRaises(check.InputError) as caught:self.qualify()
        self.assertEqual(str(caught.exception),companion.REFUSAL)

    def test_real_carrier_revalidates_sections_and_two_debug_name_streams(self):
        report=self.qualify()
        for n in check.scanner.SELECTIONS:
            self.assertEqual(report['artifacts'][n]['measured'],self.driver.claim['comparison']['artifacts'][n])
            self.assertTrue(report['artifacts'][n]['group_presence'][check.scanner.ROLES[2]][check.GROUPS[5]])
        self.assertIn('SEPARATE READS',report['section_agreement']);self.assertIn('IN MEMORY',report['symbol_agreement'])

    def test_invalid_preceding_carrier_refuses_before_new_name_read(self):
        self.driver.claim['selected_profile']['target_scope']='synthetic altered';self.driver.save()
        with patch.object(check,'inspect',side_effect=AssertionError('must refuse first')):self.refuses()

    def test_changed_file_between_acquisitions_refuses_without_repair(self):
        original=companion.previous.qualify
        def changed(*args):
            value=original(*args);path=self.driver.worker('first');path.write_bytes(path.read_bytes()+b'changed');return value
        with patch.object(companion.previous,'qualify',side_effect=changed):self.refuses()
        self.assertTrue(self.driver.worker('first').read_bytes().endswith(b'changed'))

    def test_complete_row_format_and_byte_disagreement_each_refuse(self):
        original=check.inspect
        for field in ('row','format','relation'):
            def changed(*args):
                report=original(*args)
                if field=='row':report['artifacts']['first']['measured']['bytes']+=1
                elif field=='format':report['artifacts']['first']['format']='synthetic changed'
                else:report['byte_relation']='DIFFER'
                return report
            with patch.object(check,'inspect',side_effect=changed):self.refuses()

    def test_matching_caller_claim_and_copied_names_supply_no_source_identity(self):
        self.driver.claim['uninterpreted_claim']='synthetic claimed producer';self.driver.save();report=self.qualify()
        self.assertEqual(report['byte_relation'],'MATCH');self.assertEqual(report['producer_attribution'],'NOT DETERMINED');self.assertEqual(report['source_to_worker'],'NOT VERIFIED')
        self.assertNotIn('synthetic claimed producer',check.scanner.encoded(report).decode('ascii'))

    def test_no_private_name_carrier_fingerprint_or_native_launch_escapes(self):
        with patch.object(subprocess,'run',side_effect=AssertionError('no worker belongs in qualify')):raw=check.scanner.encoded(self.qualify()).decode('ascii')
        for values in self.driver.selected.values():
            for value in values.values():
                for forbidden in (value.decode('ascii'),value.hex(),digest(value)):self.assertNotIn(forbidden,raw)
        self.assertNotIn(digest(self.driver.carrier.read_bytes()),raw)

    def test_failures_sanitize_and_cancellation_propagates_in_both_phases(self):
        for module,method in ((companion.previous,'qualify'),(check,'inspect')):
            with patch.object(module,method,side_effect=RuntimeError('private details')):self.refuses()
            for error in (KeyboardInterrupt,SystemExit):
                with patch.object(module,method,side_effect=error):
                    with self.assertRaises(error):self.qualify()

    def test_real_companion_cli_returns_exact_observation_and_private_refusal(self):
        d=self.driver;command=[sys.executable,'-B','scripts/qualify_worker_debug_names.py','--root',str(d.root),'--cargo-home',str(d.home),'--platform',d.platform,'--private-pair-report',str(d.carrier)]
        for n in check.scanner.SELECTIONS:command.extend(('--'+n+'-workspace',str(d.pairs[n][0]),'--'+n+'-build-directory',str(d.pairs[n][1])))
        result=subprocess.run(command,capture_output=True,check=False);self.assertEqual(result.returncode,0);self.assertEqual(result.stderr,b'')
        report,end=json.JSONDecoder().raw_decode(result.stdout.decode('ascii'));self.assertEqual(report,self.qualify());self.assertIn('PASS: bounded retained worker debug names',result.stdout.decode('ascii')[end:]);self.assertNotIn(str(d.root).encode(),result.stdout)
        result=subprocess.run(command+['--unselected-option',str(d.root)],capture_output=True,check=False)
        self.assertEqual(result.returncode,1);self.assertEqual(result.stdout,b'');self.assertNotIn(str(d.root).encode(),result.stderr)
