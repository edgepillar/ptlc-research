"""Synthetic symbol references, private output and separate carrier acquisitions."""

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

from scripts import check_worker_symbols as check
from scripts import qualify_worker_symbols as companion
import test_worker_sections as fixtures


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def elf(strings=b'\x00\x00', references=(), kind=2, second=None):
    cells = b'\x00'*24+b''.join(struct.pack('<IBBHQQ', index, info, 0, 0, 0, 0)
                                 for index, info in references)
    entries = [(b'.strings', 3, strings, 0, 0), (b'.symbols', kind, cells, 2, 24)]
    if second is not None:
        entries.append((b'.strings_second', 3, second, 0, 0))
        entries.append((b'.symbols_second', 2, b'\x00'*24, 4, 24))
    names, indexes = b'\x00.shstrtab\x00', []
    for name, _, _, _, _ in entries:
        indexes.append(len(names)); names += name+b'\x00'
    count = len(entries)+2
    position = 64+count*64
    rows = [(0,)*10, (1, 3, 0, 0, position, len(names), 0, 0, 1, 0)]
    payload, position = names, position+len(names)
    for name_at, (_, entry_kind, body, link, size) in zip(indexes, entries):
        rows.append((name_at, entry_kind, 0, 0, position, len(body), link, 0, 1, size))
        payload += body; position += len(body)
    header = b'\x7fELF\x02\x01\x01'+b'\x00'*9
    header += struct.pack('<HHIQQQIHHHHHH', 2, 62, 1, 0, 0, 64, 0, 64, 0, 0, 64, count, 1)
    return header+b''.join(struct.pack('<IIQQQQIIQQ', *row) for row in rows)+payload


def macho(strings=b'\x00', references=(), tail=b''):
    cells = b''.join(struct.pack('<IBBHQ', index, flags, 0, 0, 0) for index, flags in references)
    return fixtures.macho(strings=strings, symbols=cells, tail=tail)


class WorkerSymbolTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(); self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.paths = {name:self.root/name for name in check.scanner.SELECTIONS}
        self.selected = fixtures.prefixes()
        self.bodies = {'first':elf(b'\x00'+self.selected['first'][check.scanner.ROLES[0]]+b'\x00', [(1,4)]),
                       'second':macho(b' '+self.selected['second'][check.scanner.ROLES[2]]+b'\x00', [(1,0x66)])}
        self.save()

    def save(self):
        for name in check.scanner.SELECTIONS:self.paths[name].write_bytes(self.bodies[name])

    def inspect(self, **changes):
        values = dict(first=self.paths['first'],first_sha256=digest(self.bodies['first']),first_bytes=len(self.bodies['first']),
                      second=self.paths['second'],second_sha256=digest(self.bodies['second']),second_bytes=len(self.bodies['second']),prefixes=self.selected)
        values.update(changes); return check.inspect(**values)

    def refuses(self, **changes):
        with self.assertRaises(check.InputError) as caught:self.inspect(**changes)
        self.assertEqual(str(caught.exception),check.REFUSAL)

    def test_elf_file_and_macho_object_names_have_fixed_reference_classes(self):
        report=self.inspect()
        for name,role,group in (('first',check.scanner.ROLES[0],check.GROUPS[1]),('second',check.scanner.ROLES[2],check.GROUPS[3])):
            row=report['artifacts'][name]
            self.assertEqual(set(row),{'measured','format','group_presence'})
            self.assertEqual([g for g,v in row['group_presence'][role].items() if v],[check.GROUPS[0],group])
            self.assertEqual(row['measured']['sha256'],digest(self.bodies[name]))

    def test_elf_other_types_and_dynamic_table_use_only_name_type_declarations(self):
        needle=self.selected['first'][check.scanner.ROLES[0]]
        for kind in (2,11):
            for info in (0,2,0x14,0xf4,0x12):
                self.bodies['first']=elf(b'\x00'+needle+b'\x00',[(1,info)],kind);self.save()
                row=self.inspect()['artifacts']['first']['group_presence'][check.scanner.ROLES[0]]
                self.assertTrue(row[check.GROUPS[1] if info & 15 == 4 else check.GROUPS[2]])

    def test_macho_exact_object_other_stab_and_non_stab_types_are_separate(self):
        needle=self.selected['second'][check.scanner.ROLES[0]]
        for flags,group in ((0x66,3),(0x64,4),(0x20,4),(0xfe,4),(0x67,4),(0,5),(0x0e,5),(0x1f,5)):
            self.bodies['second']=macho(b' '+needle+b'\x00',[(1,flags)]);self.save()
            row=self.inspect()['artifacts']['second']['group_presence'][check.scanner.ROLES[0]]
            self.assertEqual([g for g,v in row.items() if v],[check.GROUPS[0],check.GROUPS[group]])

    def test_zero_name_indices_ignore_nonempty_tables_and_macho_first_byte(self):
        for name in check.scanner.SELECTIONS:
            needle=self.selected[name][check.scanner.ROLES[0]]
            self.bodies[name]=elf(b'\x00'+needle+b'\x00',[(0,4)]) if name=='first' else macho(needle+b'\x00',[(0,0x66)])
        self.save();report=self.inspect()
        for name in check.scanner.SELECTIONS:
            row=report['artifacts'][name]['group_presence'][check.scanner.ROLES[0]]
            self.assertEqual([g for g,v in row.items() if v],[check.GROUPS[0]])

    def test_interior_suffix_indices_and_repeated_cross_class_references(self):
        needle=self.selected['second'][check.scanner.ROLES[0]]
        self.bodies['second']=macho(b' prefix'+needle+b'\x00',[(7,0x66),(7,0x66),(7,0x64),(7,0x0e)])
        self.save();row=self.inspect()['artifacts']['second']['group_presence'][check.scanner.ROLES[0]]
        self.assertEqual([g for g,v in row.items() if v],[check.GROUPS[0],*check.GROUPS[3:6]])

    def test_reference_beginning_after_match_cannot_claim_that_complete_match(self):
        needle=self.selected['first'][check.scanner.ROLES[0]]
        self.bodies['first']=elf(b'\x00'+needle+b'\x00',[(2,4)]);self.save()
        row=self.inspect()['artifacts']['first']['group_presence'][check.scanner.ROLES[0]]
        self.assertTrue(row[check.GROUPS[0]]);self.assertFalse(row[check.GROUPS[1]])

    def test_complete_raw_matches_across_internal_zero_are_not_name_matches(self):
        role=check.scanner.ROLES[0];needle=b'synthetic\x00split'
        self.selected['first'][role]=needle
        self.bodies['first']=elf(b'\x00'+needle+b'\x00',[(1,4),(11,2)]);self.save()
        row=self.inspect()['artifacts']['first']['group_presence'][role]
        self.assertEqual([g for g,v in row.items() if v],[check.GROUPS[0]])

    def test_unreferenced_raw_matches_do_not_require_symbol_authority(self):
        needle=self.selected['first'][check.scanner.ROLES[0]]
        self.bodies['first']=elf(b'\x00'+needle+b'\x00');self.save()
        row=self.inspect()['artifacts']['first']['group_presence'][check.scanner.ROLES[0]]
        self.assertEqual([g for g,v in row.items() if v],[check.GROUPS[0]])

    def test_absent_and_empty_symbol_selections_leave_complete_complement(self):
        self.bodies['first']=fixtures.elf(tail=self.selected['first'][check.scanner.ROLES[0]])
        self.bodies['second']=fixtures.macho(tail=self.selected['second'][check.scanner.ROLES[0]])
        self.save();report=self.inspect()
        for name in check.scanner.SELECTIONS:
            self.assertTrue(report['artifacts'][name]['group_presence'][check.scanner.ROLES[0]][check.GROUPS[6]])

    def test_all_table_boundary_splits_are_observed_without_reference_claim(self):
        role=check.scanner.ROLES[0];needle=self.selected['second'][role]
        for split in range(1,len(needle)):
            self.bodies['second']=macho(b' '+needle[:split],tail=needle[split:]);self.save()
            row=self.inspect()['artifacts']['second']['group_presence'][role]
            self.assertEqual([g for g,v in row.items() if v],[check.GROUPS[7]])

    def test_exact_table_boundary_containment_is_not_crossing(self):
        role=check.scanner.ROLES[0];needle=self.selected['second'][role]
        for strings,tail in ((needle,b'synthetic tail'),(b' ',needle)):
            self.bodies['second']=macho(strings,tail=tail);self.save()
            self.assertFalse(self.inspect()['artifacts']['second']['group_presence'][role][check.GROUPS[7]])

    def test_raw_reference_union_agrees_with_both_existing_readers(self):
        report=self.inspect();arguments=[]
        for name in check.scanner.SELECTIONS:arguments.extend((self.paths[name],digest(self.bodies[name]),len(self.bodies[name])))
        old=check.sections.inspect(*arguments,self.selected)
        for name in check.scanner.SELECTIONS:
            row=report['artifacts'][name]
            self.assertEqual(row['measured'],old['artifacts'][name]['measured'])
            for role,groups in row['group_presence'].items():
                self.assertEqual(any(groups.values()),row['measured']['selected_prefix_presence'][role])
                self.assertFalse(groups[check.GROUPS[0]] and not old['artifacts'][name]['group_presence'][role][check.sections.GROUPS[1]])

    def test_private_names_values_indices_and_fingerprints_are_never_reported(self):
        raw=check.scanner.encoded(self.inspect()).decode('ascii')
        for values in self.selected.values():
            for value in values.values():
                for forbidden in (value.decode('ascii'),value.hex(),digest(value)):self.assertNotIn(forbidden,raw)
        for forbidden in (str(self.root),'.symbols','.strings','index','reference_count','offset','timestamp','prefix_length'):
            self.assertNotIn(forbidden,raw)

    def test_equal_copies_and_arbitrary_symbol_values_remain_private_unattested(self):
        raw=self.bodies['second'];self.bodies['first']=self.bodies['second']=raw;self.save()
        report=self.inspect();self.assertEqual(report['byte_relation'],'MATCH')
        self.assertEqual(report['producer_attribution'],'NOT DETERMINED')
        self.assertEqual(report['artifact_publication'],'KEEP BOTH ARTIFACTS PRIVATE')
        self.assertEqual(report['source_to_worker'],report['reproducibility']);self.assertEqual(report['reproducibility'],'NOT VERIFIED')
        self.assertEqual(report['application_and_core'],'NO-GO')

    def test_elf_bad_record_width_divisibility_and_link_bounds_refuse(self):
        original=self.bodies['first']
        for offset,fmt,value in ((256+56,'Q',16),(256+32,'Q',47),(256+40,'I',0),(256+40,'I',0xffffffff),(256+40,'I',3)):
            self.bodies['first']=fixtures.replace(original,offset,fmt,value);self.save();self.refuses()

    def test_elf_null_first_record_must_be_exactly_zero(self):
        original=self.bodies['first'];start=struct.unpack_from('<Q',original,256+24)[0]
        for offset in (0,4,5,6,8,16):
            self.bodies['first']=fixtures.replace(original,start+offset,'B',1);self.save();self.refuses()

    def test_elf_compressed_symbol_and_string_declarations_refuse(self):
        original=self.bodies['first']
        for offset in (192+8,256+8):
            self.bodies['first']=fixtures.replace(original,offset,'Q',0x800);self.save();self.refuses()

    def test_elf_linked_string_table_type_initial_final_and_empty_refuse(self):
        original=self.bodies['first'];start,size=struct.unpack_from('<QQ',original,192+24)
        for raw in (fixtures.replace(original,192+4,'I',1),fixtures.replace(original,start,'B',1),
                    fixtures.replace(original,start+size-1,'B',1),fixtures.replace(original,192+32,'Q',0)):
            self.bodies['first']=raw;self.save();self.refuses()

    def test_each_format_nonzero_name_indices_must_fit_table(self):
        original=deepcopy(self.bodies)
        for name in check.scanner.SELECTIONS:
            raw=original[name]
            if name=='first':
                start=struct.unpack_from('<Q',raw,256+24)[0]+24;amount=struct.unpack_from('<Q',raw,192+32)[0]
            else:start=128;amount=struct.unpack_from('<I',raw,124)[0]
            for index in (amount,0xffffffff):
                self.bodies=deepcopy(original);self.bodies[name]=fixtures.replace(raw,start,'I',index);self.save();self.refuses()

    def test_each_format_nonzero_names_require_termination_inside_table(self):
        for name in check.scanner.SELECTIONS:
            raw=self.bodies[name]
            if name=='first':start,amount=struct.unpack_from('<QQ',raw,192+24)
            else:start,amount=struct.unpack_from('<II',raw,120)
            self.bodies[name]=fixtures.replace(raw,start+amount-1,'B',88)
            self.save();self.refuses();self.bodies[name]=raw

    def test_exact_name_length_limit_passes_and_next_byte_refuses(self):
        needle=self.selected['first'][check.scanner.ROLES[0]]
        for size,positive in ((check.MAX_NAME_BYTES,True),(check.MAX_NAME_BYTES+1,False)):
            self.bodies['first']=elf(b'\x00'+needle+b'X'*(size-len(needle))+b'\x00',[(1,4)]);self.save()
            if positive:self.assertTrue(self.inspect()['artifacts']['first']['group_presence'][check.scanner.ROLES[0]][check.GROUPS[1]])
            else:self.refuses()

    def test_symbol_limit_counts_all_records_including_empty_names(self):
        with patch.object(check,'MAX_SYMBOLS',2):self.inspect()
        with patch.object(check,'MAX_SYMBOLS',1):self.refuses()

    def test_distinct_string_table_limit_counts_shared_tables_once(self):
        self.bodies['first']=elf(second=b'\x00shared\x00');self.bodies['second']=macho();self.save()
        with patch.object(check,'MAX_STRING_BYTES',10):self.inspect()
        with patch.object(check,'MAX_STRING_BYTES',9):self.refuses()
        self.bodies['first']=fixtures.replace(self.bodies['first'],384+40,'I',2);self.save()
        with patch.object(check,'MAX_STRING_BYTES',2):self.inspect()
        with patch.object(check,'MAX_STRING_BYTES',1):self.refuses()

    def test_arbitrary_uninterpreted_values_do_not_change_reference_classes(self):
        earlier=self.inspect()['artifacts']['second']['group_presence']
        raw=self.bodies['second']
        for value in (1,2**64-1):
            self.bodies['second']=fixtures.replace(raw,128+8,'Q',value);self.save()
            self.assertEqual(self.inspect()['artifacts']['second']['group_presence'],earlier)

    def test_bad_complete_pins_and_role_aliases_refuse_before_parsing(self):
        for changes in ({'first_sha256':'0'*64},{'first_bytes':True},{'first_bytes':check.sections.MAX_BYTES+1},{'prefixes':{}}):
            with patch.object(check,'_localize',side_effect=AssertionError('must refuse first')):self.refuses(**changes)

    def test_symlink_inode_alias_and_foreign_owner_refuse(self):
        linked=self.root/'linked';linked.symlink_to(self.paths['first']);self.refuses(first=linked)
        self.refuses(second=self.paths['first'],second_sha256=digest(self.bodies['first']),second_bytes=len(self.bodies['first']))
        with patch.object(check.os,'geteuid',return_value=os.geteuid()+1):self.refuses()

    def test_named_replacement_after_descriptor_read_refuses_on_guard_close(self):
        original=check._localize
        def changed(raw,prefix):
            value=original(raw,prefix);replacement=self.root/'replacement';replacement.write_bytes(self.bodies['first']);os.replace(replacement,self.paths['first']);return value
        with patch.object(check,'_localize',side_effect=changed):self.refuses()

    def test_parser_errors_are_sanitized_and_cancellation_closes_guards(self):
        for error in (OSError('private detail'),ValueError('private detail'),RuntimeError('private detail'),struct.error('private detail')):
            with patch.object(check,'_localize',side_effect=error):self.refuses()
        for error in (KeyboardInterrupt,SystemExit):
            with patch.object(check,'_localize',side_effect=error):
                with self.assertRaises(error):self.inspect()
        self.inspect()

    def test_real_reader_cli_emits_exact_fixed_report_and_sanitized_refusal(self):
        selected=self.root/'selection';selected.write_bytes(check.scanner.encoded(dict(schema=check.scanner.SCHEMA,**{
            name:{role:value.hex() for role,value in row.items()} for name,row in self.selected.items()})));selected.chmod(0o600)
        command=[sys.executable,'-B','scripts/check_worker_symbols.py','--private-prefixes',str(selected)]
        for name in check.scanner.SELECTIONS:
            command.extend(('--'+name,str(self.paths[name]),'--expect-'+name+'-sha256',digest(self.bodies[name]),'--expect-'+name+'-bytes',str(len(self.bodies[name]))))
        result=subprocess.run(command,capture_output=True,check=False);self.assertEqual(result.returncode,0);self.assertEqual(result.stderr,b'')
        self.assertEqual(json.loads(result.stdout),self.inspect())
        result=subprocess.run(command+['--private-unrecognized',str(self.root)],capture_output=True,check=False)
        self.assertEqual(result.returncode,1);self.assertEqual(result.stdout,b'');self.assertNotIn(str(self.root).encode(),result.stderr)


class WorkerSymbolCarrierTests(unittest.TestCase):
    def setUp(self):
        self.driver=fixtures.WorkerSectionCarrierTests();self.driver.setUp();self.addCleanup(self.driver.doCleanups)
        for name in check.scanner.SELECTIONS:
            needle=self.driver.selected[name][check.scanner.ROLES[2]]
            raw=macho(b' '+needle+b'\x00',[(1,0x66)])
            self.driver.worker(name).write_bytes(raw);self.driver.raw[name]=raw
            measured=self.driver.claim['builds'][name]['measured_inputs']['original-response-worker']
            measured.update(bytes=len(raw),selected_sha256=digest(raw),measured_sha256=digest(raw))
        arguments=[]
        for name in check.scanner.SELECTIONS:arguments.extend((self.driver.worker(name),digest(self.driver.raw[name]),len(self.driver.raw[name])))
        self.driver.claim['comparison']=check.scanner.inspect(*arguments,self.driver.selected);self.driver.save()

    def qualify(self):
        d=self.driver;return companion.qualify(d.root,d.pairs,d.home,d.platform,d.carrier)

    def refuses(self):
        with self.assertRaises(check.InputError) as caught:self.qualify()
        self.assertEqual(str(caught.exception),companion.REFUSAL)

    def test_real_carrier_revalidates_sections_and_two_symbol_streams(self):
        report=self.qualify()
        for name in check.scanner.SELECTIONS:
            self.assertEqual(report['artifacts'][name]['measured'],self.driver.claim['comparison']['artifacts'][name])
            self.assertTrue(report['artifacts'][name]['group_presence'][check.scanner.ROLES[2]][check.GROUPS[3]])
        self.assertIn('SEPARATE READS',report['section_agreement']);self.assertIn('NOT ATTESTED',report['carrier_binding'])

    def test_invalid_preceding_carrier_refuses_before_new_symbol_read(self):
        self.driver.claim['selected_profile']['target_scope']='synthetic changed scope';self.driver.save()
        with patch.object(check,'inspect',side_effect=AssertionError('must refuse before new reads')):self.refuses()

    def test_changed_file_between_acquisitions_refuses_without_repair(self):
        original=companion.previous.qualify
        def changed(*args):
            report=original(*args);path=self.driver.worker('first');path.write_bytes(path.read_bytes()+b'changed');return report
        with patch.object(companion.previous,'qualify',side_effect=changed):self.refuses()
        self.assertTrue(self.driver.worker('first').read_bytes().endswith(b'changed'))

    def test_complete_row_format_and_byte_disagreement_each_refuse(self):
        original=check.inspect
        for field in ('row','format','relation'):
            def changed(*args):
                report=original(*args)
                if field=='row':report['artifacts']['first']['measured']['bytes']+=1
                elif field=='format':report['artifacts']['first']['format']='synthetic alternate format'
                else:report['byte_relation']='DIFFER'
                return report
            with patch.object(check,'inspect',side_effect=changed):self.refuses()

    def test_matching_caller_carrier_and_copies_supply_no_source_identity(self):
        self.driver.claim['uninterpreted_claim']='synthetic self-selected producer';self.driver.save()
        report=self.qualify();self.assertEqual(report['byte_relation'],'MATCH')
        self.assertEqual(report['producer_attribution'],'NOT DETERMINED');self.assertEqual(report['source_to_worker'],'NOT VERIFIED')
        self.assertNotIn('synthetic self-selected producer',check.scanner.encoded(report).decode('ascii'))

    def test_no_private_name_path_carrier_fingerprint_or_native_launch_escape(self):
        with patch.object(subprocess,'run',side_effect=AssertionError('no process belongs in qualify')):
            raw=check.scanner.encoded(self.qualify()).decode('ascii')
        for rows in self.driver.selected.values():
            for value in rows.values():
                for forbidden in (value.decode('ascii'),value.hex(),digest(value)):self.assertNotIn(forbidden,raw)
        self.assertNotIn(digest(self.driver.carrier.read_bytes()),raw)

    def test_failures_sanitize_and_cancellation_propagates_in_both_phases(self):
        for module,method in ((companion.previous,'qualify'),(check,'inspect')):
            with patch.object(module,method,side_effect=RuntimeError('private details')):self.refuses()
            for error in (KeyboardInterrupt,SystemExit):
                with patch.object(module,method,side_effect=error):
                    with self.assertRaises(error):self.qualify()

    def test_real_companion_cli_returns_exact_observation_and_no_private_stdout(self):
        d=self.driver;command=[sys.executable,'-B','scripts/qualify_worker_symbols.py','--root',str(d.root),
            '--cargo-home',str(d.home),'--platform',d.platform,'--private-pair-report',str(d.carrier)]
        for name in check.scanner.SELECTIONS:command.extend(('--'+name+'-workspace',str(d.pairs[name][0]),'--'+name+'-build-directory',str(d.pairs[name][1])))
        result=subprocess.run(command,capture_output=True,check=False);self.assertEqual(result.returncode,0);self.assertEqual(result.stderr,b'')
        report,end=json.JSONDecoder().raw_decode(result.stdout.decode('ascii'));self.assertEqual(report,self.qualify())
        self.assertIn('PASS: bounded retained worker symbol references',result.stdout.decode('ascii')[end:]);self.assertNotIn(str(d.root).encode(),result.stdout)
        result=subprocess.run(command+['--unselected-option',str(d.root)],capture_output=True,check=False)
        self.assertEqual(result.returncode,1);self.assertEqual(result.stdout,b'');self.assertNotIn(str(d.root).encode(),result.stderr)
