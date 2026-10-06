"""Synthetic raw range localization and carrier controls; no producer authority."""

from copy import deepcopy
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts import check_worker_sections as check
from scripts import qualify_worker_sections as companion


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def prefixes():
    return {name: {role: ('synthetic-'+name+'-'+role).encode('ascii') for role in check.scanner.ROLES}
            for name in check.scanner.SELECTIONS}


def elf(entries=(), tail=b''):
    names = b'\x00.shstrtab\x00'
    indexes = []
    for name, _, _, _ in entries:
        indexes.append(len(names)); names += name+b'\x00'
    count = len(entries)+2
    position = 64+64*count
    rows = [(0,)*10, (1, 3, 0, 0, position, len(names), 0, 0, 1, 0)]
    payload, position = names, position+len(names)
    for name_at, (_, kind, flags, body) in zip(indexes, entries):
        start = 2**50 if kind == 8 else position
        rows.append((name_at, kind, flags, 0, start, len(body), 0, 0, 1, 0))
        if kind != 8:
            payload += body; position += len(body)
    header = b'\x7fELF\x02\x01\x01'+b'\x00'*9
    header += struct.pack('<HHIQQQIHHHHHH', 2, 62, 1, 0, 0, 64, 0, 64, 0, 0, 64, count, 1)
    return header+b''.join(struct.pack('<IIQQQQIIQQ', *row) for row in rows)+payload+tail


def macho(entries=(), strings=b'', symbols=b'', extra=b'', tail=b''):
    segment_size = 72+80*len(entries)
    commands_size = segment_size+(24 if strings or symbols else 0)+len(extra)
    position = 32+commands_size
    payload, rows = b'', []
    for i, (flags, body) in enumerate(entries):
        zero = flags & 0xff in (1, 0xc, 0x12)
        rows.append(struct.pack('<16s16sQQIIIIIIII', ('synthetic'+str(i)).encode('ascii'),
                                b'synthetic-group', 0, len(body), 0 if zero else position,
                                0, 0, 0, flags, 0, 0, 0))
        if not zero:
            payload += body; position += len(body)
    segment = struct.pack('<II16sQQQQiiII', 0x19, segment_size, b'synthetic-group', 0, 0,
                          32+commands_size, len(payload), 0, 0, len(entries), 0)+b''.join(rows)
    sym = b''
    if strings or symbols:
        assert len(symbols) % 16 == 0
        sym = struct.pack('<6I', 2, 24, position, len(symbols)//16, position+len(symbols), len(strings))
    head = struct.pack('<8I', 0xfeedfacf, 0x0100000c, 0, 2,
                       1+bool(sym)+bool(extra), commands_size, 0, 0)
    return head+segment+sym+extra+payload+symbols+strings+tail


def replace(raw, offset, fmt, *values):
    changed = bytearray(raw)
    struct.pack_into(fmt, changed, offset, *values)
    return bytes(changed)


class WorkerSectionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.paths = {name: self.root/name for name in check.scanner.SELECTIONS}
        self.selected = prefixes()
        self.bodies = {
            'first': elf([(b'.debug_info', 1, 0, self.selected['first'][check.scanner.ROLES[0]])]),
            'second': macho([(0, self.selected['second'][check.scanner.ROLES[1]])])}
        self.save()

    def save(self):
        for name in check.scanner.SELECTIONS:
            self.paths[name].write_bytes(self.bodies[name])

    def inspect(self, **changes):
        arguments = dict(first=self.paths['first'], first_sha256=digest(self.bodies['first']),
                         first_bytes=len(self.bodies['first']), second=self.paths['second'],
                         second_sha256=digest(self.bodies['second']), second_bytes=len(self.bodies['second']),
                         prefixes=self.selected)
        arguments.update(changes)
        return check.inspect(**arguments)

    def refuses(self, **changes):
        with self.assertRaises(check.InputError) as caught:
            self.inspect(**changes)
        self.assertEqual(str(caught.exception), check.REFUSAL)

    def test_elf_and_macho_have_fixed_groups_bound_to_complete_streams(self):
        report = self.inspect()
        self.assertEqual(report['byte_relation'], 'DIFFER')
        for name, group, role in (('first', check.GROUPS[2], check.scanner.ROLES[0]),
                                  ('second', check.GROUPS[3], check.scanner.ROLES[1])):
            row = report['artifacts'][name]
            self.assertEqual(set(row), {'measured', 'format', 'group_presence'})
            self.assertEqual(row['measured']['sha256'], digest(self.bodies[name]))
            self.assertEqual(row['measured']['bytes'], len(self.bodies[name]))
            self.assertEqual(set(row['group_presence']), set(check.scanner.ROLES))
            self.assertEqual(row['group_presence'][role], {g:g==group for g in check.GROUPS})
            self.assertTrue(all(not any(v.values()) for r,v in row['group_presence'].items() if r != role))

    def test_elf_compressed_symbol_string_and_unknown_sections_are_declarations(self):
        needle = self.selected['first'][check.scanner.ROLES[0]]
        cases = [(b'.debug_info', 1, 0x800, check.GROUPS[0]), (b'.zdebug_info', 1, 0, check.GROUPS[0]),
                 (b'.strings', 3, 0, check.GROUPS[1]), (b'.symbols', 2, 0, check.GROUPS[1]),
                 (b'.dynsymbols', 11, 0, check.GROUPS[1]), (b'.private-label', 0x80000001, 0, check.GROUPS[3])]
        for name, kind, flags, group in cases:
            with self.subTest(group=group):
                self.bodies['first'] = elf([(name, kind, flags, needle)])
                self.save(); row = self.inspect()['artifacts']['first']
                self.assertEqual([g for g,v in row['group_presence'][check.scanner.ROLES[0]].items() if v], [group])
        self.assertEqual(self.inspect()['producer_attribution'], 'NOT DETERMINED')

    def test_macho_debug_attribute_and_symbol_string_ranges(self):
        needle = self.selected['second'][check.scanner.ROLES[0]]
        for raw, group in ((macho([(0x02000000, needle)]), check.GROUPS[2]),
                           (macho(strings=needle), check.GROUPS[1]),
                           (macho(symbols=(needle+b'\x00'*16)[:48]), check.GROUPS[1])):
            self.bodies['second'] = raw; self.save()
            self.assertTrue(self.inspect()['artifacts']['second']['group_presence'][check.scanner.ROLES[0]][group])

    def test_all_crossing_splits_and_same_group_adjacency_are_preserved(self):
        role = check.scanner.ROLES[0]
        needle = self.selected['first'][role]
        for split in range(1, len(needle)):
            for right_name in (b'.debug_right', b'.data_right'):
                self.bodies['first'] = elf([(b'.debug_left', 1, 0, needle[:split]),
                                             (right_name, 1, 0, needle[split:])])
                self.save(); found = self.inspect()['artifacts']['first']['group_presence'][role]
                self.assertEqual([g for g,v in found.items() if v], [check.GROUPS[5]])

    def test_exact_boundary_containment_is_not_crossing(self):
        role = check.scanner.ROLES[0];needle = self.selected['first'][role]
        for entries in ([(b'.debug_left',1,0,needle),(b'.right',1,0,b'abc')],
                        [(b'.left',1,0,b'abc'),(b'.debug_right',1,0,needle)]):
            self.bodies['first']=elf(entries);self.save()
            row=self.inspect()['artifacts']['first']['group_presence'][role]
            self.assertTrue(row[check.GROUPS[2]]);self.assertFalse(row[check.GROUPS[5]])

    def test_trailing_padding_and_uninterpreted_commands_are_outside(self):
        first_needle=self.selected['first'][check.scanner.ROLES[0]]
        self.bodies['first']=elf(tail=first_needle)
        needle=self.selected['second'][check.scanner.ROLES[1]]
        length=(8+len(needle)+7)//8*8
        extra=struct.pack('<II',0x80005555,length)+needle+b'\x00'*(length-8-len(needle))
        self.bodies['second']=macho(extra=extra);self.save()
        for name,role in (('first',check.scanner.ROLES[0]),('second',check.scanner.ROLES[1])):
            self.assertTrue(self.inspect()['artifacts'][name]['group_presence'][role][check.GROUPS[4]])

    def test_zero_fill_and_nobits_do_not_select_conceptual_file_bytes(self):
        needle=self.selected['first'][check.scanner.ROLES[0]]
        self.bodies['first']=elf([(b'.bss',8,0,needle)],tail=needle)
        for kind in (1,0xc,0x12):
            self.bodies['second']=macho([(kind,b'synthetic zero fill')],tail=self.selected['second'][check.scanner.ROLES[0]])
            self.save();report=self.inspect()
            self.assertTrue(report['artifacts']['first']['group_presence'][check.scanner.ROLES[0]][check.GROUPS[4]])
            self.assertTrue(report['artifacts']['second']['group_presence'][check.scanner.ROLES[0]][check.GROUPS[4]])

    def test_nested_and_repeated_prefixes_report_presence_only(self):
        self.selected['first']={role:b'q'*(8+i) for i,role in enumerate(check.scanner.ROLES)}
        self.bodies['first']=elf([(b'.debug_info',1,0,b'q'*20),(b'.data',1,0,b'q'*20)],tail=b'q'*20)
        self.save();row=self.inspect()['artifacts']['first']
        for role in check.scanner.ROLES:
            self.assertTrue(row['group_presence'][role][check.GROUPS[2]])
            self.assertTrue(row['group_presence'][role][check.GROUPS[3]])
            self.assertTrue(row['group_presence'][role][check.GROUPS[4]])
        self.assertNotIn('occurrence_count',check.scanner.encoded(row).decode('ascii'))

    def test_maximum_prefix_across_many_short_sections_is_not_lost(self):
        needle=b'Q'+b'r'*(check.scanner.MAX_PREFIX_BYTES-2)+b'S'
        self.selected['first'][check.scanner.ROLES[0]]=needle
        self.bodies['first']=elf([(b'.data',1,0,needle[i:i+31]) for i in range(0,len(needle),31)])
        self.save();found=self.inspect()['artifacts']['first']['group_presence'][check.scanner.ROLES[0]]
        self.assertEqual([g for g,v in found.items() if v],[check.GROUPS[5]])

    def test_group_union_equals_the_unchanged_scanner_for_both_artifacts(self):
        section=self.inspect()
        whole=check.scanner.inspect(self.paths['first'],digest(self.bodies['first']),len(self.bodies['first']),
                                   self.paths['second'],digest(self.bodies['second']),len(self.bodies['second']),self.selected)
        self.assertEqual(section['byte_relation'],whole['byte_relation'])
        for name in check.scanner.SELECTIONS:
            self.assertEqual(section['artifacts'][name]['measured'],whole['artifacts'][name])

    def test_no_private_labels_strings_offsets_context_or_selection_digest_escape(self):
        self.bodies['first']=elf([(b'private-section-label',1,0,self.selected['first'][check.scanner.ROLES[0]])])
        self.save();raw=check.scanner.encoded(self.inspect()).decode('ascii')
        for row in self.selected.values():
            for value in row.values():
                for forbidden in (value.decode('ascii'),value.hex(),digest(value)):
                    self.assertNotIn(forbidden,raw)
        for forbidden in (str(self.root),'private-section-label','synthetic-group','offset','occurrence_count','context','prefix_length'):
            self.assertNotIn(forbidden,raw)

    def test_equal_copies_and_no_matches_remain_private_and_unattested(self):
        self.bodies['first']=self.bodies['second']=elf()
        self.save();report=self.inspect()
        self.assertEqual(report['byte_relation'],'MATCH')
        self.assertTrue(all(not any(groups.values()) for a in report['artifacts'].values() for groups in a['group_presence'].values()))
        for key,value in (('artifact_publication','KEEP BOTH ARTIFACTS PRIVATE'),('source_to_worker','NOT VERIFIED'),
                          ('reproducibility','NOT VERIFIED'),('independent_privacy_assessment','NOT ASSESSED'),('application_and_core','NO-GO')):
            self.assertEqual(report[key],value)

    def test_unsupported_magic_class_endian_and_truncation_refuse_sanitized(self):
        variants=[b'private unknown image',self.bodies['first'][:63],self.bodies['second'][:31],
                  replace(self.bodies['first'],4,'B',1),replace(self.bodies['first'],5,'B',2),
                  replace(self.bodies['second'],0,'I',0xcffaedfe),replace(self.bodies['second'],0,'I',0xcafebabe)]
        for raw in variants:
            self.bodies['first']=raw;self.save();self.refuses()

    def test_elf_bad_header_counts_tables_and_extended_indexes_refuse(self):
        original=self.bodies['first']
        for offset,fmt,value in ((20,'I',0),(52,'H',63),(58,'H',63),(60,'H',0),(60,'H',check.MAX_RECORDS+1),
                                  (62,'H',0xffff),(40,'Q',1),(40,'Q',len(original)),(56,'H',check.MAX_RECORDS+1),
                                  (64+32,'Q',1),(32,'Q',1)):
            self.bodies['first']=replace(original,offset,fmt,value);self.save();self.refuses()

    def test_elf_names_require_bounded_index_termination_and_string_table(self):
        original=self.bodies['first'];name_row=64+64
        for raw in (replace(original,name_row+4,'I',1),replace(original,64+128,'I',2**32-1),
                    replace(original,name_row+32,'Q',check.MAX_TABLE_BYTES+1),
                    replace(original,name_row+8,'Q',0x800),elf([(b'x'*(check.MAX_NAME_BYTES+1),1,0,b'')])):
            self.bodies['first']=raw;self.save();self.refuses()

    def test_elf_header_and_section_overlaps_and_out_of_file_ranges_refuse(self):
        original=elf([(b'.data_a',1,0,b'123456789'),(b'.data_b',1,0,b'abcdefghijk')])
        start=struct.unpack_from('<Q',original,64+2*64+24)[0]
        for offset,value in ((64+2*64+24,0),(64+3*64+24,start+1),(64+2*64+32,len(original)+1)):
            self.bodies['first']=replace(original,offset,'Q',value);self.save();self.refuses()

    def test_macho_command_count_alignment_size_and_bounds_refuse(self):
        original=self.bodies['second']
        for offset,value in ((16,0),(16,check.MAX_RECORDS+1),(20,check.MAX_TABLE_BYTES+1),(20,len(original)),
                              (36,7),(36,79),(36,80),(32,1),(32+64,check.MAX_RECORDS+1)):
            self.bodies['second']=replace(original,offset,'I',value);self.save();self.refuses()

    def test_macho_section_bounds_segment_containment_and_overlap_refuse(self):
        original=macho([(0,b'abcdefghijk'),(0,b'ABCDEFGHIJK')])
        row=32+72;start=struct.unpack_from('<I',original,row+48)[0]
        variants=[replace(original,row+48,'I',0),replace(original,row+40,'Q',len(original)+1),
                  replace(original,row+80+48,'I',start+1),replace(original,32+48,'Q',1)]
        for raw in variants:
            self.bodies['second']=raw;self.save();self.refuses()

    def test_macho_symbol_tables_are_bounded_disjoint_and_single(self):
        original=macho(strings=b'synthetic-symbols',symbols=b'\x00'*16)
        at=32+72
        for offset,value in ((at+4,16),(at+8,0),(at+12,2**32-1),(at+16,0),(at+20,len(original)+1)):
            self.bodies['second']=replace(original,offset,'I',value);self.save();self.refuses()
        self.bodies['second']=macho(strings=b'synthetic',extra=struct.pack('<6I',2,24,0,0,0,0));self.save();self.refuses()

    def test_bad_expectations_and_over_bound_files_refuse_before_parsing(self):
        with patch.object(check,'_localize',side_effect=AssertionError('must refuse before parsing')):
            for value in (True,0,-1,1.0,check.MAX_BYTES+1):self.refuses(first_bytes=value)
            self.refuses(first_sha256='private claimed digest')
            self.refuses(first_sha256='0'*64)
            with self.paths['first'].open('wb') as handle:handle.truncate(check.MAX_BYTES+1)
            self.refuses()

    def test_role_aliases_foreign_types_and_missing_fields_refuse_before_io(self):
        class Foreign(dict):
            def __iter__(self):raise AssertionError('foreign hook')
        with patch.object(check.scanner,'owned_file',side_effect=AssertionError('must refuse first')):
            self.refuses(prefixes=Foreign(self.selected))
            for role in check.scanner.ROLES:
                value=deepcopy(self.selected);value['first'].pop(role);self.refuses(prefixes=value)
            value=deepcopy(self.selected);value['first'][check.scanner.ROLES[1]]=value['first'][check.scanner.ROLES[0]];self.refuses(prefixes=value)
        with self.assertRaises(check.InputError):check._layout(bytearray(self.bodies['first']))

    def test_aliases_symlinks_linked_parents_and_foreign_owner_refuse(self):
        self.refuses(second=self.paths['first'],second_sha256=digest(self.bodies['first']),second_bytes=len(self.bodies['first']))
        self.paths['second'].unlink();os.link(self.paths['first'],self.paths['second']);self.refuses(second_sha256=digest(self.bodies['first']),second_bytes=len(self.bodies['first']))
        self.paths['second'].unlink();self.save()
        linked=self.root/'linked';linked.symlink_to(self.paths['first']);self.refuses(first=linked)
        parent=self.root/'linked-parent';parent.symlink_to(self.root,target_is_directory=True);self.refuses(first=parent/'first')
        with patch.object(check.scanner.os,'geteuid',return_value=os.geteuid()+1):self.refuses()

    def test_named_replacement_during_localization_refuses_after_descriptor_read(self):
        original=check._localize;changed=[False]
        def localize(raw,selected):
            result=original(raw,selected)
            if not changed[0]:
                changed[0]=True;other=self.root/'replacement';other.write_bytes(self.bodies['first']);other.replace(self.paths['first'])
            return result
        with patch.object(check,'_localize',side_effect=localize):self.refuses()

    def test_parser_errors_are_sanitized_and_cancellation_propagates(self):
        for error in (OSError('private parser detail'),ValueError('private parser detail'),struct.error('private detail')):
            with patch.object(check,'_localize',side_effect=error):self.refuses()
        with patch.object(check,'_localize',side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):self.inspect()

    def test_actual_reader_cli_emits_only_fixed_report_and_sanitized_refusal(self):
        selected=self.root/'selection.json'
        selected.write_bytes(check.scanner.encoded(dict(schema=check.scanner.SCHEMA,**{
            name:{role:value.hex() for role,value in row.items()} for name,row in self.selected.items()})))
        selected.chmod(0o600)
        command=[sys.executable,'-B','scripts/check_worker_sections.py','--private-prefixes',str(selected)]
        for name in check.scanner.SELECTIONS:
            command.extend(('--'+name,str(self.paths[name]),'--expect-'+name+'-sha256',digest(self.bodies[name]),
                            '--expect-'+name+'-bytes',str(len(self.bodies[name]))))
        result=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False)
        self.assertEqual(result.returncode,0);self.assertEqual(result.stderr,b'')
        self.assertEqual(json.loads(result.stdout),self.inspect())
        result=subprocess.run(command+['--private-unknown-option',str(self.root)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False)
        self.assertEqual(result.returncode,1);self.assertEqual(result.stdout,b'');self.assertNotIn(str(self.root).encode(),result.stderr)


class WorkerSectionCarrierTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory();self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name);self.home=self.root/'synthetic-cache';self.home.mkdir()
        self.platform='aarch64-apple-darwin';self.pairs={};self.raw={};self.selected={}
        for name in check.scanner.SELECTIONS:
            source,build=self.root/(name+'-source'),self.root/(name+'-build');source.mkdir();build.mkdir()
            self.pairs[name]=(source,build)
            self.selected[name]=companion.remapping.selected_locations(self.root,source,build,self.home)
            body=macho(strings=self.selected[name][check.scanner.ROLES[2]])
            path=build/self.platform/'debug/examples'/companion.remapping.check.WORKER;path.parent.mkdir(parents=True);path.write_bytes(body)
            self.raw[name]=body
        arguments=[]
        for name in check.scanner.SELECTIONS:
            arguments.extend((self.worker(name),digest(self.raw[name]),len(self.raw[name])))
        comparison=check.scanner.inspect(*arguments,self.selected)
        builds={name:dict(schema='ptlc-offline-selected-worker-build-evidence-v1',
                        source_commit=companion.remapping.original.COMMIT,
                        witness_manifest_sha256=companion.remapping.original.MANIFEST_SHA256,
                        resolution_baseline_sha256=companion.remapping.original.BASELINE_SHA256,
                        platform=self.platform,prepared_source_files=55,resolution_sha256='1'*64,selected_contents_sha256='2'*64,
                        measured_inputs={'original-response-worker':dict(bytes=len(self.raw[name]),
                            selected_sha256=digest(self.raw[name]),measured_sha256=digest(self.raw[name]))})
                for name in check.scanner.SELECTIONS}
        self.claim=dict(schema='ptlc-offline-rust-path-remapping-pair-v1',selected_profile=companion.remapping.selected_profile(),
                        builds=builds,comparison=comparison,artifact_publication='KEEP BOTH ARTIFACTS PRIVATE')
        self.carrier=self.root/'private-carrier';self.save()

    def worker(self,name):return self.pairs[name][1]/self.platform/'debug/examples'/companion.remapping.check.WORKER

    def save(self):
        self.carrier.write_bytes(check.scanner.encoded(self.claim)+companion.TERMINAL);self.carrier.chmod(0o600)

    def qualify(self,**changes):
        arguments=dict(root=self.root,selections=self.pairs,home=self.home,platform=self.platform,carrier=self.carrier)
        arguments.update(changes);return companion.qualify(**arguments)

    def refuses(self,**changes):
        with self.assertRaises(check.InputError) as caught:self.qualify(**changes)
        self.assertEqual(str(caught.exception),companion.REFUSAL)

    def test_canonical_private_carrier_binds_rows_without_authenticating_history(self):
        result=self.qualify()
        for name in check.scanner.SELECTIONS:
            self.assertEqual(result['artifacts'][name]['measured'],self.claim['comparison']['artifacts'][name])
        self.assertIn('NOT ATTESTED',result['carrier_binding']);self.assertEqual(result['producer_attribution'],'NOT DETERMINED')
        self.assertIn('NO WORKER',result['previous_math_launch_binding'])

    def test_every_fixed_source_platform_and_profile_selection_is_required(self):
        original=deepcopy(self.claim)
        changes=[('source_commit','0'*40),('witness_manifest_sha256','0'*64),('resolution_baseline_sha256','0'*64),('platform','private-platform')]
        for name in check.scanner.SELECTIONS:
            for field,value in changes:
                self.claim=deepcopy(original);self.claim['builds'][name][field]=value;self.save();self.refuses()
        self.claim=deepcopy(original);self.claim['selected_profile']['target_scope']='private caller';self.save();self.refuses()

    def test_changed_artifact_hash_size_and_worker_claim_refuse(self):
        original=deepcopy(self.claim)
        for name in check.scanner.SELECTIONS:
            for field,value in (('bytes',True),('bytes',1),('selected_sha256','0'*64),('measured_sha256','0'*64)):
                self.claim=deepcopy(original);self.claim['builds'][name]['measured_inputs']['original-response-worker'][field]=value
                self.save();self.refuses()

    def test_numeric_aliases_cannot_replace_fixed_profile_booleans(self):
        self.claim['selected_profile']['root_claim_profile']['debug_assertions']=1
        self.save();self.refuses()

    def test_changed_role_observation_count_and_byte_relation_refuse(self):
        original=deepcopy(self.claim)
        for name in check.scanner.SELECTIONS:
            self.claim=deepcopy(original);self.claim['comparison']['artifacts'][name]['selected_prefix_presence'][check.scanner.ROLES[0]]=True
            self.claim['comparison']['artifacts'][name]['present_role_count']+=1;self.save();self.refuses()
            self.claim=deepcopy(original);self.claim['comparison']['artifacts'][name]['present_role_count']=True;self.save();self.refuses()
        self.claim=deepcopy(original);self.claim['comparison']['byte_relation']='DIFFER' if original['comparison']['byte_relation']=='MATCH' else 'MATCH';self.save();self.refuses()

    def test_cross_build_logical_mismatch_refuses_before_artifact_read(self):
        self.claim['builds']['second']['selected_contents_sha256']='3'*64;self.save()
        with patch.object(check,'inspect',side_effect=AssertionError('must refuse first')):self.refuses()

    def test_noncanonical_duplicate_alias_and_trailing_carriers_refuse(self):
        canonical=check.scanner.encoded(self.claim)+companion.TERMINAL
        variants=[b' '+canonical,canonical+b'\n',check.scanner.encoded(self.claim),
                  canonical.replace(b'"bytes": ',b'"bytes": 1, "bytes": ',1),canonical.replace(b'"prepared_source_files": 55',b'"prepared_source_files": 55.0',1)]
        for raw in variants:
            self.carrier.write_bytes(raw);self.refuses()

    def test_oversize_nonascii_depth_and_number_bounds_refuse_before_json(self):
        for raw in (b'x'*(companion.MAX_CARRIER_BYTES+1),b'\xff',b'['*13+b']'*13,b'{"x": 1234567890123}',b'{"x": NaN}'):
            with self.assertRaises(check.InputError):companion.decode_carrier(raw)
        class Foreign(bytes):
            def __len__(self):raise AssertionError('foreign hook')
        with self.assertRaises(check.InputError):companion.decode_carrier(Foreign(b'private'))

    def test_public_symlink_missing_and_foreign_owner_carriers_refuse(self):
        self.carrier.chmod(0o644);self.refuses();self.carrier.chmod(0o600)
        linked=self.root/'linked-carrier';linked.symlink_to(self.carrier);self.refuses(carrier=linked)
        self.refuses(carrier=self.root/'absent-carrier')
        with patch.object(companion.os,'geteuid',return_value=os.geteuid()+1):self.refuses()

    def test_incomplete_extra_directory_alias_and_nesting_selections_refuse(self):
        self.refuses(selections={'first':self.pairs['first']})
        self.refuses(selections=dict(self.pairs,third=self.pairs['first']))
        self.refuses(selections=dict(first=self.pairs['first'],second=self.pairs['first']))
        child=self.pairs['first'][0]/'nested';child.mkdir()
        self.refuses(selections=dict(self.pairs,second=(child,self.pairs['second'][1])))

    def test_changed_native_bytes_refuse_without_rewriting_or_requalifying(self):
        path=self.worker('first');before=path.read_bytes();path.write_bytes(before+b'synthetic changed bytes')
        self.refuses();self.assertEqual(path.read_bytes(),before+b'synthetic changed bytes')

    def test_no_private_selections_or_carrier_fingerprint_are_reported(self):
        raw=check.scanner.encoded(self.qualify()).decode('ascii')
        for rows in self.selected.values():
            for value in rows.values():
                for forbidden in (value.decode('ascii'),value.hex(),digest(value)):self.assertNotIn(forbidden,raw)
        self.assertNotIn(digest(self.carrier.read_bytes()),raw)

    def test_current_matching_directory_claim_is_not_authenticated_source_truth(self):
        self.claim['uninterpreted_claim']='synthetic unassessed claim';self.save()
        self.assertEqual(self.qualify()['source_to_worker'],'NOT VERIFIED')
        self.assertNotIn('synthetic unassessed claim',check.scanner.encoded(self.qualify()).decode('ascii'))

    def test_carrier_or_reader_failures_are_sanitized_and_cancellation_propagates(self):
        for error in (OSError('private detail'),ValueError('private detail'),KeyError('private detail')):
            with patch.object(companion,'load_carrier',side_effect=error):self.refuses()
        with patch.object(check,'inspect',side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):self.qualify()

    def test_actual_companion_cli_returns_bound_public_only_report(self):
        command=[sys.executable,'-B','scripts/qualify_worker_sections.py','--root',str(self.root),
                 '--cargo-home',str(self.home),'--platform',self.platform,'--private-pair-report',str(self.carrier)]
        for name in check.scanner.SELECTIONS:
            command.extend(('--'+name+'-workspace',str(self.pairs[name][0]),'--'+name+'-build-directory',str(self.pairs[name][1])))
        result=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False)
        self.assertEqual(result.returncode,0);self.assertEqual(result.stderr,b'');self.assertNotIn(str(self.root).encode(),result.stdout)
        value,end=json.JSONDecoder().raw_decode(result.stdout.decode('ascii'))
        self.assertEqual(value,self.qualify());self.assertIn('PASS: bounded retained worker sections',result.stdout.decode('ascii')[end:])
