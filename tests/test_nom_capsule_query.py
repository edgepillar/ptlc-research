"""Exact retained-query controls; unsigned labels never authorize recovery."""
import copy
from dataclasses import FrozenInstanceError
import json
import unittest
from unittest.mock import patch

import test_nom_journal_hold as previous_tests
from offline_session import enrollment_contract as codec, nom_authority_contract as authority
from offline_session import nom_capsule_query as binding, nom_recovery as recovery
from scripts import qualify_nom_capsule_query as qualification


class CapsuleQueryControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        class FixtureHost(previous_tests.JournalHoldControls):
            pass
        FixtureHost.setUpClass(); cls.host=FixtureHost
        cls.views=[qualification.prior.from_journal(
            bytes.fromhex(FixtureHost.report["cases"][i]["projection"]["journal_hex"]), challenge_hex="a1" * 32)
            for i in (1, 2, 3, 4)]

    @classmethod
    def tearDownClass(cls):
        cls.host.tearDownClass()

    def setUp(self):
        self.selected=qualification.read_selection(self.views[-1])
        self.query=authority.read_query(**self.selected)
        self.bound=binding.bind_read_query(self.views[-1], self.query)

    def changed_query(self, change):
        selected=copy.deepcopy(self.selected); change(selected)
        return authority.read_query(**selected)

    def assert_hold(self, result):
        self.assertEqual((result["state"],result["recovery_action"],result["application"],result["core"]),
                         ("HOLD","NONE","NO-GO","NO-GO"))
        self.assertEqual(result["source_authentication"],"NOT_PERFORMED")
        self.assertEqual((result["source_currentness"],result["restore_fence"]),("UNFILLED","UNFILLED"))
        self.assertIs(result["automatic_retry"],False); self.assertIs(result["replenish_work"],False)

    def rewrite(self, transform):
        events=[json.loads(line)["event"] for line in self.views[-1].journal_bytes.splitlines()]
        transform(events); head="00" * 32; raw=b""
        for index,event in enumerate(events,1):
            row=dict(schema="ptlc-nom-recovery-log-v1",sequence=index,previous_hash_hex=head,event=event)
            row["hash_hex"]=recovery.digest(b"ptlc-nom-log-v1",row); head=row["hash_hex"]
            raw+=recovery.canonical(row)+b"\n"
        return qualification.prior.from_journal(raw,challenge_hex="a1" * 32)

    def test_complete_actual_originals_bind_exact_capsule_and_query(self):
        value=self.bound.as_dict(); self.assertEqual(value["query_hex"],self.query.canonical_bytes.hex())
        self.assertEqual(value["capsule_sha256"],self.views[-1].digest_hex)
        self.assertEqual(value["charged_work"],self.views[-1].partial_hold.selection()["charged_work"])

    def test_three_partial_cuts_cannot_fill_the_complete_query(self):
        for retained in self.views[:-1]:
            with self.assertRaises(binding.CapsuleQueryRefused): binding.bind_read_query(retained,self.query)

    def test_query_fixture_preparation_refuses_missing_long_instead_of_filling_it(self):
        for retained in self.views[:-1]:
            with self.assertRaises(ValueError): qualification.read_selection(retained)

    def test_complete_result_alone_does_not_supply_original_custody(self):
        self.assertIsNotNone(self.views[2].partial_hold.selection()["recovered_long_signature_hex"])
        self.assertIsNone(self.views[2].partial_hold.selection()["original_long_hex"])
        with self.assertRaises(binding.CapsuleQueryRefused): binding.bind_read_query(self.views[2],self.query)

    def test_changed_long_original_refuses_even_if_independently_shaped(self):
        query=self.changed_query(lambda v:v["originals"].update(long=recovery.synthetic_claim(v["terms"],"long","00" * 64)))
        with self.assertRaises(binding.CapsuleQueryRefused): binding.bind_read_query(self.views[-1],query)

    def test_changed_short_original_refuses_even_if_independently_shaped(self):
        query=self.changed_query(lambda v:v["originals"].update(short=recovery.synthetic_claim(v["terms"],"short","00" * 64)))
        with self.assertRaises(binding.CapsuleQueryRefused): binding.bind_read_query(self.views[-1],query)

    def test_changed_complete_terms_and_matching_originals_refuse(self):
        def change(value):
            value["terms"]["session_id_hex"]="81" * 32
            value["originals"]={leg:recovery.synthetic_claim(value["terms"],leg,
                self.views[-1].partial_hold.selection()["recovered_long_signature_hex"] if leg=="long" else self.host.short)
                for leg in ("long","short")}
        query=self.changed_query(change)
        with self.assertRaises(binding.CapsuleQueryRefused): binding.bind_read_query(self.views[-1],query)

    def test_false_disclosure_in_independent_read_refuses(self):
        query=self.changed_query(lambda v:v["consumer_selection"].update(disclosure_possible=False))
        with self.assertRaises(binding.CapsuleQueryRefused): binding.bind_read_query(self.views[-1],query)

    def test_observer_retention_pins_are_not_relabelled_as_recovery_journal(self):
        selected=self.query.as_dict()["consumer_selection"]
        self.assertNotEqual(selected["retention_sequence"],self.bound.as_dict()["journal_sequence"])
        self.assertEqual(self.bound._query.as_dict()["consumer_selection"],selected)
        self.assertEqual(self.bound.review()["consumer_retention_pins"],
                         "SEPARATE CALLER ASSERTIONS; NOT DERIVED FROM RECOVERY JOURNAL")

    def test_new_challenge_changes_read_binding_without_resetting_work_scope(self):
        query=self.changed_query(lambda v:v.update(challenge_hex="42" * 32))
        changed=binding.bind_read_query(self.views[-1],query)
        self.assertNotEqual(self.bound.digest_hex,changed.digest_hex)
        self.assertEqual(self.bound.review()["work_scope_digest_hex"],changed.review()["work_scope_digest_hex"])
        self.assertEqual(self.bound.as_dict()["charged_work"],changed.as_dict()["charged_work"])

    def test_new_source_revision_changes_binding_without_a_new_work_scope(self):
        query=self.changed_query(lambda v:v["checkpoint_selection"].update(authority_revision=8))
        changed=binding.bind_read_query(self.views[-1],query)
        self.assertNotEqual(self.bound.digest_hex,changed.digest_hex)
        self.assertEqual(self.bound.review()["work_scope_digest_hex"],changed.review()["work_scope_digest_hex"])

    def test_source_rotation_does_not_mint_a_new_work_scope(self):
        query=self.changed_query(lambda v:v["network_selection"].update(authority_incarnation_hex="84" * 32))
        changed=binding.bind_read_query(self.views[-1],query)
        self.assertNotEqual(self.bound.digest_hex,changed.digest_hex)
        self.assertEqual(self.bound.review()["work_scope_digest_hex"],changed.review()["work_scope_digest_hex"])

    def test_older_observer_pins_remain_untrusted_without_erasing_journal_charges(self):
        query=self.changed_query(lambda v:v["consumer_selection"].update(retention_sequence=1))
        changed=binding.bind_read_query(self.views[-1],query)
        self.assertEqual(changed.review()["charged_work"],1); self.assert_hold(changed.review())

    def test_added_selected_unknown_charge_changes_binding_but_not_existing_work_scope(self):
        retained=self.rewrite(lambda events:events.append(dict(kind="recovery-admitted")))
        changed=binding.bind_read_query(retained,self.query)
        self.assertEqual(changed.review()["charged_work"],2)
        self.assertNotEqual(self.bound.digest_hex,changed.digest_hex)
        self.assertEqual(self.bound.review()["work_scope_digest_hex"],changed.review()["work_scope_digest_hex"])
        self.assertEqual(changed.as_dict()["charged_work"][:1],self.bound.as_dict()["charged_work"])

    def test_same_old_source_read_cannot_supply_a_claim_for_another_capsule_binding(self):
        retained=self.rewrite(lambda events:events.append(dict(kind="recovery-admitted")))
        changed=binding.bind_read_query(retained,self.query)
        self.assertEqual(changed._query.digest_hex,self.query.digest_hex)
        with self.assertRaises(binding.CapsuleQueryRefused):
            binding.parse_claim(changed,qualification.claim_wire(self.bound))

    def test_rewrapped_unsigned_claim_can_match_and_remains_without_authority(self):
        retained=self.rewrite(lambda events:events.append(dict(kind="recovery-admitted")))
        changed=binding.bind_read_query(retained,self.query)
        forged=json.loads(qualification.claim_wire(self.bound)); forged["binding_digest_hex"]=changed.digest_hex
        result=binding.parse_claim(changed,codec._canonical(forged))
        self.assertEqual(result["coverage"],"COMPLETE_CLAIM"); self.assert_hold(result)
        self.assertEqual(result["selected_binding"]["charged_work"],2)

    def test_coherent_old_capsule_query_claim_still_matches_without_restore_authority(self):
        result=binding.parse_claim(self.bound,qualification.claim_wire(self.bound))
        self.assertEqual(result["coverage"],"COMPLETE_CLAIM"); self.assert_hold(result)

    def test_all_four_source_labels_remain_hold_without_retry_or_output_invention(self):
        results=[binding.parse_claim(self.bound,qualification.claim_wire(self.bound,status=s,availability=a))
                 for s,a in (("supported","available"),("unknown","available"),
                             ("contradicted","available"),("unknown","unavailable"))]
        self.assertEqual([r["coverage"] for r in results],qualification.corpus()["source_coverage"])
        for result in results:self.assert_hold(result)

    def test_changed_challenge_source_claim_refuses(self):
        changed=binding.bind_read_query(self.views[-1],self.changed_query(lambda v:v.update(challenge_hex="42" * 32)))
        with self.assertRaises(binding.CapsuleQueryRefused): binding.parse_claim(changed,qualification.claim_wire(self.bound))

    def test_inner_source_claim_mismatch_refuses_under_matching_outer_binding(self):
        forged=json.loads(qualification.claim_wire(self.bound)); inner=json.loads(bytes.fromhex(forged["source_claim_hex"]))
        inner["query_digest_hex"]="00" * 32; forged["source_claim_hex"]=codec._canonical(inner).hex()
        with self.assertRaises(binding.CapsuleQueryRefused): binding.parse_claim(self.bound,codec._canonical(forged))

    def test_noncanonical_extra_duplicate_and_numeric_alias_bindings_refuse(self):
        original=self.bound.canonical_bytes; value=self.bound.as_dict(); value["journal_sequence"]=float(value["journal_sequence"])
        for raw in (original+b"\n",b' '+original,original.replace(b'{',b'{"extra":true,',1),codec._canonical(value)):
            with self.assertRaises(binding.CapsuleQueryRefused): binding.parse_binding(self.bound,raw)

    def test_malformed_oversized_and_nonbytes_binding_inputs_refuse(self):
        for raw in (b"",b"[" * 13+b"]" * 13,b"x" * (binding.MAX_WIRE_BYTES+1),None,bytearray(b"{}")):
            with self.assertRaises(binding.CapsuleQueryRefused): binding.parse_binding(self.bound,raw)

    def test_duplicate_outer_claim_and_uppercase_inner_hex_refuse(self):
        wire=qualification.claim_wire(self.bound); value=json.loads(wire)
        for raw in (wire.replace(b'{',b'{"schema":"duplicate",',1),
                    codec._canonical(dict(value,source_claim_hex=value["source_claim_hex"].upper()))):
            with self.assertRaises(binding.CapsuleQueryRefused): binding.parse_claim(self.bound,raw)

    def test_invalid_capsule_query_and_expected_types_refuse(self):
        for value in (None,{},object(),self.views[-1].canonical_bytes):
            with self.assertRaises(binding.CapsuleQueryRefused): binding.bind_read_query(value,self.query)
            with self.assertRaises(binding.CapsuleQueryRefused): binding.bind_read_query(self.views[-1],value)
            with self.assertRaises(binding.CapsuleQueryRefused): binding.parse_claim(value,qualification.claim_wire(self.bound))

    def test_direct_binding_construction_refuses(self):
        with self.assertRaises(TypeError): binding.CapsuleReadBinding()

    def test_binding_and_input_views_are_immutable(self):
        old=self.bound.canonical_bytes
        with self.assertRaises(FrozenInstanceError):self.bound._query=authority.read_query(**self.selected)
        copy_value=self.bound.as_dict(); copy_value["charged_work"].clear()
        self.assertEqual(self.bound.canonical_bytes,old)

    def test_exact_binding_replay_creates_no_new_object_or_operation(self):
        self.assertIs(binding.parse_binding(self.bound,self.bound.canonical_bytes),self.bound)
        self.assert_hold(self.bound.review())

    def test_unsupported_claim_fields_and_wrong_digest_refuse(self):
        wire=qualification.claim_wire(self.bound); value=json.loads(wire)
        for changed in (dict(value,extra=True),dict(value,binding_digest_hex="00" * 32),dict(value,schema="other")):
            with self.assertRaises(binding.CapsuleQueryRefused):binding.parse_claim(self.bound,codec._canonical(changed))

    def test_binding_claim_and_replay_do_not_enter_paths_workers_or_processes(self):
        with patch("offline_session.nom_capsule.os.open",side_effect=AssertionError("path entry")), \
             patch("subprocess.Popen",side_effect=AssertionError("process entry")), \
             patch("offline_session.nom_verifier.run_clean_environment_public_worker",side_effect=AssertionError("worker entry")):
            bound=binding.bind_read_query(self.views[-1],self.query)
            binding.parse_binding(bound,bound.canonical_bytes)
            self.assert_hold(binding.parse_claim(bound,qualification.claim_wire(bound)))

    def test_all_previous_inputs_and_frozen_profiles_remain_exact(self):
        manifest,measured=qualification.inputs()
        self.assertEqual(len(manifest["preserved_file_sha256"]),174); self.assertEqual(len(measured),179)
        self.assertEqual(manifest["boundary"]["new_core_source_outcomes"],0)
