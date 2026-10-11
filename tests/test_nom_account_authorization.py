"""Actual outer signatures and typed values cannot replace retained originals."""

import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from offline_session.nom_wire import account_block_hash
from offline_session.public_worker import WorkerError
from scripts import qualify_nom_account_authorization as auth
from scripts.generate_nom_account_authorization import FIXTURE, USER_ROLES, USER_KINDS, vectors, corpus

ROOT = Path(__file__).resolve().parents[1]
FIX = json.loads((ROOT / FIXTURE).read_text("ascii"))


class NoMAccountAuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.records = copy.deepcopy(FIX["records"])
        self.source = auth.frozen_records()

    def record(self, kind, role="funding", leg="long"):
        return self.records[leg + "-" + role + "-" + kind]

    def validate(self):
        return auth.validate_records(self.records, self.source)

    def stream(self):
        return b"\n".join(json.dumps({"Package":auth.PACKAGE, "Test":auth.TEST + "/" + vector["id"],
            "Action":"output", "Output":"    zz_research_nom_account_authorization_test.go:250: "
            + auth.PREFIX + json.dumps(self.records[vector["id"]], sort_keys=True) + "\n"}).encode("ascii")
            for vector in vectors()) + b"\n"

    def test_complete_exact_subject_has_twelve_roles_and_one_hundred_twenty_six_controls(self):
        self.assertEqual(FIX, corpus(self.validate()))
        manifest, fixture, measured = auth.inputs(ROOT)
        self.assertEqual(fixture, FIX)
        self.assertEqual(manifest["expected_counts"], auth.COUNTS)
        self.assertEqual((len(vectors()),len(auth.expected_tests()[auth.PACKAGE])),(126,127))
        self.assertIn(auth.MANIFEST, measured)
        self.assertEqual(FIX["boundary"]["recovery_action"], "NONE")
        self.assertEqual((FIX["boundary"]["application"],FIX["boundary"]["core"]),("NO-GO","NO-GO"))

    def test_every_advertised_and_computed_hash_keeps_the_explicit_old_hash_conflict(self):
        self.validate()
        for vector in vectors():
            r = self.records[vector["id"]]
            self.assertEqual(r["computed_hash_hex"],account_block_hash(r["block"]))
            self.assertEqual(r["hash_hex"] == r["computed_hash_hex"],vector["kind"] != "changed-data-old-hash")

    def test_unsigned_user_originals_match_source_hash_and_refuse_missing_signature(self):
        for leg in ("long","short"):
            for role in USER_ROLES:
                r=self.record("unsigned",role,leg)
                self.assertEqual(r["hash_hex"],r["source_hash_hex"])
                self.assertEqual(r["wire_hex"],r["original_wire_hex"])
                self.assertEqual(r["checks"]["signature"],"ErrABSignatureMissing")

    def test_signature_validity_with_foreign_key_does_not_authorize_source_account(self):
        for leg in ("long","short"):
            for role in USER_ROLES:
                r=self.record("foreign-signature",role,leg)
                self.assertEqual(r["hash_hex"],r["source_hash_hex"])
                self.assertEqual(r["checks"],{"hash":"PASS","signature":"PASS","producer":"ErrABPublicKeyWrongAddress"})
                address="00"+hashlib.sha3_256(bytes.fromhex(r["public_key_hex"])).hexdigest()[:38]
                self.assertNotEqual(address,r["block"]["address_hex"])

    def test_relocated_authorized_controls_are_different_accounts_hashes_and_original_bytes(self):
        for leg in ("long","short"):
            for role in USER_ROLES:
                r=self.record("relocated-authorized",role,leg)
                old=self.source[leg+"-direct-success"]["blocks"][role]
                self.assertEqual(set(r["checks"].values()),{"PASS"})
                self.assertNotEqual(r["block"]["address_hex"],old["block"]["address_hex"])
                self.assertNotEqual(r["hash_hex"],r["source_hash_hex"])
                self.assertNotEqual(r["wire_hex"],r["original_wire_hex"])

    def test_rehashed_content_cannot_use_retained_signature(self):
        for role in USER_ROLES:
            changed=self.record("changed-data-old-signature",role)
            self.assertEqual(changed["signature_hex"],self.record("relocated-authorized",role)["signature_hex"])
            self.assertEqual(changed["checks"]["signature"],"ErrABSignatureInvalid")
            self.assertNotEqual(changed["block"]["data_hex"],self.record("unsigned",role)["block"]["data_hex"])

    def test_resigning_changed_content_only_satisfies_outer_checks_for_new_original(self):
        for role in USER_ROLES:
            r=self.record("changed-data-resigned",role)
            self.assertEqual(set(r["checks"].values()),{"PASS"})
            self.assertNotEqual(r["wire_hex"],self.record("relocated-authorized",role)["wire_hex"])
            self.assertNotEqual(r["hash_hex"],self.record("relocated-authorized",role)["hash_hex"])

    def test_excluded_patch_and_plasma_fields_change_raw_bytes_without_changing_hash_or_signature(self):
        for leg in ("long","short"):
            for role in USER_ROLES:
                original=self.record("relocated-authorized",role,leg)
                for kind in ("changed-changes-hash","changed-base-plasma","changed-total-plasma"):
                    changed=self.record(kind,role,leg)
                    self.assertEqual((changed["hash_hex"],changed["signature_hex"]),(original["hash_hex"],original["signature_hex"]))
                    self.assertNotEqual(changed["wire_hex"],original["wire_hex"])
                    self.assertEqual(set(changed["checks"].values()),{"PASS"})

    def test_raw_unknown_and_duplicate_field_aliases_collapse_only_after_typed_reencoding(self):
        for r in self.records.values():
            if r["kind"] in ("unknown-protobuf-field","duplicate-protobuf-version"):
                self.assertNotEqual(r["wire_hex"],r["reencoded_wire_hex"])
                self.assertEqual(set(r["checks"].values()),{"PASS"})
                self.assertNotEqual(r["wire_sha256"],hashlib.sha256(bytes.fromhex(r["reencoded_wire_hex"])).hexdigest())

    def test_embedded_empty_authorization_requirement_is_separate_from_source_or_external_admission(self):
        for role in auth.EMBEDDED_ROLES:
            self.assertEqual(set(self.record("empty-authorization",role)["checks"].values()),{"PASS"})
            self.assertEqual(self.record("nonempty-key",role)["checks"]["signature"],"ErrABPublicKeyMustBeZero")
            self.assertEqual(self.record("nonempty-signature",role)["checks"]["signature"],"ErrABSignatureMustBeZero")
        self.assertEqual(FIX["boundary"]["account_admission"],"NOT_PERFORMED")

    def test_changed_selected_address_is_not_silently_repaired(self):
        self.record("relocated-authorized")["block"]["address_hex"]="00"+"77"*19
        with self.assertRaises(ValueError): self.validate()

    def test_source_original_hash_replacement_refuses(self):
        self.record("foreign-signature")["source_hash_hex"]="01"*32
        with self.assertRaises(ValueError): self.validate()

    def test_success_label_cannot_replace_selected_refusal(self):
        self.record("foreign-signature")["checks"]["producer"]="PASS"
        with self.assertRaises(ValueError): self.validate()

    def test_raw_byte_commitment_replacement_refuses(self):
        self.record("relocated-authorized")["wire_sha256"]="22"*32
        with self.assertRaises(ValueError): self.validate()

    def test_alias_suffix_replacement_refuses_even_when_digest_is_updated(self):
        r=self.record("unknown-protobuf-field"); r["wire_hex"]=r["wire_hex"][:-2]+"02"
        r["wire_sha256"]=hashlib.sha256(bytes.fromhex(r["wire_hex"])).hexdigest()
        with self.assertRaises(ValueError): self.validate()

    def test_extra_record_fields_refuse(self):
        self.record("unsigned")["permission"]=True
        with self.assertRaises(ValueError): self.validate()

    def test_retained_signature_mutation_cannot_hide_in_hash_excluded_fields(self):
        r=self.record("changed-base-plasma"); r["signature_hex"]="33"*64
        with self.assertRaises(ValueError): self.validate()

    def test_missing_and_unselected_controls_cannot_pass_as_complete(self):
        self.records.pop(next(iter(self.records)))
        with self.assertRaises(ValueError): self.validate()
        self.records=copy.deepcopy(FIX["records"]); self.records["other"]=self.record("unsigned")
        with self.assertRaises(ValueError): self.validate()

    def test_public_wire_bounds_widths_case_and_canonical_plasma_are_required(self):
        for key,value in (("wire_hex","00"*8193),("public_key_hex","00"*33),("signature_hex","AA"*64),
                          ("base_plasma",str(1<<64)),("base_plasma",1),("total_plasma","01")):
            self.records=copy.deepcopy(FIX["records"]); self.record("relocated-authorized")[key]=value
            with self.assertRaises(ValueError): self.validate()

    def test_actual_output_framing_refuses_duplicates_truncation_and_wrong_subject(self):
        wire=self.stream(); self.assertEqual(auth.collect_records(wire,self.source),self.records)
        for changed in (wire+wire.splitlines()[0]+b"\n",b"\n".join(wire.splitlines()[:-1])+b"\n",
                        wire.replace(auth.PACKAGE.encode(),b"different/package",1)):
            with self.assertRaises(ValueError): auth.collect_records(changed,self.source)

    def test_zero_exit_needs_all_exact_parent_and_child_passes_without_skip_or_fail(self):
        names=auth.expected_tests(); events=[{"Package":auth.PACKAGE,"Action":"pass","Test":name} for name in names[auth.PACKAGE]]
        events.append({"Package":auth.PACKAGE,"Action":"pass"})
        encode=lambda value: b"\n".join(json.dumps(event).encode("ascii") for event in value)
        self.assertEqual(auth.vm.selected_outcome(encode(events),names),127)
        for changed in (events[1:],events+events[:1],events+[{"Package":auth.PACKAGE,"Action":"skip","Test":auth.TEST}],
                        events+[{"Package":auth.PACKAGE,"Action":"fail"}]):
            with self.assertRaises(ValueError): auth.vm.selected_outcome(encode(changed),names)

    def test_uint64_parser_takes_bit_width_and_does_not_treat_maximum_as_bit_count(self):
        r=self.record("changed-base-plasma")
        self.assertEqual(r["base_plasma"],"1")
        self.assertEqual(auth.validate_record(r,next(v for v in vectors() if v["id"]==r["id"]),self.source),r)
        r["base_plasma"]=str(1<<64)
        with self.assertRaises(ValueError): auth.validate_record(r,next(v for v in vectors() if v["id"]==r["id"]),self.source)

    def test_failed_fresh_vm_preserves_failed_outcome_and_never_uses_fixture_fallback(self):
        with tempfile.TemporaryDirectory(prefix="ptlc-account-qualification-") as folder:
            parent=Path(folder)
            with patch.object(auth.vm,"core_state"), patch.object(auth.vm,"qualify",side_effect=WorkerError("selected source failed")),\
                 patch.object(auth,"execute") as executed:
                with self.assertRaises(WorkerError): auth.qualify(ROOT,Path(__file__),evidence_parent=parent)
                executed.assert_not_called()
            results=list(parent.glob("account-authorization-*/outcome.json"))
            self.assertEqual(len(results),1)
            outcome=json.loads(results[0].read_text("ascii"))
            self.assertEqual(outcome["outcome"],"FAILED_OR_INCOMPLETE")
            self.assertNotIn("fresh_projection",outcome)
            self.assertEqual(outcome["recovery_action"],"NONE")


class NoMAccountSignatureIndependentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.openssl=shutil.which("openssl")
        reason="OpenSSL Ed25519 backend unavailable"
        if cls.openssl is not None:
            try:
                result=subprocess.run([cls.openssl,"list","-signature-algorithms"],capture_output=True,timeout=10)
                if result.returncode==0 and b"ED25519" in result.stdout.upper(): return
            except (OSError,subprocess.TimeoutExpired): pass
        if os.environ.get("REQUIRE_OPENSSL")=="1": raise RuntimeError(reason+"; required independent verification cannot skip")
        raise unittest.SkipTest(reason+"; independent verification not performed")

    def verify(self,record,message=None):
        # RFC 8410 SubjectPublicKeyInfo; only public key, message and signature.
        key=bytes.fromhex("302a300506032b6570032100"+record["public_key_hex"])
        message=bytes.fromhex(record["hash_hex"]) if message is None else message
        with tempfile.TemporaryDirectory(prefix="ptlc-public-signature-") as folder:
            work=Path(folder); (work/"public.der").write_bytes(key); (work/"message.bin").write_bytes(message)
            (work/"signature.bin").write_bytes(bytes.fromhex(record["signature_hex"]))
            result=subprocess.run([self.openssl,"pkeyutl","-verify","-pubin","-keyform","DER","-inkey","public.der",
                                   "-rawin","-in","message.bin","-sigfile","signature.bin"],cwd=work,capture_output=True,timeout=10)
        return result.returncode,result.stdout.strip()

    def test_all_source_claimed_valid_user_signatures_pass_independent_openssl(self):
        observed=0
        for record in FIX["records"].values():
            if record["role"] in USER_ROLES and record["checks"]["signature"]=="PASS":
                self.assertEqual(self.verify(record),(0,b"Signature Verified Successfully")); observed+=1
        self.assertEqual(observed,54)

    def test_all_full_key_invalid_signature_controls_have_exact_cryptographic_refusal(self):
        observed=0
        for record in FIX["records"].values():
            if record["kind"] in ("changed-data-old-signature","short-signature","bad-signature"):
                self.assertEqual(self.verify(record),(1,b"Signature Verification Failure")); observed+=1
        self.assertEqual(observed,18)

    def test_old_advertised_hash_signature_does_not_cover_changed_computed_block(self):
        for record in FIX["records"].values():
            if record["kind"]=="changed-data-old-hash":
                self.assertEqual(self.verify(record),(0,b"Signature Verified Successfully"))
                self.assertEqual(self.verify(record,bytes.fromhex(record["computed_hash_hex"])),(1,b"Signature Verification Failure"))

    def test_valid_foreign_signatures_still_have_wrong_selected_account(self):
        observed=0
        for record in FIX["records"].values():
            if record["kind"]=="foreign-signature":
                self.assertEqual(self.verify(record),(0,b"Signature Verified Successfully"))
                self.assertEqual(record["checks"]["producer"],"ErrABPublicKeyWrongAddress"); observed+=1
        self.assertEqual(observed,6)
