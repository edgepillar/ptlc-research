"""Capsule ownership and fault controls; fixture workers assert no mathematics."""
import copy
import dataclasses
import errno
import hashlib
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

import test_nom_journal_hold as previous_tests
from offline_session import nom_capsule as capsule, nom_journal_hold as projection
from offline_session import nom_recovery as recovery
from offline_session.nom_strict_open import StrictNomRecovery
from scripts.nom_cut_capture import retain
from scripts import qualify_nom_capsule as qualification


class CapsuleControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        class FixtureHost(previous_tests.JournalHoldControls):
            pass
        FixtureHost.setUpClass()
        cls.fixture = FixtureHost
        cls.terms, cls.pair = FixtureHost.terms, FixtureHost.pair
        cls.short, cls.long = FixtureHost.short, FixtureHost.long
        cls.sources = FixtureHost.sources
        cls.capsule_report = qualification.qualify(FixtureHost.worker,
            evidence_directory=(FixtureHost.directory / "capsule-originals").resolve())

    @classmethod
    def tearDownClass(cls):
        cls.fixture.tearDownClass()

    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.directory = Path(temp.name).resolve(); self.directory.chmod(0o700)
        self.path = self.directory / "capsule-owner"
        self.journal = self.directory / "journal.log"
        retain(self.journal, bytes.fromhex(self.sources[3]["journal_hex"]))

    def selected(self, index=3, challenge="a1" * 32):
        self.journal.write_bytes(bytes.fromhex(self.sources[index]["journal_hex"]))
        verifier = previous_tests.FixtureVerifier(
            recovery.verification_context_digest(self.terms, self.pair), self.short, self.long)
        with StrictNomRecovery.open(self.journal, self.terms, self.pair, role="bob",
                                   verifier=verifier, observation_verifier=lambda _: False) as owner:
            return projection.project_partial_hold(owner, challenge_hex=challenge)

    def stored(self, index=3):
        selected = self.selected(index)
        with capsule.CapsuleOwner.create(self.path) as owner:
            receipt = owner.store(selected)
        return selected, receipt

    def wire(self, selected=None):
        return capsule.encode_capsule(self.selected() if selected is None else selected)

    def digest(self, wire):
        return hashlib.sha256(wire).hexdigest()

    def read_value(self, wire):
        return capsule.read_capsule(wire, expected_digest_hex=self.digest(wire))

    def test_four_admitted_states_keep_exact_full_custody(self):
        for index in range(1, 5):
            selected = self.selected(index); wire = self.wire(selected); view = self.read_value(wire)
            self.assertEqual(view.projection(), selected.as_dict())
            self.assertEqual(view.journal_bytes, selected.journal_bytes)
            self.assertEqual(view.partial_hold.canonical_bytes, selected.partial_hold.canonical_bytes)
            self.assertEqual(view.review()["state"], "HOLD")

    def test_missing_output_stays_null(self):
        view = self.read_value(self.wire(self.selected(2)))
        selection = view.partial_hold.selection()
        self.assertIsNone(selection["recovered_long_signature_hex"])
        self.assertIsNone(selection["original_long_hex"])

    def test_every_persisted_ordinal_stays_unknown(self):
        view = self.read_value(self.wire())
        self.assertEqual([r["outcome"] for r in view.partial_hold.selection()["charged_work"]], ["UNKNOWN"])
        self.assertEqual(view.review()["signature_mathematics"], "NOT_PERFORMED BY CAPSULE CONSUMER")

    def test_present_original_stays_exact(self):
        selected = self.selected(4); view = self.read_value(self.wire(selected))
        self.assertEqual(view.partial_hold.selection()["original_long_hex"],
                         selected.partial_hold.selection()["original_long_hex"])

    def test_challenge_changes_capsule_but_not_work_identity(self):
        first = self.read_value(self.wire(self.selected(challenge="a1" * 32)))
        second = self.read_value(self.wire(self.selected(challenge="b2" * 32)))
        self.assertNotEqual(first.digest_hex, second.digest_hex)
        self.assertEqual(first.partial_hold.selection()["charged_work"], second.partial_hold.selection()["charged_work"])

    def test_full_journal_is_outside_bounded_prior_evidence(self):
        view = self.read_value(self.wire())
        self.assertEqual(view.partial_hold.selection()["prior_evidence_hex"], [])
        self.assertGreater(len(view.journal_bytes), 512)

    def test_arbitrary_label_cannot_encode_a_selected_projection(self):
        for value in (None, {}, projection.PROFILE, object()):
            with self.assertRaises(capsule.CapsuleRefused): capsule.encode_capsule(value)

    def test_view_is_immutable_and_copies_do_not_change_it(self):
        view = self.read_value(self.wire()); original = view.canonical_bytes
        with self.assertRaises(dataclasses.FrozenInstanceError): view._wire = b"changed"
        altered = view.projection(); altered["journal_hex"] = "00"
        self.assertEqual(view.canonical_bytes, original)

    def test_direct_view_construction_is_refused(self):
        with self.assertRaises(TypeError): capsule.CapsuleView()

    def test_explicit_digest_mismatch_refuses(self):
        with self.assertRaises(capsule.CapsuleRefused):
            capsule.read_capsule(self.wire(), expected_digest_hex="00" * 32)

    def test_invalid_digest_types_and_uppercase_refuse(self):
        for value in (None, "", "0" * 63, "GG" * 32, "AA" * 32, 1):
            with self.assertRaises(capsule.CapsuleRefused):
                capsule.read_capsule(self.wire(), expected_digest_hex=value)

    def test_noncanonical_duplicate_and_extra_fields_refuse(self):
        wire = self.wire(); value = json.loads(wire)
        extra = copy.deepcopy(value); extra["extra"] = True
        for altered in (wire + b"\n", b" " + wire, wire.replace(b'{"schema":', b'{"extra":true,"schema":', 1),
                        capsule._wire(extra), b'{"schema":"x","schema":"y"}'):
            with self.assertRaises(capsule.CapsuleRefused): self.read_value(altered)

    def test_torn_and_wrong_schema_refuse(self):
        wire = self.wire()
        for altered in (b"", wire[:-1], wire[:len(wire)//2], wire.replace(capsule.PROFILE.encode(), b"other")):
            with self.assertRaises(capsule.CapsuleRefused): self.read_value(altered)

    def test_size_bound_and_nonbytes_refuse(self):
        for wire in (b"x" * (capsule.MAX_BYTES + 1), "text", bytearray(b"{}"), None):
            with self.assertRaises(capsule.CapsuleRefused): capsule.read_capsule(wire, expected_digest_hex="00" * 32)

    def test_rehashed_capsule_cannot_erase_charged_work(self):
        value = json.loads(self.wire()); value["selected_projection"]["journal_sequence"] -= 1
        with self.assertRaises(capsule.CapsuleRefused): self.read_value(capsule._wire(value))

    def test_rehashed_decimal_metadata_refuses_equal_integer_aliases(self):
        for index in range(1, 5):
            original = self.wire(self.selected(index))
            self.assertEqual(self.read_value(original).canonical_bytes, original)
            for field in ("journal_sequence", "journal_bytes"):
                with self.subTest(index=index, field=field):
                    value = json.loads(original)
                    exact = value["selected_projection"][field]
                    self.assertIs(type(exact), int)
                    value["selected_projection"][field] = float(exact)
                    self.assertEqual(value["selected_projection"][field], exact)
                    with self.assertRaises(capsule.CapsuleRefused):
                        self.read_value(capsule._wire(value))

    def test_rehashed_capsule_cannot_fill_absent_output(self):
        value = json.loads(self.wire(self.selected(2)))
        other = self.selected(3).as_dict()
        value["selected_projection"]["partial_hold_hex"] = other["partial_hold_hex"]
        value["selected_projection"]["selection_digest_hex"] = other["selection_digest_hex"]
        with self.assertRaises(capsule.CapsuleRefused): self.read_value(capsule._wire(value))

    def test_pure_reader_never_enters_worker_or_opens_path(self):
        wire = self.wire()
        with patch.object(capsule.os, "open", side_effect=AssertionError("path entry")), \
             patch("offline_session.nom_verifier.run_clean_environment_public_worker", side_effect=AssertionError("worker entry")):
            self.assertEqual(self.read_value(wire).review()["recovery_action"], "NONE")

    def test_store_and_fresh_read_only_owner_preserve_original_bytes(self):
        selected, receipt = self.stored()
        path = self.path / capsule.CAPSULE_NAME
        before = path.read_bytes(); mode = path.stat().st_mode & 0o777
        with capsule.CapsuleOwner.open(self.path) as owner:
            view = owner.read(expected_digest_hex=receipt["capsule_sha256"])
        self.assertEqual(view.projection(), selected.as_dict())
        self.assertEqual(path.read_bytes(), before); self.assertEqual(mode, 0o400)
        self.assertEqual(receipt["power_loss"], "NOT_QUALIFIED")

    def test_existing_owner_open_creates_nothing(self):
        self.stored(); before = sorted(p.name for p in self.path.iterdir())
        with patch.object(capsule.os, "mkdir", side_effect=AssertionError("creation")):
            with capsule.CapsuleOwner.open(self.path): pass
        self.assertEqual(sorted(p.name for p in self.path.iterdir()), before)

    def test_missing_owner_is_not_created(self):
        with self.assertRaises(capsule.CapsuleRefused): capsule.CapsuleOwner.open(self.path)
        self.assertFalse(self.path.exists())

    def test_missing_capsule_is_not_created_by_consumer(self):
        with capsule.CapsuleOwner.create(self.path) as owner:
            with self.assertRaises(capsule.CapsuleRefused): owner.read(expected_digest_hex="00" * 32)
        self.assertFalse((self.path / capsule.CAPSULE_NAME).exists())

    def test_existing_directory_cannot_be_adopted_by_create(self):
        self.path.mkdir(mode=0o700)
        with self.assertRaises(capsule.CapsuleRefused): capsule.CapsuleOwner.create(self.path)
        self.assertEqual(list(self.path.iterdir()), [])

    def test_nonprivate_parent_or_owner_directory_refuses(self):
        self.directory.chmod(0o755)
        with self.assertRaises(capsule.CapsuleRefused): capsule.CapsuleOwner.create(self.path)
        self.directory.chmod(0o700); self.stored(); self.path.chmod(0o755)
        with self.assertRaises(capsule.CapsuleRefused): capsule.CapsuleOwner.open(self.path)
        self.path.chmod(0o700)

    def test_symlink_owner_and_ancestor_refuse(self):
        self.stored(); link = self.directory / "owner-link"; link.symlink_to(self.path, target_is_directory=True)
        with self.assertRaises(capsule.CapsuleRefused): capsule.CapsuleOwner.open(link)
        with self.assertRaises(capsule.CapsuleRefused): capsule.CapsuleOwner.open(link / "nested")

    def test_capsule_symlink_refuses_without_following(self):
        _, receipt = self.stored(); path = self.path / capsule.CAPSULE_NAME
        target = self.directory / "other"; target.write_bytes(path.read_bytes()); target.chmod(0o400)
        path.unlink(); path.symlink_to(target)
        with capsule.CapsuleOwner.open(self.path) as owner:
            with self.assertRaises(capsule.CapsuleRefused): owner.read(expected_digest_hex=receipt["capsule_sha256"])

    def test_capsule_hard_link_refuses(self):
        _, receipt = self.stored(); os.link(self.path / capsule.CAPSULE_NAME, self.directory / "alias")
        with capsule.CapsuleOwner.open(self.path) as owner:
            with self.assertRaises(capsule.CapsuleRefused): owner.read(expected_digest_hex=receipt["capsule_sha256"])

    def test_writable_capsule_refuses_without_chmod_repair(self):
        _, receipt = self.stored(); path = self.path / capsule.CAPSULE_NAME; path.chmod(0o600)
        with capsule.CapsuleOwner.open(self.path) as owner:
            with self.assertRaises(capsule.CapsuleRefused): owner.read(expected_digest_hex=receipt["capsule_sha256"])
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_same_directory_has_one_cooperating_owner(self):
        with capsule.CapsuleOwner.create(self.path):
            with self.assertRaises(capsule.CapsuleRefused): capsule.CapsuleOwner.open(self.path)
        with capsule.CapsuleOwner.open(self.path): pass

    def test_second_store_cannot_replace_existing_capsule(self):
        selected = self.selected()
        with capsule.CapsuleOwner.create(self.path) as owner:
            owner.store(selected); original = (self.path / capsule.CAPSULE_NAME).read_bytes()
            with self.assertRaises(capsule.CapsuleRefused): owner.store(selected)
        self.assertEqual((self.path / capsule.CAPSULE_NAME).read_bytes(), original)

    def test_closed_owner_refuses(self):
        owner = capsule.CapsuleOwner.create(self.path); owner.close()
        with self.assertRaises(capsule.CapsuleRefused): owner.store(self.selected())

    def test_cross_thread_cannot_read_or_release_owner(self):
        selected = self.selected()
        with capsule.CapsuleOwner.create(self.path) as owner:
            failures = []
            def other():
                for action in (owner._check, owner.close, lambda: owner.store(selected),
                               lambda: owner.read(expected_digest_hex="00" * 32)):
                    try: action()
                    except capsule.CapsuleRefused: failures.append(True)
            thread = threading.Thread(target=other); thread.start(); thread.join()
            self.assertEqual(failures, [True, True, True, True]); owner._check()
            self.assertFalse((self.path / capsule.CAPSULE_NAME).exists())

    def test_replaced_owner_directory_refuses(self):
        with capsule.CapsuleOwner.create(self.path) as owner:
            self.path.rename(self.directory / "old-owner"); self.path.mkdir(mode=0o700)
            with self.assertRaises(capsule.CapsuleRefused): owner._check()

    def test_replaced_owner_lock_refuses(self):
        with capsule.CapsuleOwner.create(self.path) as owner:
            lock = self.path / capsule.LOCK_NAME; lock.unlink(); retain(lock, capsule.LOCK_BYTES)
            with self.assertRaises(capsule.CapsuleRefused): owner._check()

    def test_store_partial_write_failure_preserves_bytes_and_poison(self):
        selected = self.selected(); original_write = os.write
        with capsule.CapsuleOwner.create(self.path) as owner:
            calls = []
            def failed(fd, wire):
                calls.append(True)
                if len(calls) == 1: return original_write(fd, wire[:7])
                raise OSError(errno.ENOSPC, "disclosed fixture fault")
            with patch.object(capsule.os, "write", side_effect=failed):
                with self.assertRaises(capsule.CapsuleRefused): owner.store(selected)
            self.assertEqual((self.path / capsule.CAPSULE_NAME).read_bytes(), self.wire(selected)[:7])
            with self.assertRaises(capsule.CapsuleRefused): owner._check()

    def test_file_fsync_failure_does_not_return_success_or_retry(self):
        selected = self.selected()
        with capsule.CapsuleOwner.create(self.path) as owner:
            with patch.object(capsule.os, "fsync", side_effect=OSError("disclosed fault")) as sync:
                with self.assertRaises(capsule.CapsuleRefused): owner.store(selected)
                self.assertEqual(sync.call_count, 1)
            self.assertEqual((self.path / capsule.CAPSULE_NAME).stat().st_mode & 0o777, 0o600)

    def test_directory_fsync_failure_retains_readable_hold_without_success_receipt(self):
        selected = self.selected(); sync = os.fsync
        with capsule.CapsuleOwner.create(self.path) as owner:
            def failed(fd):
                if fd == owner._fd: raise OSError("disclosed directory fault")
                return sync(fd)
            with patch.object(capsule.os, "fsync", side_effect=failed):
                with self.assertRaises(capsule.CapsuleRefused): owner.store(selected)
        with capsule.CapsuleOwner.open(self.path) as owner:
            view = owner.read(expected_digest_hex=self.digest(self.wire(selected)))
        self.assertIn("DOES NOT PROVE", view.review()["durability"])

    def test_write_interruption_propagates_and_poison_retains_empty_file(self):
        selected = self.selected()
        with capsule.CapsuleOwner.create(self.path) as owner:
            with patch.object(capsule.os, "write", side_effect=KeyboardInterrupt) as write:
                with self.assertRaises(KeyboardInterrupt): owner.store(selected)
                self.assertEqual(write.call_count, 1)
            self.assertEqual((self.path / capsule.CAPSULE_NAME).read_bytes(), b"")
            with self.assertRaises(capsule.CapsuleRefused): owner._check()

    def test_read_failure_and_interruption_are_not_retried(self):
        _, receipt = self.stored()
        for error in (OSError("disclosed read fault"), KeyboardInterrupt()):
            with capsule.CapsuleOwner.open(self.path) as owner:
                original = os.pread
                def failed(fd, size, offset):
                    if fd == owner._lock: return original(fd, size, offset)
                    raise error
                with patch.object(capsule.os, "pread", side_effect=failed):
                    with self.assertRaises(capsule.CapsuleRefused if isinstance(error, OSError) else KeyboardInterrupt):
                        owner.read(expected_digest_hex=receipt["capsule_sha256"])
                with self.assertRaises(capsule.CapsuleRefused): owner._check()

    def test_coherent_old_copy_has_no_currentness_or_restore_authority(self):
        selected, receipt = self.stored(1); copied = self.directory / "copied-owner"
        with capsule.CapsuleOwner.create(copied): pass
        source = self.path / capsule.CAPSULE_NAME; target = copied / capsule.CAPSULE_NAME
        retain(target, source.read_bytes()); target.chmod(0o400)
        with capsule.CapsuleOwner.open(copied) as owner:
            view = owner.read(expected_digest_hex=receipt["capsule_sha256"])
        self.assertEqual(view.projection(), selected.as_dict())
        self.assertEqual(view.review()["source_currentness"], "UNFILLED")
        self.assertEqual(view.review()["restore_fence"], "UNFILLED")

    def test_readable_bytes_do_not_authenticate_producer_or_fsync(self):
        view = self.read_value(self.wire())
        self.assertEqual(view.review()["producer_origin"], "NOT_AUTHENTICATED")
        self.assertIn("DOES NOT PROVE", view.review()["durability"])

    def test_returned_view_survives_owner_close_as_memory_only(self):
        _, receipt = self.stored()
        with capsule.CapsuleOwner.open(self.path) as owner:
            view = owner.read(expected_digest_hex=receipt["capsule_sha256"])
        self.assertEqual(view.digest_hex, receipt["capsule_sha256"])
        self.assertEqual(view.review()["recovery_action"], "NONE")

    def test_frozen_partial_review_is_not_promoted(self):
        selected = self.selected(); view = self.read_value(self.wire(selected))
        self.assertEqual(view.review()["frozen_partial_review"], selected.partial_hold.review())
        self.assertEqual(view.review()["frozen_partial_review"]["durable_retention"], "NOT_IMPLEMENTED")

    def test_consumer_enters_zero_workers_and_leaves_capsule_unchanged(self):
        _, receipt = self.stored(); before = (self.path / capsule.CAPSULE_NAME).read_bytes()
        with patch("offline_session.nom_verifier.run_clean_environment_public_worker", side_effect=AssertionError("worker entry")):
            with capsule.CapsuleOwner.open(self.path) as owner:
                owner.read(expected_digest_hex=receipt["capsule_sha256"])
        self.assertEqual((self.path / capsule.CAPSULE_NAME).read_bytes(), before)

    def test_corpus_pins_all_163_prior_inputs_and_169_selected_inputs(self):
        manifest, measured = qualification.inputs()
        self.assertEqual(len(manifest["preserved_file_sha256"]), 163)
        self.assertEqual(len(measured), 169)
        self.assertEqual(measured, self.capsule_report["input_sha256"])

    def test_fixture_actors_exit_73_at_all_seven_selected_cuts(self):
        rows = self.capsule_report["cases"]
        self.assertEqual([r["cut"] for r in rows], list(capsule.PHASES))
        self.assertEqual([r["actor_exit_code"] for r in rows], [73] * 7)
        self.assertEqual([r["outcome"] for r in rows],
            ["REFUSED; INCOMPLETE OR WRITABLE SHAPE"] * 3 + ["HOLD"] * 4)

    def test_fixture_requests_extract_signature_from_exact_short_original(self):
        row = self.capsule_report["cases"][0]["actor_worker_calls"][1]
        request = json.loads(bytes.fromhex(row["request_hex"]))
        self.assertEqual(request["completion_hex"], self.short)
        self.assertEqual(len(request["completion_hex"]), 128)
        qualification.check_cases(self.capsule_report)

    def test_forged_actor_exit_and_consumer_work_refuse(self):
        for key,value in (("actor_exit_code", 0), ("consumer_worker_calls", 1)):
            report = copy.deepcopy(self.capsule_report); report["cases"][0][key] = value
            with self.assertRaises(ValueError): qualification.check_cases(report)

    def test_missing_original_worker_request_refuses(self):
        report = copy.deepcopy(self.capsule_report); report["cases"][0]["actor_worker_calls"].pop()
        with self.assertRaises(ValueError): qualification.check_cases(report)

    def test_changed_worker_reply_or_signature_context_refuses(self):
        for key,value in (("stdout_hex", "00"), ("request_hex", "00"), ("exit_code", 2)):
            report = copy.deepcopy(self.capsule_report)
            report["cases"][0]["actor_worker_calls"][1][key] = value
            with self.assertRaises(ValueError): qualification.check_cases(report)

    def test_readability_cannot_promote_copied_capsule_currentness(self):
        report = copy.deepcopy(self.capsule_report)
        report["coherent_old_copy"]["consumer"]["review"]["source_currentness"] = "VERIFIED"
        with self.assertRaises(ValueError): qualification.check_cases(report)


if __name__ == "__main__": unittest.main()
