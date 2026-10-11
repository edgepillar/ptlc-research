"""Public retention evidence and honest coherent-restore counterexamples."""

import copy
import json
import os
from pathlib import Path
import shutil
import tempfile
import threading
import unittest
from unittest.mock import patch

from offline_session import nom_retention as retention
from offline_session.nom_recovery import synthetic_claim
from nom_retention_support import MOMENTA, TERMS, open_store, original, selection, wire


class NoMRetentionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.root.chmod(0o700)
        self.path = self.root / "evidence.log"

    def open(self, path=None):
        store = open_store(path or self.path)
        self.addCleanup(store.close)
        return store

    def seed(self, store):
        for leg in ("short", "long"):
            store.retain_original(leg, original(leg))
        store.retain_observation("previous", wire(MOMENTA["baseline"]), disclosure_possible=True)

    def test_empty_selection_is_not_evidence_or_permission(self):
        status = self.open().status()
        self.assertEqual((status["sequence"], status["originals"], status["observation_ids"]), (1, {}, []))
        self.assertFalse(status["disclosure_possible"])
        self.assertEqual((status["accepted_branch"], status["recovery_action"]), ("NONE", "NONE"))
        self.assertEqual((status["source_authority"], status["power_loss"], status["rollback_or_clone"]),
                         ("UNFILLED", "UNQUALIFIED", "UNPROTECTED"))
        self.assertEqual((status["application"], status["core"]), ("NO-GO", "NO-GO"))
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_two_originals_and_all_comparison_vectors_survive_reopen(self):
        for number, vector in enumerate(MOMENTA["reorg_vectors"]):
            path = self.root / ("vector-" + str(number) + ".log")
            with self.open(path) as store:
                for leg in ("short", "long"):
                    store.retain_original(leg, original(leg))
                store.retain_observation("previous", wire(vector["previous"]), disclosure_possible=True)
                store.retain_observation("candidate", wire(vector["candidate"]), previous_id="previous")
                plan = store.observation("candidate")["analysis"]["comparison"]
                self.assertEqual(plan["relation"], vector["expect_relation"])
                self.assertEqual(plan["recheck_inclusions"], vector["expect_recheck_inclusions"])
            with self.open(path) as reopened:
                self.assertEqual(reopened.observation("previous")["wire"], wire(vector["previous"]))
                self.assertEqual(reopened.observation("candidate")["wire"], wire(vector["candidate"]))
                self.assertTrue(reopened.status()["disclosure_possible"])
                for leg in ("short", "long"):
                    self.assertEqual(reopened.original(leg), original(leg))

    def test_every_structural_claim_is_retained_even_when_refused(self):
        store = self.open()
        for number, vector in enumerate(MOMENTA["claim_vectors"]):
            ident = "claim-" + str(number)
            raw = wire(vector["claim"])
            store.retain_observation(ident, raw)
            row = store.observation(ident)
            self.assertEqual(row["wire"], raw)
            # This store freezes its own selection; a vector's alternative
            # selected anchor/inclusions is not permission to change it.
            self.assertEqual(row["analysis"]["recovery_action"], "NONE")
            self.assertEqual(row["analysis"]["source_authority"], "UNFILLED")
        self.assertEqual(len(store.status()["observation_ids"]), len(MOMENTA["claim_vectors"]))

    def test_malformed_empty_duplicate_nonfinite_nonascii_and_deep_replies_are_retained(self):
        store = self.open()
        store.retain_observation("positive", wire(MOMENTA["baseline"]), disclosure_possible=True)
        invalid = (b"", b"{", b"null", b'[{"a":0,"a":1}]', b'{"x":NaN}', b"\xff", b"[" * 17 + b"0" + b"]" * 17)
        for number, raw in enumerate(invalid):
            ident = "refused-" + str(number)
            store.retain_observation(ident, raw, previous_id="positive")
            row = store.observation(ident)
            self.assertEqual(row["wire"], raw)
            self.assertEqual(row["analysis"]["inspection"]["structure"], "REFUSED")
            self.assertEqual(row["analysis"]["comparison"]["relation"], "UNKNOWN")
        store.close()
        reopened = self.open()
        self.assertTrue(reopened.status()["disclosure_possible"])
        self.assertEqual(reopened.observation("positive")["analysis"]["inspection"]["structure"], "MATCH")
        for number, raw in enumerate(invalid):
            self.assertEqual(reopened.observation("refused-" + str(number))["wire"], raw)

    def test_noncanonical_claim_spacing_is_preserved_without_reencoding(self):
        store = self.open()
        raw = b" \n" + json.dumps(MOMENTA["baseline"], indent=1).encode("ascii") + b"\n "
        store.retain_observation("spacing", raw)
        self.assertEqual(store.observation("spacing")["wire"], raw)
        self.assertEqual(store.observation("spacing")["analysis"]["inspection"]["structure"], "MATCH")
        store.close()
        self.assertEqual(self.open().observation("spacing")["wire"], raw)

    def test_common_prefix_funding_still_requires_fresh_funding_and_live_entry(self):
        store = self.open()
        vector = next(value for value in MOMENTA["reorg_vectors"] if value["id"] == "divergent-fork-rechecks-displaced")
        store.retain_observation("previous", wire(vector["previous"]))
        store.retain_observation("fork", wire(vector["candidate"]), previous_id="previous")
        result = store.observation("fork")["analysis"]
        self.assertNotIn("funding", result["comparison"]["recheck_inclusions"])
        self.assertTrue(result["revalidate_funding_before_recovery"])
        self.assertTrue(result["revalidate_live_entry_before_recovery"])
        self.assertEqual(result["comparison"]["durable_retention"], "NOT_IMPLEMENTED")
        self.assertEqual(result["comparison"]["accepted_branch"], "NONE")

    def test_missing_shorter_and_conflicting_claims_cannot_erase_prior_evidence(self):
        store = self.open()
        self.seed(store)
        for number, vector in enumerate(MOMENTA["reorg_vectors"]):
            store.retain_observation("next-" + str(number), wire(vector["candidate"]), previous_id="previous", disclosure_possible=False)
        self.assertTrue(store.status()["disclosure_possible"])
        self.assertEqual(store.observation("previous")["wire"], wire(MOMENTA["baseline"]))
        self.assertEqual(store.original("short"), original("short"))
        self.assertEqual(store.original("long"), original("long"))

    def test_disclosure_is_monotone_even_before_any_original_is_retained(self):
        store = self.open()
        store.note_possible_disclosure()
        status = store.status()
        store.note_possible_disclosure()
        self.assertEqual(store.status(), status)
        store.retain_observation("missing", b"", disclosure_possible=False)
        store.close()
        self.assertTrue(self.open().status()["disclosure_possible"])

    def test_original_replay_is_free_and_replacement_is_refused(self):
        store = self.open()
        ack = store.retain_original("short", original("short"))
        status = store.status()
        self.assertEqual(ack, store.retain_original("short", original("short")))
        replacement = synthetic_claim(TERMS, "short", "00" * 64)
        with self.assertRaises(retention.RetentionRefused):
            store.retain_original("short", replacement)
        self.assertEqual(store.status(), status)
        self.assertEqual(store.original("short"), original("short"))

    def test_synthetic_signature_is_not_authenticated_by_storage(self):
        store = self.open()
        raw = synthetic_claim(TERMS, "short", "00" * 64)
        ack = store.retain_original("short", raw)
        self.assertEqual(store.original("short"), raw)
        self.assertEqual((ack["source_authority"], ack["recovery_action"]), ("UNFILLED", "NONE"))

    def test_observation_id_replay_is_free_and_changed_inputs_are_refused(self):
        store = self.open()
        raw = wire(MOMENTA["baseline"])
        ack = store.retain_observation("previous", raw)
        status = store.status()
        self.assertEqual(ack, store.retain_observation("previous", raw))
        for options in ({"wire": raw + b" "}, {"wire": raw, "previous_id": "previous"},
                        {"wire": raw, "disclosure_possible": True}):
            with self.assertRaises(retention.RetentionRefused):
                store.retain_observation("previous", **options)
        self.assertEqual(store.status(), status)

    def test_invalid_original_types_legs_bounds_context_and_spacing_write_nothing(self):
        store = self.open()
        status, before = store.status(), self.path.read_bytes()
        invalid = ((True, original("short")), ("other", b"x"), ("short", "x"), ("short", b""),
                   ("short", bytearray(original("short"))), ("short", b"x" * (8192 + 1)),
                   ("short", original("long")), ("short", b" " + original("short")))
        for leg, raw in invalid:
            with self.assertRaises(retention.RetentionRefused):
                store.retain_original(leg, raw)
        self.assertEqual(store.status(), status)
        self.assertEqual(self.path.read_bytes(), before)

    def test_invalid_observation_types_ids_bounds_and_previous_refs_write_nothing(self):
        store = self.open()
        before = self.path.read_bytes()
        for ident, raw, options in ((True, b"", {}), ("", b"", {}), ("x" * 65, b"", {}),
                ("test", "text", {}), ("test", bytearray(b""), {}), ("test", b"x" * (512 * 1024 + 1), {}),
                ("test", b"", {"disclosure_possible": 1}), ("test", b"", {"previous_id": "missing"}),
                ("test", b"", {"previous_id": True})):
            with self.assertRaises(retention.RetentionRefused):
                store.retain_observation(ident, raw, **options)
        self.assertEqual(self.path.read_bytes(), before)

    def test_mutable_selection_and_returned_descriptions_do_not_change_retained_bytes(self):
        selected = selection()
        terms = copy.deepcopy(TERMS)
        store = retention.NomEvidenceRetention.open(self.path, terms, **selected)
        self.addCleanup(store.close)
        terms["chain_id"] = "70"
        selected["selected_anchor_claim"]["hash_hex"] = "ff" * 32
        selected["retained_inclusions"].clear()
        store.retain_observation("previous", wire(MOMENTA["baseline"]))
        result = store.observation("previous")
        result["wire"] = b"changed"
        result["analysis"]["inspection"]["structure"] = "FORGED"
        store.status()["observation_ids"].clear()
        self.assertEqual(store.observation("previous")["analysis"]["inspection"]["structure"], "MATCH")
        self.assertEqual(store.status()["observation_ids"], ["previous"])

    def test_complete_selection_cannot_migrate_on_reopen(self):
        store = self.open()
        self.seed(store)
        store.close()
        before = self.path.read_bytes()
        changes = []
        for field in ("session_id_hex", "genesis_hash_hex"):
            terms = copy.deepcopy(TERMS)
            terms[field] = "ff" * 32
            changes.append((terms, selection()))
        selected = selection()
        selected["selected_anchor_claim"]["hash_hex"] = "ff" * 32
        changes.append((TERMS, selected))
        selected = selection()
        selected["retained_inclusions"][0]["header"]["hash_hex"] = "ff" * 32
        changes.append((TERMS, selected))
        for terms, selected in changes:
            with self.assertRaises(retention.RetentionQuarantined):
                retention.NomEvidenceRetention.open(self.path, terms, **selected)
            self.assertEqual(self.path.read_bytes(), before)

    def test_invalid_selection_is_refused_before_file_creation(self):
        for terms, selected in (({}, selection()), (TERMS, {"selected_anchor_claim": {}, "retained_inclusions": []}),
                                (TERMS, dict(selection(), retained_inclusions=[{}]))):
            with self.assertRaises(retention.RetentionRefused):
                retention.NomEvidenceRetention.open(self.path, terms, **selected)
            self.assertFalse(self.path.exists())

    def test_observation_count_exhaustion_never_evicts_evidence_or_disclosure(self):
        store = self.open()
        store.retain_original("short", original("short"))
        for number in range(retention.MAX_OBSERVATIONS):
            store.retain_observation("item-" + str(number), b"", disclosure_possible=number == 0)
        before = store.status()
        with self.assertRaises(retention.RetentionRefused):
            store.retain_observation("overflow", b"", disclosure_possible=False)
        self.assertEqual(store.status(), before)
        self.assertTrue(before["disclosure_possible"])
        self.assertEqual(store.original("short"), original("short"))

    def test_real_byte_allowance_exhaustion_keeps_every_bounded_raw_reply(self):
        store = self.open()
        store.note_possible_disclosure()
        count = 0
        while True:
            try:
                store.retain_observation("large-" + str(count), b" " * (512 * 1024))
            except retention.RetentionRefused:
                break
            count += 1
        self.assertGreater(count, 0)
        self.assertLess(count, retention.MAX_OBSERVATIONS)
        self.assertLessEqual(self.path.stat().st_size, retention.MAX_LOG_BYTES)
        self.assertEqual(len(store.status()["observation_ids"]), count)
        self.assertTrue(store.status()["disclosure_possible"])
        store.close()
        self.assertEqual(self.open().observation("large-0")["wire"], b" " * (512 * 1024))

    def test_separately_selected_small_event_limit_refuses_without_mutation(self):
        with patch.object(retention, "MAX_EVENTS", 3):
            store = self.open()
            store.retain_original("short", original("short"))
            store.note_possible_disclosure()
            before = self.path.read_bytes()
            with self.assertRaises(retention.RetentionRefused):
                store.retain_observation("overflow", b"")
            self.assertEqual(self.path.read_bytes(), before)
            store.close()
            self.assertTrue(self.open().status()["disclosure_possible"])

    def test_acknowledgement_follows_file_and_initial_directory_fsync(self):
        calls = []
        real = os.fsync
        def sync(descriptor):
            calls.append(descriptor)
            return real(descriptor)
        with patch.object(retention.os, "fsync", side_effect=sync):
            store = self.open()
            self.assertEqual(calls, [store._fd, store._directory])
            calls.clear()
            ack = store.retain_original("short", original("short"))
            self.assertEqual(calls, [store._fd])
            self.assertEqual(ack["local_retention"], "SELECTED_FSYNC_ACKNOWLEDGED")

    def test_short_writes_finish_exact_record_before_acknowledgement(self):
        store = self.open()
        real = os.write
        with patch.object(retention.os, "write", side_effect=lambda fd, raw: real(fd, raw[:13])):
            store.retain_observation("short-writes", wire(MOMENTA["baseline"]))
        store.close()
        self.assertEqual(self.open().observation("short-writes")["wire"], wire(MOMENTA["baseline"]))

    def test_reopen_syncs_validated_file_and_directory_before_local_replay_ack(self):
        store = self.open()
        store.retain_original("short", original("short"))
        store.close()
        calls = []
        real = os.fsync
        def sync(fd):
            calls.append(fd)
            return real(fd)
        with patch.object(retention.os, "fsync", side_effect=sync):
            reopened = self.open()
            self.assertEqual(calls, [reopened._fd, reopened._directory])
            self.assertEqual(reopened.retain_original("short", original("short"))["local_retention"],
                             "SELECTED_FSYNC_ACKNOWLEDGED")

    def test_reopen_sync_failure_returns_no_owned_handle_and_preserves_valid_history(self):
        store = self.open()
        self.seed(store)
        store.close()
        before = self.path.read_bytes()
        with patch.object(retention.os, "fsync", side_effect=OSError("synthetic reopen sync interruption")):
            with self.assertRaises(retention.RetentionQuarantined):
                self.open()
        self.assertEqual(self.path.read_bytes(), before)
        reopened = self.open()
        self.assertTrue(reopened.status()["disclosure_possible"])
        self.assertEqual(reopened.original("short"), original("short"))

    def test_write_failure_before_bytes_returns_unknown_and_requires_reopen(self):
        store = self.open()
        before = self.path.read_bytes()
        with patch.object(retention.os, "write", side_effect=OSError("untrusted-provider-details")):
            with self.assertRaises(retention.RetentionOutcomeUnknown) as caught:
                store.retain_observation("candidate", b"")
        self.assertNotIn("untrusted-provider-details", str(caught.exception))
        with self.assertRaises(retention.RetentionQuarantined):
            store.status()
        self.assertEqual(self.path.read_bytes(), before)
        store.close()
        self.assertEqual(self.open().status()["observation_ids"], [])

    def test_partial_write_failure_preserves_torn_bytes_and_quarantines_without_repair(self):
        store = self.open()
        before = self.path.read_bytes()
        real = os.write
        calls = 0
        def write_some(fd, raw):
            nonlocal calls
            calls += 1
            if calls == 1:
                return real(fd, raw[:31])
            raise OSError("synthetic write interruption")
        with patch.object(retention.os, "write", side_effect=write_some):
            with self.assertRaises(retention.RetentionOutcomeUnknown):
                store.retain_observation("candidate", b"")
        store.close()
        torn = self.path.read_bytes()
        self.assertTrue(torn.startswith(before))
        self.assertGreater(len(torn), len(before))
        with self.assertRaises(retention.RetentionQuarantined):
            self.open()
        self.assertEqual(self.path.read_bytes(), torn)

    def test_failed_file_fsync_has_unknown_result_and_separate_reopen_preserves_full_event(self):
        store = self.open()
        with patch.object(retention.os, "fsync", side_effect=OSError("synthetic sync interruption")):
            with self.assertRaises(retention.RetentionOutcomeUnknown):
                store.retain_observation("candidate", b"", disclosure_possible=True)
        with self.assertRaises(retention.RetentionQuarantined):
            store.status()
        store.close()
        reopened = self.open()
        self.assertTrue(reopened.status()["disclosure_possible"])
        self.assertEqual(reopened.observation("candidate")["wire"], b"")

    def test_post_fsync_lost_acknowledgement_returns_unknown_despite_retained_disclosure(self):
        store = self.open()
        def fail(label):
            if label == "append-before-ack":
                raise retention.RetentionRefused("synthetic lost result")
        with patch.object(store, "_cut", side_effect=fail):
            with self.assertRaises(retention.RetentionOutcomeUnknown):
                store.note_possible_disclosure()
        store.close()
        self.assertTrue(self.open().status()["disclosure_possible"])

    def test_directory_sync_failure_leaves_original_init_evidence_without_positive_ack(self):
        real = os.fsync
        calls = 0
        def sync(fd):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("synthetic directory interruption")
            real(fd)
        with patch.object(retention.os, "fsync", side_effect=sync):
            with self.assertRaises(retention.RetentionOutcomeUnknown):
                self.open()
        before = self.path.read_bytes()
        self.assertEqual(self.open().status()["sequence"], 1)
        self.assertEqual(self.path.read_bytes(), before)

    def test_closed_foreign_thread_and_reentrant_handles_cannot_read_write_or_close(self):
        store = self.open()
        errors = []
        def foreign():
            for action in (store.status, lambda: store.retain_observation("foreign", b""), store.close):
                try:
                    action()
                except retention.RetentionQuarantined:
                    errors.append(True)
        thread = threading.Thread(target=foreign)
        thread.start()
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(errors), 3)
        def reentrant(label):
            if label == "append-before-write":
                with self.assertRaises(retention.RetentionQuarantined):
                    store.status()
                with self.assertRaises(retention.RetentionQuarantined):
                    store.close()
        with patch.object(store, "_cut", side_effect=reentrant):
            store.retain_observation("valid", b"")
        store.close()
        with self.assertRaises(retention.RetentionQuarantined):
            store.status()

    def test_cooperating_owner_exclusion_releases_only_after_close(self):
        store = self.open()
        with self.assertRaises(retention.RetentionBusy):
            self.open()
        store.close()
        self.assertEqual(self.open().status()["sequence"], 1)

    def test_live_owner_detects_same_size_corruption_and_path_replacement(self):
        store = self.open()
        data = self.path.read_bytes()
        self.path.write_bytes(data.replace(b'"sequence":1', b'"sequence":2', 1))
        with self.assertRaises(retention.RetentionQuarantined):
            store.status()
        store.close()
        self.path.write_bytes(data)
        store = self.open()
        replacement = self.root / "replacement.log"
        replacement.write_bytes(data)
        replacement.chmod(0o600)
        replacement.replace(self.path)
        with self.assertRaises(retention.RetentionQuarantined):
            store.status()

    def test_empty_torn_noncanonical_duplicate_and_extra_records_quarantine_without_repair(self):
        store = self.open()
        store.close()
        good = self.path.read_bytes()
        for raw in (b"", good[:-1], good + b"{", b" " + good, good + b"\n",
                    good.replace(b'"sequence":1', b'"sequence":1,"sequence":1', 1)):
            self.path.write_bytes(raw)
            with self.assertRaises(retention.RetentionQuarantined):
                self.open()
            self.assertEqual(self.path.read_bytes(), raw)

    def test_rehashed_forged_inspection_still_fails_recomputed_analysis(self):
        store = self.open()
        store.retain_observation("refused", b"")
        store.close()
        records = [json.loads(line) for line in self.path.read_bytes().splitlines()]
        records[-1]["event"]["analysis"]["inspection"]["structure"] = "MATCH"
        old = {key: value for key, value in records[-1].items() if key != "hash_hex"}
        records[-1]["hash_hex"] = retention.NomEvidenceRetention._record_hash(old)
        bad = b"".join(retention._canonical(value) + b"\n" for value in records)
        self.path.write_bytes(bad)
        with self.assertRaises(retention.RetentionQuarantined):
            self.open()
        self.assertEqual(self.path.read_bytes(), bad)

    def test_private_file_directory_hardlink_and_symlink_boundaries_refuse(self):
        store = self.open()
        store.close()
        self.path.chmod(0o644)
        with self.assertRaises(retention.RetentionRefused):
            self.open()
        self.path.chmod(0o600)
        alias = self.root / "alias.log"
        os.link(self.path, alias)
        with self.assertRaises(retention.RetentionRefused):
            self.open()
        alias.unlink()
        alias.symlink_to(self.path.name)
        with self.assertRaises(retention.RetentionRefused):
            self.open(alias)
        self.root.chmod(0o755)
        with self.assertRaises(retention.RetentionRefused):
            self.open()
        self.root.chmod(0o700)

    def test_coherent_old_restore_erases_disclosure_and_admits_another_future(self):
        store = self.open()
        saved = self.path.read_bytes()
        self.seed(store)
        completed = store.status()
        store.close()
        self.path.write_bytes(saved)
        restored = self.open()
        self.assertFalse(restored.status()["disclosure_possible"])
        self.assertEqual(restored.status()["originals"], {})
        other = synthetic_claim(TERMS, "short", "00" * 64)
        restored.retain_original("short", other)
        restored.retain_observation("previous", b"")
        self.assertNotEqual(restored.status()["head_hex"], completed["head_hex"])
        self.assertEqual(restored.original("short"), other)
        self.assertEqual(restored.status()["rollback_or_clone"], "UNPROTECTED")

    def test_separate_copies_accept_incomparable_evidence_under_independent_locks(self):
        store = self.open()
        self.seed(store)
        store.close()
        copied = self.root / "copied.log"
        shutil.copyfile(self.path, copied)
        copied.chmod(0o600)
        first, second = self.open(), self.open(copied)
        first.retain_observation("candidate", b"first", previous_id="previous")
        second.retain_observation("candidate", b"second", previous_id="previous")
        self.assertNotEqual(first.status()["head_hex"], second.status()["head_hex"])
        self.assertEqual(first.observation("candidate")["wire"], b"first")
        self.assertEqual(second.observation("candidate")["wire"], b"second")


if __name__ == "__main__":
    unittest.main()
