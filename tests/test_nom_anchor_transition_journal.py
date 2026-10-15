"""Actual custody, selected POSIX retention and abrupt process-death controls."""
import copy
import hashlib
import os
from pathlib import Path
import resource
import signal
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from offline_session import nom_anchor_transition_journal as journal
from offline_session import nom_anchor_lifecycle as lifecycle
from scripts import qualify_nom_anchor_lifecycle as prior


class NoMAnchorTransitionJournalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.f = prior.fixture_contexts()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.path = self.root / "anchor.log"
        self.before, self.held = self.f['anchors']['initial'], self.f['holds']['first']

    def create(self, path=None, before=None, held=None, cls=journal.AnchorTransitionJournal):
        owner = cls.create(path or self.path, before or self.before, held or self.held)
        self.addCleanup(owner.close)
        return owner

    def reopen(self, path=None, before=None, held=None, cls=journal.AnchorTransitionJournal):
        owner = cls.open_existing(path or self.path, before or self.before, held or self.held)
        self.addCleanup(owner.close)
        return owner

    def hold(self, value):
        self.assertEqual((value['state'], value['publication_outcome'], value['recovery_action']), ('HOLD', 'UNKNOWN', 'NONE'))
        self.assertEqual((value['application'], value['core']), ('NO-GO', 'NO-GO'))
        for field in ('new_work_allowed', 'automatic_retry', 'same_request_republication', 'replenish_work',
                      'replacement_original_allowed', 'automatic_bootstrap', 'automatic_reenrollment'):
            self.assertIs(value[field], False)

    def write(self, path, data):
        path.write_bytes(data)
        path.chmod(0o600)

    def child(self, operation, expected):
        pid = os.fork()
        if pid == 0:
            try:
                operation()
            except BaseException:
                os._exit(91)
            os._exit(92)
        limit = time.monotonic() + 60
        while time.monotonic() < limit:
            done, status = os.waitpid(pid, os.WNOHANG)
            if done:
                self.assertEqual(os.waitstatus_to_exitcode(status), expected)
                return
            time.sleep(0.02)
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
        self.fail('selected child exceeded its finite deadline')

    def death(self, path, point, *, creating):
        before, held = self.before, self.held
        class DeathOwner(journal.AnchorTransitionJournal):
            def _cut(self, label):
                if label == point:
                    os.kill(os.getpid(), signal.SIGKILL)
        def operation():
            if creating:
                DeathOwner.create(path, before, held)
            else:
                owner = DeathOwner.open_existing(path, before, held)
                owner.commit_retained_reference()
        self.child(operation, -signal.SIGKILL)

    def test_open_missing_file_never_creates_or_supplies_safe_absence(self):
        with self.assertRaises(journal.AnchorJournalMissing):
            self.reopen()
        self.assertFalse(self.path.exists())
        self.assertEqual(list(self.root.iterdir()), [])

    def test_explicit_creation_is_exclusive_and_preserves_the_old_record(self):
        owner = self.create()
        before = self.path.read_bytes()
        with self.assertRaises(journal.AnchorJournalRefused):
            self.create()
        self.assertEqual(self.path.read_bytes(), before)
        self.hold(owner.status())

    def test_complete_existing_record_reopens_only_with_actual_original_custody(self):
        owner = self.create()
        ack = owner.status()
        owner.close()
        self.assertEqual(self.reopen().status(), ack)
        self.assertEqual(ack['file_sha256'], hashlib.sha256(self.path.read_bytes()).hexdigest())
        self.assertEqual(ack['record_count'], 1)
        self.hold(ack)

    def test_before_transition_lookup_keeps_proposed_unknown_work_and_no_retry(self):
        owner = self.create()
        before = self.path.read_bytes()
        value = owner.inspect(self.f['contexts']['primary'])
        self.assertEqual(value['reference_acknowledgment_relation'], 'REFERENCE_REQUEST_NOT_FOUND')
        self.assertEqual(len(value['effective_charged_work']), 2)
        self.assertEqual(self.path.read_bytes(), before)
        self.hold(value)
        self.hold(value['local_reference_retention'])

    def test_fixed_reference_transition_appends_once_and_duplicate_refuses(self):
        owner = self.create()
        first = self.path.read_bytes()
        ack = owner.commit_retained_reference()
        complete = self.path.read_bytes()
        self.assertTrue(complete.startswith(first))
        self.assertEqual(len(complete.splitlines()), 2)
        self.assertEqual(ack['record_count'], 2)
        with self.assertRaises(journal.AnchorJournalRefused):
            owner.commit_retained_reference()
        self.assertEqual(self.path.read_bytes(), complete)
        owner.close()
        self.assertEqual(self.reopen().status(), ack)
        self.hold(ack)

    def test_repeated_inspection_cannot_commit_retry_or_mutate_retained_history(self):
        owner = self.create()
        owner.commit_retained_reference()
        before = self.path.read_bytes()
        with patch.object(owner, 'commit_retained_reference', side_effect=AssertionError('lookup must not append')):
            first = owner.inspect(self.f['contexts']['primary'])
            second = owner.inspect(self.f['contexts']['primary'])
        self.assertEqual(first, second)
        self.assertEqual(first['reference_acknowledgment_relation'], 'EXACT_RETAINED_REFERENCE_REQUEST')
        self.assertEqual(self.path.read_bytes(), before)
        self.hold(first)

    def test_retirement_preserves_complete_history_and_terminal_tombstone(self):
        before, held = self.f['anchors']['after_third'], self.f['holds']['retirement']
        owner = self.create(before=before, held=held)
        ack = owner.commit_retained_reference()
        self.assertEqual(ack['reference_anchor_phase'], 'RETIRED')
        image = self.path.read_bytes()
        owner.close()
        reopened = self.reopen(before=before, held=held)
        value = reopened.inspect(self.f['contexts']['third'])
        self.assertEqual(value['reference_anchor_phase'], 'RETIRED')
        self.assertEqual(len(value['effective_charged_work']), 3)
        with self.assertRaises(journal.AnchorJournalRefused):
            reopened.commit_retained_reference()
        self.assertEqual(image, self.path.read_bytes())
        self.hold(value)

    def test_descriptors_digests_and_missing_actual_contexts_never_create_files(self):
        for before, held in ((self.before.as_dict(), self.held), (self.before, self.held.as_dict()),
                             (self.before.digest_hex, self.held), (None, self.held), (self.before, None)):
            with self.assertRaises(journal.AnchorJournalRefused):
                journal.AnchorTransitionJournal.create(self.path, before, held)
            self.assertFalse(self.path.exists())

    def test_changed_request_before_state_or_actual_custody_refuses_without_writing(self):
        owner = self.create()
        image = self.path.read_bytes()
        owner.close()
        other = prior.advance(self.before, self.f['traces']['second'], 'f8')
        other_hold = lifecycle.retain_unknown_anchor_acknowledgment(other)
        for before, held in ((self.before, other_hold), (self.f['anchors']['active'], self.held)):
            with self.assertRaises(journal.AnchorJournalRefused):
                journal.AnchorTransitionJournal.open_existing(self.path, before, held)
            self.assertEqual(image, self.path.read_bytes())

    def test_noncanonical_reframed_and_altered_records_are_preserved_and_refused(self):
        owner = self.create()
        image = self.path.read_bytes()
        owner.close()
        for number, data in enumerate((b' ' + image, image + b'\n', image.replace(b'UNKNOWN', b'KNOWN__', 1),
                                       image.replace(b'false', b'true', 1), image.replace(b'"position":1', b'"position":1.0', 1))):
            path = self.root / ('altered-' + str(number) + '.log')
            self.write(path, data)
            with self.assertRaises(journal.AnchorJournalRefused):
                self.reopen(path)
            self.assertEqual(path.read_bytes(), data)

    def test_empty_partial_duplicate_and_reordered_records_refuse_without_repair(self):
        owner = self.create()
        initial = self.path.read_bytes()
        owner.commit_retained_reference()
        complete = self.path.read_bytes()
        transition = complete[len(initial):]
        owner.close()
        for number, data in enumerate((b'', initial[:-1], complete[:-1], initial + initial,
                                       transition + initial, complete + transition, complete + b'x')):
            path = self.root / ('partial-' + str(number) + '.log')
            self.write(path, data)
            with self.assertRaises(journal.AnchorJournalRefused):
                self.reopen(path)
            self.assertEqual(path.read_bytes(), data)

    def test_finite_byte_bounds_refuse_before_creation_and_do_not_drop_history(self):
        # Isolated record-model caps only; no storage policy or free-space change.
        for field in ('MAX_RECORD_BYTES', 'MAX_LOG_BYTES'):
            with patch.object(journal, field, 1):
                with self.assertRaises(journal.AnchorJournalRefused):
                    self.create()
            self.assertFalse(self.path.exists())
        owner = self.create()
        image = self.path.read_bytes()
        self.assertLessEqual(len(image), journal.MAX_RECORD_BYTES)
        self.assertEqual(len(image.splitlines()), 1)
        self.hold(owner.status())

    def test_private_modes_symlinks_and_hardlinks_are_checked(self):
        owner = self.create()
        owner.close()
        alias = self.root / 'alias.log'
        alias.symlink_to(self.path.name)
        with self.assertRaises(journal.AnchorJournalRefused):
            self.reopen(alias)
        alias.unlink()
        os.link(self.path, alias)
        with self.assertRaises(journal.AnchorJournalRefused):
            self.reopen()
        alias.unlink()
        self.path.chmod(0o644)
        with self.assertRaises(journal.AnchorJournalRefused):
            self.reopen()
        self.path.chmod(0o600)
        self.root.chmod(0o755)
        with self.assertRaises(journal.AnchorJournalRefused):
            self.reopen()

    def test_replaced_directory_entry_poisoning_cannot_return_cached_status(self):
        owner = self.create()
        image = self.path.read_bytes()
        moved = self.root / 'original.log'
        self.path.rename(moved)
        self.write(self.path, image)
        with self.assertRaises(journal.AnchorJournalQuarantined):
            owner.status()
        with self.assertRaises(journal.AnchorJournalQuarantined):
            owner.commit_retained_reference()
        self.assertEqual(self.path.read_bytes(), image)

    def test_external_tail_or_changed_actual_input_poison_the_live_owner(self):
        owner = self.create()
        with self.path.open('ab') as stream:
            stream.write(b'x')
        image = self.path.read_bytes()
        with self.assertRaises(journal.AnchorJournalQuarantined):
            owner.status()
        self.assertEqual(self.path.read_bytes(), image)
        owner.close()
        clone = copy.copy(self.held)
        path = self.root / 'actual.log'
        other = self.create(path, held=clone)
        object.__setattr__(clone, '_wire', clone._wire + b'\n')
        with self.assertRaises(journal.AnchorJournalQuarantined):
            other.status()

    def test_foreign_thread_cannot_write_inspect_or_close_owner(self):
        owner = self.create()
        outcomes = []
        def foreign():
            for operation in (owner.status, owner.commit_retained_reference, owner.close):
                try:
                    operation()
                except journal.AnchorJournalQuarantined:
                    outcomes.append('REFUSED')
        thread = threading.Thread(target=foreign)
        thread.start()
        thread.join(timeout=20)
        self.assertFalse(thread.is_alive())
        self.assertEqual(outcomes, ['REFUSED'] * 3)
        self.hold(owner.status())

    def test_inherited_owner_refuses_and_child_close_preserves_parent_exclusion(self):
        owner = self.create()
        def inherited():
            try:
                owner.status()
            except journal.AnchorJournalQuarantined:
                owner.close()
                os._exit(0)
        self.child(inherited, 0)
        with self.assertRaises(journal.AnchorJournalBusy):
            self.reopen()
        self.hold(owner.status())
        descriptor = owner._fd
        owner.close()
        with self.assertRaises(OSError):
            os.fstat(descriptor)
        self.hold(self.reopen().status())

    def test_failed_write_is_unknown_poisoned_and_preserves_exact_pending_record(self):
        owner = self.create()
        image = self.path.read_bytes()
        with patch.object(journal.os, 'write', side_effect=OSError('synthetic selected write failure')):
            with self.assertRaises(journal.AnchorJournalOutcomeUnknown):
                owner.commit_retained_reference()
        self.assertEqual(image, self.path.read_bytes())
        for operation in (owner.status, owner.commit_retained_reference):
            with self.assertRaises(journal.AnchorJournalQuarantined):
                operation()
        owner.close()
        self.hold(self.reopen().inspect(self.f['contexts']['primary']))

    def test_lost_ack_before_or_after_fsync_reopens_complete_bytes_without_retry(self):
        class FaultOwner(journal.AnchorTransitionJournal):
            point = None
            def _cut(self, label):
                if label == self.point:
                    raise OSError('synthetic selected acknowledgment failure')
        for number, point in enumerate(('append-before-fsync', 'append-after-fsync', 'append-before-ack')):
            path = self.root / ('lost-' + str(number) + '.log')
            owner = self.create(path, cls=FaultOwner)
            owner.point = point
            with self.assertRaises(journal.AnchorJournalOutcomeUnknown):
                owner.commit_retained_reference()
            with self.assertRaises(journal.AnchorJournalQuarantined):
                owner.status()
            image = path.read_bytes()
            owner.close()
            reopened = self.reopen(path)
            value = reopened.inspect(self.f['contexts']['primary'])
            self.assertEqual(value['reference_acknowledgment_relation'], 'EXACT_RETAINED_REFERENCE_REQUEST')
            self.assertEqual(path.read_bytes(), image)
            self.hold(value)
            reopened.close()

    def test_reopen_fsync_failure_reports_unknown_without_altering_or_replacing_record(self):
        owner = self.create()
        image = self.path.read_bytes()
        owner.close()
        with patch.object(journal.os, 'fsync', side_effect=OSError('synthetic selected fsync failure')):
            with self.assertRaises(journal.AnchorJournalOutcomeUnknown):
                self.reopen()
        self.assertEqual(image, self.path.read_bytes())
        self.hold(self.reopen().status())

    def test_actual_creation_death_preserves_empty_partial_or_complete_images(self):
        for number, point in enumerate(('append-before-write', 'append-first-write', 'append-after-fsync', 'append-before-ack')):
            path = self.root / ('creation-' + str(number) + '.log')
            self.death(path, point, creating=True)
            image = path.read_bytes()
            if point in ('append-before-write', 'append-first-write'):
                with self.assertRaises(journal.AnchorJournalRefused):
                    self.reopen(path)
            else:
                self.hold(self.reopen(path).status())
            self.assertEqual(path.read_bytes(), image)
            with self.assertRaises(journal.AnchorJournalRefused):
                self.create(path)

    def test_actual_transition_death_preserves_original_pending_request_and_unknown_work(self):
        for number, point in enumerate(('append-before-write', 'append-first-write', 'append-after-write',
                                       'append-after-fsync', 'append-before-ack')):
            path = self.root / ('transition-' + str(number) + '.log')
            owner = self.create(path)
            initial = path.read_bytes()
            owner.close()
            self.death(path, point, creating=False)
            image = path.read_bytes()
            self.assertTrue(image.startswith(initial))
            if point == 'append-first-write':
                self.assertEqual(len(image) - len(initial), journal.WRITE_CHUNK_BYTES)
                with self.assertRaises(journal.AnchorJournalRefused):
                    self.reopen(path)
            else:
                reopened = self.reopen(path)
                value = reopened.inspect(self.f['contexts']['primary'])
                expected = 'REFERENCE_REQUEST_NOT_FOUND' if point == 'append-before-write' else 'EXACT_RETAINED_REFERENCE_REQUEST'
                self.assertEqual(value['reference_acknowledgment_relation'], expected)
                self.hold(value)
                reopened.close()
            self.assertEqual(path.read_bytes(), image)

    def test_coherent_copies_restore_and_explicit_reenrollment_remain_unsafe(self):
        before, held = self.f['anchors']['after_third'], self.f['holds']['retirement']
        owner = self.create(before=before, held=held)
        old = self.path.read_bytes()
        owner.commit_retained_reference()
        retired = self.path.read_bytes()
        owner.close()
        self.assertNotEqual(old, retired)
        for number in range(2):
            path = self.root / ('copy-' + str(number) + '.log')
            self.write(path, old)
            cloned = self.reopen(path, before, held)
            self.assertEqual(cloned.status()['reference_anchor_phase'], 'ACTIVE')
            self.hold(cloned.commit_retained_reference())
            self.assertEqual(path.read_bytes(), retired)
            cloned.close()
        self.write(self.path, old)
        restored = self.reopen(before=before, held=held)
        self.assertEqual(restored.status()['reference_anchor_phase'], 'ACTIVE')
        self.hold(restored.status())
        other = self.create(self.root / 'reenrolled.log', before, held)
        self.hold(other.status())

    def test_real_native_file_size_limit_retains_torn_output_with_unknown_outcome(self):
        owner = self.create()
        initial = self.path.read_bytes()
        owner.close()
        def limited():
            selected = journal.AnchorTransitionJournal.open_existing(self.path, self.before, self.held)
            signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
            resource.setrlimit(resource.RLIMIT_FSIZE, (len(initial) + 100, len(initial) + 100))
            try:
                selected.commit_retained_reference()
            except journal.AnchorJournalOutcomeUnknown:
                try:
                    selected.status()
                except journal.AnchorJournalQuarantined:
                    selected.close()
                    os._exit(0)
        self.child(limited, 0)
        image = self.path.read_bytes()
        self.assertTrue(image.startswith(initial))
        self.assertEqual(len(image) - len(initial), 100)
        with self.assertRaises(journal.AnchorJournalRefused):
            self.reopen()
        self.assertEqual(self.path.read_bytes(), image)


if __name__ == '__main__':
    unittest.main()
