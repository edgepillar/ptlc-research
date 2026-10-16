"""Stored descriptions cannot enter native comparison as actual custody."""
from pathlib import Path
import unittest
from unittest.mock import patch

from offline_session import nom_anchor_lifecycle as lifecycle
from qualification import nom_anchor_sqlite_comparison as comparison


class SqlComparisonCustodyRefusals(unittest.TestCase):
    def test_missing_actual_custody_refuses_before_binary_read(self):
        with patch.object(Path, 'read_bytes') as read:
            with self.assertRaises(ValueError):
                comparison.compare_prepared(None, None, None, None, None, None, None)
        read.assert_not_called()

    def test_descriptors_cannot_replace_original_objects(self):
        selected = dict(anchors={name: dict(revision=0) for name in
            ('initial', 'active', 'after_read', 'after_third', 'retired')},
            requests={name: dict(kind='ADVANCE') for name in ('first', 'read', 'third', 'retirement')})
        with self.assertRaises(ValueError):
            comparison.require_actual_custody(selected)

    def test_forged_exact_types_without_complete_inputs_are_refused(self):
        selected = dict(anchors={name: object.__new__(lifecycle.ReferenceAnchorState) for name in
            ('initial', 'active', 'after_read', 'after_third', 'retired')},
            requests={name: object.__new__(lifecycle.ReferenceAnchorTransition) for name in
                ('first', 'read', 'third', 'retirement')})
        with self.assertRaises(ValueError) as refused:
            comparison.require_actual_custody(selected)
        self.assertEqual(str(refused.exception), 'complete actual reference custody refused')
