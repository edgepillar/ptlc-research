"""Descriptor substitution and finite storage material refusal boundaries."""
import unittest

from offline_session import nom_anchor_lifecycle as lifecycle
from qualification import nom_anchor_sqlite_material as material


class SqlAnchorMaterialRefusals(unittest.TestCase):
    def test_anchor_descriptor_cannot_supply_actual_custody(self):
        with self.assertRaises(material.MaterialRefused):
            material.anchor_bytes(dict(schema=lifecycle.STATE_SCHEMA, revision=0))

    def test_request_descriptor_cannot_supply_actual_custody(self):
        with self.assertRaises(material.MaterialRefused):
            material.request_material(dict(schema=lifecycle.REQUEST_SCHEMA))

    def test_incomplete_actual_anchor_is_a_sanitized_refusal(self):
        incomplete = object.__new__(lifecycle.ReferenceAnchorState)
        with self.assertRaises(material.MaterialRefused) as refused:
            material.anchor_bytes(incomplete)
        self.assertEqual(str(refused.exception), 'complete actual reference anchor material refused')

    def test_incomplete_actual_request_is_a_sanitized_refusal(self):
        incomplete = object.__new__(lifecycle.ReferenceAnchorTransition)
        with self.assertRaises(material.MaterialRefused) as refused:
            material.request_material(incomplete)
        self.assertEqual(str(refused.exception), 'complete actual reference request material refused')

    def test_oversized_storage_material_refuses_before_sql(self):
        with self.assertRaises(ValueError):
            material.bounded(dict(selected='public synthetic material'), 1)

    def test_nonserializable_material_cannot_reach_storage(self):
        with self.assertRaises(TypeError):
            material.bounded(dict(selected=object()), 1024)
