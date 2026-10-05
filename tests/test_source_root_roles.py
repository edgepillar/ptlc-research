"""Offline root expectations and transport; fake callbacks prove no mathematics."""

import copy
from dataclasses import FrozenInstanceError
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from offline_session.public_worker import WorkerError
from qualification import source_root_roles as root
from qualification.source_root_verifier import PublicRootCheck


def fixture():
    return json.loads(Path("qualification/fixtures/source_root_roles.json").read_text("ascii"))


def selection(name="primary", declaration=None):
    value = declaration if declaration is not None else fixture()["positive_vectors"][name]["declaration"]
    return root.root_declaration(source_context=value["source_context"],
        governor_profile=value["governor_profile"], delegated_keys=value["delegated_keys"],
        revision=value["declaration_revision"])


def fake_check(request):
    """Forge all expected transport fields without checking any signature."""
    return root.expected_result(root.request_digest(request))


class SourceRootRoleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = fixture()
        cls.primary = cls.vectors["positive_vectors"]["primary"]
        cls.expected = selection()
        cls.wire = root._canonical(cls.primary["envelope"])

    def refuse(self, packet):
        calls = []
        with self.assertRaises(root.RootStatementError):
            root.verify_selected_statement(self.expected, root._canonical(packet), verifier=lambda r: calls.append(r))
        self.assertEqual(calls, [])

    def test_public_fixture_reproduces_complete_selected_wire_and_both_domains(self):
        self.assertEqual(root.envelope(self.expected, root_signature=bytes.fromhex(self.primary["envelope"]["root_signature_hex"])), self.wire)
        self.assertEqual(root.request(self.expected, self.wire), self.primary["request"])
        self.assertEqual(self.expected.message_digest_hex, self.primary["message_digest_hex"])
        self.assertEqual(self.primary["message_digest_hex"], hashlib.sha256(root.DECLARATION_DOMAIN+self.expected.canonical_bytes).hexdigest())
        self.assertEqual(root.request_digest(self.primary["request"]), self.primary["result"]["request_digest_hex"])
        self.assertEqual(set(self.primary["result"]), {"schema", "request_digest_hex", "root_signature_valid"})

    def test_all_peer_valid_alternatives_refuse_before_work_under_old_expectation(self):
        for name, vector in self.vectors["positive_vectors"].items():
            if name != "primary": self.refuse(vector["envelope"])
            selected = selection(name)
            self.assertIs(root.verify_selected_statement(selected, root._canonical(vector["envelope"]), verifier=fake_check), selected)

    def test_all_signed_fields_refuse_changes_before_work(self):
        for path in (("declaration",), ("declaration", "source_context"), ("declaration", "governor_profile"), ("declaration", "delegated_keys")):
            fields = self.primary["envelope"]
            for part in path: fields = fields[part]
            for field, old in fields.items():
                packet = copy.deepcopy(self.primary["envelope"]); target = packet
                for part in path: target = target[part]
                target[field] = old+1 if type(old) is int else "99"*32
                with self.subTest(path=path, field=field): self.refuse(packet)

    def test_exact_fields_and_types_required_at_all_five_levels(self):
        for path in ((), ("declaration",), ("declaration", "source_context"), ("declaration", "governor_profile"), ("declaration", "delegated_keys")):
            fields = self.primary["envelope"]
            for part in path: fields = fields[part]
            for field in fields:
                for wrong in (None, True, [], {}):
                    packet = copy.deepcopy(self.primary["envelope"]); target = packet
                    for part in path: target = target[part]
                    target[field] = wrong
                    self.refuse(packet)
                packet = copy.deepcopy(self.primary["envelope"]); target = packet
                for part in path: target = target[part]
                target.pop(field); self.refuse(packet)
            packet = copy.deepcopy(self.primary["envelope"]); target = packet
            for part in path: target = target[part]
            target["authorized"] = True; self.refuse(packet)

    def test_namespace_resource_and_role_must_match_profile(self):
        for field in ("authority_id_hex", "resource_digest_hex", "role"):
            value = copy.deepcopy(self.primary["declaration"])
            value["source_context"][field] = "ee"*32
            with self.assertRaises(root.RootStatementError): selection(declaration=value)

    def test_revision_epoch_and_caps_refuse_bool_float_string_and_bounds(self):
        for path, field, maximum in (((), "declaration_revision", root.MAX_REVISION),
                (("governor_profile",), "authority_epoch", root.MAX_REVISION),
                (("governor_profile",), "max_attempt_limit", 64), (("governor_profile",), "max_target_limit", 64)):
            for wrong in (True, False, 1.0, "1", 0, -1, maximum+1):
                value = copy.deepcopy(self.primary["declaration"]); target = value
                for part in path: target = target[part]
                target[field] = wrong
                with self.assertRaises(root.RootStatementError): selection(declaration=value)

    def test_all_role_key_collisions_refuse_in_this_selected_construction(self):
        paths = [("source_context", "provisioning_root_key_hex"), ("governor_profile", "owner_auth_key_hex")]
        paths += [("delegated_keys", k) for k in root._KEY_FIELDS]
        for i, (obj, field) in enumerate(paths):
            for obj2, field2 in paths[i+1:]:
                value = copy.deepcopy(self.primary["declaration"])
                value[obj2][field2] = value[obj][field]
                with self.assertRaises(root.RootStatementError): selection(declaration=value)

    def test_format_only_selection_allows_noncurve_keys_without_mathematics(self):
        for obj, field in (("source_context", "provisioning_root_key_hex"), ("governor_profile", "owner_auth_key_hex"), *[("delegated_keys", k) for k in root._KEY_FIELDS]):
            value = copy.deepcopy(self.primary["declaration"]); value[obj][field] = "00"*32
            selected = selection(declaration=value)
            wire = root.envelope(selected, root_signature=bytes(64))
            self.assertIs(root.verify_selected_statement(selected, wire, verifier=fake_check), selected)

    def test_exact_lowercase_key_and_signature_encodings_required(self):
        for wrong in ("00"*31, "00"*33, "GG"*32, "AB"*32, b"00"*32):
            value = copy.deepcopy(self.primary["declaration"]); value["delegated_keys"]["policy_admin_key_hex"] = wrong
            with self.assertRaises(root.RootStatementError): selection(declaration=value)
        for wrong in ("00"*63, "00"*65, "AB"*64, "gg"*64):
            self.refuse(dict(self.primary["envelope"], root_signature_hex=wrong))

    def test_canonical_wire_refuses_duplicates_aliases_whitespace_depth_and_nonascii(self):
        for wire in (b"", self.wire+b"\n", b" "+self.wire, self.wire+b" ", b"\xff",
                self.wire.replace(b'"declaration":', b'"\\u0064eclaration":'),
                self.wire.replace(b'"declaration_revision":1', b'"declaration_revision":1,"declaration_revision":1'),
                self.wire.replace(b'"declaration_revision":1', b'"declaration_revision":1e0'),
                b"["*512+b"]"*512, b" "*(root.MAX_WIRE_BYTES+1)):
            calls=[]
            with self.assertRaises(root.RootStatementError): root.verify_selected_statement(self.expected, wire, verifier=lambda r: calls.append(r))
            self.assertEqual(calls, [])

    def test_wire_signature_and_factory_exact_types_refuse_without_hooks(self):
        for wrong in (self.wire.decode("ascii"), bytearray(self.wire), memoryview(self.wire), None):
            with self.assertRaises(root.RootStatementError): root.request(self.expected, wrong)
        for wrong in (bytes(63), bytes(65), bytearray(64), memoryview(bytes(64)), "00"*64):
            with self.assertRaises(root.RootStatementError): root.envelope(self.expected, root_signature=wrong)
        with self.assertRaises(TypeError): root.RootDeclaration()

    def test_constructor_inputs_and_returned_mapping_are_defensive_copies(self):
        value = copy.deepcopy(self.primary["declaration"]); selected = selection(declaration=value)
        before = selected.canonical_bytes
        value["declaration_revision"] = 2
        selected.as_dict()["delegated_keys"]["policy_admin_key_hex"] = "00"*32
        self.assertEqual(selected.canonical_bytes, before)
        with self.assertRaises(FrozenInstanceError): selected._wire = b"{}"

    def test_damaged_incomplete_and_nonexact_selection_refuses_before_work(self):
        incomplete = object.__new__(root.RootDeclaration)
        damaged = selection(); object.__setattr__(damaged, "_wire", b"{}")
        class Foreign:
            def as_dict(self): raise AssertionError("must not invoke a foreign hook")
        for wrong in (None, self.expected.as_dict(), incomplete, damaged, Foreign()):
            with self.assertRaises(root.RootStatementError): root.verify_selected_statement(wrong, self.wire, verifier=fake_check)

    def test_hostile_mapping_key_and_string_subclasses_refuse_without_hooks(self):
        class HostileDict(dict):
            def items(self): raise AssertionError("must not invoke mapping hooks")
        class HostileString(str):
            def __eq__(self, other): raise AssertionError("must not invoke string hooks")
            __hash__ = str.__hash__
        value = copy.deepcopy(self.primary["declaration"])
        value["delegated_keys"] = HostileDict(value["delegated_keys"])
        with self.assertRaises(root.RootStatementError): selection(declaration=value)
        value = copy.deepcopy(self.primary["declaration"])
        value["delegated_keys"]["policy_admin_key_hex"] = HostileString("00"*32)
        with self.assertRaises(root.RootStatementError): selection(declaration=value)
        expected = fake_check(self.primary["request"])
        result = {HostileString("schema"): expected["schema"],
            "request_digest_hex": expected["request_digest_hex"], "root_signature_valid": True}
        with self.assertRaises(root.RootStatementError): root.verify_selected_statement(self.expected, self.wire, verifier=lambda r: result)

    def test_ordinary_callback_failure_sanitizes_and_cancellation_propagates(self):
        def fail(r): raise RuntimeError("synthetic private detail")
        with self.assertRaises(root.RootStatementError) as caught: root.verify_selected_statement(self.expected, self.wire, verifier=fail)
        self.assertNotIn("synthetic private detail", str(caught.exception))
        for exception in (KeyboardInterrupt, SystemExit):
            def cancel(r): raise exception()
            with self.assertRaises(exception): root.verify_selected_statement(self.expected, self.wire, verifier=cancel)

    def test_callback_receives_copy_and_cannot_rebind_complete_request(self):
        def changed(request):
            request["declaration"]["declaration_revision"] = 2
            return fake_check(request)
        with self.assertRaises(root.RootStatementError): root.verify_selected_statement(self.expected, self.wire, verifier=changed)
        self.assertEqual(self.expected, selection())

    def test_changed_independent_selection_during_check_refuses(self):
        selected = selection()
        def changed(request):
            object.__setattr__(selected, "_wire", selection("new_revision").canonical_bytes)
            return fake_check(request)
        with self.assertRaises(root.RootStatementError): root.verify_selected_statement(selected, self.wire, verifier=changed)

    def test_complete_result_requires_exact_true_digest_and_schema(self):
        expected = self.primary["result"]
        wrongs = [None, [], {}, dict(expected, permit=True), dict(expected, root_signature_valid=1),
            dict(expected, root_signature_valid=False), dict(expected, request_digest_hex="00"*32), dict(expected, schema="foreign")]
        for field in expected:
            wrong = expected.copy(); wrong.pop(field); wrongs.append(wrong)
        for wrong in wrongs:
            with self.assertRaises(root.RootStatementError): root.verify_selected_statement(self.expected, self.wire, verifier=lambda r: wrong)
        with self.assertRaises(root.RootStatementError): root.verify_selected_statement(self.expected, self.wire, verifier=None)

    def test_alternate_valid_signature_changes_result_binding(self):
        packet = dict(self.primary["envelope"], root_signature_hex=self.vectors["alternate_root_signature_hex"])
        wire = root._canonical(packet)
        self.assertNotEqual(root.request_digest(root.request(self.expected, wire)), self.primary["result"]["request_digest_hex"])
        self.assertIs(root.verify_selected_statement(self.expected, wire, verifier=fake_check), self.expected)
        with self.assertRaises(root.RootStatementError): root.verify_selected_statement(self.expected, wire, verifier=lambda r: self.primary["result"])

    def test_forged_zero_signature_callback_positive_remains_explicit_trust_premise(self):
        wire = root.envelope(self.expected, root_signature=bytes(64))
        self.assertIs(root.verify_selected_statement(self.expected, wire, verifier=fake_check), self.expected)
        for name in ("authorized", "current", "provisioned", "enrolled", "quota", "permit", "root_signature_valid"):
            self.assertFalse(hasattr(self.expected, name))

    def test_old_revision_and_copied_selection_replay_supplies_no_freshness(self):
        newer = selection("new_revision")
        with self.assertRaises(root.RootStatementError): root.verify_selected_statement(newer, self.wire, verifier=fake_check)
        for _ in range(3):
            old = copy.deepcopy(self.expected)
            self.assertIs(root.verify_selected_statement(old, self.wire, verifier=fake_check), old)
        self.assertEqual(self.primary["result"], fake_check(root.request(self.expected, self.wire)))

    def test_root_replacement_requires_an_independent_new_complete_selection(self):
        self.refuse(self.vectors["positive_vectors"]["alternate_root"]["envelope"])
        selected = selection("alternate_root")
        self.assertIs(root.verify_selected_statement(selected, root._canonical(self.vectors["positive_vectors"]["alternate_root"]["envelope"]), verifier=fake_check), selected)
        packet = copy.deepcopy(self.primary["envelope"]); packet["declaration"]["root_transition"] = "self-signed-rotation"
        self.refuse(packet)

    def test_full_request_digest_revalidates_shape_and_excludes_no_public_field(self):
        for signature in (self.vectors["alternate_root_signature_hex"], "00"*64):
            changed = dict(self.primary["request"], root_signature_hex=signature)
            self.assertNotEqual(root.request_digest(changed), root.request_digest(self.primary["request"]))
        for wrong in (dict(self.primary["request"], permit=True), dict(self.primary["request"], schema=root.ENVELOPE_SCHEMA), {}):
            with self.assertRaises(root.RootStatementError): root.request_digest(wrong)


class SourceRootPublicCheckTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="synthetic-root-check-")
        self.addCleanup(temporary.cleanup)
        self.entry = Path(temporary.name)/"worker"
        self.entry.write_bytes(b"synthetic executable measurement only"); self.entry.chmod(0o700)
        self.digest = hashlib.sha256(self.entry.read_bytes()).hexdigest()
        self.check = PublicRootCheck(self.entry, expected_executable_sha256_hex=self.digest)
        self.request = fixture()["positive_vectors"]["primary"]["request"]
        self.result = fake_check(self.request)

    def test_exact_result_with_optional_one_lf_uses_bounded_public_runner(self):
        for suffix in (b"", b"\n"):
            with patch("qualification.source_root_verifier.run_public_worker", return_value=root._canonical(self.result)+suffix) as run:
                self.assertEqual(self.check(self.request), self.result)
                run.assert_called_once_with(str(self.entry), root._canonical(self.request), timeout=5, max_input_bytes=8192, max_output_bytes=512)

    def test_wrong_binding_flags_extra_fields_and_output_refuse(self):
        for response in (b"", b"{}", root._canonical(dict(self.result, permit=True)),
                root._canonical(dict(self.result, root_signature_valid=1)),
                root._canonical(dict(self.result, request_digest_hex="00"*32)), root._canonical(self.result)+b"\n\n"):
            with patch("qualification.source_root_verifier.run_public_worker", return_value=response), self.assertRaises(root.RootStatementError): self.check(self.request)

    def test_changed_or_missing_entry_refuses_before_any_launch(self):
        self.entry.write_bytes(b"changed synthetic entry")
        with patch("qualification.source_root_verifier.run_public_worker") as run:
            with self.assertRaises(root.RootStatementError): self.check(self.request)
            self.entry.unlink()
            with self.assertRaises(root.RootStatementError): self.check(self.request)
            run.assert_not_called()

    def test_path_pin_timeout_and_executable_mode_must_be_selected_exactly(self):
        for entry, digest, timeout in (("relative-worker", self.digest, 5), (self.entry, "00"*32, 5),
                (self.entry, self.digest, True), (self.entry, self.digest, 0), (self.entry, self.digest, 31)):
            with self.assertRaises(root.RootStatementError): PublicRootCheck(entry, expected_executable_sha256_hex=digest, timeout=timeout)
        self.entry.chmod(0o600)
        with self.assertRaises(root.RootStatementError): PublicRootCheck(self.entry, expected_executable_sha256_hex=self.digest)

    def test_malformed_request_refuses_before_any_launch(self):
        with patch("qualification.source_root_verifier.run_public_worker") as run:
            with self.assertRaises(root.RootStatementError): self.check(dict(self.request, permit=True))
            run.assert_not_called()

    def test_runner_failures_sanitize_and_cancellation_propagates(self):
        with patch("qualification.source_root_verifier.run_public_worker", side_effect=WorkerError("synthetic private detail")):
            with self.assertRaises(root.RootStatementError) as caught: self.check(self.request)
            self.assertNotIn("synthetic private detail", str(caught.exception))
        with patch("qualification.source_root_verifier.run_public_worker", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt): self.check(self.request)
