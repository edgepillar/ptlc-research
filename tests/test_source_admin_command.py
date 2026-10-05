"""Offline command selection and transport; fake results establish no signatures."""

import copy
from dataclasses import FrozenInstanceError
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from offline_session.public_worker import WorkerError
from qualification import source_admin_command as admin, source_root_roles as root
from qualification.source_admin_verifier import PublicAdminCheck


def fixture():
    return json.loads(Path("qualification/fixtures/source_admin_command.json").read_text("ascii"))


def selection(name="primary", *, command=None, declaration=None):
    vector = fixture()["positive_vectors"][name]
    c = vector["command"] if command is None else command
    d = vector["envelope"]["root_envelope"]["declaration"] if declaration is None else declaration
    selected_root = root.root_declaration(source_context=d["source_context"], governor_profile=d["governor_profile"],
        delegated_keys=d["delegated_keys"], revision=d["declaration_revision"])
    return admin.admin_command(selected_root, operation=c["operation"], original_command_id_hex=c["original_command_id_hex"],
        expected_policy_revision=c["expected_policy_revision"], old_profile=c["old_profile"], new_profile=c["new_profile"],
        old_active=c["old_active"], new_active=c["new_active"])


def fake_check(request):
    """Deliberately forge both positives, with no root or administrator mathematics."""
    return admin.expected_result(admin.request_digest(request))


class SourceAdminCommandTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = fixture()
        cls.primary = cls.vectors["positive_vectors"]["primary"]
        cls.expected = selection()
        cls.wire = admin._canonical(cls.primary["envelope"])

    def refuse(self, packet):
        calls = []
        with self.assertRaises(admin.AdminCommandError):
            admin.verify_selected_command(self.expected, admin._canonical(packet), verifier=lambda r: calls.append(r))
        self.assertEqual(calls, [])

    def test_public_fixture_complete_selection_and_domains_match(self):
        p = self.primary["envelope"]
        self.assertEqual(admin.envelope(self.expected, root_signature=bytes.fromhex(p["root_envelope"]["root_signature_hex"]),
            admin_signature=bytes.fromhex(p["admin_signature_hex"])), self.wire)
        self.assertEqual(admin.request(self.expected, self.wire), self.primary["request"])
        self.assertEqual(self.expected.message_digest_hex, self.primary["message_digest_hex"])
        self.assertEqual(self.expected.message_digest_hex, hashlib.sha256(admin.COMMAND_DOMAIN+self.expected.canonical_bytes).hexdigest())
        self.assertEqual(fake_check(self.primary["request"]), self.primary["result"])
        self.assertEqual(len(self.primary["result"]), 4)

    def test_all_valid_peer_replacements_refuse_before_work(self):
        for name, vector in self.vectors["positive_vectors"].items():
            if name != "primary": self.refuse(vector["envelope"])
            selected = selection(name)
            self.assertIs(admin.verify_selected_command(selected, admin._canonical(vector["envelope"]), verifier=fake_check), selected)

    def test_signed_forbidden_transitions_cannot_gain_powers_from_a_role_label(self):
        self.assertEqual(len(self.vectors["signed_refusal_vectors"]), 18)
        for name, vector in self.vectors["signed_refusal_vectors"].items():
            with self.subTest(command=name): self.refuse(vector["envelope"])
            with self.assertRaises(admin.AdminCommandError): admin.request_digest(vector["request"])

    def test_all_command_context_old_new_profiles_and_root_fields_are_selected(self):
        paths = (("command",), ("command", "source_context"), ("command", "old_profile"), ("command", "new_profile"),
            ("root_envelope", "declaration"), ("root_envelope", "declaration", "source_context"),
            ("root_envelope", "declaration", "governor_profile"), ("root_envelope", "declaration", "delegated_keys"))
        for path in paths:
            fields = self.primary["envelope"]
            for p in path: fields = fields[p]
            for f, old in fields.items():
                packet = copy.deepcopy(self.primary["envelope"]); target = packet
                for p in path: target = target[p]
                target[f] = old+1 if type(old) is int else "ee"*32
                self.refuse(packet)

    def test_exact_objects_refuse_missing_extra_and_wrong_types(self):
        paths = ((), ("command",), ("command", "source_context"), ("command", "old_profile"), ("command", "new_profile"),
            ("root_envelope",), ("root_envelope", "declaration"), ("root_envelope", "declaration", "source_context"),
            ("root_envelope", "declaration", "governor_profile"), ("root_envelope", "declaration", "delegated_keys"))
        for path in paths:
            fields = self.primary["envelope"]
            for p in path: fields = fields[p]
            for f in fields:
                for value in (None, [], {}):
                    packet = copy.deepcopy(self.primary["envelope"]); target = packet
                    for p in path: target = target[p]
                    target[f] = value; self.refuse(packet)
                packet = copy.deepcopy(self.primary["envelope"]); target = packet
                for p in path: target = target[p]
                del target[f]; self.refuse(packet)
            packet = copy.deepcopy(self.primary["envelope"]); target = packet
            for p in path: target = target[p]
            target["authorized"] = True; self.refuse(packet)

    def test_factory_allows_only_componentwise_reduction_or_exact_revocation(self):
        for name in ("increase", "mixed_increase", "no_op", "reactivate", "unknown_operation", "changed_owner",
                "changed_epoch", "changed_config", "revoke_changes_profile", "revoke_stays_active", "exceeds_anchor"):
            with self.assertRaises(admin.AdminCommandError): selection(command=self.vectors["signed_refusal_vectors"][name]["command"])
        for name in ("reduce_attempt_only", "reduce_target_only", "revoke", "revoke_reduced"):
            self.assertEqual(selection(name).as_dict(), self.vectors["positive_vectors"][name]["command"])

    def test_numeric_aliases_boolean_states_and_revision_headroom_refuse(self):
        for wrong in (True, False, -1, 0.0, "0", admin.MAX_EXPECTED_REVISION+1):
            c = copy.deepcopy(self.primary["command"]); c["expected_policy_revision"] = wrong
            with self.assertRaises(admin.AdminCommandError): selection(command=c)
        for name in ("old_active", "new_active"):
            for wrong in (0, 1, None, "true"):
                c = copy.deepcopy(self.primary["command"]); c[name] = wrong
                with self.assertRaises(admin.AdminCommandError): selection(command=c)
        for profile in ("old_profile", "new_profile"):
            for cap in admin._CAPS:
                for wrong in (True, 1.0, "1", 0, -1, 65):
                    c = copy.deepcopy(self.primary["command"]); c[profile][cap] = wrong
                    with self.assertRaises(admin.AdminCommandError): selection(command=c)
        self.assertEqual(selection("max_policy_revision").as_dict()["expected_policy_revision"], admin.MAX_EXPECTED_REVISION)

    def test_wire_duplicates_numeric_unicode_aliases_bounds_and_cross_schema_refuse(self):
        for wire in (b"", b"\xff", self.wire+b"\n", b" "+self.wire, self.wire+b" ", b" "*8193, b"["*512+b"]"*512,
                self.wire.replace(b'"command":', b'"\\u0063ommand":'),
                self.wire.replace(b'"expected_policy_revision":0', b'"expected_policy_revision":0,"expected_policy_revision":0'),
                self.wire.replace(b'"expected_policy_revision":0', b'"expected_policy_revision":0e0'),
                root._canonical(self.primary["envelope"]["root_envelope"])):
            calls=[]
            with self.assertRaises(admin.AdminCommandError): admin.verify_selected_command(self.expected, wire, verifier=lambda r:calls.append(r))
            self.assertEqual(calls, [])

    def test_exact_signature_wire_selection_types_reject_foreign_hooks(self):
        for wrong in (self.wire.decode("ascii"), bytearray(self.wire), memoryview(self.wire), None):
            with self.assertRaises(admin.AdminCommandError): admin.request(self.expected, wrong)
        for wrong in (bytes(63), bytes(65), bytearray(64), memoryview(bytes(64)), "00"*64):
            for which in ("root_signature", "admin_signature"):
                kwargs = dict(root_signature=bytes(64), admin_signature=bytes(64)); kwargs[which] = wrong
                with self.assertRaises(admin.AdminCommandError): admin.envelope(self.expected, **kwargs)
        with self.assertRaises(TypeError): admin.AdminCommand()
        class Foreign:
            def as_dict(self): raise AssertionError("foreign selection hook invoked")
        for wrong in (None, self.expected.as_dict(), Foreign()):
            with self.assertRaises(admin.AdminCommandError): admin.verify_selected_command(wrong, self.wire, verifier=fake_check)

    def test_inputs_root_selection_and_returned_mappings_are_copied(self):
        c = copy.deepcopy(self.primary["command"]); d = copy.deepcopy(self.primary["envelope"]["root_envelope"]["declaration"])
        selected = selection(command=c, declaration=d); before = (selected._root_wire, selected.canonical_bytes)
        c["old_profile"]["max_attempt_limit"] = 1; d["declaration_revision"] = 2
        selected.as_dict()["expected_policy_revision"] = 3; selected.root_dict()["declaration_revision"] = 3
        self.assertEqual((selected._root_wire, selected.canonical_bytes), before)
        with self.assertRaises(FrozenInstanceError): selected._wire = b"{}"

    def test_damaged_or_incomplete_selection_refuses_before_any_work(self):
        incomplete = object.__new__(admin.AdminCommand)
        for field in ("_wire", "_root_wire"):
            damaged = selection(); object.__setattr__(damaged, field, b"{}")
            for wrong in (damaged, incomplete):
                calls=[]
                with self.assertRaises(admin.AdminCommandError): admin.verify_selected_command(wrong, self.wire, verifier=lambda r:calls.append(r))
                self.assertEqual(calls, [])

    def test_nonexact_command_conversion_refuses_before_descriptor_or_override_hooks(self):
        class ForeignCommand(admin.AdminCommand):
            @property
            def _wire(self):
                raise AssertionError("foreign byte descriptor invoked")

            def root_dict(self):
                raise AssertionError("foreign root override invoked")

        foreign = object.__new__(ForeignCommand)
        with self.assertRaises(admin.AdminCommandError): admin.AdminCommand.as_dict(foreign)
        with self.assertRaises(admin.AdminCommandError): admin.AdminCommand.root_dict(foreign)
        with self.assertRaises(admin.AdminCommandError): admin.verify_selected_command(foreign, self.wire, verifier=fake_check)

    def test_hostile_mapping_string_and_result_key_subclasses_refuse_without_hooks(self):
        class HostileDict(dict):
            def items(self): raise AssertionError("mapping hook invoked")
        class HostileString(str):
            def __eq__(self, other): raise AssertionError("string hook invoked")
            __hash__ = str.__hash__
        c = copy.deepcopy(self.primary["command"]); c["old_profile"] = HostileDict(c["old_profile"])
        with self.assertRaises(admin.AdminCommandError): selection(command=c)
        c = copy.deepcopy(self.primary["command"]); c["operation"] = HostileString("reduce-limits")
        with self.assertRaises(admin.AdminCommandError): selection(command=c)
        good = fake_check(self.primary["request"])
        result = {HostileString("schema"): good["schema"], "request_digest_hex": good["request_digest_hex"],
            "root_signature_valid": True, "administrator_signature_valid": True}
        with self.assertRaises(admin.AdminCommandError): admin.verify_selected_command(self.expected, self.wire, verifier=lambda r:result)

    def test_callback_failures_sanitize_and_cancellation_propagates(self):
        def fail(r): raise RuntimeError("synthetic private detail")
        with self.assertRaises(admin.AdminCommandError) as caught: admin.verify_selected_command(self.expected, self.wire, verifier=fail)
        self.assertNotIn("synthetic private detail", str(caught.exception))
        for exception in (KeyboardInterrupt, SystemExit):
            def cancel(r): raise exception()
            with self.assertRaises(exception): admin.verify_selected_command(self.expected, self.wire, verifier=cancel)

    def test_callback_request_copy_cannot_rebind_original_command(self):
        def changed(r):
            r["command"]["expected_policy_revision"] = 1
            return fake_check(r)
        with self.assertRaises(admin.AdminCommandError): admin.verify_selected_command(self.expected, self.wire, verifier=changed)
        self.assertEqual(self.expected, selection())

    def test_changed_command_or_root_selection_during_callback_refuses(self):
        for field, wire in (("_wire", selection("new_policy_revision").canonical_bytes),
                ("_root_wire", selection("new_root_revision")._root_wire)):
            selected = selection()
            def changed(r):
                object.__setattr__(selected, field, wire)
                return fake_check(r)
            with self.assertRaises(admin.AdminCommandError): admin.verify_selected_command(selected, self.wire, verifier=changed)

    def test_result_requires_two_exact_true_flags_and_complete_binding(self):
        good = fake_check(self.primary["request"])
        wrongs = [None, [], {}, dict(good, permit=True), dict(good, request_digest_hex="00"*32), dict(good, schema="foreign")]
        for f in good:
            c = good.copy(); c.pop(f); wrongs.append(c)
        for flag in ("root_signature_valid", "administrator_signature_valid"):
            wrongs += [dict(good, **{flag:v}) for v in (1, False, None)]
        for wrong in wrongs:
            with self.assertRaises(admin.AdminCommandError): admin.verify_selected_command(self.expected, self.wire, verifier=lambda r:wrong)
        with self.assertRaises(admin.AdminCommandError): admin.verify_selected_command(self.expected, self.wire, verifier=None)

    def test_each_signature_variant_requires_a_distinct_complete_result(self):
        for field in ("alternate_admin_signature_hex", "alternate_root_signature_hex"):
            packet = copy.deepcopy(self.primary["envelope"])
            if field == "alternate_admin_signature_hex": packet["admin_signature_hex"] = self.vectors[field]
            else: packet["root_envelope"]["root_signature_hex"] = self.vectors[field]
            wire = admin._canonical(packet)
            self.assertIs(admin.verify_selected_command(self.expected, wire, verifier=fake_check), self.expected)
            self.assertNotEqual(admin.request_digest(admin.request(self.expected, wire)), self.primary["result"]["request_digest_hex"])
            with self.assertRaises(admin.AdminCommandError): admin.verify_selected_command(self.expected, wire, verifier=lambda r:self.primary["result"])

    def test_forged_two_zero_signature_positive_exposes_selected_callback_trust(self):
        wire = admin.envelope(self.expected, root_signature=bytes(64), admin_signature=bytes(64))
        self.assertIs(admin.verify_selected_command(self.expected, wire, verifier=fake_check), self.expected)
        for field in ("authorized", "current", "provisioned", "committed", "permit", "revision_advanced", "root_signature_valid"):
            self.assertFalse(hasattr(self.expected, field))

    def test_old_commands_and_coherent_restored_copies_replay_without_deduplication(self):
        for name in ("new_policy_revision", "revoke", "alternate_admin", "alternate_root"):
            with self.assertRaises(admin.AdminCommandError): admin.verify_selected_command(selection(name), self.wire, verifier=fake_check)
            restored = copy.deepcopy(self.expected)
            self.assertIs(admin.verify_selected_command(restored, self.wire, verifier=fake_check), restored)
        for _ in range(3): self.assertIs(admin.verify_selected_command(self.expected, self.wire, verifier=fake_check), self.expected)

    def test_format_only_selection_can_accept_noncurve_admin_with_forged_callback(self):
        d = copy.deepcopy(self.primary["envelope"]["root_envelope"]["declaration"])
        d["delegated_keys"]["policy_admin_key_hex"] = "00"*32
        selected = selection(declaration=d)
        wire = admin.envelope(selected, root_signature=bytes(64), admin_signature=bytes(64))
        self.assertIs(admin.verify_selected_command(selected, wire, verifier=fake_check), selected)


class SourceAdminPublicCheckTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="synthetic-root-check-")
        self.addCleanup(temporary.cleanup)
        self.entry = Path(temporary.name)/"worker"
        self.entry.write_bytes(b"synthetic executable measurement only"); self.entry.chmod(0o700)
        self.digest = hashlib.sha256(self.entry.read_bytes()).hexdigest()
        self.check = PublicAdminCheck(self.entry, expected_executable_sha256_hex=self.digest)
        self.request = fixture()["positive_vectors"]["primary"]["request"]
        self.result = fake_check(self.request)

    def test_exact_result_with_optional_one_lf_uses_bounded_public_runner(self):
        for suffix in (b"", b"\n"):
            with patch("qualification.source_admin_verifier.run_public_worker", return_value=admin._canonical(self.result)+suffix) as run:
                self.assertEqual(self.check(self.request), self.result)
                run.assert_called_once_with(str(self.entry), admin._canonical(self.request), timeout=5, max_input_bytes=8192, max_output_bytes=512)

    def test_wrong_binding_flags_extra_fields_and_output_refuse(self):
        for response in (b"", b"{}", admin._canonical(dict(self.result, permit=True)),
                admin._canonical(dict(self.result, administrator_signature_valid=1)),
                admin._canonical(dict(self.result, root_signature_valid=1)),
                admin._canonical(dict(self.result, request_digest_hex="00"*32)), admin._canonical(self.result)+b"\n\n"):
            with patch("qualification.source_admin_verifier.run_public_worker", return_value=response), self.assertRaises(admin.AdminCommandError): self.check(self.request)

    def test_changed_or_missing_entry_refuses_before_any_launch(self):
        self.entry.write_bytes(b"changed synthetic entry")
        with patch("qualification.source_admin_verifier.run_public_worker") as run:
            with self.assertRaises(admin.AdminCommandError): self.check(self.request)
            self.entry.unlink()
            with self.assertRaises(admin.AdminCommandError): self.check(self.request)
            run.assert_not_called()

    def test_path_pin_timeout_and_executable_mode_must_be_selected_exactly(self):
        for entry, digest, timeout in (("relative-worker", self.digest, 5), (self.entry, "00"*32, 5),
                (self.entry, self.digest, True), (self.entry, self.digest, 0), (self.entry, self.digest, 31)):
            with self.assertRaises(admin.AdminCommandError): PublicAdminCheck(entry, expected_executable_sha256_hex=digest, timeout=timeout)
        self.entry.chmod(0o600)
        with self.assertRaises(admin.AdminCommandError): PublicAdminCheck(self.entry, expected_executable_sha256_hex=self.digest)

    def test_malformed_request_refuses_before_any_launch(self):
        with patch("qualification.source_admin_verifier.run_public_worker") as run:
            with self.assertRaises(admin.AdminCommandError): self.check(dict(self.request, permit=True))
            run.assert_not_called()

    def test_runner_failures_sanitize_and_cancellation_propagates(self):
        with patch("qualification.source_admin_verifier.run_public_worker", side_effect=WorkerError("synthetic private detail")):
            with self.assertRaises(admin.AdminCommandError) as caught: self.check(self.request)
            self.assertNotIn("synthetic private detail", str(caught.exception))
        with patch("qualification.source_admin_verifier.run_public_worker", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt): self.check(self.request)
