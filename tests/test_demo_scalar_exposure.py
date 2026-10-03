"""Offline, test-only counterexample for the pinned demo's scalar disclosure.

The fixture pins the source formulas and contains only public synthetic inputs
and an RFC 8032 public test vector. No upstream implementation is copied or run.

This deliberately small Edwards25519 model is VARIABLE-TIME and incomplete as
a general cryptography implementation. Never use it for secrets, production
signing, wallets, or a replacement adaptor-signature protocol. It models only
valid subgroup points generated from the standard base point. The RFC vector
checks its arithmetic; optional OpenSSL checks signatures independently.

These tests establish a scalar-disclosure/signature counterexample, not node
acceptance, an executed swap, on-chain theft, or a complete security audit.
Run offline: python3 -B -m unittest discover -s tests -v
"""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


FIELD = 2**255 - 19
ORDER = 2**252 + 27742317777372353535851937790883648493
CURVE_D = (-121665 * pow(121666, -1, FIELD)) % FIELD
IDENTITY = (0, 1)
BASE = (
    15112221349535400772501151409588531511454012693041857206046113283949847762202,
    46316835694926478169428394003475163141307993866256225615783033603165251855960,
)
FIXTURE_PATH = Path(__file__).parent / "fixtures" / "demo_scalar_exposure.json"


def _add(left, right):
    """Variable-time affine addition, solely for valid test points."""
    x1, y1 = left
    x2, y2 = right
    term = CURVE_D * x1 * x2 * y1 * y2 % FIELD
    return (
        (x1 * y2 + y1 * x2) * pow(1 + term, -1, FIELD) % FIELD,
        (y1 * y2 + x1 * x2) * pow(1 - term, -1, FIELD) % FIELD,
    )


def _multiply(scalar, point=BASE):
    """Variable-time double-and-add for nonnegative synthetic scalars."""
    if scalar < 0:
        raise ValueError("test scalar must be nonnegative")
    result = IDENTITY
    while scalar:
        if scalar & 1:
            result = _add(result, point)
        point = _add(point, point)
        scalar >>= 1
    return result


def _encode(point):
    x, y = point
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _decode_public_vector_point(encoded):
    """Decode the published RFC test points; never a production verifier."""
    if len(encoded) != 32:
        raise ValueError("public vector point must have 32 bytes")
    packed = int.from_bytes(encoded, "little")
    sign = packed >> 255
    y = packed & (2**255 - 1)
    if y >= FIELD:
        raise ValueError("noncanonical public vector point")
    squared_x = (y * y - 1) * pow(CURVE_D * y * y + 1, -1, FIELD) % FIELD
    x = pow(squared_x, (FIELD + 3) // 8, FIELD)
    if x * x % FIELD != squared_x:
        x = x * pow(2, (FIELD - 1) // 4, FIELD) % FIELD
    if x * x % FIELD != squared_x:
        raise ValueError("public vector point is not on the curve")
    if (x & 1) != sign:
        x = (-x) % FIELD
    if x == 0 and sign:
        raise ValueError("noncanonical public vector sign")
    return x, y


def _challenge(nonce_point, public_point, message):
    payload = _encode(nonce_point) + _encode(public_point) + message
    return int.from_bytes(hashlib.sha512(payload).digest(), "little") % ORDER


def _recover_disclosed_scalar(disclosed, challenge):
    """The precise leakage relation under test, not a signing API."""
    challenge %= ORDER
    if challenge == 0:
        raise ValueError("zero challenge has no inverse modulo the subgroup order")
    return disclosed * pow(challenge, -1, ORDER) % ORDER


def _fixture():
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def _public_transcript():
    """Simulate disclosed values; do not return Alice's scalar or adaptor t."""
    values = _fixture()["synthetic"]
    alice = int(values["alice_scalar"])
    bob = int(values["bob_scalar"])
    public_point = _add(_multiply(alice), _multiply(bob))
    original_nonce_point = _multiply(int(values["original_nonce_scalar"]))
    adaptor_point = _multiply(int(values["adaptor_scalar"]))
    adapted_nonce_point = _add(original_nonce_point, adaptor_point)
    message = values["message_utf8"].encode("utf-8")
    challenge = _challenge(adapted_nonce_point, public_point, message)
    return {
        "bob_scalar": bob,
        "public_point": public_point,
        "message": message,
        "challenge": challenge,
        "disclosed": challenge * alice % ORDER,
    }


def _fixed_counterexample():
    """Construct one fixture-only signature without receiving the adaptor t.

    Knowing the aggregate scalar allows a fresh nonce and signature. There is
    no need to complete the honest adaptor pre-signature. This is intentionally
    restricted to the fixed public fixture, not a general signing interface.
    """
    transcript = _public_transcript()
    recovered = _recover_disclosed_scalar(
        transcript["disclosed"], transcript["challenge"]
    )
    aggregate = (recovered + transcript["bob_scalar"]) % ORDER
    fresh_nonce = int(_fixture()["synthetic"]["fresh_nonce_scalar"])
    nonce_point = _multiply(fresh_nonce)
    challenge = _challenge(
        nonce_point, transcript["public_point"], transcript["message"]
    )
    response = (fresh_nonce + challenge * aggregate) % ORDER
    signature = _encode(nonce_point) + response.to_bytes(32, "little")
    return transcript, nonce_point, response, signature


class ScalarExposureTests(unittest.TestCase):
    def test_reference_arithmetic_matches_rfc8032_test_1(self):
        vector = _fixture()["rfc8032_test_1"]
        public_point = _decode_public_vector_point(bytes.fromhex(vector["public_key_hex"]))
        self.assertEqual(_encode(public_point).hex(), vector["public_key_hex"])
        message = bytes.fromhex(vector["message_hex"])
        signature = bytes.fromhex(vector["signature_hex"])
        nonce_point = _decode_public_vector_point(signature[:32])
        response = int.from_bytes(signature[32:], "little")
        self.assertLess(response, ORDER)
        challenge = _challenge(nonce_point, public_point, message)
        self.assertEqual(
            _multiply(response),
            _add(nonce_point, _multiply(challenge, public_point)),
        )

    def test_public_challenge_recovers_alice_scalar(self):
        transcript = _public_transcript()
        self.assertNotEqual(transcript["challenge"], 0)
        recovered = _recover_disclosed_scalar(
            transcript["disclosed"], transcript["challenge"]
        )
        self.assertEqual(recovered, int(_fixture()["synthetic"]["alice_scalar"]))
        self.assertEqual(
            _multiply(recovered + transcript["bob_scalar"]),
            transcript["public_point"],
        )

    def test_recovery_respects_subgroup_order(self):
        for scalar in (1, 2, ORDER - 1, ORDER + 17):
            for challenge in (1, 2, ORDER - 1, ORDER + 19):
                with self.subTest(scalar=scalar, challenge=challenge):
                    disclosed = challenge * scalar % ORDER
                    self.assertEqual(
                        _recover_disclosed_scalar(disclosed, challenge),
                        scalar % ORDER,
                    )

    def test_zero_challenge_cannot_recover_scalar(self):
        for challenge in (0, ORDER, 2 * ORDER):
            with self.subTest(challenge=challenge):
                with self.assertRaisesRegex(ValueError, "zero challenge"):
                    _recover_disclosed_scalar(0, challenge)

    def test_fresh_signature_equation_holds_without_adaptor_secret(self):
        transcript, nonce_point, response, _ = _fixed_counterexample()
        self.assertNotIn("adaptor_scalar", transcript)
        self.assertNotIn("alice_scalar", transcript)
        challenge = _challenge(
            nonce_point, transcript["public_point"], transcript["message"]
        )
        self.assertEqual(
            _multiply(response),
            _add(nonce_point, _multiply(challenge, transcript["public_point"])),
        )

    def test_equation_rejects_altered_message(self):
        transcript, nonce_point, response, _ = _fixed_counterexample()
        wrong_challenge = _challenge(
            nonce_point, transcript["public_point"], transcript["message"] + b"!"
        )
        self.assertNotEqual(
            _multiply(response),
            _add(nonce_point, _multiply(wrong_challenge, transcript["public_point"])),
        )

    def test_equation_rejects_altered_signature_scalar(self):
        transcript, nonce_point, response, _ = _fixed_counterexample()
        challenge = _challenge(
            nonce_point, transcript["public_point"], transcript["message"]
        )
        self.assertNotEqual(
            _multiply((response + 1) % ORDER),
            _add(nonce_point, _multiply(challenge, transcript["public_point"])),
        )


class OpenSSLIndependentVerificationTests(unittest.TestCase):
    @staticmethod
    def _backend_unavailable(reason):
        if os.environ.get("REQUIRE_OPENSSL") == "1":
            raise RuntimeError(reason + "; REQUIRE_OPENSSL=1 forbids skipping")
        raise unittest.SkipTest(reason + "; independent verification not run")

    @classmethod
    def setUpClass(cls):
        cls.openssl = shutil.which("openssl")
        if cls.openssl is None:
            cls._backend_unavailable("OpenSSL executable unavailable")
        try:
            listing = subprocess.run(
                [cls.openssl, "list", "-signature-algorithms"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            cls._backend_unavailable("OpenSSL capability check unavailable")
        if listing.returncode != 0 or "ED25519" not in listing.stdout.upper():
            cls._backend_unavailable("OpenSSL Ed25519 backend unsupported")

    def _verify(self, public_key, message, signature):
        # RFC 8410 Ed25519 SubjectPublicKeyInfo: algorithm OID 1.3.101.112,
        # absent parameters, followed by a 32-byte public-key BIT STRING.
        spki = bytes.fromhex("302a300506032b6570032100") + public_key
        with tempfile.TemporaryDirectory(prefix="ptlc-offline-test-") as directory:
            work = Path(directory)
            (work / "public.der").write_bytes(spki)
            (work / "message.bin").write_bytes(message)
            (work / "signature.bin").write_bytes(signature)
            result = subprocess.run(
                [
                    self.openssl, "pkeyutl", "-verify", "-pubin", "-keyform", "DER",
                    "-inkey", "public.der", "-rawin", "-in", "message.bin",
                    "-sigfile", "signature.bin",
                ],
                cwd=work,
                capture_output=True,
                timeout=10,
                check=False,
            )
        # Return only the status and an exact, non-sensitive result marker.
        # A crash or setup failure must not pass as cryptographic rejection.
        # Deliberately omit environment paths and raw backend diagnostics.
        expected_rejection = result.stdout.strip() == b"Signature Verification Failure"
        return result.returncode, expected_rejection

    def test_openssl_accepts_synthetic_aggregate_signature(self):
        transcript, _, _, signature = _fixed_counterexample()
        self.assertEqual(
            self._verify(_encode(transcript["public_point"]), transcript["message"], signature)[0],
            0,
            "OpenSSL did not accept the synthetic signature; independent check failed",
        )

    def test_openssl_rejects_altered_message(self):
        transcript, _, _, signature = _fixed_counterexample()
        self.assertEqual(
            self._verify(
                _encode(transcript["public_point"]), transcript["message"] + b"!", signature
            ),
            (1, True),
            "OpenSSL did not report the expected signature-verification rejection",
        )

    def test_openssl_rejects_altered_signature(self):
        transcript, _, response, signature = _fixed_counterexample()
        altered = signature[:32] + ((response + 1) % ORDER).to_bytes(32, "little")
        self.assertEqual(
            self._verify(_encode(transcript["public_point"]), transcript["message"], altered),
            (1, True),
            "OpenSSL did not report the expected signature-verification rejection",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
