"""Offline fixed-recipient NoM reference recovery over public synthetic bytes.

No account block, signer, wallet, RPC or transport is implemented. The original
envelope hash is explicitly synthetic, not a Zenon account-block hash. A trusted
public verifier checks the retained adaptor pair and completions. A separately
selected observation verifier supplies reference chain facts: these are not
authenticated here. Hash-chained local history detects corruption, not coherent
rollback, malicious rewriting or copied owners. Production use remains NO-GO.
"""

import copy
import hashlib
import json
import os
import stat
import threading

try:
    import fcntl
except ImportError:
    fcntl = None

from .pr138 import CORE_COMMIT, PROFILE, CompatibilityError, decimal, fixed_hex, payable, unlock_message


MAX_WIRE = 8192
MAX_LOG = 2 * 1024 * 1024
MAX_EVENTS = 256
MAX_RECOVERIES = 16
SCHEMA = "ptlc-nom-fixed-terms-v1"
CLAIM_SCHEMA = "ptlc-nom-synthetic-claim-v1"
OBSERVATION_SCHEMA = "ptlc-nom-reference-observation-v1"


class RecoveryError(ValueError):
    """Sanitized local reference refusal."""


class Quarantined(RecoveryError):
    """The original evidence must be retained for external reconciliation."""


def canonical(value):
    try:
        result = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
    except (ValueError, TypeError, RecursionError):
        raise RecoveryError("invalid public reference value") from None
    if len(result) > MAX_WIRE:
        raise RecoveryError("public reference value exceeds its boundary")
    return result


def decode(wire):
    if type(wire) is not bytes or not 0 < len(wire) <= MAX_WIRE:
        raise RecoveryError("invalid public reference wire")
    try:
        value = json.loads(wire.decode("ascii"))
        if canonical(value) != wire:
            raise RecoveryError("noncanonical public reference wire")
        return value
    except (UnicodeError, ValueError, TypeError, RecursionError):
        raise RecoveryError("invalid canonical public reference wire") from None


def fields(value, expected):
    if type(value) is not dict or value.keys() != frozenset(expected):
        raise RecoveryError("unexpected public reference fields")


def digest(domain, value):
    return hashlib.sha256(domain + b"\0" + canonical(value)).hexdigest()


def validate_terms(terms):
    fields(terms, ("schema", "profile", "core_commit", "session_id_hex", "chain_id", "genesis_hash_hex",
                   "alice_address_hex", "bob_address_hex", "adaptor_point_sec1_hex", "minimum_expiry_gap_seconds", "long", "short"))
    if terms["schema"] != SCHEMA or terms["profile"] != PROFILE or terms["core_commit"] != CORE_COMMIT:
        raise RecoveryError("unsupported fixed-recipient profile")
    try:
        fixed_hex(terms["session_id_hex"], 32); fixed_hex(terms["genesis_hash_hex"], 32)
        decimal(terms["chain_id"], 64)
        point = fixed_hex(terms["adaptor_point_sec1_hex"], 33)
        if point[0] not in (2, 3): raise RecoveryError("invalid adaptor point encoding")
        addresses = [terms[role + "_address_hex"] for role in ("alice", "bob")]
        if addresses[0] == addresses[1] or not all(payable(address) for address in addresses):
            raise RecoveryError("distinct fixed recipients are required")
        gap = decimal(terms["minimum_expiry_gap_seconds"], 63, positive=True)
        for name, funder, recipient in (("long", "alice", "bob"), ("short", "bob", "alice")):
            leg = terms[name]
            fields(leg, ("entry_id_hex", "funder", "recipient", "funder_key_xonly_hex", "token_standard_hex", "amount", "expires_at"))
            if leg["funder"] != funder or leg["recipient"] != recipient:
                raise RecoveryError("fixed-recipient roles do not match")
            fixed_hex(leg["entry_id_hex"], 32); fixed_hex(leg["funder_key_xonly_hex"], 32)
            fixed_hex(leg["token_standard_hex"], 10); decimal(leg["amount"], 256, positive=True)
            decimal(leg["expires_at"], 63, positive=True)
        if (terms["long"]["entry_id_hex"] == terms["short"]["entry_id_hex"]
                or terms["long"]["funder_key_xonly_hex"] == terms["short"]["funder_key_xonly_hex"]
                or int(terms["long"]["expires_at"]) - int(terms["short"]["expires_at"]) < gap):
            raise RecoveryError("entry, key or expiry separation is invalid")
    except CompatibilityError:
        raise RecoveryError("invalid fixed-recipient encoding") from None
    canonical(terms)
    return copy.deepcopy(terms)


def terms_digest(terms):
    return digest(b"ptlc-nom-fixed-terms-v1", validate_terms(terms))


def context(terms, leg):
    terms = validate_terms(terms)
    if leg not in ("long", "short"): raise RecoveryError("unknown swap leg")
    selected = terms[leg]
    return {"profile": PROFILE, "chain_id": terms["chain_id"], "point_type": 1,
            "entry_id_hex": selected["entry_id_hex"],
            "destination_hex": terms[selected["recipient"] + "_address_hex"]}


def validate_pair(pair):
    fields(pair, ("schema", "long_presignature_hex", "short_presignature_hex"))
    if pair["schema"] != "ptlc-nom-public-pair-v1": raise RecoveryError("unsupported adaptor pair")
    try:
        fixed_hex(pair["long_presignature_hex"], 65); fixed_hex(pair["short_presignature_hex"], 65)
    except CompatibilityError:
        raise RecoveryError("invalid public adaptor encoding") from None
    return copy.deepcopy(pair)


def verification_context_digest(terms, pair):
    return digest(b"ptlc-nom-verification-context-v1", {"terms": validate_terms(terms), "pair": validate_pair(pair)})


def synthetic_claim(terms, leg, signature_hex):
    """Reference envelope only. This is not account-block construction or signing."""
    try: fixed_hex(signature_hex, 64)
    except CompatibilityError: raise RecoveryError("invalid public completion encoding") from None
    c = context(terms, leg)
    return canonical({"schema": CLAIM_SCHEMA, "terms_digest_hex": terms_digest(terms), "leg": leg,
                      "context": c, "message_hex": unlock_message(c), "signature_hex": signature_hex})


def claim_signature(terms, leg, wire):
    value = decode(wire)
    fields(value, ("schema", "terms_digest_hex", "leg", "context", "message_hex", "signature_hex"))
    signature = value["signature_hex"]
    if synthetic_claim(terms, leg, signature) != wire:
        raise RecoveryError("original claim does not match the retained terms")
    return signature


def synthetic_transaction_hash(wire):
    decode(wire)
    return hashlib.sha3_256(b"ptlc-nom-synthetic-transaction-v1\0" + wire).hexdigest()


def observation(terms, leg, kind, *, transaction_hash_hex="", send_timestamp="0", send_momentum_hash_hex="",
                receive_timestamp="0", receive_momentum_hash_hex=""):
    """Construct an unsigned reference observation; independent validation is required."""
    context(terms, leg)
    return {"schema": OBSERVATION_SCHEMA, "terms_digest_hex": terms_digest(terms), "chain_id": terms["chain_id"],
            "genesis_hash_hex": terms["genesis_hash_hex"], "leg": leg, "kind": kind,
            "entry_digest_hex": digest(b"ptlc-nom-entry-v1", {"entry": terms[leg], "context": context(terms, leg)}),
            "transaction_hash_hex": transaction_hash_hex, "send_timestamp": send_timestamp,
            "send_momentum_hash_hex": send_momentum_hash_hex, "receive_timestamp": receive_timestamp,
            "receive_momentum_hash_hex": receive_momentum_hash_hex}


class NomRecovery:
    """One cooperating POSIX owner of append-only public reference evidence.

    Both verifier arguments are explicit trusted local boundaries, not peer
    assertions. The supplied observation verifier is not implemented by this
    class. A complete old log can be restored or copied: there is no anti-rollback
    authority, live finality source, authenticated peer or private nonce custody.
    """

    @classmethod
    def open(cls, path, terms, pair, *, role, verifier, observation_verifier, hook=None):
        instance = cls.__new__(cls)
        instance._fd = None; instance._dir = None; instance._closed = False; instance._poisoned = False
        instance._pid = os.getpid(); instance._thread = threading.current_thread(); instance._hook = hook
        try:
            instance._terms = validate_terms(terms); instance._pair = validate_pair(pair)
            if role not in ("alice", "bob") or not callable(observation_verifier):
                raise RecoveryError("explicit role and observation verifier are required")
            expected = verification_context_digest(terms, pair)
            if verifier.context_digest_hex != expected or verifier.verify_pair() is not True:
                raise RecoveryError("adaptor pair verification failed")
            instance._role = role; instance._verifier = verifier; instance._observer = observation_verifier
            if fcntl is None or os.name != "posix": raise RecoveryError("reference journal requires POSIX ownership")
            path = os.fspath(path); parent, name = os.path.split(path)
            if not name or name in (".", ".."): raise RecoveryError("invalid journal selection")
            instance._name = name
            instance._dir = os.open(parent or ".", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            directory = os.fstat(instance._dir)
            if directory.st_uid != os.getuid() or stat.S_IMODE(directory.st_mode) != 0o700:
                raise RecoveryError("a private owned journal directory is required")
            flags = os.O_RDWR | os.O_NOFOLLOW
            created = False
            try:
                instance._fd = os.open(name, flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=instance._dir)
                created = True
            except FileExistsError:
                instance._fd = os.open(name, flags, dir_fd=instance._dir)
            try: fcntl.flock(instance._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError: raise RecoveryError("journal already has an owner") from None
            instance._state = {"initialized": False, "funded": {}, "originals": {}, "remote_short_hex": "",
                               "recovery_count": 0, "recovered_long_hex": "", "attempts": {}, "phases": {},
                               "disclosure_possible": False, "observations": [], "confirmations": {}}
            instance._head = "00" * 32; instance._sequence = 0; instance._size = 0
            instance._check_file()
            if created:
                os.fsync(instance._dir)
                instance._append({"kind": "init", "terms": instance.terms, "pair": instance.pair, "role": role})
            else:
                instance._load()
                for leg, encoded in instance._state["originals"].items():
                    instance._verify_claim(leg, bytes.fromhex(encoded))
                if instance._state["remote_short_hex"]:
                    instance._verify_claim("short", bytes.fromhex(instance._state["remote_short_hex"]))
            return instance
        except RecoveryError:
            instance.close(); raise
        except (OSError, ValueError, TypeError, AttributeError, RecursionError):
            instance.close(); raise Quarantined("unable to open the reference journal") from None

    def _check_file(self):
        info = os.fstat(self._fd)
        entry = os.stat(self._name, dir_fd=self._dir, follow_symlinks=False)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or (info.st_dev, info.st_ino) != (entry.st_dev, entry.st_ino)
                or info.st_size > MAX_LOG):
            raise Quarantined("journal ownership or file boundary changed")

    @property
    def terms(self): return copy.deepcopy(self._terms)

    @property
    def pair(self): return copy.deepcopy(self._pair)

    @property
    def role(self): return self._role

    def _check(self):
        if self._closed or self._poisoned or self._pid != os.getpid() or self._thread is not threading.current_thread():
            raise Quarantined("reference journal owner is unavailable")
        try:
            self._check_file()
            if os.fstat(self._fd).st_size != self._size: raise Quarantined("journal changed outside its owner")
        except OSError: raise Quarantined("journal continuity cannot be established") from None

    def _load(self):
        os.lseek(self._fd, 0, os.SEEK_SET)
        data = b""
        while True:
            part = os.read(self._fd, min(65536, MAX_LOG + 1 - len(data)))
            if not part: break
            data += part
            if len(data) > MAX_LOG: raise Quarantined("reference history is oversized")
        if not data or not data.endswith(b"\n"): raise Quarantined("incomplete reference history")
        for line in data.splitlines():
            record = decode(line)
            fields(record, ("schema", "sequence", "previous_hash_hex", "event", "hash_hex"))
            unhashed = {key: record[key] for key in record if key != "hash_hex"}
            if (record["schema"] != "ptlc-nom-recovery-log-v1" or type(record["sequence"]) is not int
                    or record["sequence"] != self._sequence + 1 or record["sequence"] > MAX_EVENTS
                    or record["previous_hash_hex"] != self._head
                    or digest(b"ptlc-nom-log-v1", unhashed) != record["hash_hex"]):
                raise Quarantined("reference history continuity failed")
            self._state = self._apply(record["event"])
            self._head = record["hash_hex"]; self._sequence += 1
        self._size = len(data)

    def _owned(self, leg):
        return leg == ("short" if self.role == "alice" else "long")

    def _original(self, leg, state):
        return state["originals"].get(leg, state["remote_short_hex"] if leg == "short" else "")

    def _validate_observation(self, proof, state):
        fields(proof, ("schema", "terms_digest_hex", "chain_id", "genesis_hash_hex", "leg", "kind", "entry_digest_hex",
                       "transaction_hash_hex", "send_timestamp", "send_momentum_hash_hex", "receive_timestamp", "receive_momentum_hash_hex"))
        leg, kind = proof["leg"], proof["kind"]
        if leg not in ("long", "short") or kind not in ("funded", "unseen", "send-confirmed", "unlock-confirmed", "reorged"):
            raise RecoveryError("unsupported reference observation")
        expected = observation(self.terms, leg, kind, **{key: proof[key] for key in (
            "transaction_hash_hex", "send_timestamp", "send_momentum_hash_hex", "receive_timestamp", "receive_momentum_hash_hex")})
        if proof != expected: raise RecoveryError("observation does not match the frozen network and entry")
        original = self._original(leg, state)
        if kind == "funded":
            if any(proof[key] != default for key, default in (("transaction_hash_hex", ""), ("send_timestamp", "0"),
                    ("send_momentum_hash_hex", ""), ("receive_timestamp", "0"), ("receive_momentum_hash_hex", ""))):
                raise RecoveryError("funding observation includes claim assertions")
        else:
            if not original or proof["transaction_hash_hex"] != synthetic_transaction_hash(bytes.fromhex(original)):
                raise RecoveryError("observation does not refer to the exact original")
            if kind in ("send-confirmed", "unlock-confirmed"):
                timestamp = decimal(proof["send_timestamp"], 63, positive=True)
                fixed_hex(proof["send_momentum_hash_hex"], 32)
                if timestamp >= int(self.terms[leg]["expires_at"]):
                    raise RecoveryError("claim send confirmation misses the expiry boundary")
                prior = state["confirmations"].get(leg)
                if prior and any(prior[key] != proof[key] for key in ("send_timestamp", "send_momentum_hash_hex")):
                    raise RecoveryError("original send confirmation requires explicit reorg reconciliation")
            elif proof["send_timestamp"] != "0" or proof["send_momentum_hash_hex"] != "":
                raise RecoveryError("unknown observation asserts a confirmation")
            if kind == "unlock-confirmed":
                received = decimal(proof["receive_timestamp"], 63, positive=True)
                fixed_hex(proof["receive_momentum_hash_hex"], 32)
                if received < int(proof["send_timestamp"]): raise RecoveryError("receive precedes send confirmation")
            elif proof["receive_timestamp"] != "0" or proof["receive_momentum_hash_hex"] != "":
                raise RecoveryError("observation does not establish contract execution")
        return leg, kind

    def _apply(self, event):
        state = copy.deepcopy(self._state)
        kind = event.get("kind") if type(event) is dict else None
        if kind == "init":
            fields(event, ("kind", "terms", "pair", "role"))
            if state["initialized"] or event != {"kind": "init", "terms": self.terms, "pair": self.pair, "role": self.role}:
                raise Quarantined("journal selections do not match")
            state["initialized"] = True
        elif not state["initialized"]:
            raise Quarantined("reference history has no initial selection")
        elif kind == "observation":
            fields(event, ("kind", "proof")); leg, result = self._validate_observation(event["proof"], state)
            if result == "funded": state["funded"][leg] = True
            else:
                prior_phase = state["phases"].get(leg)
                phase = {"unseen": "OUTCOME_UNKNOWN", "reorged": "OUTCOME_UNKNOWN",
                         "send-confirmed": "SEND_CONFIRMED", "unlock-confirmed": "UNLOCK_CONFIRMED"}[result]
                if not ((result == "unseen" and prior_phase in ("SEND_CONFIRMED", "UNLOCK_CONFIRMED"))
                        or (result == "send-confirmed" and prior_phase == "UNLOCK_CONFIRMED")):
                    state["phases"][leg] = phase
                if result == "reorged":
                    state["funded"][leg] = False; state["confirmations"].pop(leg, None)
                elif result in ("send-confirmed", "unlock-confirmed"):
                    state["confirmations"][leg] = {key: event["proof"][key] for key in ("send_timestamp", "send_momentum_hash_hex")}
            state["observations"].append(copy.deepcopy(event["proof"]))
        elif kind in ("original", "remote-short"):
            fields(event, ("kind", "leg", "wire_hex")); leg = event["leg"]
            wire = bytes.fromhex(event["wire_hex"]); claim_signature(self.terms, leg, wire)
            if kind == "remote-short":
                if self.role != "bob" or leg != "short" or state["remote_short_hex"]:
                    raise RecoveryError("remote original is already selected or unavailable")
                state["remote_short_hex"] = event["wire_hex"]
                state["disclosure_possible"] = True
            else:
                if not self._owned(leg) or leg in state["originals"]:
                    raise RecoveryError("original ownership is immutable")
                if leg == "long" and claim_signature(self.terms, leg, wire) != state["recovered_long_hex"]:
                    raise RecoveryError("long completion has no retained recovery")
                state["originals"][leg] = event["wire_hex"]; state["phases"][leg] = "ORIGINAL_RETAINED"
        elif kind == "recovery-admitted":
            fields(event, ("kind",))
            if (self.role != "bob" or not state["remote_short_hex"] or state["phases"].get("short") != "UNLOCK_CONFIRMED"
                    or not state["funded"].get("long") or state["recovery_count"] >= MAX_RECOVERIES):
                raise RecoveryError("long recovery is not admitted")
            state["recovery_count"] += 1
        elif kind == "recovered":
            fields(event, ("kind", "signature_hex")); fixed_hex(event["signature_hex"], 64)
            if self.role != "bob" or state["recovery_count"] == 0 or state["recovered_long_hex"]:
                raise RecoveryError("long recovery result is already selected or unavailable")
            state["recovered_long_hex"] = event["signature_hex"]
        elif kind == "attempt":
            fields(event, ("kind", "leg")); leg = event["leg"]
            if (not self._owned(leg) or leg not in state["originals"] or not all(state["funded"].get(x) for x in ("long", "short"))
                    or state["phases"].get(leg) == "UNLOCK_CONFIRMED"):
                raise RecoveryError("original disclosure is not admitted")
            state["attempts"][leg] = state["attempts"].get(leg, 0) + 1
            state["phases"][leg] = "OUTCOME_UNKNOWN"; state["disclosure_possible"] = True
        else:
            raise RecoveryError("unsupported reference history event")
        return state

    def _append(self, event):
        self._check()
        next_state = self._apply(event)
        if self._sequence >= MAX_EVENTS: raise RecoveryError("reference history allowance is exhausted")
        record = {"schema": "ptlc-nom-recovery-log-v1", "sequence": self._sequence + 1,
                  "previous_hash_hex": self._head, "event": event}
        record["hash_hex"] = digest(b"ptlc-nom-log-v1", record)
        wire = canonical(record) + b"\n"
        if self._size + len(wire) > MAX_LOG: raise RecoveryError("reference history byte allowance is exhausted")
        try:
            os.lseek(self._fd, 0, os.SEEK_END)
            offset = 0
            while offset < len(wire):
                count = os.write(self._fd, wire[offset:])
                if count <= 0: raise OSError()
                offset += count
            os.fsync(self._fd)
            self._state = next_state; self._sequence += 1; self._size += len(wire); self._head = record["hash_hex"]
            if self._hook is not None: self._hook(event["kind"])
        except BaseException:
            self._poisoned = True
            raise Quarantined("reference write outcome is uncertain") from None

    def _verify_claim(self, leg, wire):
        signature = claim_signature(self.terms, leg, wire)
        if self._verifier.verify_claim(leg, signature) is not True:
            raise RecoveryError("claim does not complete the retained adaptor signature")
        return signature

    def status(self):
        self._check()
        return copy.deepcopy(self._state)

    def record_observation(self, proof):
        self._check(); self._validate_observation(proof, self._state)
        if self._observer(copy.deepcopy(proof)) is not True:
            raise RecoveryError("independent reference observation refused")
        prior = next((item for item in reversed(self._state["observations"]) if item["leg"] == proof["leg"]), None)
        if prior == proof: return
        self._append({"kind": "observation", "proof": copy.deepcopy(proof)})

    def retain_original(self, leg, wire):
        self._check(); self._verify_claim(leg, wire)
        original = self._state["originals"].get(leg)
        if original:
            if original != wire.hex(): raise RecoveryError("original replacement is forbidden")
            return synthetic_transaction_hash(wire)
        self._append({"kind": "original", "leg": leg, "wire_hex": wire.hex()})
        return synthetic_transaction_hash(wire)

    def prepare_attempt(self, leg):
        """Persist unknown outcome and disclosure intent before returning original bytes."""
        self._append({"kind": "attempt", "leg": leg})
        return bytes.fromhex(self._state["originals"][leg])

    def recover_long(self, original_short, proof):
        """Bob retains original short evidence before public-only adaptor recovery."""
        self._check()
        if self.role != "bob": raise RecoveryError("long recovery belongs to bob")
        signature = self._verify_claim("short", original_short)
        retained = self._state["remote_short_hex"]
        if retained and retained != original_short.hex(): raise RecoveryError("remote original replacement is forbidden")
        if not retained: self._append({"kind": "remote-short", "leg": "short", "wire_hex": original_short.hex()})
        if type(proof) is not dict or proof.get("kind") != "unlock-confirmed" or proof.get("leg") != "short":
            raise RecoveryError("send acknowledgement alone cannot authorize recovery")
        self.record_observation(proof)
        if not self._state["recovered_long_hex"]:
            self._append({"kind": "recovery-admitted"})
            recovered = self._verifier.recover_long(signature)
            # The verifier returns only a public completion, never the extracted scalar.
            if self._verifier.verify_claim("long", recovered) is not True:
                raise RecoveryError("recovered long completion verification failed")
            self._append({"kind": "recovered", "signature_hex": recovered})
        wire = synthetic_claim(self.terms, "long", self._state["recovered_long_hex"])
        self.retain_original("long", wire)
        return wire

    def close(self):
        if self._closed: return
        self._closed = True
        if self._fd is not None:
            try: os.close(self._fd)
            except OSError: pass
            self._fd = None
        if self._dir is not None:
            try: os.close(self._dir)
            except OSError: pass
            self._dir = None

    def __enter__(self): return self
    def __exit__(self, *_): self.close()
