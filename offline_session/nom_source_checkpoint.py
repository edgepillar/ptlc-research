"""Selected historical NoM role statements, never source trust or protected use.

All expectations precede incoming packets. Native public signature mathematics
is a separate qualification boundary; copied signed checkpoints can still replay.
"""
from dataclasses import dataclass

from . import enrollment_contract as codec, nom_authority_contract as authority
from . import nom_capsule_query as binding


DECLARATION_SCHEMA = "ptlc-nom-source-checkpoint-declaration-v1"
SOURCE_SCHEMA = "ptlc-nom-historical-source-statement-v1"
CHECKPOINT_SCHEMA = "ptlc-nom-historical-custody-checkpoint-v1"
ENVELOPE_SCHEMA = "ptlc-nom-source-checkpoint-envelope-v1"
REQUEST_SCHEMA = "ptlc-nom-source-checkpoint-request-v1"
RESULT_SCHEMA = "ptlc-nom-source-checkpoint-result-v1"
ROOT_KEY_DOMAIN = b"ptlc-nom-selected-root-key-v1"
DECLARATION_DOMAIN = b"ptlc-nom-source-checkpoint-declaration-message-v1"
SOURCE_DOMAIN = b"ptlc-nom-historical-source-message-v1"
CHECKPOINT_DOMAIN = b"ptlc-nom-historical-custody-message-v1"
CLAIM_DOMAIN = b"ptlc-nom-retained-source-claim-v1"
WORK_DOMAIN = b"ptlc-nom-retained-charged-work-v1"
REQUEST_DOMAIN = b"ptlc-nom-source-checkpoint-request-v1"
MAX_WIRE_BYTES = 8192
_DECLARATION = ("schema", "purpose", "algorithm", "declaration_epoch", "network_selection",
    "root_key_hex", "source_response_key_hex", "consumer_checkpoint_key_hex", "root_transition")
_PACKET = ("schema", "declaration", "source_statement", "checkpoint_statement",
    "root_signature_hex", "source_signature_hex", "checkpoint_signature_hex")
_ERRORS = (ValueError, TypeError, KeyError, AttributeError, RecursionError, OverflowError, UnicodeError)


class SourceCheckpointRefused(ValueError):
    """Sanitized selected-byte or public-check refusal; no verdict on source truth."""


def _require(condition):
    if not condition:
        raise SourceCheckpointRefused("selected NoM role statement refused")


def _hash(domain, wire):
    return authority._digest(domain, wire)


def root_key_digest(key_hex):
    codec._hex(key_hex)
    return _hash(ROOT_KEY_DOMAIN, bytes.fromhex(key_hex))


def _decode(wire):
    _require(type(wire) is bytes and 0 < len(wire) <= MAX_WIRE_BYTES)
    return authority._decode(wire)


def _declaration(value):
    codec._object(value, _DECLARATION)
    _require(value["schema"] == DECLARATION_SCHEMA and value["purpose"] == "historical-nom-source-and-custody-roles"
        and value["algorithm"] == "BIP340-SHA256" and value["root_transition"] == "independent-reprovisioning")
    authority._number(value["declaration_epoch"], positive=True)
    keys = [value[name] for name in ("root_key_hex", "source_response_key_hex", "consumer_checkpoint_key_hex")]
    for key in keys:
        codec._hex(key)
    _require(len(set(keys)) == 3)
    network = value["network_selection"]
    authority._network(network, dict(chain_id=network["chain_id"], genesis_hash_hex=network["genesis_hash_hex"]))
    _require(network["provisioning_root_digest_hex"] == root_key_digest(value["root_key_hex"]))
    return value


@dataclass(frozen=True, init=False)
class NoMRoleDeclaration:
    """Independent complete byte expectation, without provisioned root authority."""
    _wire: bytes

    def __init__(self):
        raise TypeError("use select_declaration")

    def as_dict(self):
        try:
            _require(type(self) is NoMRoleDeclaration)
            return _declaration(_decode(self._wire))
        except _ERRORS:
            raise SourceCheckpointRefused("invalid selected NoM declaration") from None

    @property
    def canonical_bytes(self):
        return codec._canonical(self.as_dict())

    @property
    def digest_hex(self):
        return _hash(DECLARATION_DOMAIN, self.canonical_bytes)


def select_declaration(*, network_selection, root_key_hex, source_response_key_hex,
                       consumer_checkpoint_key_hex, epoch):
    """Select three distinct encodings; shape establishes no ownership or curve fact."""
    try:
        value = _declaration(dict(schema=DECLARATION_SCHEMA, purpose="historical-nom-source-and-custody-roles",
            algorithm="BIP340-SHA256", declaration_epoch=epoch, network_selection=network_selection,
            root_key_hex=root_key_hex, source_response_key_hex=source_response_key_hex,
            consumer_checkpoint_key_hex=consumer_checkpoint_key_hex, root_transition="independent-reprovisioning"))
        wire = codec._canonical(value); _decode(wire)
        result = object.__new__(NoMRoleDeclaration); object.__setattr__(result, "_wire", wire)
        return result
    except _ERRORS:
        raise SourceCheckpointRefused("NoM role declaration selection refused") from None


def _statements(declaration, retained, claim_wire):
    _require(type(declaration) is NoMRoleDeclaration and type(retained) is binding.CapsuleReadBinding)
    selected = retained.as_dict(); query = retained._query.as_dict()
    root = declaration.as_dict()
    _require(root["network_selection"] == query["network_selection"])
    claim = binding.parse_claim(retained, claim_wire)
    knowledge = query["consumer_selection"]
    source = dict(schema=SOURCE_SCHEMA, purpose="historical-selected-capsule-source-claim",
        declaration_digest_hex=declaration.digest_hex, binding_digest_hex=retained.digest_hex,
        query_digest_hex=retained._query.digest_hex, work_scope_digest_hex=selected["work_scope_digest_hex"],
        source_claim_digest_hex=_hash(CLAIM_DOMAIN, claim_wire), claim_coverage=claim["coverage"])
    checkpoint = dict(schema=CHECKPOINT_SCHEMA, purpose="historical-held-capsule-and-unknown-work",
        declaration_digest_hex=declaration.digest_hex, capsule_sha256=selected["capsule_sha256"],
        journal_sha256=selected["journal_sha256"], journal_head_hex=selected["journal_head_hex"],
        journal_sequence=selected["journal_sequence"], work_scope_digest_hex=selected["work_scope_digest_hex"],
        charged_work_digest_hex=_hash(WORK_DOMAIN, codec._canonical(selected["charged_work"])),
        charged_work_count=len(selected["charged_work"]), consumer_incarnation_hex=knowledge["consumer_incarnation_hex"],
        observer_retention_selection_digest_hex=knowledge["retention_selection_digest_hex"],
        observer_retention_head_digest_hex=knowledge["retention_head_digest_hex"],
        observer_retention_sequence=knowledge["retention_sequence"],
        external_checkpoint_digest_hex=knowledge["external_checkpoint_digest_hex"],
        disclosure_possible=True, work_outcome="UNKNOWN")
    return dict(declaration=root, source_statement=source, checkpoint_statement=checkpoint)


@dataclass(frozen=True, init=False)
class NoMSourceCheckpointSelection:
    """Immutable selected retained context; never a current source capability."""
    _declaration: NoMRoleDeclaration
    _binding: binding.CapsuleReadBinding
    _claim_wire: bytes

    def __init__(self):
        raise TypeError("use select_transcript")

    def as_dict(self):
        try:
            _require(type(self) is NoMSourceCheckpointSelection)
            return _statements(self._declaration, self._binding, self._claim_wire)
        except _ERRORS:
            raise SourceCheckpointRefused("invalid selected NoM source/checkpoint transcript") from None

    @property
    def canonical_bytes(self):
        wire = codec._canonical(self.as_dict()); _decode(wire)
        return wire

    def review(self):
        value = self.as_dict()
        return dict(state="HOLD", recovery_action="NONE", selected_declaration_digest_hex=self._declaration.digest_hex,
            selected_binding_digest_hex=self._binding.digest_hex, claim_coverage=value["source_statement"]["claim_coverage"],
            charged_work=value["checkpoint_statement"]["charged_work_count"],
            work_outcome="UNKNOWN FOR EVERY PERSISTED CHARGED ORDINAL",
            root_provisioning="UNFILLED", operational_source_authentication="NOT_PERFORMED",
            source_currentness="UNFILLED", checkpoint_nonrollback="UNFILLED", checkpoint_storage="NOT_IMPLEMENTED",
            atomic_entry="NOT_IMPLEMENTED", public_check="SELECTED VERIFIER/RUNTIME TRUST PREMISE",
            observer_retention_pins="SEPARATE FROM RECOVERY JOURNAL; CALLER ASSERTIONS",
            automatic_retry=False, replenish_work=False, replacement_original_allowed=False,
            application="NO-GO", core="NO-GO")


def select_transcript(declaration, retained, claim_wire):
    """Retain exact original context and raw claim before interpreting peer signatures."""
    try:
        _statements(declaration, retained, claim_wire)
        result = object.__new__(NoMSourceCheckpointSelection)
        object.__setattr__(result, "_declaration", declaration); object.__setattr__(result, "_binding", retained)
        object.__setattr__(result, "_claim_wire", claim_wire); result.canonical_bytes
        return result
    except _ERRORS:
        raise SourceCheckpointRefused("NoM source/checkpoint selection refused") from None


def envelope(expected, *, root_signature, source_signature, checkpoint_signature):
    """Package supplied public signatures; no signer or curve verification exists here."""
    try:
        _require(type(expected) is NoMSourceCheckpointSelection)
        signatures = dict(root_signature_hex=root_signature, source_signature_hex=source_signature,
                          checkpoint_signature_hex=checkpoint_signature)
        _require(all(type(sig) is bytes and len(sig) == 64 for sig in signatures.values()))
        wire = codec._canonical(dict(schema=ENVELOPE_SCHEMA, **expected.as_dict(),
            **{name: sig.hex() for name, sig in signatures.items()})); _decode(wire)
        return wire
    except _ERRORS:
        raise SourceCheckpointRefused("NoM public signature packaging refused") from None


def request(expected, wire):
    """Exact independent context comparison before any selected public-only check."""
    try:
        _require(type(expected) is NoMSourceCheckpointSelection)
        value = _decode(wire); codec._object(value, _PACKET)
        _require(value["schema"] == ENVELOPE_SCHEMA)
        for key, selected in expected.as_dict().items():
            _require(codec._canonical(value[key]) == codec._canonical(selected))
        for field in _PACKET[-3:]:
            encoded = value[field]
            _require(type(encoded) is str and len(encoded) == 128
                     and all(byte in "0123456789abcdef" for byte in encoded))
        value["schema"] = REQUEST_SCHEMA
        return value
    except _ERRORS:
        raise SourceCheckpointRefused("NoM source/checkpoint packet differs from selection") from None


def request_digest(value):
    wire = codec._canonical(value); _decode(wire); codec._object(value, _PACKET)
    _require(value["schema"] == REQUEST_SCHEMA)
    return _hash(REQUEST_DOMAIN, wire)


def expected_result(digest_hex):
    codec._hex(digest_hex)
    return dict(schema=RESULT_SCHEMA, request_digest_hex=digest_hex, root_signature_valid=True,
        source_signature_valid=True, checkpoint_signature_valid=True)


def verify_selected_transcript(expected, wire, *, verifier):
    """Return the same held selection; a forged callback positive is an unsafe control."""
    value = request(expected, wire); before = expected.canonical_bytes
    digest_hex = request_digest(value); _require(callable(verifier))
    try:
        result = verifier(codec._decode(codec._canonical(value), MAX_WIRE_BYTES))
    except Exception:
        raise SourceCheckpointRefused("selected NoM public signature check unavailable") from None
    try:
        _require(type(result) is dict and codec._canonical(result) == codec._canonical(expected_result(digest_hex)))
        _require(expected.canonical_bytes == before)
        return expected
    except _ERRORS:
        raise SourceCheckpointRefused("selected NoM public signature result refused") from None
