"""Test-only retained-prefix comparison of two complete synthetic openings.

Both queries are independently selected historical byte expectations. Neither
this relation nor the frozen description authenticates them, finds a latest
head, retains a consumer witness or authorizes lookup, recovery or use.
"""

from dataclasses import dataclass

from qualification import original_read_contract as reads
import original_snapshot_opening as opening


PURPOSE = "synthetic-retained-prefix-comparison-only"


class PrefixRefused(ValueError):
    """Sanitized refusal with no returned comparison or permission."""


@dataclass(frozen=True)
class PrefixDescription:
    """Unsigned scalar description; directly constructing it proves nothing."""

    relation: str
    earlier_query_digest_hex: str
    later_query_digest_hex: str
    earlier_revision: int
    later_revision: int
    earlier_event_sequence: int
    later_event_sequence: int
    earlier_observation: str
    later_observation: str
    retained_originals: int
    appended_originals: int
    retained_effects: int
    appended_effects: int

    def as_dict(self):
        return dict(purpose=PURPOSE, relation=self.relation,
            earlier=dict(query_digest_hex=self.earlier_query_digest_hex,
                revision=self.earlier_revision, event_sequence=self.earlier_event_sequence,
                observation=self.earlier_observation),
            later=dict(query_digest_hex=self.later_query_digest_hex,
                revision=self.later_revision, event_sequence=self.later_event_sequence,
                observation=self.later_observation),
            retained_originals=self.retained_originals, appended_originals=self.appended_originals,
            retained_effects=self.retained_effects, appended_effects=self.appended_effects)


def _require(condition):
    if not condition:
        raise PrefixRefused("synthetic retained-prefix comparison refused")


def _same(earlier, later):
    return opening.canonical(earlier) == opening.canonical(later)


def compare_openings(earlier_query, earlier_wire, later_query, later_wire):
    """Describe retained history relative to an externally retained witness.

    Complete root/source/incarnation and original tuple must match. Root/profile
    replacement and authorized incarnation changes are outside this experiment.
    A challenge may change, but confers no freshness or currentness here.
    Both complete openings use the unchanged Stage 51 validator and bounds.
    No incoming claim, signature result or Boolean permission is consumed.
    """
    if (type(earlier_query) is not reads.OriginalReadQuery
            or type(later_query) is not reads.OriginalReadQuery):
        raise PrefixRefused("exact independent original queries are required")
    if type(earlier_wire) is not bytes or type(later_wire) is not bytes:
        raise PrefixRefused("exact synthetic opening bytes are required")
    try:
        earlier_selected, later_selected = earlier_query.as_dict(), later_query.as_dict()
        _require(earlier_query._root.canonical_bytes == later_query._root.canonical_bytes
            and _same(earlier_selected["source_context"], later_selected["source_context"])
            and _same(earlier_selected["original_operation"], later_selected["original_operation"]))
        earlier_claim = opening.derive_claim(earlier_query, earlier_wire)
        later_claim = opening.derive_claim(later_query, later_wire)
        # Immutable bounded bytes have already opened both independent selections.
        earlier = opening._decode(earlier_wire)["record_material"]
        later = opening._decode(later_wire)["record_material"]
        old_sequence, new_sequence = len(earlier["events"]), len(later["events"])
        _require(old_sequence <= new_sequence
            and _same(earlier["events"], later["events"][:old_sequence]))
        _require(len(earlier["policies"]) <= len(later["policies"])
            and _same(earlier["policies"], later["policies"][:len(earlier["policies"])]))
        old_rows = {row["original_operation"]["operation_id_hex"]: row
            for row in earlier["operations"]}
        new_rows = {row["original_operation"]["operation_id_hex"]: row
            for row in later["operations"]}
        for operation_id, old in old_rows.items():
            _require(operation_id in new_rows)
            new = new_rows[operation_id]
            _require(_same(old["original_operation"], new["original_operation"])
                and old["charge_sequence"] == new["charge_sequence"])
            if old["effect_sequence"] is not None:
                _require(_same(old, new))
            elif new["effect_sequence"] is not None:
                _require(new["effect_sequence"] > old_sequence)
        for operation_id, new in new_rows.items():
            if operation_id not in old_rows:
                _require(new["charge_sequence"] > old_sequence)
        old_effects = {row["operation_id_hex"]: row for row in earlier["effects"]}
        new_effects = {row["operation_id_hex"]: row for row in later["effects"]}
        for operation_id, old in old_effects.items():
            _require(operation_id in new_effects and _same(old, new_effects[operation_id]))
        for operation_id, new in new_effects.items():
            if operation_id not in old_effects:
                _require(new["event_sequence"] > old_sequence)
        return PrefixDescription(
            relation="same-history" if old_sequence == new_sequence else "retained-extension",
            earlier_query_digest_hex=earlier_query.digest_hex,
            later_query_digest_hex=later_query.digest_hex,
            earlier_revision=earlier["source"]["revision"], later_revision=later["source"]["revision"],
            earlier_event_sequence=old_sequence, later_event_sequence=new_sequence,
            earlier_observation=earlier_claim.as_dict()["observation"],
            later_observation=later_claim.as_dict()["observation"],
            retained_originals=len(old_rows), appended_originals=len(new_rows)-len(old_rows),
            retained_effects=len(old_effects), appended_effects=len(new_effects)-len(old_effects))
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError, OverflowError):
        raise PrefixRefused("synthetic retained-prefix comparison refused") from None
