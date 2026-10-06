"""Test-only composition of complete openings and historical public responses.

The selected checker remains a trust premise: arbitrary callbacks can forge
mathematics flags. The returned unsigned prefix description is neither a latest
head nor authority, durable witness retention, original receipt or permission.
"""

from qualification import original_read_contract as reads
from qualification import original_read_response as response
import original_snapshot_opening as opening
import original_snapshot_prefix as prefix


class PrefixResponseRefused(ValueError):
    """Sanitized refusal with no returned comparison or permission."""


def compare_public_responses(earlier_query, earlier_opening, earlier_response,
        later_query, later_opening, later_response, *, verifier):
    """Compare independently opened expectations with a selected public check.

    Validate both complete openings, their retained-prefix relation and both
    response packets before invoking either check. Incoming claims or callback
    flags never supply the independent expectations. Two successful checks do
    not select an authoritative future or protect a copied consumer witness.
    """
    if (type(earlier_query) is not reads.OriginalReadQuery
            or type(later_query) is not reads.OriginalReadQuery
            or any(type(wire) is not bytes for wire in
                (earlier_opening, later_opening, earlier_response, later_response))
            or not callable(verifier)):
        raise PrefixResponseRefused("exact selections, bytes and selected checker are required")
    try:
        description = prefix.compare_openings(earlier_query, earlier_opening,
            later_query, later_opening)
        earlier = response.original_read_response(earlier_query._root, earlier_query,
            opening.derive_claim(earlier_query, earlier_opening))
        later = response.original_read_response(later_query._root, later_query,
            opening.derive_claim(later_query, later_opening))
        # A bad later packet must not cause even the earlier check to run.
        response.request(earlier, earlier_response)
        response.request(later, later_response)
        response.verify_selected_response(earlier, earlier_response, verifier=verifier)
        response.verify_selected_response(later, later_response, verifier=verifier)
        return description
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError, OverflowError):
        raise PrefixResponseRefused("synthetic public-response prefix comparison refused") from None
