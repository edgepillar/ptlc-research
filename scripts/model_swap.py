"""Finite offline schedule model for a REVIEW-PENDING bilateral swap graph.

Alice owns the adaptor secret, funds Bitcoin first, and claims the shorter-lived
Zenon lock. Bob extracts from that signature and claims Bitcoin. Both success
authorities are idealized exact two-party artifacts, NOT implemented signatures.

Assumptions: validated funding never disappears; ideal cryptography and exact
artifact binding; one abstract shared tick clock; bounded honest observation and
inclusion; only the configured bounded Zenon-claim rollbacks; no Bitcoin-spend
rollback. A due honest action prevents time advancing: this explicitly restricts
the scheduler and is not a measured network guarantee. Fees, chain consensus,
real locktime conversion, nonce storage and crashes are outside this model.

The ownership invariant is checked independently of action guards. Exhaustive
search of this finite abstraction is NOT a cryptographic or cross-chain proof.
No RPC, wallet, transaction, signer, network or production client exists here.
"""

import argparse
from collections import deque
from dataclasses import asdict, dataclass, replace
from enum import IntEnum
import json


class Leg(IntEnum):
    UNFUNDED = 0
    LOCKED = 1
    CLAIMED = 2
    REFUNDED = 3


@dataclass(frozen=True)
class Bounds:
    zenon_expiry: int = 6
    bitcoin_refund: int = 10
    inclusion_delay: int = 1
    observation_delay: int = 1
    zenon_reorg_budget: int = 1
    zenon_reorg_window: int = 1
    horizon: int = 12

    @property
    def last_safe_reveal(self):
        recovery = (
            (self.zenon_reorg_budget + 1) * self.inclusion_delay
            + self.zenon_reorg_budget * self.zenon_reorg_window
        )
        return self.zenon_expiry - 1 - recovery

    def validate(self):
        values = asdict(self)
        if any(not isinstance(value, int) or value < 0 for value in values.values()):
            raise ValueError("bounds must be nonnegative integer ticks")
        if self.inclusion_delay < 1 or self.observation_delay < 1:
            raise ValueError("modeled delay bounds must be positive")
        if self.last_safe_reveal < 0:
            raise ValueError("no modeled safe disclosure interval")
        if self.bitcoin_refund <= self.zenon_expiry - 1 + self.observation_delay + self.inclusion_delay:
            raise ValueError("Bitcoin refund margin does not cover the latest Zenon claim")
        if self.horizon < self.bitcoin_refund + self.inclusion_delay:
            raise ValueError("horizon must include the modeled refund recovery interval")


@dataclass(frozen=True)
class Policy:
    verify_funding: bool = True
    retain_extraction: bool = True
    enforce_reveal_cutoff: bool = True
    bounded_response: bool = True


POLICIES = {
    "safe": Policy(),
    "observed-only": Policy(verify_funding=False),
    "forget-extraction": Policy(retain_extraction=False),
    "late-reveal": Policy(enforce_reveal_cutoff=False),
    "unbounded-response": Policy(bounded_response=False),
}


@dataclass(frozen=True)
class State:
    time: int = 0
    btc: Leg = Leg.UNFUNDED
    znn: Leg = Leg.UNFUNDED
    btc_observed: bool = False
    btc_validated: bool = False
    znn_observed: bool = False
    znn_validated: bool = False
    btc_artifact: bool = False
    znn_partial: bool = False
    extraction_retained: bool = False
    znn_artifact: bool = False
    exposed_at: int = -1
    secret_extracted: bool = False
    btc_claim_due: int = -1
    znn_claim_due: int = -1
    btc_refund_due: int = -1
    znn_refund_due: int = -1
    znn_included_at: int = -1
    reorgs: int = 0


def refund_eligible(asset, actor, time, bounds):
    if asset == "btc":
        return actor == "alice" and time >= bounds.bitcoin_refund
    if asset == "znn":
        return actor == "bob" and time >= bounds.zenon_expiry
    return False


def principal_loss(state, honest):
    """Derive the adversary's two principals from ledger outcomes alone."""
    if honest == "alice":
        return state.btc == Leg.CLAIMED and state.znn in (Leg.UNFUNDED, Leg.REFUNDED)
    if honest == "bob":
        return state.znn == Leg.CLAIMED and state.btc in (Leg.UNFUNDED, Leg.REFUNDED)
    raise ValueError("honest participant must be alice or bob")


def _funding_accepted(state, asset, policy):
    return getattr(state, asset + ("_validated" if policy.verify_funding else "_observed"))


def _time_may_advance(state, honest, bounds, policy):
    """Restrict schedules to explicitly assumed honest response/inclusion bounds."""
    if honest == "alice":
        if state.btc == Leg.LOCKED and state.time >= bounds.bitcoin_refund:
            if state.btc_refund_due < 0 or state.time >= state.btc_refund_due:
                return False
        if state.znn == Leg.LOCKED and state.time < bounds.zenon_expiry:
            if state.znn_claim_due >= 0 and state.time >= state.znn_claim_due:
                return False
    else:
        if state.znn == Leg.LOCKED and state.time >= bounds.zenon_expiry:
            if state.znn_refund_due < 0 or state.time >= state.znn_refund_due:
                return False
        if policy.bounded_response:
            if state.exposed_at >= 0 and state.extraction_retained and not state.secret_extracted:
                if state.time >= state.exposed_at + bounds.observation_delay:
                    return False
            if state.btc == Leg.LOCKED and state.btc_claim_due >= 0:
                if state.time >= state.btc_claim_due:
                    return False
    return True


def successors(state, honest="alice", bounds=Bounds(), policy=Policy()):
    """Yield legal ledger actions and honest-policy/adversarial choices.

    The adversary may withhold any optional action or report nonexistent funding.
    Artifacts are exact, idealized spend capabilities. Their possession has an
    explicit exchange order; they do not encode the ownership invariant.
    """
    if honest not in ("alice", "bob"):
        raise ValueError("honest participant must be alice or bob")
    alice_honest = honest == "alice"
    bob_honest = honest == "bob"
    now = state.time
    if state.btc == Leg.UNFUNDED and now < bounds.zenon_expiry:
        yield "alice_funds_btc", replace(state, btc=Leg.LOCKED)
    if not state.btc_observed and (state.btc == Leg.LOCKED or not alice_honest):
        yield "bob_observes_btc", replace(state, btc_observed=True)
    if state.btc_observed and not state.btc_validated and state.btc == Leg.LOCKED:
        yield "bob_validates_btc", replace(state, btc_validated=True)
    if not state.btc_artifact and (state.btc == Leg.LOCKED or not alice_honest):
        yield "alice_delivers_exact_btc_artifact", replace(state, btc_artifact=True)

    bob_may_fund = state.btc_artifact and _funding_accepted(state, "btc", policy)
    if state.znn == Leg.UNFUNDED and now < bounds.zenon_expiry and (not bob_honest or bob_may_fund):
        yield "bob_funds_znn", replace(state, znn=Leg.LOCKED)
    if not state.znn_observed and (state.znn == Leg.LOCKED or not bob_honest):
        yield "alice_observes_znn", replace(state, znn_observed=True)
    if state.znn_observed and not state.znn_validated and state.znn == Leg.LOCKED:
        yield "alice_validates_znn", replace(state, znn_validated=True)

    alice_may_share = state.btc_artifact and _funding_accepted(state, "znn", policy)
    if not state.znn_partial and (not alice_honest or alice_may_share):
        yield "alice_delivers_exact_znn_partial", replace(state, znn_partial=True)
    if state.znn_partial and not state.znn_artifact and not state.extraction_retained:
        if not bob_honest or (policy.retain_extraction and state.znn == Leg.LOCKED):
            yield "bob_retains_exact_extraction_material", replace(state, extraction_retained=True)
    bob_may_release = (
        state.znn == Leg.LOCKED
        and state.btc_artifact
        and (state.extraction_retained or not policy.retain_extraction)
    )
    if state.znn_partial and not state.znn_artifact and (not bob_honest or bob_may_release):
        yield "bob_releases_exact_znn_artifact", replace(state, znn_artifact=True)

    alice_may_reveal = (
        state.btc_artifact
        and state.btc == Leg.LOCKED
        and _funding_accepted(state, "znn", policy)
        and now < bounds.zenon_expiry
        and (not policy.enforce_reveal_cutoff or now <= bounds.last_safe_reveal)
    )
    if state.znn_artifact and state.exposed_at < 0 and (not alice_honest or alice_may_reveal):
        due = now + bounds.inclusion_delay if alice_honest else bounds.horizon + 1
        yield "alice_publishes_revealing_znn_claim", replace(state, exposed_at=now, znn_claim_due=due)
    if state.znn_claim_due >= 0 and state.znn == Leg.LOCKED and now < bounds.zenon_expiry:
        yield "include_znn_claim", replace(state, znn=Leg.CLAIMED, znn_claim_due=-1, znn_included_at=now)

    if state.exposed_at >= 0 and state.extraction_retained and state.btc_artifact and not state.secret_extracted:
        due = now + bounds.inclusion_delay if bob_honest else bounds.horizon + 1
        yield "bob_extracts_and_publishes_btc_claim", replace(state, secret_extracted=True, btc_claim_due=due)
    # Bitcoin claim authority has NO expiry. It races the refund once it opens.
    if state.btc_claim_due >= 0 and state.btc == Leg.LOCKED:
        yield "include_btc_claim", replace(state, btc=Leg.CLAIMED, btc_claim_due=-1)

    if state.btc == Leg.LOCKED and refund_eligible("btc", "alice", now, bounds):
        if state.btc_refund_due < 0:
            yield "alice_requests_btc_refund", replace(state, btc_refund_due=now + bounds.inclusion_delay)
        else:
            yield "include_alice_btc_refund", replace(state, btc=Leg.REFUNDED, btc_refund_due=-1)
    if state.znn == Leg.LOCKED and refund_eligible("znn", "bob", now, bounds):
        if state.znn_refund_due < 0:
            yield "bob_requests_znn_refund", replace(state, znn_refund_due=now + bounds.inclusion_delay)
        else:
            yield "include_bob_znn_refund", replace(state, znn=Leg.REFUNDED, znn_refund_due=-1)

    if (
        state.znn == Leg.CLAIMED
        and state.reorgs < bounds.zenon_reorg_budget
        and now <= state.znn_included_at + bounds.zenon_reorg_window
    ):
        due = now + bounds.inclusion_delay if alice_honest else bounds.horizon + 1
        # Knowledge and exact broadcast bytes survive rollback of the ledger.
        yield "reorg_znn_claim", replace(
            state, znn=Leg.LOCKED, znn_included_at=-1,
            znn_claim_due=due, reorgs=state.reorgs + 1,
        )
    if now < bounds.horizon and _time_may_advance(state, honest, bounds, policy):
        yield "tick", replace(state, time=now + 1)


def step(state, action, honest="alice", bounds=Bounds(), policy=Policy()):
    for candidate, result in successors(state, honest, bounds, policy):
        if candidate == action:
            return result
    raise ValueError("action is unavailable in this modeled state: " + action)


@dataclass(frozen=True)
class SearchResult:
    states: int
    transitions: int
    horizon_states: int
    complete: bool
    counterexample: tuple


def explore(honest="alice", bounds=Bounds(), policy=Policy(), max_states=250000):
    """Breadth-first exploration with a concrete shortest violating trace."""
    bounds.validate()
    start = State()
    parents = {start: None}
    queue = deque([start])
    transitions = 0
    horizon_states = 0
    while queue:
        state = queue.popleft()
        if state.time == bounds.horizon:
            horizon_states += 1
        if principal_loss(state, honest):
            trace = []
            cursor = state
            while parents[cursor] is not None:
                previous, action = parents[cursor]
                trace.append("t=" + str(previous.time) + ": " + action)
                cursor = previous
            return SearchResult(len(parents), transitions, horizon_states, False, tuple(reversed(trace)))
        for action, following in successors(state, honest, bounds, policy):
            transitions += 1
            if following not in parents:
                if len(parents) >= max_states:
                    raise RuntimeError("state-space limit reached; search is incomplete")
                parents[following] = (state, action)
                queue.append(following)
    return SearchResult(len(parents), transitions, horizon_states, True, ())


def main():
    parser = argparse.ArgumentParser(description="Offline finite swap schedule model; not a security proof")
    parser.add_argument("--honest", choices=("alice", "bob", "both"), default="both")
    parser.add_argument("--policy", choices=tuple(POLICIES), default="safe")
    arguments = parser.parse_args()
    roles = ("alice", "bob") if arguments.honest == "both" else (arguments.honest,)
    reports = {}
    try:
        for role in roles:
            reports[role] = asdict(explore(role, policy=POLICIES[arguments.policy]))
    except RuntimeError as error:
        print(json.dumps({"error": str(error), "claim": "incomplete finite model search"}))
        return 2
    print(json.dumps({
        "claim": "finite abstraction only; no cryptographic or chain security proof",
        "policy": arguments.policy,
        "bounds": asdict(Bounds()),
        "last_safe_reveal": Bounds().last_safe_reveal,
        "results": reports,
    }, indent=2))
    return int(any(report["counterexample"] for report in reports.values()))


if __name__ == "__main__":
    raise SystemExit(main())
