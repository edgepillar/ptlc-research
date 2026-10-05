"""Test-only synthetic store scenarios; no application source or signing API."""

from contextlib import contextmanager
from dataclasses import replace
import copy
import hashlib
import json
from pathlib import Path
import tempfile

from qualification import original_read_contract as reads, original_read_response as responses
from qualification import original_read_snapshot as snapshots, policy_effect_store as local
from qualification import source_root_roles as roots


INPUT = Path("qualification/fixtures/original_read_snapshot_inputs.json")
OUTPUT = Path("qualification/fixtures/original_read_snapshot_response.json")
SCENARIOS = ("initial_absent", "pending", "completed", "revoked_absent", "revoked_pending",
    "revoked_completed", "replaced_completed", "reduced_pending_two_charges",
    "unavailable_pending", "mode_round_trip_pending")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def root_from(declaration):
    return roots.root_declaration(source_context=declaration["source_context"],
        governor_profile=declaration["governor_profile"], delegated_keys=declaration["delegated_keys"],
        revision=declaration["declaration_revision"])


def primary_root():
    old = json.loads(Path("qualification/fixtures/original_read_response.json").read_text("ascii"))
    return root_from(old["positive_vectors"]["primary"]["envelope"]["root_envelope"]["declaration"])


class Scenario:
    def __init__(self, path, name):
        if name not in SCENARIOS:
            raise ValueError("unsupported synthetic snapshot scenario")
        self.path, self.root = path, primary_root()
        declaration = self.root.as_dict()
        context = declaration["source_context"]
        self.labels = local.SourceLabels(context["source_id_hex"], context["source_incarnation_hex"],
            context["authority_id_hex"], context["resource_digest_hex"])
        self.profile = canonical(declaration["governor_profile"])
        self.original = local.OriginalRequest("01"*32, 0, self.profile, "02"*32)
        self.store = local.OfflinePolicyEffectStore(str(path), self.labels, initial_profile=self.profile)
        if name not in ("initial_absent", "revoked_absent"):
            self.store.allocate_synthetic(self.original)
        if name in ("completed", "revoked_completed", "replaced_completed"):
            self.store.apply_synthetic_effect(self.original)
        if name.startswith("revoked_"):
            self.store.replace_local_policy(0, self.profile, active=False)
        if name == "replaced_completed":
            # Reuse a public synthetic curve key; no signer material is read here.
            old = json.loads(Path("qualification/fixtures/original_read_response.json").read_text("ascii"))
            other = old["positive_vectors"]["new_head_profile"]["response"]["claim"]["head_policy"]["governor_profile"]
            declaration["governor_profile"].update(owner_auth_key_hex=other["owner_auth_key_hex"],
                authority_epoch=2, max_attempt_limit=1, max_target_limit=1,
                authority_profile_digest_hex="09"*32, verifier_profile_digest_hex="0a"*32,
                pool_profile_digest_hex="0b"*32, resource_profile_digest_hex="0c"*32)
            declaration["declaration_revision"] += 1
            self.root = root_from(declaration)
            self.store.replace_local_policy(0, canonical(declaration["governor_profile"]), active=False)
        if name == "reduced_pending_two_charges":
            self.store.allocate_synthetic(replace(self.original, operation_id_hex="04"*32, proposal_digest_hex="05"*32))
            declaration["governor_profile"].update(max_attempt_limit=1, max_target_limit=1)
            declaration["declaration_revision"] += 1
            self.root = root_from(declaration)
            self.store.replace_local_policy(0, canonical(declaration["governor_profile"]), active=True)
        if name in ("unavailable_pending", "mode_round_trip_pending"):
            self.store.set_local_source_mode("unavailable")
        if name == "mode_round_trip_pending":
            self.store.set_local_source_mode("live")

    def query(self, *, challenge="03", original=None, heads=None):
        original = original or self.original
        operation = reads.original_operation(operation_id_hex=original.operation_id_hex,
            expected_revision=original.expected_revision, profile_wire=original.profile_wire,
            proposal_digest_hex=original.proposal_digest_hex)
        heads = heads or snapshots.local_checkpoints(self.store, self.root)
        return reads.original_read_query(self.root, operation, checkpoint=heads.policy_checkpoint,
            record_checkpoint=heads.record_checkpoint, challenge_hex=challenge*32)

    def response(self, query=None):
        query = query or self.query()
        claim = snapshots.sample_original(self.store, self.root, query)
        return responses.original_read_response(self.root, query, claim)

    def material(self):
        """Public synthetic retained rows, separate from the signed claim."""
        db, declaration = self.store._db, self.root.as_dict()
        source = db.execute("SELECT revision,profile,active,mode FROM source").fetchone()
        policies = [dict(revision=r, profile_hex=p.hex(), active=bool(a), event_sequence=s)
            for r,p,a,s in db.execute("SELECT revision,profile,active,event_seq FROM policies ORDER BY revision")]
        operations = [dict(original_operation=reads.original_operation(operation_id_hex=o,
            expected_revision=r, profile_wire=p, proposal_digest_hex=d).as_dict(),
            charge_sequence=c, effect_sequence=e) for o,r,p,d,c,e in db.execute(
                "SELECT operation_id,revision,profile,proposal,charge_seq,effect_seq FROM operations ORDER BY operation_id")]
        effects = [dict(operation_id_hex=o, event_sequence=s, payload=p) for o,s,p in db.execute(
            "SELECT operation_id,event_seq,payload FROM effects ORDER BY operation_id")]
        events = [dict(event_sequence=s, kind=k, revision=r, operation_id_hex=o, detail=d)
            for s,k,r,o,d in db.execute("SELECT seq,kind,revision,operation_id,detail FROM events ORDER BY seq")]
        return dict(root_declaration=declaration, retention_rule=reads.RETENTION_RULE,
            source=dict(revision=source[0], profile_hex=source[1].hex(), active=bool(source[2]), mode=source[3]),
            policies=policies, operations=operations, effects=effects, events=events)


@contextmanager
def scenario(name):
    with tempfile.TemporaryDirectory(prefix="synthetic-signed-snapshot-") as directory:
        value = Scenario(Path(directory)/"policy.sqlite3", name)
        try:
            yield value
        finally:
            if not value.store._closed:
                value.store.close()


def selected(vector):
    """Grammar reconstruction only; counterclaims here are explicitly self-selected."""
    root = root_from(vector["root_declaration"])
    response = vector["response"]
    query = responses._prepared(root.as_dict(), response["query"])
    claim = reads.parse_claim(query, canonical(response["claim"]))
    return responses.original_read_response(root, query, claim)


def unsigned_inputs():
    positive = {}
    for name in SCENARIOS:
        with scenario(name) as value:
            expected = value.response()
            positive[name] = dict(root_declaration=value.root.as_dict(), response=expected.as_dict(),
                message_digest_hex=expected.message_digest_hex, record_material=value.material())
    counter = {}
    cases = (("false_absence_at_pending_head", "pending"),
        ("false_completion_at_two_charge_head", "reduced_pending_two_charges"),
        ("false_active_at_revoked_head", "revoked_pending"),
        ("same_id_other_proposal", "pending"),
        ("same_id_other_historical_profile", "replaced_completed"),
        ("fresh_challenge_over_initial_absence", "initial_absent"))
    for name, base in cases:
        vector = copy.deepcopy(positive[base])
        vector.pop("record_material")
        r = vector["response"]
        q, c = r["query"], r["claim"]
        if name.startswith("false_absence"):
            c.update(observation="absent", original_record=None)
        elif name.startswith("false_completion"):
            c["observation"] = "completed"
            c["original_record"]["effect_sequence"] = 2
        elif name.startswith("false_active"):
            c["head_policy"]["active"] = True
        elif name == "same_id_other_proposal":
            q["original_operation"]["proposal_digest_hex"] = "06"*32
            c["original_record"]["original_operation"] = copy.deepcopy(q["original_operation"])
        elif name == "same_id_other_historical_profile":
            q["original_operation"]["governor_profile"]["authority_epoch"] += 1
            c["original_record"]["original_operation"] = copy.deepcopy(q["original_operation"])
        else:
            q["challenge_hex"] = "07"*32
            c["challenge_hex"] = q["challenge_hex"]
        c["query_digest_hex"] = hashlib.sha256(reads.QUERY_DOMAIN+canonical(q)).hexdigest()
        r["claim_digest_hex"] = hashlib.sha256(reads.CLAIM_DOMAIN+canonical(c)).hexdigest()
        vector["message_digest_hex"] = selected(vector).message_digest_hex
        vector["actual_scenario"] = base
        counter[name] = vector
    return dict(schema="ptlc-original-read-snapshot-inputs-v1", purpose="offline-owned-snapshot-binding-only",
        positive_vectors=positive, counterclaim_vectors=counter)
