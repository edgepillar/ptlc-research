"""Synthetic local original-read cuts for native ordering and death controls."""

import json
from pathlib import Path
import sys

sys.path[:0] = [str(Path(__file__).resolve().parents[1])]

from offline_session import current_authority_contract as current
from qualification import original_read_contract as reads, original_read_snapshot as snapshot
from qualification import policy_effect_store as local, source_root_roles as roots


def main():
    path, point = sys.argv[1:3]
    packet = json.loads(sys.stdin.readline())
    d = packet["declaration"]
    root = roots.root_declaration(source_context=d["source_context"], governor_profile=d["governor_profile"],
        delegated_keys=d["delegated_keys"], revision=d["declaration_revision"])
    q = packet["query"]
    original = q["original_operation"]
    query = reads.original_read_query(root, reads.original_operation(
        operation_id_hex=original["operation_id_hex"], expected_revision=original["expected_revision"],
        profile_wire=snapshot.ordering._canonical(original["governor_profile"]),
        proposal_digest_hex=original["proposal_digest_hex"]),
        checkpoint=current.PolicyCheckpoint(**q["expected_checkpoint"]),
        record_checkpoint=reads.RecordCheckpoint(q["expected_record_checkpoint"]["event_sequence"],
            q["expected_record_checkpoint"]["record_lineage_digest_hex"]), challenge_hex=q["challenge_hex"])
    with local.OfflinePolicyEffectStore(path, local.SourceLabels(**packet["labels"])) as store:
        def cut(label):
            if label == point:
                print("paused", flush=True)
                sys.stdin.readline()
        store._cut = cut
        try:
            claim = snapshot.sample_original(store, root, query)
            print(json.dumps(claim.as_dict()), flush=True)
            return 0
        except (local.StoreRefused, local.StoreOutcomeUnknown) as error:
            print(type(error).__name__, flush=True)
            return 20


if __name__ == "__main__":
    raise SystemExit(main())
