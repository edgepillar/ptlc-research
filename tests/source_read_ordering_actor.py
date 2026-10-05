"""Synthetic local read checkpoints for native writer/death qualification."""

import json
from pathlib import Path
import sys

sys.path[:0] = [str(Path(__file__).resolve().parents[1]), str(Path(__file__).resolve().parent)]

from offline_session import current_authority_contract as current, governor_authentication as signatures
from qualification import policy_effect_store as local, source_read_ordering as ordering
from qualification import source_root_roles as roots
from test_source_response import selection


def main():
    path, point = sys.argv[1:3]
    packet = json.loads(sys.stdin.readline())
    selected = selection()
    declaration = packet["declaration"]
    root = roots.root_declaration(source_context=declaration["source_context"],
        governor_profile=declaration["governor_profile"], delegated_keys=declaration["delegated_keys"],
        revision=declaration["declaration_revision"])
    query = current.policy_read_query(selected._query._expected,
        ordering._canonical(dict(selected._query.as_dict()["governor_signature_request"],
            schema=signatures.ENVELOPE_SCHEMA)),
        source=selected._query._source, checkpoint=current.PolicyCheckpoint(**packet["checkpoint"]),
        challenge_hex=packet["challenge"])
    original = local.OriginalRequest(packet["operation"], packet["revision"],
        bytes.fromhex(packet["profile_hex"]), packet["proposal"])
    with local.OfflinePolicyEffectStore(path, local.SourceLabels(**packet["labels"])) as store:
        def cut(label):
            if label == point:
                print("paused", flush=True)
                sys.stdin.readline()
        store._cut = cut
        try:
            sample = ordering.sample_original(store, root, query, original)
            print(json.dumps(dict(observation=sample.response.as_dict()["claim"]["observation"],
                sample_digest=sample.digest_hex)), flush=True)
            return 0
        except (local.StoreRefused, local.StoreOutcomeUnknown) as error:
            print(type(error).__name__, flush=True)
            return 20


if __name__ == "__main__":
    raise SystemExit(main())
