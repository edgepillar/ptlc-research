"""Synthetic-only subprocess cuts for the isolated SQLite ordering candidate."""

import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from qualification.policy_effect_store import (
    OfflinePolicyEffectStore, OriginalRequest, SourceLabels, StoreOutcomeUnknown, StoreRefused,
)
from policy_effect_native_observation import ObservedConnection, emit


def main():
    path, operation, point, mode = sys.argv[1:5]
    observed = sys.argv[5:] == ["native-execute-errors-v1"]
    if sys.argv[5:] and not observed:
        raise ValueError("fixed synthetic observation option required")
    context = json.loads(sys.stdin.readline())
    labels = SourceLabels(**context["labels"])
    request = OriginalRequest(context["operation"], context["revision"],
        bytes.fromhex(context["profile_hex"]), context["proposal"])
    with OfflinePolicyEffectStore(path, labels) as store:
        store._db.execute("PRAGMA cache_size=1")
        store._db.execute("PRAGMA cache_spill=ON")
        observer = ObservedConnection(store._db) if observed else None
        if observer is not None:
            store._db = observer
        def cut(label):
            if label == point:
                print("paused", flush=True)
                sys.stdin.readline()
        store._cut = cut
        if mode == "ready":
            print("ready", flush=True)
            sys.stdin.readline()
        try:
            if operation == "allocation":
                record = store.allocate_synthetic(request)
            elif operation == "effect":
                record = store.apply_synthetic_effect(request)
            elif operation == "policy":
                revision = store.replace_local_policy(request.expected_revision,
                    bytes.fromhex(context["replacement_hex"]), active=context["active"])
                print(json.dumps(dict(revision=revision)), flush=True)
                emit(observer)
                return 0
            else:
                raise StoreRefused("unsupported synthetic actor command")
            print(json.dumps(dict(charge_sequence=record.charge_sequence,
                effect_sequence=record.effect_sequence)), flush=True)
            emit(observer)
            return 0
        except (StoreRefused, StoreOutcomeUnknown) as error:
            print(type(error).__name__, flush=True)
            emit(observer)
            return 20


if __name__ == "__main__":
    raise SystemExit(main())
