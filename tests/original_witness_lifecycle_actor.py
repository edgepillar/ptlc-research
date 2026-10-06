"""Bounded synthetic constructor actor; no signer, source or protected use."""

import json
from pathlib import Path
import sys

sys.path[:0] = [str(Path(__file__).resolve().parents[1]), str(Path(__file__).resolve().parent)]
from qualification.original_read_response_verifier import PublicOriginalResponseCheck
from original_witness_store_actor import callback_control, named_packet
from original_witness_store import OfflineOriginalWitnessStore, WitnessOutcomeUnknown, WitnessRefused


def main():
    path, point, mode = sys.argv[1:4]
    context = json.loads(sys.stdin.readline())
    if mode == "flags":
        check = callback_control
    elif mode == "actual":
        check = PublicOriginalResponseCheck(Path(context["entry"]),
            expected_executable_sha256_hex=context["entry_sha256"])
    else:
        return 21

    class PausedCreation(OfflineOriginalWitnessStore):
        def _cut(self, label):
            if label == "create-connected":
                self._db.execute("PRAGMA cache_size=1")
                self._db.execute("PRAGMA cache_spill=ON")
            if label == point:
                print("paused", flush=True)
                if sys.stdin.readline().strip() != "release":
                    raise RuntimeError("synthetic constructor release unavailable")

    try:
        with PausedCreation(path, named_packet("pending")[0], verifier=check) as store:
            print("empty" if store.inspect_retained() is None else "unexpected", flush=True)
        return 0
    except (WitnessRefused, WitnessOutcomeUnknown) as error:
        print(type(error).__name__, flush=True)
        return 20


if __name__ == "__main__":
    raise SystemExit(main())
