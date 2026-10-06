"""Synthetic witness writer and controlled process-death cuts for tests only."""

import json
from pathlib import Path
import sys

sys.path[:0] = [str(Path(__file__).resolve().parents[1]), str(Path(__file__).resolve().parent)]
from qualification import original_read_response as response
from qualification.original_read_response_verifier import PublicOriginalResponseCheck
from original_snapshot_vectors import OUTPUT, canonical, scenario
from scripts.qualify_original_snapshot_prefix_response import capture
from original_witness_store import OfflineOriginalWitnessStore, WitnessOutcomeUnknown, WitnessRefused


def callback_control(packet):
    """Deliberately forged callback flags, never signature mathematics."""
    return response.expected_result(response.request_digest(packet))


def named_packet(name):
    fixture = json.loads(OUTPUT.read_text("ascii"))
    if name == "fresh_initial_absent":
        with scenario("initial_absent") as actual:
            pair = capture(actual, challenge="07")
        vector = fixture["counterclaim_vectors"]["fresh_challenge_over_initial_absence"]
    else:
        with scenario(name) as actual:
            pair = capture(actual)
        vector = fixture["positive_vectors"][name]
    return *pair, canonical(vector["envelope"])


def main():
    path, point, mode = sys.argv[1:4]
    context = json.loads(sys.stdin.readline())
    if mode == "flags":
        check = callback_control
    elif mode == "actual":
        entry = Path(context["entry"])
        # The parent independently selected and measured this test executable.
        check = PublicOriginalResponseCheck(entry,
            expected_executable_sha256_hex=context["entry_sha256"])
    else:
        return 21
    binding = named_packet("pending")[0]
    with OfflineOriginalWitnessStore(path, binding, verifier=check) as store:
        store._db.execute("PRAGMA cache_size=1")
        store._db.execute("PRAGMA cache_spill=ON")
        print("ready", flush=True)
        command = sys.stdin.readline().strip()
        def cut(label):
            if label == point:
                print("paused", flush=True)
                sys.stdin.readline()
        store._cut = cut
        try:
            result = store.retain(*named_packet(command))
            print(json.dumps(dict(version=result.version, observation=result.observation)), flush=True)
            return 0
        except (WitnessRefused, WitnessOutcomeUnknown) as error:
            print(type(error).__name__, flush=True)
            return 20


if __name__ == "__main__":
    raise SystemExit(main())
