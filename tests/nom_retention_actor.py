"""Private deterministic process-death and real write-failure qualification."""

import os
from pathlib import Path
import signal
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from offline_session.nom_retention import NomEvidenceRetention, RetentionOutcomeUnknown
from nom_retention_support import MOMENTA, open_store, original, wire


def main():
    path, operation, point = sys.argv[1:]

    class Actor(NomEvidenceRetention):
        def _cut(self, label):
            if label == point:
                print("CUT " + label, flush=True)
                sys.stdin.readline()

    with open_store(path, cls=Actor) as store:
        if operation == "hold":
            print("HELD", flush=True)
            sys.stdin.readline()
        elif operation == "observation":
            store.retain_observation("candidate", wire(MOMENTA["reorg_vectors"][3]["candidate"]),
                                     previous_id="previous", disclosure_possible=True)
        elif operation == "large":
            store.retain_observation("candidate", b" " * (512 * 1024), previous_id="previous", disclosure_possible=True)
        elif operation == "original":
            store.retain_original("long", original("long"))
        elif operation == "disclosure":
            store.note_possible_disclosure()
        elif operation == "write-limit":
            import resource
            limit = os.stat(path).st_size + 100
            signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
            resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
            try:
                store.retain_observation("candidate", wire(MOMENTA["baseline"]), previous_id="previous")
            except RetentionOutcomeUnknown:
                print("WRITE_OUTCOME_UNKNOWN", flush=True)
                return
            raise AssertionError("native file-size fault did not refuse")
        elif operation != "create":
            raise AssertionError("unknown synthetic operation")
    print("ACKNOWLEDGED", flush=True)


if __name__ == "__main__":
    main()
