"""Synthetic positive receipts only; this actor performs no curve arithmetic.

Used exclusively by the separate public exchange qualifier. The hash binds
public request bytes; it does not certify the mathematical claims in them.
"""

import hashlib
import json
import signal
import sys


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def main():
    signal.alarm(3)
    if len(sys.argv) != 2 or sys.argv[1] not in ("bound", "wrong-digest", "false"):
        return 2
    wire = sys.stdin.buffer.read(32769)
    if not wire or len(wire) > 32768:
        return 2
    try:
        request = json.loads(wire.decode("ascii"))
        if type(request) is not dict or canonical(request) != wire:
            return 2
    except (ValueError, RecursionError):
        return 2
    digest = hashlib.sha256(b"PTLC/artifact-verification/v1\x00" + wire).hexdigest()
    if sys.argv[1] == "wrong-digest":
        digest = ("1" if digest[0] == "0" else "0") + digest[1:]
    result = {"schema": "ptlc-artifact-verification-result-v1",
              "request_digest_hex": digest, "valid": sys.argv[1] != "false"}
    sys.stdout.buffer.write(canonical(result) + b"\n")
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
