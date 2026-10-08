"""Fixed public contention probes; no retry, signer or application interface."""

import json
from pathlib import Path
import sqlite3
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import test_policy_effect_store as prior
from qualification import policy_effect_store as source


class ControlFrames:
    """Retain framing refusal independently of the store exception wrapper."""

    def __init__(self):
        self.refused = False

    def resume(self, point=None):
        if point is not None:
            print("paused-" + point, flush=True)
        if sys.stdin.buffer.readline(4) != b"go\n":
            self.refused = True
            raise ValueError("fixed synthetic control required")


class ObservedConnection:
    """Delegate unchanged SQL and retain only fixed error phases and codes."""

    def __init__(self, connection, pause, control):
        self.connection = connection
        self.pause = pause
        self.control = control
        self.errors = []

    @property
    def in_transaction(self):
        return self.connection.in_transaction

    def close(self):
        self.connection.close()

    def execute(self, statement, parameters=()):
        phases = {
            "BEGIN IMMEDIATE": "begin",
            "COMMIT": "commit",
            "ROLLBACK": "rollback",
            "INSERT INTO events VALUES (?,?,?,?,?)": "event-insert",
            "INSERT INTO operations VALUES (?,?,?,?,?,NULL)": "operation-insert",
        }
        phase = phases.get(statement, "read-or-validate")
        if self.pause == "before-first-write" and phase == "event-insert":
            self.control.resume("before-first-write")
        try:
            return self.connection.execute(statement, parameters)
        except sqlite3.Error as error:
            code = getattr(error, "sqlite_errorcode", None)
            # Never publish SQLite exception text, SQL parameters or locations.
            self.errors.append(dict(phase=phase, code=code if code == sqlite3.SQLITE_BUSY else None))
            raise

def main():
    if len(sys.argv) != 5:
        raise ValueError("fixed synthetic arguments required")
    path, slot, pause, buffering = sys.argv[1:]
    if slot not in ("first", "second") or buffering not in ("small", "buffered"):
        raise ValueError("fixed synthetic selection required")
    if pause not in ("plain", "before-first-write", "before-commit", "lose-before-commit", "lose-after-commit"):
        raise ValueError("fixed synthetic cut required")
    wire = prior.canonical(dict(prior.PROFILE, max_attempt_limit=1))
    request = source.OriginalRequest(("01" if slot == "first" else "03") * 32, 1, wire, "02" * 32)
    control = ControlFrames()
    with source.OfflinePolicyEffectStore(path, prior.LABELS) as store:
        if buffering == "small":
            store._db.execute("PRAGMA cache_size=1")
            store._db.execute("PRAGMA cache_spill=ON")
        else:
            store._db.execute("PRAGMA cache_size=-2000")
            store._db.execute("PRAGMA cache_spill=OFF")
        observer = ObservedConnection(store._db, pause, control)
        store._db = observer

        def cut(point):
            if point == "allocation-before-commit" and pause in ("before-commit", "lose-before-commit"):
                control.resume("before-commit")
                if pause == "lose-before-commit":
                    raise RuntimeError("synthetic precommit reply loss")
            if point == "allocation-after-commit" and pause == "lose-after-commit":
                control.resume("after-commit")
                raise RuntimeError("synthetic committed reply loss")

        store._cut = cut
        print("ready", flush=True)
        control.resume()
        try:
            record = store.allocate_synthetic(request)
            outcome, charge, effect, status = "record", record.charge_sequence, record.effect_sequence, 0
        except (source.StoreRefused, source.StoreOutcomeUnknown) as error:
            outcome, charge, effect, status = type(error).__name__, None, None, 20
        # A cut's ValueError may have been wrapped as an unknown store reply.
        if control.refused:
            raise ValueError("fixed synthetic control required")
        print(json.dumps(dict(outcome=outcome, charge_sequence=charge, effect_sequence=effect,
            native_errors=observer.errors, transaction_open=observer.in_transaction), sort_keys=True), flush=True)
        return status


if __name__ == "__main__":
    try:
        status = main()
    except Exception:
        # A setup or framing failure is not a qualifying unknown store outcome.
        print("synthetic-contention-helper-refused", flush=True)
        status = 30
    raise SystemExit(status)
