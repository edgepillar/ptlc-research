"""Explicit native-authorizer fixture delegating the unchanged original actor."""

from pathlib import Path
import runpy
import sqlite3
import sys
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from qualification import policy_effect_store as source


def denied(action, first, second, database, trigger):
    if (action == sqlite3.SQLITE_INSERT and first == "events"
            or action == sqlite3.SQLITE_TRANSACTION and first == "ROLLBACK"):
        return sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_OK


def main():
    constructor = source.OfflinePolicyEffectStore

    def selected(*args, **kwargs):
        store = constructor(*args, **kwargs)
        store._db.set_authorizer(denied)
        return store

    def sanitized(kind, error, traceback):
        label = ("synthetic-secondary-store-refusal" if kind is source.StoreRefused
                 else "synthetic-unhandled-error")
        print(label, file=sys.stderr, flush=True)

    sys.excepthook = sanitized
    with patch.object(source, "OfflinePolicyEffectStore", selected):
        runpy.run_path(str(Path(__file__).with_name("policy_effect_store_actor.py")), run_name="__main__")


if __name__ == "__main__":
    main()
