"""Bounded test-only execute observations, never a result or retry decision."""

import json
import sqlite3


SCHEMA = "synthetic-native-execute-errors-v1"
MAX_ERRORS = 4
PHASES = frozenset(("begin", "commit", "rollback", "event-insert",
                    "operation-insert", "execute-other"))
STATEMENTS = {
    "BEGIN IMMEDIATE": "begin",
    "COMMIT": "commit",
    "ROLLBACK": "rollback",
    "INSERT INTO events VALUES (?,?,?,?,?)": "event-insert",
    "INSERT INTO operations VALUES (?,?,?,?,?,NULL)": "operation-insert",
}
NATIVE_TYPES = (sqlite3.Error, sqlite3.DatabaseError, sqlite3.OperationalError,
                sqlite3.IntegrityError, sqlite3.ProgrammingError,
                sqlite3.InterfaceError, sqlite3.NotSupportedError)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


class ObservedConnection:
    """Forward the same calls; retain only an allowlisted execute phase and code."""

    def __init__(self, connection):
        self.connection = connection
        self.errors = []
        self.overflow = False

    @property
    def in_transaction(self):
        return self.connection.in_transaction

    def close(self):
        return self.connection.close()

    def execute(self, statement, parameters=()):
        try:
            return self.connection.execute(statement, parameters)
        except sqlite3.Error as error:
            code = vars(error).get("sqlite_errorcode") if any(type(error) is kind for kind in NATIVE_TYPES) else None
            code = 5 if type(code) is int and code == 5 else None
            if len(self.errors) < MAX_ERRORS:
                phase = STATEMENTS.get(statement, "execute-other") if type(statement) is str else "execute-other"
                self.errors.append(dict(phase=phase, code=code))
            else:
                self.overflow = True
            raise

    def report(self):
        return dict(schema=SCHEMA, errors=[dict(row) for row in self.errors], overflow=self.overflow)


def emit(observer):
    if observer is not None:
        print(canonical(observer.report()).decode("ascii"), flush=True)


def decode(wire):
    """Accept only the fixed canonical report; malformed bytes are never echoed."""
    if type(wire) is not bytes or not 1 <= len(wire) <= 1024:
        return None
    try:
        row = json.loads(wire.decode("ascii"))
        if (type(row) is not dict or set(row) != {"schema", "errors", "overflow"}
                or row["schema"] != SCHEMA or type(row["overflow"]) is not bool
                or type(row["errors"]) is not list or len(row["errors"]) > MAX_ERRORS):
            return None
        for error in row["errors"]:
            if (type(error) is not dict or set(error) != {"phase", "code"}
                    or type(error["phase"]) is not str or error["phase"] not in PHASES
                    or not (error["code"] is None or type(error["code"]) is int and error["code"] == 5)):
                return None
        if row["overflow"] and len(row["errors"]) != MAX_ERRORS:
            return None
        return row if canonical(row) == wire else None
    except (UnicodeError, ValueError, TypeError, RecursionError):
        return None
