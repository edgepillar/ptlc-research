"""Cooperative pre-invocation records for offline fixtures, never applications.

Creation-record retention and outcome writes must complete without interruption.
Python identity covers retained selected objects only, not opaque native aliases.
Raw references and exceptions remain private; no recovery authority is produced.
"""

from dataclasses import dataclass, field

from selected_cursor_owner import (CursorAdmissionObservation,
    CursorCloseObservation, CursorDisposalReport, CursorOwnershipRefused)


@dataclass
class _CursorAttemptRecord:
    ordinal: int
    cursor: object = field(repr=False)
    status: str = "not-attempted"
    secondary: object = field(default=None, repr=False)


class SelectedCursorAttemptOwner:
    """One cooperative scope with creation records independent of admission.

    Retention precedes the selected registration callback. Disposal visits
    creation records in reverse order, never registry entries. A record changes
    to attempted before close lookup/invocation; later visits preserve its first
    outcome without another call. Parent disposal is independent. A scope
    primary takes priority; normal exit surfaces the first selected cleanup
    escape after all attempts. None of these states proves native retirement.
    """

    def __init__(self, connection_factory):
        if not callable(connection_factory):
            raise CursorOwnershipRefused("one selected connection factory required")
        self._connection = connection_factory()
        self._records = []
        self._cursors = []
        self._pending = None
        self._admission = None
        self._phase = "fresh"
        self._report = CursorDisposalReport()

    @property
    def report(self):
        return self._report

    def __enter__(self):
        if self._phase != "fresh":
            raise CursorOwnershipRefused("selected owner scope cannot be reused")
        self._phase = "entered"
        return self

    def _register(self, record):
        self._cursors.append(record)

    def _attempt(self, record):
        if record.status != "not-attempted":
            return
        record.status = "attempted"
        try:
            record.cursor.close()
        except BaseException as error:
            record.secondary = error
            record.status = "escaped"
        else:
            record.status = "returned"

    def cursor(self):
        if self._phase != "entered" or self._pending is not None:
            raise CursorOwnershipRefused("selected cursor admission unavailable")
        cursor = self._connection.cursor()
        if any(record.cursor is cursor for record in self._records):
            raise CursorOwnershipRefused("selected cursor object already retained")
        record = _CursorAttemptRecord(len(self._records), cursor)
        self._records.append(record)
        self._pending = record
        try:
            self._register(record)
        except BaseException as primary:
            self._attempt(record)
            self._admission = CursorAdmissionObservation(primary,
                record.status, record.secondary)
            raise
        self._pending = None
        return cursor

    def __exit__(self, kind, primary, traceback):
        if self._phase != "entered":
            raise CursorOwnershipRefused("selected disposal requires one entry")
        self._phase = "disposed"
        connection_secondary = None
        try:
            for record in reversed(self._records):
                self._attempt(record)
        finally:
            try:
                self._connection.close()
            except BaseException as error:
                connection_status, connection_secondary = "escaped", error
            else:
                connection_status = "returned"
        observations = tuple(CursorCloseObservation(record.ordinal,
            record.status, record.secondary) for record in reversed(self._records))
        self._report = CursorDisposalReport(observations, connection_status,
            primary, connection_secondary, self._admission)
        if primary is None:
            errors = ([self._admission.secondary] if self._admission is not None
                and self._admission.secondary is not None else [])
            errors += [row.secondary for row in observations if row.secondary is not None]
            if connection_secondary is not None:
                errors.append(connection_secondary)
            if errors:
                raise errors[0]
        return False
