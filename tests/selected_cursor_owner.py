"""A cooperative cursor-disposal experiment for offline fixtures only.

No store or application uses this owner. Its registry covers only its selected
creation interface, not every native object or independently retained alias.
Raw exceptions are private diagnostics; no serialization or authority is added.
"""

from dataclasses import dataclass, field


class CursorOwnershipRefused(ValueError):
    """The selected creation or disposal phase is unavailable."""


@dataclass(frozen=True)
class CursorCloseObservation:
    ordinal: int
    status: str
    secondary: object = field(default=None, repr=False)


@dataclass(frozen=True)
class CursorAdmissionObservation:
    primary: object = field(repr=False)
    close_status: str
    secondary: object = field(default=None, repr=False)


@dataclass(frozen=True)
class CursorDisposalReport:
    cursors: tuple = ()
    connection_status: str = "not-attempted"
    primary: object = field(default=None, repr=False)
    connection_secondary: object = field(default=None, repr=False)
    admission: object = field(default=None, repr=False)


class SelectedCursorOwner:
    """One selected factory return and one cooperative scope.

    Registration precedes exposure. A selected registration escape before list
    mutation closes the pending cursor once; a failed close retains its reference.
    Disposal attempts registered cursors in reverse admission order, then the
    connection. References remain available for separate fixture observations.
    A scope exception takes priority. On normal exit the first cleanup escape
    propagates after all selected attempts. Arbitrary interruption is unqualified.
    """

    def __init__(self, connection_factory):
        if not callable(connection_factory):
            raise CursorOwnershipRefused("one selected connection factory required")
        self._connection = connection_factory()
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

    def _register(self, cursor):
        self._cursors.append(cursor)

    def cursor(self):
        if self._phase != "entered" or self._pending is not None:
            raise CursorOwnershipRefused("selected cursor admission unavailable")
        self._pending = self._connection.cursor()
        try:
            self._register(self._pending)
        except BaseException as primary:
            secondary, status = None, "returned"
            try:
                self._pending.close()
            except BaseException as error:
                secondary, status = error, "escaped"
            else:
                self._pending = None
            self._admission = CursorAdmissionObservation(primary, status, secondary)
            raise
        cursor, self._pending = self._pending, None
        return cursor

    def __exit__(self, kind, primary, traceback):
        if self._phase != "entered":
            raise CursorOwnershipRefused("selected disposal requires one entry")
        self._phase = "disposed"
        observations, connection_secondary = [], None
        try:
            for ordinal in reversed(range(len(self._cursors))):
                try:
                    self._cursors[ordinal].close()
                except BaseException as error:
                    observations.append(CursorCloseObservation(ordinal, "escaped", error))
                else:
                    observations.append(CursorCloseObservation(ordinal, "returned"))
        finally:
            try:
                self._connection.close()
            except BaseException as error:
                connection_status, connection_secondary = "escaped", error
            else:
                connection_status = "returned"
        self._report = CursorDisposalReport(tuple(observations), connection_status,
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
