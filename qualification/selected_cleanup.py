"""A selected failure-cleanup experiment; no store or application uses this guard.

Callback outcomes are diagnostics, not evidence of native release or authority.
The first exception has priority only within this offline selected construction.
"""

from dataclasses import dataclass, field


class CleanupSelectionRefused(ValueError):
    """The selected guard requires two callbacks and one ordinary scope entry."""


@dataclass(frozen=True)
class SelectedCleanupReport:
    """Raw exceptions remain private diagnostics; no serialization is provided."""

    rollback_status: str = "not-attempted"
    close_status: str = "not-attempted"
    primary: object = field(default=None, repr=False)
    rollback_secondary: object = field(default=None, repr=False)
    close_secondary: object = field(default=None, repr=False)


class SelectedFailureCleanup:
    """One selected failure scope, one rollback attempt and one close attempt.

    A normal exit invokes neither callback. During a failed exit, close is in a
    finally branch even if rollback escapes. Callback exceptions are retained
    separately and the original scope exception propagates unchanged by this
    guard. This does not qualify arbitrary interruption inside this machinery.
    """

    def __init__(self, rollback, close):
        if not callable(rollback) or not callable(close):
            raise CleanupSelectionRefused("two selected cleanup callbacks required")
        self._rollback, self._close = rollback, close
        self._phase = "fresh"
        self._report = SelectedCleanupReport()

    @property
    def report(self):
        return self._report

    def __enter__(self):
        if self._phase != "fresh":
            raise CleanupSelectionRefused("selected cleanup scope cannot be reused")
        self._phase = "entered"
        return self

    def __exit__(self, kind, primary, traceback):
        if self._phase != "entered":
            raise CleanupSelectionRefused("selected cleanup exit requires one entry")
        self._phase = "finished"
        if primary is None:
            return False
        rollback_status, close_status = "not-attempted", "not-attempted"
        rollback_secondary = close_secondary = None
        try:
            try:
                self._rollback()
            except BaseException as error:
                rollback_status, rollback_secondary = "escaped", error
            else:
                rollback_status = "returned"
        finally:
            try:
                self._close()
            except BaseException as error:
                close_status, close_secondary = "escaped", error
            else:
                close_status = "returned"
        self._report = SelectedCleanupReport(rollback_status, close_status,
            primary, rollback_secondary, close_secondary)
        return False
