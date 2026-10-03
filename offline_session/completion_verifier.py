"""Bounded adapter for public-input verification/extraction/Bitcoin adaptation."""

import json

from .artifact_verifier import SubprocessVerifier
from .completion import CompletionError, validate_result
from .exchange import canonical
from .public_worker import WorkerError, run_public_worker


class SubprocessCompletion(SubprocessVerifier):
    """The executable returns a public signature, never the extracted scalar."""

    def __call__(self, request):
        try:
            wire = canonical(request)
            if len(wire) > 65536:
                raise CompletionError("public completion request exceeds its bound")
            response = run_public_worker(
                self._executable, wire, timeout=self._timeout, max_input_bytes=65536,
            )
            result = json.loads(response.decode("ascii"))
            validate_result(request, result)
            if response not in (canonical(result), canonical(result) + b"\n"):
                raise CompletionError("public completion executable returned noncanonical output")
            return result
        except (OSError, ValueError, TypeError, KeyError, RecursionError, WorkerError):
            raise CompletionError("public completion executable failed") from None
