"""Bounded adapter for public-input verification/extraction/Bitcoin adaptation."""

import json
import subprocess
import tempfile

from .artifact_verifier import SubprocessVerifier
from .completion import CompletionError, validate_result
from .exchange import canonical


class SubprocessCompletion(SubprocessVerifier):
    """The executable returns a public signature, never the extracted scalar."""

    def __call__(self, request):
        try:
            wire = canonical(request)
            if len(wire) > 65536:
                raise CompletionError("public completion request exceeds its bound")
            with tempfile.TemporaryFile() as output:
                process = subprocess.run([self._executable], input=wire, stdout=output, stderr=subprocess.DEVNULL,
                                         timeout=self._timeout, check=False)
                output.seek(0)
                response = output.read(4097)
            if process.returncode != 0 or len(response) > 4096:
                raise CompletionError("public completion executable rejected or exceeded its output bound")
            result = json.loads(response.decode("ascii"))
            validate_result(request, result)
            if response not in (canonical(result), canonical(result) + b"\n"):
                raise CompletionError("public completion executable returned noncanonical output")
            return result
        except (OSError, ValueError, TypeError, KeyError, RecursionError, subprocess.SubprocessError):
            raise CompletionError("public completion executable failed") from None
