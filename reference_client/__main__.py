"""Bounded offline public client tools; no RPC, signer or persistent state."""

import argparse
import json
import os
import sys

from offline_session.nom_wire import account_block_hash, account_block_preimage, encode_call
from offline_session.pr138 import CompatibilityError
from .plan import MAX_INPUT, canonical, inspect_terms
from .agreement import bind_funding, inspect_agreement
from .presignature import inspect_presignature_result, prepare_presignature


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise CompatibilityError("duplicate public JSON field")
        result[key] = value
    return result


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise CompatibilityError("unsupported public command")


def _refuse(errors, message):
    # A missing diagnostic cannot turn an incomplete request into success.
    try:
        errors.write(message + "\n")
        errors.flush()
    except (OSError, ValueError):
        pass
    return 2


def _read_input(source):
    """Read bounded public bytes through declared EOF before parsing."""
    raw = bytearray()
    while len(raw) <= MAX_INPUT:
        remaining = MAX_INPUT + 1 - len(raw)
        part = source.read(remaining)
        if type(part) is not bytes or len(part) > remaining:
            raise CompatibilityError("invalid public input boundary")
        if not part:
            if not raw:
                raise CompatibilityError("invalid public input boundary")
            return bytes(raw)
        raw.extend(part)
    raise CompatibilityError("invalid public input boundary")


def main(argv=None, *, input_stream=None, output_stream=None, error_stream=None):
    parser = _Parser(description=__doc__, allow_abbrev=False)
    parser.add_argument("command", choices=("inspect-terms", "inspect-agreement", "bind-funding", "prepare-presignature-check", "inspect-presignature-result", "encode-call", "hash-account-block"))
    source = sys.stdin.buffer if input_stream is None else input_stream
    output = sys.stdout if output_stream is None else output_stream
    errors = sys.stderr if error_stream is None else error_stream
    try:
        args = parser.parse_args(argv)
        raw = _read_input(source)
        value = json.loads(raw.decode("ascii"), object_pairs_hook=_object,
                           parse_constant=lambda unused: (_ for _ in ()).throw(ValueError()))
        if args.command == "inspect-terms":
            result = inspect_terms(value)
        elif args.command == "inspect-agreement":
            result = inspect_agreement(value)
        elif args.command == "bind-funding":
            result = bind_funding(value)
        elif args.command == "prepare-presignature-check":
            result = prepare_presignature(value)["crypto_request"]
        elif args.command == "inspect-presignature-result":
            result = inspect_presignature_result(value)
        elif args.command == "encode-call":
            result = dict(schema="ptlc-nom-client-call-v1", data_hex=encode_call(value).hex(),
                          action_permission="NONE", contract_admission="NOT_VERIFIED")
        else:
            result = dict(schema="ptlc-nom-client-account-hash-v1",
                          preimage_hex=account_block_preimage(value).hex(),
                          hash_hex=account_block_hash(value), action_permission="NONE",
                          signed_serialization="NOT_IMPLEMENTED")
        encoded = canonical(result).decode("ascii") + "\n"
        written = output.write(encoded)
        if type(written) is not int or written != len(encoded):
            raise OSError("incomplete public output")
        output.flush()
        return 0
    except OSError:
        return _refuse(errors, "REFUSED: public IO failure; no action authorized")
    except (CompatibilityError, UnicodeError, ValueError, TypeError, RecursionError):
        return _refuse(errors, "REFUSED: invalid public input; no action authorized")


def _discard_shutdown_buffers():
    # Only the standalone process uses this after a refusal. Already written
    # bytes cannot be recalled; remaining buffers are not delivery evidence.
    targets = set()
    for stream in (sys.stdout, sys.stderr):
        try:
            targets.add(stream.fileno())
        except (AttributeError, OSError, ValueError):
            pass
    descriptor = None
    try:
        descriptor = os.open(os.devnull, os.O_WRONLY)
        for target in targets:
            os.dup2(descriptor, target)
    except OSError:
        pass
    finally:
        if descriptor is not None and descriptor not in targets:
            os.close(descriptor)


if __name__ == "__main__":
    status = main()
    if status:
        _discard_shutdown_buffers()
    raise SystemExit(status)
