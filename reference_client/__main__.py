"""Bounded offline public client tools; no RPC, signer or persistent state."""

import argparse
import json
import sys

from offline_session.nom_wire import account_block_hash, account_block_preimage, encode_call
from offline_session.pr138 import CompatibilityError
from .plan import MAX_INPUT, canonical, inspect_terms
from .agreement import bind_funding, inspect_agreement
from .presignature import prepare_presignature


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


def main(argv=None, *, input_stream=None, output_stream=None, error_stream=None):
    parser = _Parser(description=__doc__, allow_abbrev=False)
    parser.add_argument("command", choices=("inspect-terms", "inspect-agreement", "bind-funding", "prepare-presignature-check", "encode-call", "hash-account-block"))
    source = sys.stdin.buffer if input_stream is None else input_stream
    output = sys.stdout if output_stream is None else output_stream
    errors = sys.stderr if error_stream is None else error_stream
    try:
        args = parser.parse_args(argv)
        raw = source.read(MAX_INPUT + 1)
        if type(raw) is not bytes or not 0 < len(raw) <= MAX_INPUT:
            raise CompatibilityError("invalid public input boundary")
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
        elif args.command == "encode-call":
            result = dict(schema="ptlc-nom-client-call-v1", data_hex=encode_call(value).hex(),
                          action_permission="NONE", contract_admission="NOT_VERIFIED")
        else:
            result = dict(schema="ptlc-nom-client-account-hash-v1",
                          preimage_hex=account_block_preimage(value).hex(),
                          hash_hex=account_block_hash(value), action_permission="NONE",
                          signed_serialization="NOT_IMPLEMENTED")
        output.write(canonical(result).decode("ascii") + "\n")
        return 0
    except (CompatibilityError, UnicodeError, ValueError, TypeError, RecursionError):
        print("REFUSED: invalid public input; no action authorized", file=errors)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
