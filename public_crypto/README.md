# Public NoM presignature checker

Status: unqualified implementation draft for offline research. The package
verifies one supplied public adaptor relation. It has no signing, adaptation,
extraction, wallet, node, network, persistence or transaction interface.

The Python reference client derives the key, message, adaptor point and local
context commitment from the complete declared funding prefix. A long-leg check
requires no invented short entry identifier. Preparation checks declared records;
it does not establish funding execution or authenticate an agreement.

The Rust library checks the pinned `schnorr_fun` encrypted-signature relation.
Its standalone executable reads one bounded request from standard input and
writes one result to standard output. Refusals exit with code 2 without echoing
input. The library accepts canonical compact ASCII JSON up to 8 KiB. The CLI
also accepts one trailing framing LF; the request digest excludes that LF.

Example with the deliberately public synthetic fixture:

```sh
python3 -B -m reference_client prepare-presignature-check \
  < reference_client/synthetic_presignature_request.json \
  | cargo run --locked --offline --quiet --manifest-path public_crypto/Cargo.toml
```

The independent package uses the same pinned backend revision as the research
qualification crate. Offline Cargo commands require those inputs to be available
already. The qualification tests also compile the exact same checker source;
older frozen qualification workers and their formats remain separate.

Backend attribution: [schnorr_fun at the selected revision](https://github.com/LLFourn/secp256kfun/tree/74d18bbf864f98e5cf7c18dcfb74ba1ecfe837ce/schnorr_fun),
licensed under 0BSD. The existing pinned qualification inputs retain their
separate provenance and licenses.

A successful response means `PUBLIC_MATHEMATICS_ONLY` with action permission
`NONE`. The context digest is caller supplied and merely echoed. It is not part
of the contract's inner message. Changing that digest can leave the public
mathematical relation valid. A backend label, matching result digest or successful
relation does not authenticate economics, genesis, peers, key ownership, current
chain state, timing, nonce safety or a signing owner.

Application/core remain NO-GO and independent assessment remains unfilled.
The historical completion fixture and witness 3 are deliberately public test
values. They are neither chain observations nor operational wallet material.
