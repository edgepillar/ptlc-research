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
The CLI checks both writing and flushing the result before returning zero.
An output error returns code 2. A zero exit still cannot prove that a recipient
captured the complete result; callers need the actual matching JSON receipt.

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

Focused process checks use the same test source from the small package:

```sh
cargo test --locked --offline --manifest-path public_crypto/Cargo.toml
```

The declared selection is five library cases and five real process cases. It
covers framing and refusal, exact locked package targets, interrupted partial
input, a broken output pipe and deliberately discarded output. Public checker
children have a bounded wait. The small package selects its own built binary; the larger
qualification crate selects its own example of the same checker source.
This command adds no dependency and avoids building the larger crate for this
focused feedback. Use the declared bounded Cargo cache and target storage for
local qualification. Complete regression and hosted acceptance remain separate
requirements; listed cases require fresh results for their selected source.

See the [public client matrix](../docs/NOM_PUBLIC_CLIENT_MATRIX.md) for the
baseline observation, selected scenario boundaries and unexecuted operational
requirements.

Backend attribution: [schnorr_fun at the selected revision](https://github.com/LLFourn/secp256kfun/tree/74d18bbf864f98e5cf7c18dcfb74ba1ecfe837ce/schnorr_fun),
with its package-level 0BSD license. Its arithmetic dependency's embedded MIT
and Apache-2.0 code and other transitive terms remain covered by the
[third-party notices](../THIRD_PARTY_NOTICES.md#embedded-and-transitive-dependency-boundaries).
The existing pinned qualification inputs retain their separate provenance.
The independent manifest and lockfile also reuse the existing `sha2` and
`serde_json` selections. Its target/feature closure remains distinct from the
larger qualification crate. No dependency source or binary is vendored.

A successful response means `PUBLIC_MATHEMATICS_ONLY` with action permission
`NONE`. The context digest is caller supplied and merely echoed. It is not part
of the contract's inner message. Changing that digest can leave the public
mathematical relation valid. A backend label, matching result digest or successful
relation does not authenticate economics, genesis, peers, key ownership, current
chain state, timing, nonce safety or a signing owner.

Application/core remain NO-GO and independent assessment remains unfilled.
The historical completion fixture and witness 3 are deliberately public test
values. They are neither chain observations nor operational wallet material.
