# Reference-only price and original-custody HOLD interface

This finite model can refuse malformed inputs or report **HOLD**. It cannot
authorize progress, even when a selected price component accepts. It writes no
journal, changes no source context, and supplies no signing, retry, work
replenishment, original release or broadcast operation. Application/core remain
**NO-GO** and independent assessment remains **UNFILLED**.

## Protocol obligation and selected scope

A preauthorized original may become unincludable when a fusion price changes.
A fresh unsigned quote cannot change the signed allowance. Recoverability also
depends on account ordering, custody, disclosure timing, timeout margins,
canonicality, finality and availability. A price-component result alone proves
none of those requirements and cannot guarantee inclusion before a timeout.

The [selected source-price comparison](NOM_SIGNED_PRICE_HOLD.md) retains sixteen
finite reference records over the two existing public synthetic originals at
[go-zenon 85c3979](https://github.com/zenon-network/go-zenon/commit/85c39796fa5ab6fb5ca16e61af34b6616f0ceafe).
This interface reads those declared values. It does not execute the node source,
observe a current price, authenticate a producer, or compose account admission.
A manufactured request or matching public fixture is not durable custody proof.

The input selection deliberately accepts only those two public synthetic
originals. It is not an application API for arbitrary wallet material. Request
bytes are finite, duplicate keys refuse, and unknown authority/action fields
refuse. Matching supplied bytes are represented by a SHA-256 fingerprint in the
report. The supplied node hash remains a separate input; the model does not
derive a missing node binding or rebuild an absent wire value from its fixture.

## Verified behavior and limits

Each leg retains separate missing-wire and missing-binding reasons. A declared
canonical price refusal adds a price reason; untrusted BasePlasma diagnostics
remain diagnostics. Matching minimum prices, work-only rises and the selected
legacy constructor behavior still return HOLD. Supplied bytes and node bindings
are not modified, and raw wire bytes are not emitted in the report.

Every result also retains unauthenticated-source, uncomposed-admission and
unverified-durable-custody reasons. The model neither reads nor changes an
UNKNOWN-work ledger. It cannot erase a charge, invent a completed operation or
replenish work. No old journal, checkpoint, source manifest or independently
reviewed subject is repinned by adding this separate model.

The [vectors](../compatibility/fixtures/nom_price_recovery_hold_v1.json) specify
expected reasons for complete and absent values across the selected price cases.
They are test inputs, not original custody evidence. The tests construct their
supplied bytes explicitly from the public synthetic fixture; the implementation
does not replace absent values that way.

For an explicitly owned synthetic request file:

```text
python3 -B -m qualification.nom_price_recovery_hold --request OWNED_REQUEST_JSON
```

Successful command exit means that a reference HOLD report was produced. It is
not a GO decision. A malformed request exits with a sanitized refusal. The
command provides no output-file, signer, observer, network or journal argument.

## Remaining acceptance

This satisfies only a bounded refusal/hold interface in the offline model.
Selected account/VM, pool and momentum subjects still need separate source-delta
review and execution on an explicit current source before any combined admission
claim. Timely recovery under price movement, account dependencies, unavailable
custody, disclosure and reorg/finality remains unresolved. A redesign requiring
a new signature has an independent signer/custody and protocol obligation.

Written external review and [AS-1 through AS-7](NOM_ANCHOR_SERVICE_ACCEPTANCE.md)
remain unfilled. The same author, another model run or more local/hosted tests
cannot supply that independence. Operational node activation, wallet access,
application signing, transaction broadcast and real funds remain outside scope.
