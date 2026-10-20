# Finite NoM explicit user receive credits

This probe extends the [contract receive commit study](NOM_RECEIVE_COMMIT.md)
at immutable [`go-zenon` commit `85c3979`](https://github.com/zenon-network/go-zenon/tree/85c39796fa5ab6fb5ca16e61af34b6616f0ceafe),
tree `cdeb5b6276c13447197c829c5855faa72afd86b9`. A source selection establishes
no current-branch, activated-network or deployed-node claim.

## Selected transition

Both fresh in-process public-genesis mock cases retain the earlier sequencing
and contract receive assertions. An Unlock confirmed before expiry pays the
fixed recipient; a Reclaim confirmed at or after expiry pays the entry owner.
Both select `PointTypeED25519`, public fixture keys and 10 synthetic ZNN.
The later contract receive commits a method error with no additional payout.

After both contract receives, the selected users' balances must still match
their values after funding. The probe explicitly receives the committed head's
exact payout, confirms that user receive, checks the stored frontier and spent
send hash, and compares an exact 1,000,000,000-unit increase. The other user's
balance must remain unchanged. A second receive of the same payout must refuse
with `ErrABFromBlockAlreadyReceived`, leave the frontier unchanged and produce
no additional credit. The user receive confirmation must follow all four
earlier send and contract receive confirmations in strict order.

These are two finite ED25519 mock transitions. They establish no exhaustive
queue schedule, network availability, liveness, canonicality, finality, reorg
handling, bilateral atomicity or safe disclosure deadline. Other point types,
adaptor-signature completion and application cryptography remain separate.
No journal write, recovery permission, original-operation replacement or
automatic retry follows from a matching record.

## Source and original output comparison

The [manifest](../compatibility/nom_receive_credit_manifest.json) pins the
444-file upstream inventory, added probe, notice, reader and synthetic tests.
The source comparator requires exactly those 445 file contents. Keep compiler
caches outside that selected source directory. Place the
[probe](../compatibility/nom_receive_credit_test.go.txt) at
`zenon/mock/zz_research_nom_receive_credit_test.go` and use one compiler context:

```sh
GOMAXPROCS=1 go test -p=1 -json -mod=readonly -count=1 -timeout=8m \
  -run '^TestResearchNoMReceiveCredit$' ./zenon/mock
```

Retain original stdout and stderr, actual exit, capture completeness, source
and toolchain selections separately. Compare their bounded contents with:

```sh
python3 -B -m qualification.nom_receive_credit \
  --source selected-core --stdout original.stdout --stderr original.stderr
```

The reader checks bounded same-test output-line reassembly, exact event order,
two case records and three Go test outcomes followed by package success.
Balances must be canonical unsigned decimal strings below 2^256, the delta
must equal the selected amount, and duplicate/other-user observations must have
their exact types and values. A record or synthetic control does not establish
an actual process exit, capture completeness, producer authentication or source
execution. Original receipts and complete source checks remain separate gates.
Changing probe bytes requires an explicit new source selection; earlier output
must never be relabelled as execution of those new bytes.

The harness uses public genesis signing helpers only inside the in-process
mock. It starts no node server, contacts no chain, accesses no user wallet and
performs no application signing or broadcast. This author study does not fill
independent review. Independent assessment and AS1-AS7 remain **UNFILLED**;
application and core remain **NO-GO**, with recovery action **NONE**.

The adapted Go probe retains [GPL-3.0-only attribution](NOM_RECEIVE_CREDIT_NOTICE.md).
Original Python code, controls and documents retain the project MIT license.
