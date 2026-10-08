# Custody mechanism feasibility: source comparison

Status: **AUTHOR SOURCE COMPARISON / UNSELECTED / NOT IMPLEMENTED**.
The [CUSTODY-01 proposal](CUSTODY_CANDIDATE_01.md) remains conditional;
every SC01-SC12 requirement remains **OPEN**, independent assessment is **NOT
ASSESSED**, and application/core progression remains **NO-GO**. AWS Nitro
Enclaves, NSM and KMS are an examined case, without a platform recommendation,
hardware qualification, cloud execution or private signing API.

## Subject, attribution and observations

The preceding source is `8f8e256ec5cd852279e9c3ad85c5a32d8d4c822c`,
tree `582c96b252e5e356efd6f9dd4665b97a09dd3a53` (516 files). Twelve named repository
files and seven named upstream files have Git blob/mode/length/SHA256 pins in the
[comparison record](../design/custody-mechanism-feasibility.json), whose SHA256 is
`a598a108a47c36e73a09df6cf1c0afb79f74d957adcc3c5e1b00142728dab715`. The unchanged CUSTODY-01 record SHA256 is
`8225498b35e4873c3a433b7126c4cbb144036d4ed4e70764782225c98bb2d2d2`.
These named rows are neither a complete new review subject nor an independent
assessment. Both historical author packets keep their original exact subjects.

The NSM source is pinned to
[`1993eeb0620d35f5cefc50b17638b432325328f9`](https://github.com/aws/aws-nitro-enclaves-nsm-api/tree/1993eeb0620d35f5cefc50b17638b432325328f9),
tree `13e2e5e2e61ca910a29121ce66c542d17eb163d8`. Its
[Apache-2.0 license](https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/1993eeb0620d35f5cefc50b17638b432325328f9/LICENSE)
and [NOTICE](https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/1993eeb0620d35f5cefc50b17638b432325328f9/NOTICE)
were inspected before original paraphrases. No implementation or external dataset
is reused, and no dependency or attribution file is changed. Only seven named
file byte pins were verified; enumerating a tree did not verify every file or
execute the upstream suite.

The inspected [Request enum](https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/1993eeb0620d35f5cefc50b17638b432325328f9/src/api/mod.rs#L82-L131)
is non-exhaustive and declares four PCR operations, DescribeNSM, Attestation and
GetRandom. It supplies no inspected implementation of our burn/entry/retention
protocol; this is not a complete negative capability claim about the platform.
The [C random wrapper](https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/1993eeb0620d35f5cefc50b17638b432325328f9/nsm-lib/src/lib.rs#L244-L267)
returns the actual copied length, bounded by caller capacity and returned bytes.
A future exact-length seed consumer must check that length and failures. No
entropy was drawn or assessed, and no library vulnerability is claimed.

The pinned [attestation protocol notes](https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/1993eeb0620d35f5cefc50b17638b432325328f9/docs/attestation_process.md#L82-L129)
require an agreed service protocol and explain limited-lifetime challenges;
public-key binding alone provides no replay protection. An attestation challenge
and a signing nonce serve different purposes. Fresh attestation does not prove
fresh signing entropy, spent-history continuity or actual participant approval.
The [manifest](https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/1993eeb0620d35f5cefc50b17638b432325328f9/Cargo.toml)
declares version 0.5.2 and Rust 1.92. The unchanged
[workspace CI](../.github/workflows/offline-tests.yml) uses Rust 1.90.0 for its
existing qualification. Those runs do not compile or qualify this NSM package;
no toolchain/dependency change was made.

## Mutable platform documentation and its limits

Official guides were read on 2026-10-08. The record stores private retrieved-byte
snapshot lengths/digests; the guide URLs have no immutable revision here. These
snapshots establish which bytes were read, without authenticating a hardware
implementation, release, loaded runtime or independent complete subject.

| Official documented claim | Implication for this proposal; author inference |
| --- | --- |
| [Concepts](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-concepts.html) describe isolated memory/CPUs and parent communication, without persistent enclave storage | Isolation is a conditional vendor claim, not measured usable-copy containment. Durable burn and original-output retention still need a named construction |
| [Measurements](https://docs.aws.amazon.com/enclaves/latest/user/set-up-attestation.html) cover image/kernel/application, parent role/instance and image signing certificate; debug mode has zero PCRs | A measured image is neither an authenticated actual input nor evidence that exactly one owner can receive a given nonce state. Debug mode cannot substitute for the intended attestation policy |
| [KMS attestation](https://docs.aws.amazon.com/kms/latest/developerguide/cryptographic-attestation.html) documents Decrypt, DeriveSharedSecret, GenerateDataKey, GenerateDataKeyPair and GenerateRandom with responses encrypted to the attested recipient key | Key delivery does not implement our adaptor entry or nonce ledger; no attested KMS Sign operation is assumed from this list |
| [KMS conditions](https://docs.aws.amazon.com/kms/latest/developerguide/conditions-attestation.html) authorize key-service operations against attestation content | A policy decision at key delivery is not current policy serialized with later backend entry. No complete condition-key inventory or administrator/reset assessment was performed |
| [Multiple enclaves](https://docs.aws.amazon.com/enclaves/latest/user/multiple-enclaves.html) permit distinct enclaves from the same or different image | Equal image measurements are compatible with several instances. Whether they can receive equivalent private work state depends on the unimplemented provisioning policy |
| [Root of trust](https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html) identifies Nitro Hypervisor and attestation PKI, plus an agreed service protocol | Choosing this case would add explicit trust roots, policy administrators and service authentication obligations. They are not assessed or selected here |

## Four fragments and the bounded decision

The following judgments concern sufficiency for CUSTODY-01. They do not claim
an AWS vulnerability, platform impossibility or a secure larger construction.
Only the original synthetic copy/restore tests are executed evidence; all new
mechanism judgments are author inferences from the limited subjects above.

| ID | Fragment examined | Decision; missing construction |
| --- | --- | --- |
| M1 | Ordinary local owner and consumption journal | INSUFFICIENT ALONE: retained matching-history copy/restore negative controls remain; current external authority and usable-copy containment are absent |
| M2 | Attested volatile domain with NSM | ATTESTATION ALONE IS INSUFFICIENT: durable burn/retention, exclusive provisioning and actual input/entry admission are not supplied by a measurement |
| M3 | Attested domain, KMS key delivery and restorable encrypted state | KEY DELIVERY ALONE IS INSUFFICIENT: encryption/access policy supplies neither spent-history continuity nor one current effect owner or entry-cutoff revocation |
| M4 | Same-domain authoritative policy/effect owner plus independent nonrewinding anchor | UNSPECIFIED / UNSELECTED / NOT IMPLEMENTED: this names the required boundary, without demonstrating its linearization, copy containment, anchor continuity or crash consistency |

The four Alice/Bob Bitcoin/Zenon partial operations, per-party key separation,
exact ordered/tweaked input mapping and common adaptor stay as proposed in
CUSTODY-01. Witness custody, completion/extraction, account/funding/refund
authentication, Bitcoin transaction construction, chain observation and core
consensus changes remain outside this partial-signer comparison.

## Failure obligations, without new executions

These are proposed discriminating observations, not platform attack traces or
measured tests. No AWS instance, NSM device, KMS operation, entropy draw, real key,
credential, private signer, attestation verifier or cloud resource was used.

| ID | Conditional scenario, NOT EXECUTED | Required later behavior |
| --- | --- | --- |
| F1 | Key release succeeds, then policy is revoked before real signing entry | Serialize policy update and actual entry; refuse work under entry-cutoff while preserving burn. A retained key or cached read grants no exception |
| F2 | Two provisioned instances receive equivalent restored nonce/work state under accepted image policy | Prevent repeated nonce computation at the actual usable-copy boundary, even if only one result is accepted. No actual clone/export capability or permissive provisioning was established here |
| F3 | Parent/custody dies after burn and before authenticated original-output retention | Keep spent uncertainty. Reconcile only already retained exact original bytes; no seed reconstruction, resigning or fresh-nonce retry as recovery |
| F4 | A successful authority read precedes lost continuity, conflicting failover or admin reset | Refuse new work and retained-output delivery until assessed current authority/continuity is established; coherent local restore is insufficient |

Before a private API, name the actual custody/policy/effect and anchor owners,
administrators, trust roots and reset/replica permissions. Specify every usable
key/nonce/grant/suspended/backend copy, real entropy/provisioning and authenticated
participant approval. Define burn, actual entry, current-policy updates and exact
original-output retention ordering across component loss. Select a nonrollback
anchor construction with restore/outage/failover/compromise limits. An exported
one-use permit, unique release, PCR extension, local mutex or result filter alone
does not establish that the real computation cannot be repeated.

The next allowed research step is an offline public-synthetic authority/effect
model with explicit premises and retained negative controls. It must distinguish
an ideal unique effect owner from its still unselected physical enforcement;
it cannot promote NSM/KMS or another platform into a real signer by assumption.
Selection and independent assessment remain separate gates.

Source-to-worker/reproducibility remain NOT VERIFIED; private consumed inputs,
producer and runtime remain NOT AUTHENTICATED; privacy remains NOT ASSESSED.
See [requirements](SIGNER_CUSTODY_REQUIREMENTS.md) and
[local validation](STAGE96_VALIDATION.md). Application/core remain NO-GO.
