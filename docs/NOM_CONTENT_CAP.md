# Default-cap public content selection

Research baseline: `2299c1e378ed815f2a6c76ca221f28d1d6f264f7`.
Selected unchanged core: `45e1bbb48ce6fc19d44c5fbf59ccf5784981fced`.
Profile: `zenon-pr138-content-cap-v1`.

The preserved two-header PTLC batch is combined with a separately generated
user prefix. The actual public account-pool selector uses its unchanged process
default of 100 headers, including contract children. Its private source unit
test changes the cap to two; that test is not the subject of this profile.
The selected test runs alone in a fresh Go process and asserts both the default
100-header content cap and the unchanged 500-block pending-account cap.

The GPL source is separately obtained and unmodified. These MIT overlays and
the Python property model are independently written research code. Source and
license hashes are pinned in the manifest. The [selected pool source](https://github.com/zenon-network/go-zenon/blob/45e1bbb48ce6fc19d44c5fbf59ccf5784981fced/chain/account_pool.go)
defines the public getters and complete-batch cap. The selected path uses legacy
pricing with the Dynamic Plasma spork inactive; the production Dynamic Plasma
content selector is outside this profile.

The original contract parent is exactly applied by the actual Supervisor and
normally added to the actual account pool. Original funding, parent, child and
inner witness bytes are unchanged. A disclosed public 0x61 test seed generates
101 separately labeled zero-value plain sends to the preserved public peer.
Every send is exactly reapplied without signing and normally admitted to the
pool. A selected synthetic fusion amount of 500000000000 provides a legacy
budget of 10500000; each send uses 21000. This is selected memory context,
not evidence of real fusion, an authenticated chain or original wallet custody.

At each prefix length, both account groups have the same preserved batch:

| User prefix | Contract group first | User group first |
| --- | --- | --- |
| 98 | Original batch plus all 98 users: 100 | All 98 users plus original batch: 100 |
| 99 | Original batch plus first 98 users: 100 | All 99 users: 99; entire batch excluded |
| 100 | Original batch plus first 98 users: 100 | First 100 users: 100; entire batch excluded |
| 101 | Original batch plus first 98 users: 100 | First 100 users: 100; later user and entire batch excluded |

Cross-account ordering is unspecified because the pool iterates an account
manager map. The actual all-pending getter and actual content getter are called
16 times independently at each window. Python checks all 128 original returns
against the two admissible account-group orders, with complete membership,
original wire identity, linear user prefix and adjacent child-before-parent
headers. It does not correlate a separate all-pending read with the following
content read. Both random variants are admissible but are not required to
appear; these 64 selected samples do not prove fairness or exhaustive scheduling.

Complete global state, both frontier pool states, all stored pool patches,
length-framed pending-wire digests, exact deltas, account hashes and protobuf
are independently projected. Every read binds identical complete before/after
checkpoint digests and signs zero times. Contract snapshot queries require the
exact selected anchor. Generation and exact application cannot mutate the
stable or pool checkpoint. The child remains an empty patch alias inside its
parent transaction; it is not an independently applied transaction.

Only after every raw observation passes does the qualifier produce a deterministic
property corpus. That projection describes all admissible orders and the
measured read count. It does not preserve an arbitrarily selected random order
as canonical truth or claim both variants were observed. Original private
source streams, all three pre-execution overlay snapshots, selected input and
commands remain unchanged. Hosted private streams may be ephemeral and are
not part of the complete public console archive.

The qualifier freshly reruns all 313 preserved source outcomes before six new
native outcomes, for 319 including parent tests. Earlier rollback behavior,
the old receipt refusal and unrelated-original retention retain their own
independent profile boundaries. No new momentum is generated, applied or
inserted in this capacity profile. The [validation record](NOM_CONTENT_CAP_VALIDATION.md)
separates local, hosted PR and push/main acceptance.

Application and core remain **NO-GO**. Recovery action remains **NONE**.
This profile does not qualify node admission, producer authentication,
Dynamic Plasma scheduling, fairness, authenticated provenance, canonicality,
finality, persistent recovery, wallet access, transaction broadcast, application
signing or real funds. Journal composition, restore fencing, independent security
assessment and a unique cause of the prior dependent eviction remain unfilled.
