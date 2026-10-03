# Stage 13 validation: independent review preparation

Scope: prepare an immutable source inventory, a concrete construction/implementation
review brief and an unfilled report template. No independent assessment is
performed. Execution code, schemas, fixtures, dependencies and CI are unchanged.

## Subject and packaging checks

The review subject is Stage 12 commit
`e592633e4c630cfe3f4669876f6f63b80d2e33d6`, Git tree
`eea8afd941b1edfcbbb361d2429dfb5883887d3f`. Its [manifest](../review/subject.json)
enumerates all 119 tracked regular files from Git objects and excludes Stage 13
packaging itself. Manifest SHA256:
`df9ae22448a71fc7bbec24cfe2654e0a7f88bc1792eefc97e7b780bff6636295`.

| Check | Result | Boundary |
| --- | --- | --- |
| Complete subject inventory and blob size/SHA256 comparison | Passed for all 119 files | Exact Git-object identity; no security or signed-provenance claim |
| Locally generated source archive against manifest | Passed for all 119 regular files | Source only; no extraction, dependency source, binaries or runtime data |
| Documented verifier and malformed inventory/archive cases | Passed; 7 manifest and 3 archive variants rejected | Packaging verification only |
| Subject hosted CI state | Seven successful jobs, exact subject head | Previously executed regression/conformance evidence |
| Required-mode full Python suite after packaging edits | 313 passed in 349.512 seconds, no skips | No implementation changes |
| Artifact hygiene, local links and whitespace | Passed; 286 local Markdown links resolve | Limited checks; no comprehensive disclosure or anonymity guarantee |

The source archive is local and ignored, not a release or a new distribution of
compiled dependency code. Its bytes are not needed to trust the manifest: each
source file is checked against the subject Git object and optional archive
independently. The documented verifier requires the complete path set, not just
successful hashing of whichever entries a manifest happens to contain.

The brief's exact embedded verifier was executed successfully against both the
Git subject and local archive. Manual negative checks rejected a missing entry,
duplicate entry, changed digest, changed size, changed Git mode, wrong subject
and unsafe path. Archive checks rejected an extra regular file, duplicate path
and symlink. These checks exercise the documented recipe; no production
verification service or new application API is added.

The local required-mode run used
`REQUIRE_OPENSSL=1 python3 -B -m unittest discover -s tests -q`, Python 3.9.6
on macOS and OpenSSL 3.6.3. It completed successfully with no failed or skipped
tests. Artifact hygiene was run with `python3 -B scripts/check_artifacts.py`;
all relative Markdown targets resolved and Git whitespace checks passed.

## Intermediate observations

An initial archive check incorrectly assumed that tar write-permission bits
must equal Git file modes. Git emitted regular source files as mode `0664`
while their tracked mode is `100644`; this check failed before completion.
Verification now checks exact Git modes against Git and archive executable class
separately, as well as every source byte. The corrected archive check passed.
No source payload or execution behavior was changed to accommodate this result.

The subject's [hosted run](https://github.com/edgepillar/ptlc-research/actions/runs/37161466574)
was rechecked as completed/successful at the exact subject with four Python
jobs, one Rust job and two Go jobs. The [Stage 12 report](STAGE12_VALIDATION.md)
retains its local implementation results and limitations. A prepared review
brief and hosted CI are not an independent construction or security assessment.

## Execution scope and remaining gates

For this documentation/inventory change, unchanged Rust/Go suites and actual
Rust subprocess integrations are not independently rerun locally. They remain
in the existing hosted CI definition; local packaging checks and required-mode
Python discovery are recorded separately above. No new test or execution API
is introduced.

The [brief](INDEPENDENT_REVIEW.md) identifies exact source/evidence boundaries
and seven substantive assessment obligations. The [report template](REVIEW_REPORT_TEMPLATE.md)
is deliberately unfilled. No reviewer assignment, outreach, completed external
review, private signing, regtest/devnet run, core port or activation is asserted.
Offline research may continue. Private signing and funded integration remain
no-go until their separate review, ownership and authorization gates are met.
