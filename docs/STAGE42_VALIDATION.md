# Stage 42 validation

Status: **All required local checks passed in their final runs, with no failed
or skipped tests. Hosted exact-head CI evidence is verified separately in the
draft PR.**

This stage adds [isolated source root role qualification](SOURCE_ROOT_ROLE_QUALIFICATION.md)
and one extra actual-worker CI step. No existing application entry point,
SQLite store, read contract, signing interface, journal, worker, fixture, locked
dependency, fixed review subject or assessment report is changed.

## Executed checks and initial failures

The public Rust generator passed one mathematical test and reproduced ten
complete public declarations. The new Rust group passed eleven tests. The new
Python suite passed 29 tests in 0.037 seconds, including six selected transport
methods. Ten actual-worker methods passed in 1.152 seconds. All 88 Rust tests
passed across the complete locked offline suite, without failures or ignored
tests. The Go modules passed 24 and eight top-level tests respectively, including
six new root methods. A rebuilt final worker passed the same ten actual methods
in 0.993 seconds after formatting; no test failed or skipped in those final runs.

The initial inspection checker failed from a missing Python import path and was
corrected before its successful parent publication audit. An initial Cargo
invocation wrongly supplied the rustup-only `+1.90.0` selector to the direct cached
Cargo executable; selecting the cached 1.90.0 executable corrected this setup.
The initial Go invocation selected a module-relative directory from the repository
root; using `go -C qualification-go` corrected this setup. None reached their
intended test execution.

Two initial affected Python runs failed the same hostile-object test because its
selection helper deep-copied a hostile mapping before calling the candidate. The
helper now passes explicit caller objects directly to the factory, allowing its
exact-type checks to reject them without invoking foreign hooks. A result-key
fixture was also constructed without accidental equality hooks. This changed
test setup, not the candidate's acceptance rules. The final affected run has no
failed or skipped tests. Earlier failed runs are not counted as successful runs.

An initial candidate link check refused a nonexistent documentation target; the
link was corrected before the staged check. The selected fixture SHA256 is
`428d45b3710501de35faae9151dc758dce9c6638d71c8e35291a8e4fa723c3e3`.

## Final local results

| Check | Selected execution | Result |
| --- | --- | --- |
| Affected Python | `python3 -B -m unittest discover -s tests -p test_source_root_roles.py -v` | 29 passed; no failures or skips |
| Required full offline suite | `REQUIRE_OPENSSL=1 python3 -B -m unittest discover -s tests -v` | 1,019 passed in 925.583 seconds; no failures or skips |
| Complete Rust suite | Cargo 1.90.0, locked offline tests | 88 passed, including all eleven new root methods; no failures or ignored tests |
| Complete Go suites | Go 1.23.12, both locked modules, `-mod=readonly -count=1 -v` | 24 and eight top-level tests passed, including six new root methods |
| New actual public worker | `python3 -B scripts/qualify_source_root_roles.py --root-verifier <selected-public-executable>` | Ten passed in 0.993 seconds after rebuilding the formatted source |
| Fixed source inventories | `python3 -B scripts/check_observation_subject.py --expect-commit f81e376e96e339647bb065739b4461235f865d2c` | Complete 189-file observation subject and 119-file baseline |
| Staged/worktree artifact hygiene | `python3 -B scripts/check_artifacts.py` | 548 index/worktree versions across 274 tracked files |
| Candidate, formatting and relative links | Exact staged bytes, whitespace, compiled Python, Cargo/gofmt, preserved base files and workflow checks | 19 changed files, ten new; four Python files compile; 956 relative file links resolve; one exact additional actual-worker step |

All required local checks passed in their final runs. Initial failures above are
retained honestly. All prior code, cryptographic fixtures, manifests, reports,
worker entry points, dependencies and workflow steps/pins are unchanged. The older
actual-worker groups were not rerun locally in this stage; their prior execution
is not fresh evidence. Hosted full logs must refresh all thirteen groups and
separately demonstrate their exact candidate merge tree, native controls,
selected CLI comparisons and SQLite runtime probes.

## Same-process role control strengthened before final publication

A follow-up test assertion derives the two reused owner/issuer public keys from
known synthetic tags 83 and 84 in the same process that derives root,
administrator and response keys 96, 97 and 98. The complete fixture must remain
byte-identical, and the generator still reproduces it. This directly executes
the claim that distinct role keys can remain under one process's control, without
claiming separate governance or custody. The complete Rust suite again passed
all 88 tests, with no ignored tests. The first format check requested multiline
layout for one new assertion; Cargo formatting corrected it and the final check
passed. This formatting failure is separate from test execution.

The local 1,019-test Python run above preceded this Rust-test-only strengthening
and documentation update. All Python/application code, worker code and public
fixture bytes are unchanged. Final artifact checks are repeated after staging;
final hosted Python and actual-worker runs require the new exact head. Publication
uses a second explicit generic project commit rather than replacing the already
published draft history. No independent assessment is supplied.

## What these checks establish

Actual signatures bind root/context/profile/role bytes and refuse wrong domains,
wrong roots, malformed points, out-of-range scalars and every one-byte signature
mutation. Every valid peer alternative fails the complete independent selection
before mathematical work. A second valid signature changes complete request
result binding. All five role points are checked, with distinct encoding as a
candidate policy; this is not independent custody or proof of possession.

The raw worker accepts mathematics under a self-selected valid packet root. Old
selection bytes remain mathematically valid after newer revision, root,
administrator, response key, incarnation or epoch selections. Coherent copied
expectations and complete replay also match. A malicious selected callback can
forge the zero-signature positive that the actual worker refuses. These deliberate
unsafe controls are essential evidence of missing provisioning, freshness and
trusted-verifier premises.

In an actual-worker control, a temporary Stage 41 store retains a charged operation
after local revocation. Repeated valid root history leaves its view and database
bytes unchanged, the pending synthetic effect refuses, and the charge is not
refunded. This is isolation evidence; no source service, SQLite authentication,
current-authority gate or physical worker entry is connected.

Entry-file measurement refuses selected changes before launch and transport
refuses incomplete/mismatched result bytes. File measurement is not atomic launch
or provenance, and the inherited pipe runner is not a sandbox. Source/root custody,
current responses, compromise recovery, independent nonrollback lineage and
physical protected-use fencing remain open. No regtest/devnet or funded execution
is authorized or performed. New cross-language checks do not fill either fixed
independent assessment.

Offline qualification is **GO**. Current-source integration, core port, activation,
deployment, private signing and funded recovery remain **NO-GO**.
