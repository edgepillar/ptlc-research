# Stage 0 validation record

Date: 2026-10-03.

This record preserves the Stage 0 checkpoint. Subsequent BIP340, Go-verifier and schedule-model work is recorded in [STAGE1_VALIDATION.md](STAGE1_VALIDATION.md); the historical exclusions and counts below apply to Stage 0 only.

## Local verification

```sh
REQUIRE_OPENSSL=1 python3 -B -m unittest discover -s tests -v
python3 scripts/check_artifacts.py
```

The final offline suite passed **17 tests with zero failures and zero skips** using Python 3.9.6 and OpenSSL 3.6.3: ten cryptographic regression tests and seven artifact-hygiene tests. Focused component runs and the final parent-level run passed. Test execution used only local synthetic fixtures, temporary Git repositories without commits or identity configuration, and the local OpenSSL verifier; it made no network requests.

Coverage includes public-challenge scalar recovery, modulo-order behavior, rejection of a noninvertible zero challenge, an RFC8032 public vector, and a newly constructed signature under the recovered aggregate key. OpenSSL accepted that signature and rejected modified-message and modified-signature controls. Required-verifier mode fails rather than skips when the verifier is unavailable; both required and optional unavailable-backend behavior were additionally checked through mocking.

Artifact regression cases cover safe staged/untracked files, staged disclosure followed by a clean edit or deletion, worktree disclosure over a clean index, untracked disclosure, a staged symlink replaced by a regular file, and sensitive filename redaction. The checker examines actual index blobs as well as working files and does not print candidate filenames or matched content.

This is independent implementation verification by OpenSSL, not an independent human cryptographic audit. It does not execute the original demo, a node, a smart contract, or a replacement swap protocol.

## Intermediate issues

- The first test run found a transcription error in the RFC8032 signature fixture. The fixture was corrected against the published vector; subsequent runs passed. No unresolved test failure remains.
- The initial artifact check rejected Unicode punctuation in two English documents under the repository's stricter ASCII policy. Those characters were normalized before the final check.
- Peer review found that the initial checker read only working-tree bytes for staged filenames. It was corrected to inspect index blobs independently, with regression tests for clean replacements and deletions.
- Peer review found that a generic nonzero OpenSSL exit could be mistaken for a correct negative result. Negative controls now require exit status 1 and the exact verification-failure marker, rejecting crashes and unrelated failures.

## Prepared but not executed

The GitHub Actions workflow defines Python 3.11 and 3.13 jobs, requires OpenSSL verification, and pins checkout/setup actions to immutable revisions. Hosted CI has not run. No Linux result is inferred from the local run.

Core Go tests, BIP340 adaptor interoperability tests, crash-recovery implementation tests, Bitcoin regtest, Zenon devnet, and live-fund workflows are outside the executed evidence.

## Content review

Repository artifacts use English and public source references. Synthetic fixtures contain no wallet seed or mnemonic. The final artifact check passed for all 14 candidate file versions, and local Markdown file links resolved. Mechanical artifact checks examine ASCII content and common local-path, email, private-key-header, and credential-token patterns without printing matching content. They are limited hygiene checks, not a complete secret scanner or proof of anonymity.

No commit identity or remote publication metadata is established by these content checks. Publication requires review of the actual destination and metadata as well as the files.
