# Repository instructions

- Use English for all repository content, code comments, fixtures, commit messages, and public artifacts.
- Include no personal identity, private conversation, local absolute paths, hostnames, credentials, wallet material, or private environment logs.
- Public upstream repository URLs and required third-party attribution are allowed. Use synthetic test values only.
- This is an offline research and reference-protocol workspace. Stage 0 does not authorize a deployed contract, node activation, wallet access, transaction broadcast, or real funds.
- Keep protocol requirements separate from selected constructions and verified implementation behavior. Mark unresolved decisions explicitly.
- Never promote test-only reference arithmetic into application cryptography. A successful regression test is not evidence that a replacement swap protocol is secure.
- Keep Bitcoin transaction construction, session recovery, and chain observation out of the core node contribution. Keep core consensus changes narrow and coordinated with upstream maintainers.
- Pin external source claims to immutable commits when possible. Attribute reused material and check its license before copying it.
- Run the offline suite and artifact checks after relevant edits. Report failed runs and skipped independent verification honestly.
- Do not use an installed Git identity implicitly for publication. Review commit metadata and the publication destination before a public action.

- Use `edgepillar` for both author and committer on every new or recreated commit, with that account's GitHub-provided no-reply email configured locally for this repository. Never use an operating-system identity or a placeholder.
- Verify the effective author and committer before committing. Keep the repository-local pre-commit and pre-push identity checks enabled; do not bypass their refusal or disable hooks for publication.
- Create authorized merge commits locally with the same author and committer. GitHub merge and squash APIs must not create source-history commits with a different committer.
- Preserve original Git object archives, old-to-new SHA mappings and source-bound verification reports during an identity migration. Equal file trees do not qualify a new revision using an old CI run or frozen assessment.
