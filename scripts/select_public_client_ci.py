"""Select a bounded public-client PR scope; every uncertainty selects full CI.

The workflow executes the policy from the trusted base commit. A decision is
source-selection data, not test execution, protocol assessment or permission.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import subprocess
import sys
import time

SCHEMA = 'ptlc-public-client-ci-scope-v1'
POLICY_PATH = 'scripts/select_public_client_ci.py'
FULL = 'full'
FAST = 'public-client'
MAX_CHANGES = 128
MAX_DIFF = 256 * 1024
PUBLIC_FILES = frozenset({
    'reference_client/__init__.py', 'reference_client/__main__.py',
    'reference_client/plan.py', 'reference_client/agreement.py',
    'reference_client/presignature.py',
    'reference_client/synthetic_terms.json', 'reference_client/synthetic_agreement.json',
    'reference_client/synthetic_funding_request.json',
    'reference_client/synthetic_presignature_request.json',
    'public_crypto/src/lib.rs', 'public_crypto/src/main.rs',
    'public_crypto/synthetic_long_request.json', 'public_crypto/synthetic_request_provenance.json',
    'qualification/tests/client_public_crypto_process.rs',
    'tests/test_reference_client.py', 'tests/test_client_agreement.py',
    'tests/test_client_presignature.py',
})
TOP_DOCUMENTS = frozenset({'README.md', 'STATUS.md'})


class SelectionUnknown(ValueError):
    """No fast eligibility can be established from the supplied source."""


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def digest(value):
    return sha(json.dumps(value, sort_keys=True, separators=(',', ':')).encode('ascii'))


def valid_sha(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{40}', value) is not None and value != '0' * 40


def valid_path(value):
    if type(value) is not str or not 0 < len(value) <= 240 or not value.isascii():
        return False
    path = PurePosixPath(value)
    return (not path.is_absolute() and path.as_posix() == value
        and all(re.fullmatch('[A-Za-z0-9_][A-Za-z0-9_.-]*', part) is not None
            and part not in ('.', '..') for part in path.parts))


def public_path(value):
    return value in PUBLIC_FILES or value in TOP_DOCUMENTS or (
        valid_path(value) and value.startswith('docs/') and value.endswith('.md'))


def classify(changes):
    """Decide only a complete canonical list; no rename/deletion/mode relaxation."""
    if type(changes) is not list or not 0 < len(changes) <= MAX_CHANGES:
        return FULL, 'CHANGE_LIST_OUTSIDE_BOUNDARY'
    seen = set()
    for change in changes:
        if type(change) is not dict or set(change) != {'path', 'status', 'old_mode', 'new_mode', 'old_blob', 'new_blob'}:
            return FULL, 'UNKNOWN_CHANGE_RECORD'
        name = change['path']
        if not valid_path(name) or name.casefold() in seen:
            return FULL, 'AMBIGUOUS_SOURCE_PATH'
        seen.add(name.casefold())
        if change['status'] not in ('A', 'M') or change['new_mode'] != '100644':
            return FULL, 'NONREGULAR_OR_DESTRUCTIVE_CHANGE'
        if not valid_sha(change['new_blob']):
            return FULL, 'UNKNOWN_SOURCE_BLOB'
        if change['status'] == 'A':
            if change['old_mode'] != '000000' or change['old_blob'] != '0' * 40:
                return FULL, 'UNKNOWN_ADDITION'
            if not (name.startswith('docs/') and name.endswith('.md')):
                return FULL, 'NEW_EXECUTABLE_OR_FIXTURE_SCOPE'
        elif change['old_mode'] != '100644' or not valid_sha(change['old_blob']):
            return FULL, 'CHANGED_FILE_TYPE'
        if not public_path(name):
            return FULL, 'SHARED_OR_UNSELECTED_SOURCE_CHANGED'
    return FAST, 'COMPLETE_PUBLIC_CLIENT_CHANGE_SET'


def git(root, *arguments, limit=MAX_DIFF, timeout=30):
    """Bound each read-only query and join its direct child; keep outer leases."""
    environment = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
    environment.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
        GIT_CONFIG_SYSTEM=os.devnull, GIT_TERMINAL_PROMPT='0', GIT_NO_REPLACE_OBJECTS='1',
        GIT_OPTIONAL_LOCKS='0', LANG='C', LC_ALL='C')
    process = subprocess.Popen(['git', '--no-lazy-fetch', '--no-replace-objects',
        '-c', 'core.fsmonitor=false', *arguments], cwd=root, env=environment,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=False)
    selector = selectors.DefaultSelector()
    chunks = {'stdout': bytearray(), 'stderr': bytearray()}
    for name in chunks:
        selector.register(getattr(process, name), selectors.EVENT_READ, name)
    deadline = time.monotonic() + timeout
    try:
        while selector.get_map() or process.poll() is None:
            if time.monotonic() >= deadline:
                raise SelectionUnknown('source query timed out')
            for key, _ in selector.select(.05):
                raw = os.read(key.fileobj.fileno(), 65536)
                if not raw:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                chunks[key.data].extend(raw)
                if len(chunks[key.data]) > (limit if key.data == 'stdout' else 32768):
                    raise SelectionUnknown('source query exceeds its boundary')
        code = process.wait()
        return code, bytes(chunks['stdout']), bytes(chunks['stderr'])
    finally:
        selector.close()
        if process.poll() is None:
            try:
                process.kill()
            except ProcessLookupError:
                pass
        process.wait()
        for name in chunks:
            stream = getattr(process, name)
            if not stream.closed:
                stream.close()


def checked_git(root, *arguments, limit=MAX_DIFF):
    code, raw, errors = git(root, *arguments, limit=limit)
    if code != 0 or errors:
        raise SelectionUnknown('source query was not complete and successful')
    return raw


def parse_diff(raw):
    if type(raw) is not bytes or not raw or len(raw) > MAX_DIFF or not raw.endswith(b'\0'):
        raise SelectionUnknown('bounded complete diff required')
    parts = raw.split(b'\0')[:-1]
    if len(parts) % 2 or len(parts) > 2 * MAX_CHANGES:
        raise SelectionUnknown('complete change list outside its boundary')
    changes = []
    for index in range(0, len(parts), 2):
        header, name = parts[index:index + 2]
        match = re.fullmatch(rb':([0-7]{6}) ([0-7]{6}) ([0-9a-f]{40}) ([0-9a-f]{40}) ([A-Z][0-9]*)', header)
        if match is None:
            raise SelectionUnknown('unknown source diff encoding')
        old_mode, new_mode, old_blob, new_blob, status = (part.decode('ascii') for part in match.groups())
        changes.append(dict(path=name.decode('ascii'), status=status, old_mode=old_mode,
            new_mode=new_mode, old_blob=old_blob, new_blob=new_blob))
    return changes


def select_source(root, *, event, base, head, base_ref):
    decision = dict(schema=SCHEMA, mode=FULL, reason='EVENT_REQUIRES_FULL', event=event,
        base=base if valid_sha(base) else None, head=head if valid_sha(head) else None,
        base_ref='main' if base_ref == 'main' else 'UNKNOWN', change_count=None, changes_sha256=None,
        head_tree=None, policy_sha256=None, source_complete=False,
        qualification='NOT_PERFORMED', application='NO-GO', core='NO-GO')
    if event not in ('pull_request', 'push', 'workflow_dispatch'):
        decision['event'] = 'UNKNOWN'
    if event != 'pull_request':
        return decision
    if not valid_sha(base) or not valid_sha(head) or base_ref != 'main' or base == head:
        return dict(decision, reason='UNSUPPORTED_SOURCE_CONTEXT')
    try:
        if checked_git(root, 'rev-parse', 'HEAD', limit=128).decode('ascii').strip() != head:
            raise SelectionUnknown('head mismatch')
        if checked_git(root, 'status', '--porcelain', '--untracked-files=all'):
            raise SelectionUnknown('unclean source')
        code, _, errors = git(root, 'merge-base', '--is-ancestor', base, head, limit=128)
        if code != 0 or errors:
            return dict(decision, reason='BASE_ANCESTRY_NOT_ESTABLISHED')
        policy = checked_git(root, 'show', base + ':' + POLICY_PATH, limit=65536)
        current = checked_git(root, 'show', head + ':' + POLICY_PATH, limit=65536)
        if policy != current or policy != Path(__file__).read_bytes():
            return dict(decision, reason='TRUSTED_BASE_POLICY_NOT_UNCHANGED')
        tree = checked_git(root, 'rev-parse', head + '^{tree}', limit=128).decode('ascii').strip()
        if not valid_sha(tree):
            raise SelectionUnknown('unknown tree')
        raw = checked_git(root, 'diff', '--raw', '-z', '--no-renames', '--no-ext-diff',
            '--no-textconv', '--abbrev=40', base, head, '--')
        changes = parse_diff(raw)
        mode, reason = classify(changes)
        return dict(decision, mode=mode, reason=reason, change_count=len(changes),
            changes_sha256=digest(changes), head_tree=tree, policy_sha256=sha(policy), source_complete=True)
    except (OSError, ValueError, UnicodeError, SelectionUnknown, subprocess.SubprocessError):
        return dict(decision, reason='SOURCE_SELECTION_UNKNOWN')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--event', required=True)
    parser.add_argument('--base', default='')
    parser.add_argument('--head', required=True)
    parser.add_argument('--base-ref', default='')
    args = parser.parse_args()
    if not sys.dont_write_bytecode or sys.flags.optimize:
        raise SystemExit('source selection requires assertions and bytecode disabled')
    result = select_source(args.root, event=args.event, base=args.base, head=args.head, base_ref=args.base_ref)
    print(json.dumps(result, sort_keys=True), flush=True)


if __name__ == '__main__':
    main()
