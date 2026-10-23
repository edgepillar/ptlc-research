"""Reject hostile archive framing before extraction using synthetic members."""
import copy
import hashlib
import io
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock
import zipfile

from scripts import prepare_nom_5cb as selected


class ArchiveSelection(unittest.TestCase):
    def setUp(self):
        self.files = {'public.txt': b'public\n', 'docs/marker.txt': b'marker\n'}
        self.index = {name: dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
            git_blob_sha1=hashlib.sha1(b'blob ' + str(len(raw)).encode('ascii')
                                     + b'\0' + raw).hexdigest(), mode='100644')
            for name, raw in self.files.items()}

    def packed(self, entries=None):
        result = io.BytesIO()
        with zipfile.ZipFile(result, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            for name, raw in (entries or self.files).items():
                item = zipfile.ZipInfo(selected.ARCHIVE_PREFIX + '/' + name)
                item.external_attr = (stat.S_IFREG | 0o644) << 16
                item.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(item, raw)
        return result.getvalue()

    def refused(self, *, entries=None, change=None, index=None):
        with zipfile.ZipFile(io.BytesIO(self.packed(entries))) as archive:
            if change is not None:
                change(archive)
            with self.assertRaises((AssertionError, ValueError)):
                selected.checked_payloads(archive, self.index if index is None else index)

    def test_complete_synthetic_contents(self):
        with zipfile.ZipFile(io.BytesIO(self.packed())) as archive:
            self.assertEqual(selected.checked_payloads(archive, self.index), self.files)

    def test_missing_selected_file(self):
        self.refused(entries={'public.txt': self.files['public.txt']})

    def test_unselected_file(self):
        self.refused(entries=dict(self.files, extra=b'foreign'))

    def test_duplicate_central_directory_member(self):
        self.refused(change=lambda archive: archive.filelist.append(copy.copy(archive.filelist[0])))

    def test_case_alias(self):
        self.refused(entries=dict(self.files, **{'PUBLIC.txt': b'alias'}))

    def test_parent_path(self):
        self.refused(entries=dict(self.files, **{'../foreign.txt': b'foreign'}))

    def test_dot_and_repeated_separator_are_not_normalized(self):
        for name in ('./public.txt', 'docs//marker.txt'):
            with self.subTest(name=name):
                self.refused(entries=dict(self.files, **{name: b'foreign'}))

    def test_backslash_path(self):
        self.refused(entries=dict(self.files, **{'docs\\foreign.txt': b'foreign'}))

    def test_unicode_name(self):
        self.refused(entries=dict(self.files, **{chr(955) + '.txt': b'foreign'}))

    def test_foreign_prefix(self):
        def change(archive):
            archive.filelist[0].filename = 'unselected/' + archive.filelist[0].filename.split('/', 1)[1]
        self.refused(change=change)

    def test_symlink_member(self):
        def change(archive):
            archive.filelist[0].external_attr = (stat.S_IFLNK | 0o777) << 16
        self.refused(change=change)

    def test_special_file_member(self):
        def change(archive):
            archive.filelist[0].external_attr = (stat.S_IFIFO | 0o600) << 16
        self.refused(change=change)

    def test_unsupported_compression(self):
        def change(archive):
            archive.filelist[0].compress_type = zipfile.ZIP_BZIP2
        self.refused(change=change)

    def test_encrypted_member(self):
        def change(archive):
            archive.filelist[0].flag_bits |= 1
        self.refused(change=change)

    def test_member_size_mismatch(self):
        def change(archive):
            archive.filelist[0].file_size += 1
        self.refused(change=change)

    def test_changed_sha256(self):
        index = copy.deepcopy(self.index)
        index['public.txt']['sha256'] = '0' * 64
        self.refused(index=index)

    def test_changed_git_object(self):
        index = copy.deepcopy(self.index)
        index['public.txt']['git_blob_sha1'] = '0' * 40
        self.refused(index=index)

    def test_oversized_member_declaration(self):
        def change(archive):
            archive.filelist[0].file_size = 8 * 1024**2 + 1
        self.refused(change=change)

    def test_total_expansion_bound(self):
        with mock.patch.object(selected, 'MAX_TOTAL', 1):
            self.refused()

    def test_existing_destination_cannot_be_adopted(self):
        raw = self.packed()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(strict=True)
            archive, target = root / 'source.zip', root / 'selected'
            archive.write_bytes(raw)
            target.mkdir()
            original = target / 'retained.txt'
            original.write_bytes(b'keep-original')
            with mock.patch.object(selected.selected, 'inputs', return_value=({}, self.index)), \
                    mock.patch.object(selected, 'ARCHIVE_BYTES', len(raw)), \
                    mock.patch.object(selected, 'ARCHIVE_SHA256', hashlib.sha256(raw).hexdigest()):
                with self.assertRaises((AssertionError, ValueError)):
                    selected.prepare(archive, target, root=root)
            self.assertEqual(original.read_bytes(), b'keep-original')
            self.assertEqual({path.name for path in target.iterdir()}, {'retained.txt'})


if __name__ == '__main__':
    unittest.main()
