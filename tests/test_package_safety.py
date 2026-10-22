from pathlib import Path
import tempfile
import unittest
import zipfile

from scripts.check_package_contents import check_archive, check_tree


class PackageSafetyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_rejects_vault_and_sidecar_names(self):
        for name in ('vault.db', 'vault.db-wal', 'credentials.sqlite3', 'old.db.backup'):
            with self.subTest(name=name):
                p = self.root / name
                p.write_bytes(b'fake')
                try:
                    with self.assertRaises(ValueError):
                        check_tree(self.root)
                finally:
                    p.unlink()

    def test_rejects_disguised_sqlite_payload(self):
        (self.root / 'data.bin').write_bytes(b'SQLite format 3\x00' + b'fake')
        with self.assertRaises(ValueError):
            check_tree(self.root)

    def test_rejects_disguised_pdf_payload(self):
        (self.root / 'data.bin').write_bytes(b'%PDF-1.7 fake')
        with self.assertRaises(ValueError):
            check_tree(self.root)

    def test_rejects_database_in_apk(self):
        p = self.root / 'fake.apk'
        with zipfile.ZipFile(p, 'w') as z:
            z.writestr('assets/vault.db', b'fake')
        with self.assertRaises(ValueError):
            check_archive(p)

    def test_rejects_disguised_private_key_in_zip(self):
        p = self.root / 'fake.zip'
        with zipfile.ZipFile(p, 'w') as z:
            z.writestr('assets/data.txt', b'-----BEGIN PRIVATE KEY-----\nfake')
        with self.assertRaises(ValueError):
            check_archive(p)

    def test_allows_application_payload(self):
        (self.root / 'vault_core.pyc').write_bytes(b'fake compiled code')
        with zipfile.ZipFile(self.root / 'base_library.zip', 'w') as z:
            z.writestr('example.pyc', b'fake compiled code')
        self.assertEqual(check_tree(self.root), 2)
