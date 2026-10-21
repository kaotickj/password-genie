import base64
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from cryptography.fernet import Fernet, InvalidToken
from vault_core import Vault, derive_key, decrypt_password, encrypt_password, default_vault_path


class VaultTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'data' / 'vault.db'
        self.vault = Vault(self.path)

    def test_first_run_and_restart(self):
        self.assertTrue(self.path.exists())
        self.assertFalse(self.vault.has_master())
        with self.vault.connect() as c:
            self.assertEqual(c.execute('SELECT version FROM schema_version').fetchall(), [(1,)])
            self.assertEqual(c.execute('SELECT COUNT(*) FROM credentials').fetchone(), (0,))
        self.vault.set_master('test passphrase')
        self.vault.save('test passphrase', 'example.test', 'user', '  secret🔐  ')
        reopened = Vault(self.path)
        self.assertTrue(reopened.verify('test passphrase'))
        self.assertFalse(reopened.verify('wrong'))
        self.assertEqual(reopened.retrieve('test passphrase', 'example.test'), ('user', '  secret🔐  '))
        if __import__('os').name != 'nt':
            self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_existing_master_cannot_be_overwritten(self):
        self.vault.set_master('original')
        with self.assertRaises(ValueError): self.vault.set_master('replacement')
        self.assertTrue(self.vault.verify('original'))

    def test_wrong_master_cannot_save_or_retrieve_or_list(self):
        self.vault.set_master('original')
        self.vault.save('original', 'site', 'user', 'secret')
        for operation in [lambda: self.vault.save('wrong', 'site', 'user', 'destroyed'),
                          lambda: self.vault.retrieve('wrong', 'site'),
                          lambda: self.vault.services('wrong')]:
            with self.assertRaises(ValueError): operation()
        self.assertEqual(self.vault.retrieve('original', 'site'), ('user', 'secret'))

    def test_update_and_sql_parameters(self):
        self.vault.set_master('original')
        service = "site'; DROP TABLE credentials; --"
        self.vault.save('original', service, 'old', 'first')
        self.vault.save('original', service, 'new', 'second')
        self.assertEqual(self.vault.retrieve('original', service), ('new', 'second'))
        self.assertEqual(self.vault.services('original'), [service])
        with self.vault.connect() as c:
            self.assertEqual(c.execute('SELECT COUNT(*) FROM credentials').fetchone(), (1,))
            self.assertNotIn(b'second', bytes(c.execute('SELECT password_encrypted FROM credentials').fetchone()[0]))

    def test_legacy_salt_with_embedded_colon(self):
        salt = b'::12345678901234'
        self.assertEqual(len(salt), 16)
        # Exactly the construction used in the old script, with synthetic data.
        old = salt + b':' + Fernet(base64.urlsafe_b64encode(derive_key('master', salt))).encrypt(b'legacy secret')
        self.assertEqual(decrypt_password('master', old), 'legacy secret')

    def test_new_ciphertext_is_legacy_compatible(self):
        blob = encrypt_password('master', 'compatibility')
        cipher = Fernet(base64.urlsafe_b64encode(derive_key('master', blob[:16])))
        self.assertEqual(cipher.decrypt(blob[17:]), b'compatibility')

    def test_tampered_ciphertext_rejected(self):
        blob = bytearray(encrypt_password('master', 'secret'))
        blob[-10] = ord('A') if blob[-10] != ord('A') else ord('B')
        with self.assertRaises(InvalidToken): decrypt_password('master', blob)

    def test_invalid_schema_does_not_reinitialize(self):
        with self.vault.connect() as c: c.execute('UPDATE schema_version SET version = 99')
        before = self.path.read_bytes()
        with self.assertRaises(ValueError): Vault(self.path)
        self.assertEqual(self.path.read_bytes(), before)

    def test_empty_existing_file_not_overwritten(self):
        path = Path(self.tmp.name) / 'existing.db'
        path.touch()
        with self.assertRaises(ValueError): Vault(path)
        self.assertEqual(path.read_bytes(), b'')

    def test_explicit_vault_path(self):
        with patch.dict('os.environ', {'PASSWORD_GENIE_VAULT': str(self.path)}):
            self.assertEqual(default_vault_path(), self.path)
