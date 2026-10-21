import os
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from PyQt6.QtWidgets import QApplication, QMessageBox
from pwgenie import PasswordGenie
from vault_core import Vault


class DesktopTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.vault = Vault(Path(self.tmp.name) / 'vault.db')
        self.window = PasswordGenie(self.vault)
        self.addCleanup(self.window.close)
        for method in ('warning', 'critical', 'information'):
            mocker = patch.object(QMessageBox, method)
            mocker.start()
            self.addCleanup(mocker.stop)

    def test_fresh_setup_save_retrieve_and_restart(self):
        w = self.window
        self.assertFalse(w.btn_set_master.isHidden())
        self.assertFalse(w.combo_platforms.isEnabled())
        w.entry_master.setText('synthetic-master')
        with patch.object(QMessageBox, 'question', return_value=QMessageBox.StandardButton.Yes):
            w.set_master_password()
        self.assertTrue(w.master_password_verified)
        w.entry_platform.setText('example.test')
        w.entry_username.setText('synthetic-user')
        w.entry_password.setText('  synthetic-secret  ')
        w.save_password()
        w.retrieve_password()
        self.assertEqual(w.entry_result.text(), '  synthetic-secret  ')
        reopened = PasswordGenie(Vault(self.vault.path))
        try:
            self.assertTrue(reopened.btn_set_master.isHidden())
            self.assertFalse(reopened.master_password_verified)
            reopened.entry_master.setText('synthetic-master')
            reopened.verify_master_password()
            self.assertTrue(reopened.master_password_verified)
        finally:
            reopened.close()

    def test_editing_master_locks_and_clears_results(self):
        w = self.window
        self.vault.set_master('original')
        w.entry_master.setText('original')
        w.verify_master_password()
        self.assertTrue(w.master_password_verified)
        w.entry_result.setText('private result')
        w.entry_master.setText('changed')
        self.assertFalse(w.master_password_verified)
        self.assertEqual(w.entry_result.text(), '')
        self.assertFalse(w.combo_platforms.isEnabled())
        w.entry_platform.setText('site')
        w.entry_username.setText('user')
        w.entry_password.setText('secret')
        w.save_password()
        self.assertEqual(self.vault.services('original'), [])
