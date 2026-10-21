import sys
import os
import secrets
import string
from datetime import datetime

from PyQt6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QCheckBox,
    QComboBox,
    QMessageBox,
    QGroupBox,
    QMenu,
    QTextEdit,
    QDialog,
    QScrollArea,
)
from PyQt6.QtGui import (
    QAction,
    QIcon,
)

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import webbrowser

from vault_core import Vault, VERSION

APP_DIR = os.path.dirname(os.path.abspath(__file__))


# ────────────────────────────────────────────────
# Main Window
# ────────────────────────────────────────────────
class PasswordGenie(QMainWindow):
    def __init__(self, vault=None):
        super().__init__()
        self.vault = vault if vault is not None else Vault()
        self.setWindowTitle("Password Genie")
        self.resize(460, 540)

        self.try_set_icon()

        self.master_password_verified = False

        self.init_ui()
        self.check_and_initialize_master_password()

    def try_set_icon(self):
        if sys.platform.startswith("win"):
            icon_file = "icon.ico"
        else:
            icon_file = "icon.png"

        icon_path = os.path.join(APP_DIR, icon_file)

        if os.path.exists(icon_path):
            icon = QIcon(icon_path)
            self.setWindowIcon(icon)
            QApplication.setWindowIcon(icon)

    def init_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setSpacing(12)
        layout.setContentsMargins(16, 12, 16, 12)

        # ── Master Passkey ───────────────────────────────
        row_master = QHBoxLayout()
        lbl_master = QLabel("Master Passkey:")
        lbl_master.setMinimumWidth(130)
        self.entry_master = QLineEdit()
        self.entry_master.setEchoMode(QLineEdit.EchoMode.Password)
        self.entry_master.textChanged.connect(self.lock_vault)
        btn_verify = QPushButton("Verify Passkey")
        btn_verify.clicked.connect(self.verify_master_password)

        row_master.addWidget(lbl_master)
        row_master.addWidget(self.entry_master)
        row_master.addWidget(btn_verify)
        layout.addLayout(row_master)

        # ── Generate section ─────────────────────────────
        group_gen = QGroupBox("Generate Password")
        lay_gen = QVBoxLayout(group_gen)
        lay_gen.setSpacing(10)

        row_len = QHBoxLayout()
        lbl_len = QLabel("Password Length:")
        self.entry_length = QLineEdit("16")
        self.entry_length.setMaximumWidth(80)
        row_len.addWidget(lbl_len)
        row_len.addWidget(self.entry_length)
        lay_gen.addLayout(row_len)

        row_req = QHBoxLayout()
        lbl_req = QLabel("Include:")
        self.chk_letters = QCheckBox("Letters")
        self.chk_digits = QCheckBox("Digits")
        self.chk_punct = QCheckBox("Punctuation")
        self.chk_letters.setChecked(True)
        self.chk_digits.setChecked(True)
        self.chk_punct.setChecked(True)

        row_req.addWidget(lbl_req)
        row_req.addWidget(self.chk_letters)
        row_req.addWidget(self.chk_digits)
        row_req.addWidget(self.chk_punct)
        lay_gen.addLayout(row_req)

        btn_generate = QPushButton("Generate Password")
        btn_generate.clicked.connect(self.generate_password)
        lay_gen.addWidget(btn_generate)
        layout.addWidget(group_gen)

        # ── Vault fields ─────────────────────────────────
        row_platform = QHBoxLayout()
        lbl_plat = QLabel("Platform:")
        self.entry_platform = QLineEdit()
        row_platform.addWidget(lbl_plat)
        row_platform.addWidget(self.entry_platform)
        layout.addLayout(row_platform)

        row_user = QHBoxLayout()
        lbl_user = QLabel("Username:")
        self.entry_username = QLineEdit()
        row_user.addWidget(lbl_user)
        row_user.addWidget(self.entry_username)
        layout.addLayout(row_user)

        row_pass = QHBoxLayout()
        lbl_pass = QLabel("Password:")
        self.entry_password = QLineEdit()
        self.entry_password.setEchoMode(QLineEdit.EchoMode.Password)
        row_pass.addWidget(lbl_pass)
        row_pass.addWidget(self.entry_password)
        layout.addLayout(row_pass)

        # Saved platforms - starts disabled
        row_saved = QHBoxLayout()
        lbl_saved = QLabel("Saved Platforms:")
        self.combo_platforms = QComboBox()
        self.combo_platforms.setEditable(False)
        self.combo_platforms.setEnabled(False)  # Disabled until verified
        self.combo_platforms.currentTextChanged.connect(self.on_platform_selected)
        row_saved.addWidget(lbl_saved)
        row_saved.addWidget(self.combo_platforms)
        layout.addLayout(row_saved)

        # Generated / Retrieved password display
        row_result = QHBoxLayout()
        self.lbl_result_title = QLabel("Generated Password:")
        self.entry_result = QLineEdit()
        self.entry_result.setReadOnly(True)
        row_result.addWidget(self.lbl_result_title)
        row_result.addWidget(self.entry_result)
        layout.addLayout(row_result)

        # ── Action buttons ───────────────────────────────
        row_btn1 = QHBoxLayout()
        self.btn_set_master = QPushButton("Set Master Password")
        self.btn_set_master.clicked.connect(self.set_master_password)
        self.btn_set_master.hide()

        btn_hash = QPushButton("Hash Password")
        btn_hash.clicked.connect(self.hash_password)

        btn_save = QPushButton("Save / Update")
        btn_save.clicked.connect(self.save_password)

        row_btn1.addWidget(self.btn_set_master)
        row_btn1.addWidget(btn_hash)
        row_btn1.addWidget(btn_save)
        layout.addLayout(row_btn1)

        row_btn2 = QHBoxLayout()
        btn_retrieve = QPushButton("Retrieve Password")
        btn_retrieve.clicked.connect(self.retrieve_password)

        btn_copy = QPushButton("Copy to Clipboard")
        btn_copy.clicked.connect(self.copy_password_to_clipboard)

        row_btn2.addWidget(btn_retrieve)
        row_btn2.addWidget(btn_copy)
        layout.addLayout(row_btn2)

        layout.addStretch()

        # ── Menu ─────────────────────────────────────────
        menubar = self.menuBar()
        help_menu = menubar.addMenu("Help")

        act_instructions = QAction("Instructions for Use", self)
        act_instructions.triggered.connect(self.show_instructions)
        help_menu.addAction(act_instructions)

        act_about = QAction("About Password Genie", self)
        act_about.triggered.connect(self.show_about)
        help_menu.addAction(act_about)

        donate_menu = QMenu("Donate", self)
        donate_menu.addAction("GitHub Sponsors", lambda: webbrowser.open("https://github.com/sponsors/kaotickj"))
        donate_menu.addAction("Patreon", lambda: webbrowser.open("https://patreon.com/KaotickJay"))
        donate_menu.addAction("PayPal", lambda: webbrowser.open("https://paypal.me/kaotickj"))
        help_menu.addMenu(donate_menu)

    # ─────────────────────────────────────────────────────
    # Core Functions
    # ─────────────────────────────────────────────────────

    def check_and_initialize_master_password(self):
        self.btn_set_master.setVisible(not self.vault.has_master())
        self.lock_vault()

    def lock_vault(self):
        self.master_password_verified = False
        self.combo_platforms.clear()
        self.combo_platforms.setEnabled(False)
        self.entry_username.clear()
        self.entry_password.clear()
        self.entry_result.clear()

    def set_master_password(self):
        master = self.entry_master.text().strip()
        if not master:
            QMessageBox.warning(self, "Error", "Please enter a master passkey.")
            return
        reply = QMessageBox.question(self, "Set Master Password",
            "Set this as the initial master password? It cannot be recovered.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply != QMessageBox.StandardButton.Yes:
            return
        try:
            self.vault.set_master(master)
            self.master_password_verified = True
            self.btn_set_master.hide()
            self.update_platform_combobox()
            self.combo_platforms.setEnabled(True)
            QMessageBox.information(self, "Success", "Master password set successfully.")
        except Exception as exc:
            QMessageBox.critical(self, "Error", str(exc))

    def verify_master_password(self):
        self.lock_vault()
        try:
            self.vault.require_master(self.entry_master.text().strip())
            self.master_password_verified = True
            self.btn_set_master.hide()
            self.update_platform_combobox()
            self.combo_platforms.setEnabled(True)
            QMessageBox.information(self, "Success", "Master password verified successfully.")
        except Exception as exc:
            QMessageBox.critical(self, "Error", str(exc))

    def generate_password(self):
        if not self.master_password_verified:
            QMessageBox.warning(self, "Locked", "Please verify or set the master password first.")
            return
        try:
            length = int(self.entry_length.text().strip())
            if length <= 0 or length > 4096:
                raise ValueError()
        except ValueError:
            QMessageBox.warning(self, "Error", "Enter a password length between 1 and 4096.")
            return

        chars = ""
        if self.chk_letters.isChecked():
            chars += string.ascii_letters
        if self.chk_digits.isChecked():
            chars += string.digits
        if self.chk_punct.isChecked():
            chars += string.punctuation

        if not chars:
            QMessageBox.warning(self, "Error", "Please select at least one character type.")
            return

        password = ''.join(secrets.choice(chars) for _ in range(length))
        self.entry_result.setText(password)
        self.lbl_result_title.setText("Generated Password:")
        QMessageBox.information(self, "Generated Password", f"Your password is:\n\n{password}")

    def hash_password(self):
        if not self.master_password_verified:
            QMessageBox.warning(self, "Locked", "Please verify or set the master password first.")
            return

        pw = self.entry_password.text().strip()
        if not pw:
            QMessageBox.warning(self, "Error", "Please enter a password to hash.")
            return

        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(pw.encode())
        hashed = digest.finalize()

        QMessageBox.information(self, "Hashed Password", f"SHA-256:\n\n{hashed.hex()}")

    def save_password(self):
        if not self.master_password_verified:
            QMessageBox.warning(self, "Locked", "Verify or set the master password first.")
            return
        try:
            self.vault.save(self.entry_master.text().strip(),
                self.entry_platform.text().strip(), self.entry_username.text().strip(),
                self.entry_password.text())
            self.update_platform_combobox()
            QMessageBox.information(self, "Success", "Credentials saved.")
        except Exception as exc:
            QMessageBox.critical(self, "Error", str(exc))

    def retrieve_password(self):
        if not self.master_password_verified:
            QMessageBox.warning(self, "Locked", "Verify or set the master password first.")
            return
        try:
            username, password = self.vault.retrieve(self.entry_master.text().strip(),
                                                   self.entry_platform.text().strip())
            self.entry_username.setText(username)
            self.entry_result.setText(password)
            self.lbl_result_title.setText("Retrieved Password:")
        except Exception as exc:
            QMessageBox.critical(self, "Error", str(exc))

    def update_platform_combobox(self):
        try:
            services = self.vault.services(self.entry_master.text().strip())
            self.combo_platforms.clear()
            self.combo_platforms.addItems(services)
        except Exception as exc:
            self.lock_vault()
            QMessageBox.critical(self, "Error", str(exc))

    def on_platform_selected(self, text):
        if text and self.master_password_verified:
            self.entry_platform.setText(text)
            self.entry_result.clear()

    def copy_password_to_clipboard(self):
        text = self.entry_result.text()
        if not text:
            return
        QApplication.clipboard().setText(text)
        QMessageBox.information(self, "Copied", "Password copied to clipboard.")

    def show_instructions(self):
        instructions = (
            "🔐 INSTRUCTIONS FOR USING PASSWORD GENIE 🔐\n\n"
            "1. Enter Your Master Passkey\n"
            "   Required for all vault operations.\n\n"
            "2. First time → click 'Set Master Password'\n"
            "   Later → click 'Verify Passkey'\n\n"
            "3. Generate secure passwords\n"
            "4. Hash strings (SHA-256)\n"
            "5. Save / update credentials\n"
            "6. Retrieve stored credentials\n\n"
            "⚠️  Remember your master password — it cannot be recovered.\n"
        )

        dialog = QDialog(self)
        dialog.setWindowTitle("Instructions")
        dialog.resize(580, 420)

        text_edit = QTextEdit()
        text_edit.setReadOnly(True)
        text_edit.setPlainText(instructions)
        text_edit.setFontFamily("Courier New")

        scroll = QScrollArea()
        scroll.setWidget(text_edit)
        scroll.setWidgetResizable(True)

        lay = QVBoxLayout(dialog)
        lay.addWidget(scroll)
        dialog.exec()

    def show_about(self):
        year = datetime.now().year
        copyright_year = f"2023–{year}" if year > 2023 else "2023"

        msg = (
            "Password Genie\n"
            f"Version {VERSION}\n\n"
            f"© {copyright_year} Kaotick Jay\n"
            "License: GNU GPL v3\n\n"
            "GitHub: https://github.com/kaotickj"
        )

        QMessageBox.about(self, "About Password Genie", msg)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setStyleSheet("""
        QWidget { background: #20242b; color: #f0f2f5; }
        QLineEdit, QComboBox, QTextEdit { background: #13171d; padding: 5px; }
        QPushButton { background: #354456; border-radius: 4px; padding: 7px; }
        QPushButton:hover { background: #46637c; }
        QGroupBox { border: 1px solid #586374; margin-top: 12px; padding-top: 12px; }
    """)
    try:
        window = PasswordGenie()
    except Exception as exc:
        QMessageBox.critical(None, "Vault startup error", str(exc))
        sys.exit(1)
    window.show()
    sys.exit(app.exec())
