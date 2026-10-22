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
from PyQt6.QtCore import Qt
from desktop_theme import apply_theme

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
        self.resize(920, 760)
        self.setMinimumSize(760, 610)

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
        central.setObjectName("canvas")
        self.setCentralWidget(central)
        outer = QVBoxLayout(central)
        outer.setContentsMargins(28, 16, 28, 14)
        outer.setSpacing(12)

        header = QHBoxLayout()
        brand = QVBoxLayout()
        brand.setSpacing(4)
        eyebrow = QLabel("YOUR KEYS. YOUR CONTROL.")
        eyebrow.setObjectName("eyebrow")
        title = QLabel("Password Genie")
        title.setObjectName("title")
        subtitle = QLabel("Generate strong passwords. Keep your credentials close.")
        subtitle.setObjectName("subtitle")
        for label in (eyebrow, title, subtitle):
            brand.addWidget(label)
        header.addLayout(brand)
        header.addStretch()
        self.status_label = QLabel("VAULT LOCKED")
        self.status_label.setObjectName("status")
        header.addWidget(self.status_label, alignment=Qt.AlignmentFlag.AlignTop)
        outer.addLayout(header)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        body = QWidget()
        body.setObjectName("body")
        layout = QVBoxLayout(body)
        layout.setContentsMargins(0, 0, 8, 0)
        layout.setSpacing(12)
        scroll.setWidget(body)
        outer.addWidget(scroll)

        def field(label, widget, parent):
            caption = QLabel(label)
            caption.setObjectName("fieldLabel")
            caption.setBuddy(widget)
            parent.addWidget(caption)
            parent.addWidget(widget)

        def button(text, action, secondary=False):
            widget = QPushButton(text)
            widget.setCursor(Qt.CursorShape.PointingHandCursor)
            widget.setProperty("secondary", secondary)
            widget.clicked.connect(action)
            return widget

        access = QGroupBox("01  /  Unlock your vault")
        access_layout = QVBoxLayout(access)
        self.entry_master = QLineEdit()
        self.entry_master.setPlaceholderText("Enter your master passkey")
        self.entry_master.setEchoMode(QLineEdit.EchoMode.Password)
        self.entry_master.textChanged.connect(self.lock_vault)
        self.entry_master.returnPressed.connect(self.verify_master_password)
        access_row = QHBoxLayout()
        access_row.addWidget(self.entry_master, 1)
        access_row.addWidget(button("Unlock vault", self.verify_master_password))
        self.btn_set_master = button("Set master password", self.set_master_password, True)
        access_row.addWidget(self.btn_set_master)
        access_layout.addLayout(access_row)
        access_hint = QLabel("First visit? Set a master password to create your private vault.")
        access_hint.setObjectName("hint")
        access_hint.setWordWrap(True)
        access_layout.addWidget(access_hint)
        layout.addWidget(access)

        columns = QHBoxLayout()
        columns.setSpacing(18)
        generator = QGroupBox("02  /  Password generator")
        gen = QVBoxLayout(generator)
        gen.setSpacing(10)
        self.entry_length = QLineEdit("16")
        self.entry_length.setMaximumWidth(95)
        self.entry_length.setAccessibleName("Password length")
        length_row = QHBoxLayout()
        length_row.addWidget(QLabel("Password length"))
        length_row.addStretch()
        length_row.addWidget(self.entry_length)
        gen.addLayout(length_row)
        hint = QLabel("Choose the characters to draw from.")
        hint.setObjectName("hint")
        gen.addWidget(hint)
        self.chk_letters = QCheckBox("Letters  ·  A–Z, a–z")
        self.chk_digits = QCheckBox("Numbers  ·  0–9")
        self.chk_punct = QCheckBox("Symbols  ·  ! @ # $")
        for checkbox in (self.chk_letters, self.chk_digits, self.chk_punct):
            checkbox.setChecked(True)
            gen.addWidget(checkbox)
        gen.addStretch()
        gen.addWidget(button("Generate password", self.generate_password))
        gen.addWidget(button("SHA-256 fingerprint", self.hash_password, True))
        columns.addWidget(generator, 4)

        credentials = QGroupBox("03  /  Saved credentials")
        cred = QVBoxLayout(credentials)
        cred.setSpacing(6)
        self.combo_platforms = QComboBox()
        self.combo_platforms.setPlaceholderText("Unlock to browse saved platforms")
        self.combo_platforms.setEnabled(False)
        self.combo_platforms.currentTextChanged.connect(self.on_platform_selected)
        field("Saved platforms", self.combo_platforms, cred)
        self.entry_platform = QLineEdit()
        self.entry_platform.setPlaceholderText("e.g. github.com")
        field("Platform", self.entry_platform, cred)
        account_row = QHBoxLayout()
        username_column, password_column = QVBoxLayout(), QVBoxLayout()
        self.entry_username = QLineEdit()
        self.entry_username.setPlaceholderText("Username or email")
        self.entry_password = QLineEdit()
        self.entry_password.setPlaceholderText("Password to store")
        self.entry_password.setEchoMode(QLineEdit.EchoMode.Password)
        field("Username", self.entry_username, username_column)
        field("Password", self.entry_password, password_column)
        account_row.addLayout(username_column)
        account_row.addLayout(password_column)
        cred.addLayout(account_row)
        actions = QHBoxLayout()
        actions.addWidget(button("Save / update", self.save_password))
        actions.addWidget(button("Retrieve", self.retrieve_password, True))
        cred.addLayout(actions)
        columns.addWidget(credentials, 6)
        layout.addLayout(columns)

        result = QGroupBox("04  /  Your result")
        result_layout = QVBoxLayout(result)
        self.lbl_result_title = QLabel("Generated or retrieved password")
        self.lbl_result_title.setObjectName("fieldLabel")
        result_layout.addWidget(self.lbl_result_title)
        result_row = QHBoxLayout()
        self.entry_result = QLineEdit()
        self.entry_result.setObjectName("result")
        self.entry_result.setReadOnly(True)
        self.entry_result.setPlaceholderText("Your password will appear here")
        self.entry_result.setAccessibleName("Generated or retrieved password")
        result_row.addWidget(self.entry_result, 1)
        result_row.addWidget(button("Copy", self.copy_password_to_clipboard))
        result_layout.addLayout(result_row)
        layout.addWidget(result)
        layout.addStretch()

        footer = QHBoxLayout()
        note = QLabel("LOCAL VAULT  /  Stored on this device")
        note.setObjectName("hint")
        footer.addWidget(note)
        footer.addStretch()
        version = QLabel(f"v{VERSION}")
        version.setObjectName("hint")
        footer.addWidget(version)
        outer.addLayout(footer)

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
        self.status_label.setText("VAULT LOCKED")
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
            self.status_label.setText("VAULT UNLOCKED")
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
            self.status_label.setText("VAULT UNLOCKED")
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
    apply_theme(app)
    try:
        window = PasswordGenie()
    except Exception as exc:
        QMessageBox.critical(None, "Vault startup error", str(exc))
        sys.exit(1)
    window.show()
    sys.exit(app.exec())
