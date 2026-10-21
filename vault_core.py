"""Schema-1 vault shared by the desktop UI and tests. No import-time writes."""
from contextlib import contextmanager
import base64
import hmac
import os
from pathlib import Path
import secrets
import sqlite3
import sys

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SCHEMA_VERSION = 1
VERSION = '2.1.0'


def default_vault_path():
    override = os.environ.get('PASSWORD_GENIE_VAULT')
    if override:
        return Path(override).expanduser().absolute()
    # Keep existing portable vaults in place; never silently replace or copy one.
    legacy_dir = Path(sys.executable).parent if getattr(sys, 'frozen', False) else Path(__file__).parent
    legacy = legacy_dir / 'vault.db'
    if legacy.is_file():
        return legacy
    if sys.platform == 'win32':
        root = Path(os.environ.get('LOCALAPPDATA', Path.home() / 'AppData' / 'Local'))
    elif sys.platform == 'darwin':
        root = Path.home() / 'Library' / 'Application Support'
    else:
        root = Path(os.environ.get('XDG_DATA_HOME', Path.home() / '.local' / 'share'))
    return root / 'PasswordGenie' / 'vault.db'


def derive_key(master_key, salt):
    # Preserve schema-1 compatibility. Changing this needs a versioned migration.
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                     iterations=100000).derive(master_key.encode('utf-8'))


def encrypt_password(master, password):
    salt = secrets.token_bytes(16)
    token = Fernet(base64.urlsafe_b64encode(derive_key(master, salt))).encrypt(password.encode('utf-8'))
    return salt + b':' + token


def decrypt_password(master, blob):
    blob = bytes(blob)
    # Salt is binary and may contain ':'. Its length, not a delimiter search,
    # defines the boundary in every vault produced by the old application.
    if len(blob) < 18 or blob[16:17] != b':':
        raise ValueError('Invalid credential format')
    return Fernet(base64.urlsafe_b64encode(derive_key(master, blob[:16]))).decrypt(blob[17:]).decode('utf-8')


class Vault:
    def __init__(self, path=None):
        self.path = Path(path) if path is not None else default_vault_path()
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        created = False
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            pass
        else:
            os.close(fd)
            created = True
        with self.connect() as conn:
            if created:
                conn.executescript('''
                    CREATE TABLE schema_version (version INTEGER NOT NULL);
                    INSERT INTO schema_version VALUES (1);
                    CREATE TABLE master_key (id INTEGER PRIMARY KEY, salt BLOB NOT NULL,
                                             hashed_master_key BLOB NOT NULL);
                    CREATE TABLE credentials (id INTEGER PRIMARY KEY AUTOINCREMENT,
                        service TEXT NOT NULL, username TEXT NOT NULL,
                        password_encrypted BLOB NOT NULL);
                ''')
            try:
                rows = conn.execute('SELECT version FROM schema_version').fetchall()
                if rows != [(SCHEMA_VERSION,)]:
                    raise ValueError('Unsupported vault schema; existing vault was left unchanged.')
                conn.execute('SELECT salt, hashed_master_key FROM master_key LIMIT 1')
                conn.execute('SELECT service, username, password_encrypted FROM credentials LIMIT 1')
            except sqlite3.DatabaseError as exc:
                raise ValueError('Invalid vault schema; existing vault was left unchanged.') from exc

    @contextmanager
    def connect(self):
        conn = sqlite3.connect(self.path)
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def has_master(self):
        with self.connect() as conn:
            return conn.execute('SELECT COUNT(*) FROM master_key').fetchone()[0] > 0

    def set_master(self, master):
        if not master:
            raise ValueError('Enter a master passkey.')
        salt = secrets.token_bytes(16)
        hashed = derive_key(master, salt)
        with self.connect() as conn:
            conn.execute('BEGIN IMMEDIATE')
            if conn.execute('SELECT COUNT(*) FROM master_key').fetchone()[0]:
                raise ValueError('Master password already exists. Use Verify instead.')
            conn.execute('INSERT INTO master_key (salt, hashed_master_key) VALUES (?, ?)', (salt, hashed))

    def verify(self, master):
        with self.connect() as conn:
            row = conn.execute('SELECT salt, hashed_master_key FROM master_key LIMIT 1').fetchone()
        return bool(row and hmac.compare_digest(derive_key(master, row[0]), row[1]))

    def require_master(self, master):
        if not self.verify(master):
            raise ValueError('Incorrect master password. Verify your passkey again.')

    def save(self, master, service, username, password):
        self.require_master(master)
        if not service or not username or not password:
            raise ValueError('Platform, username and password are required.')
        encrypted = encrypt_password(master, password)
        with self.connect() as conn:
            if conn.execute('SELECT id FROM credentials WHERE service = ?', (service,)).fetchone():
                conn.execute('UPDATE credentials SET username = ?, password_encrypted = ? WHERE service = ?',
                             (username, encrypted, service))
            else:
                conn.execute('INSERT INTO credentials (service, username, password_encrypted) VALUES (?, ?, ?)',
                             (service, username, encrypted))

    def retrieve(self, master, service):
        self.require_master(master)
        with self.connect() as conn:
            row = conn.execute('SELECT username, password_encrypted FROM credentials WHERE service = ?', (service,)).fetchone()
        if row is None:
            raise ValueError('No credentials found for this platform.')
        return row[0], decrypt_password(master, row[1])

    def services(self, master):
        self.require_master(master)
        with self.connect() as conn:
            return [row[0] for row in conn.execute('SELECT DISTINCT service FROM credentials ORDER BY service')]
