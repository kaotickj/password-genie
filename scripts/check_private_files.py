"""Fail CI if tracked files include vaults, secrets, or generated binaries."""
from pathlib import PurePosixPath
import subprocess

paths = subprocess.check_output(['git', 'ls-files', '-z']).decode().split('\0')
bad = []
for path in filter(None, paths):
    p = PurePosixPath(path)
    name = p.name.lower()
    if (name == 'silver key realty.pdf' or name == 'vault.db' or '.db' in p.suffixes or '.db-' in name or '.sqlite' in name or name.endswith(('.sqlite', '.sqlite3', '.jks', '.keystore', '.pem', '.key', '.exe', '.apk'))
        or name.startswith(('vault.db', '.env')) or any(part in ('dist', 'venv', '.venv', '__pycache__') for part in p.parts)):
        bad.append(path)
if bad:
    raise SystemExit('Private or generated files tracked: ' + ', '.join(bad))
print('Tracked-file privacy check passed')
