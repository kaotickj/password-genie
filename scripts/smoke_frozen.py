"""Exercise first-run and restart of the actual frozen app in an empty vault."""
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import time

with tempfile.TemporaryDirectory() as directory:
    vault = Path(directory) / 'vault.db'
    env = dict(os.environ, QT_QPA_PLATFORM='offscreen', PASSWORD_GENIE_VAULT=str(vault))
    for launch in range(2):
        process = subprocess.Popen(['dist/PasswordGenie/PasswordGenie'], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError(process.communicate()[1].decode())
                if vault.exists():
                    try:
                        with sqlite3.connect(vault) as conn:
                            assert conn.execute('SELECT version FROM schema_version').fetchall() == [(1,)]
                            assert conn.execute('SELECT COUNT(*) FROM credentials').fetchone() == (0,)
                        break
                    except sqlite3.DatabaseError:
                        pass
                time.sleep(0.2)
            else:
                raise RuntimeError('Frozen app did not initialize a vault')
            time.sleep(2)
            assert process.poll() is None, process.communicate()[1].decode()
        finally:
            process.terminate()
            process.communicate(timeout=10)
    print('Frozen app first-run and restart passed; empty vault generated outside the bundle')
