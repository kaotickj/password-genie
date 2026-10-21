# Reconciliation of attached folder and GitHub

Compared against GitHub `main` at `6fb4f90a50833a97f3704338c16d5024da2c293a` and the supplied `password-genie-dark` folder on 2026-10-21.

- GitHub has the Tkinter interface and schema-1 SQLite vault, with release `v2.0`. The attached `pwgenie.py` is substantially the same Tkinter implementation with comments removed. The attached `source/pwgenie.py` matches the remote copy.
- The newer attached `pwgenie-dk.py` replaces Tkinter with PyQt6, adds a platform selector gated by passkey verification, and uses constant-time comparison. It was selected as the desktop interface and reconciled into the single `pwgenie.py` entry point. An explicit Fusion dark palette is applied.
- The attached Qt About dialog incorrectly reported 1.2.0 despite the schema-1 code already being released as v2.0. The next version is consistently 2.1.0 in source and installers.
- Attached README instructions are older (including `pip install tkinter`); documentation now describes the actual Qt app, integrated first-run master setup, build tools, and vault locations.
- Attached root icons differ from GitHub; the supplied root icons are retained. License, security policy, and contribution guidelines match and are preserved. Existing screenshot images remain historical Tkinter screenshots and are no longer presented as current UI in the README.
- Removed checked-in virtual environments, build outputs, binaries, IDE files, and redundant legacy source/spec files from the new source tree. Older Git history and existing release assets are unchanged. Builds now use explicit scripts and CI.
- Neither the attached private vault nor the sensitive unrelated PDF was read, copied, committed, or used as a test fixture. Neither is part of the remote source tree at the reviewed HEAD. Ignore rules, a tracked-file check, and explicit packaging inputs prevent their inclusion.

## Correctness fixes found during reconciliation

- First-run vault creation originally ran at import time and wrote beside the executable. It now runs after QApplication initialization, defaults to user data storage, handles errors in the GUI, and preserves existing portable vaults without copying them.
- Both old variants split `salt + ':' + token` on the first colon. A random 16-byte salt can contain a colon. Read the salt at the fixed 16-byte boundary, preserving all existing schema-1 records.
- A verified flag survived edits to the master-password field and could encrypt new records under a different passkey. Edits now lock and clear sensitive fields; storage operations independently verify the passkey before accessing credentials.
- Password strings are no longer stripped, so leading/trailing spaces survive save/retrieve/copy. The old master-passkey trimming behavior is preserved for existing vault compatibility.
- SQLite connections close deterministically; password generation is capped at 4096 characters.

## Android

The attached PyQt6 desktop script is not directly an Android application. A native Java Android frontend and compatible schema-1 storage use Android's platform PBKDF2, AES-CBC, and HMAC-SHA256 primitives. Token verification precedes decryption, following the [Fernet specification](https://github.com/fernet/spec/blob/master/Spec.md). Tests use synthetic Python-generated fixtures; no actual passwords are involved. Android vault storage is app-private, backup is disabled, screenshot capture is blocked, and backgrounding locks the interface. The app requests no network or external-storage permissions. Automatic vault migration/synchronization is not provided.

## Release readiness

Do not publish this as a new stable release until all OS builds and installation tests pass and signing is configured. CI supplies unsigned desktop installers and a debug APK for verification; tag builds require Android signing secrets and create a draft release for final review. Existing v2.0 assets remain unchanged.
