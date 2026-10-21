# Password Genie

Local password generator and encrypted credential vault. The desktop app uses the newer dark PyQt6 interface; the Android app provides a native, scrollable interface with the same schema-1 credential format. Licensed under [GPL v3](LICENSE).

## Run from source

Python 3.12 is the CI build target. Python 3.11+ is required.

```sh
python3 -m venv .venv
# Linux/macOS
. .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python pwgenie.py
```

On first run the app creates an **empty** `vault.db`, then offers **Set Master Password**. On later runs, enter the existing passkey and choose **Verify Passkey**. No separate master-key utility is needed. Save credentials by platform and username, retrieve them, or generate passwords of 1–4096 characters. Character checkboxes choose the sampling alphabet; they do not guarantee every selected category appears. SHA-256 produces a fingerprint, not reversible encryption or a password-storage hash.

Keep the master passkey safe: it cannot be recovered. Editing the passkey locks the desktop vault. Android also locks when the app goes into the background. There is no automatic synchronization between devices.

## Vault location and existing users

New desktop vaults are stored in a writable per-user location:

| Platform | Default location |
| --- | --- |
| Linux | `$XDG_DATA_HOME/PasswordGenie/vault.db`, or `~/.local/share/PasswordGenie/vault.db` |
| Windows | `%LOCALAPPDATA%\PasswordGenie\vault.db` |
| macOS | `~/Library/Application Support/PasswordGenie/vault.db` |
| Android | App-private no-backup storage; uninstalling deletes it |

An existing `vault.db` beside the desktop source or executable is used in place for portable compatibility. Installed apps do not copy vaults automatically. Set `PASSWORD_GENIE_VAULT` to an existing vault's absolute path to use it explicitly, for example:

```sh
PASSWORD_GENIE_VAULT=/absolute/path/to/vault.db python pwgenie.py
```

Back up your own vault while the application is closed before trying a new version. Schema-1 data and its 100,000-iteration PBKDF2-HMAC-SHA256 + Fernet format are preserved; unsupported schemas produce an error and are not overwritten. Password values retain leading/trailing whitespace; master passkeys retain the prior UI's trimming behavior. Service names and usernames remain unencrypted in the database, as in v2.0.

Your vault, its SQLite sidecars/backups, signing keys, and unrelated sensitive documents must stay outside Git and build artifacts. `.gitignore` and CI check this. Build scripts explicitly include app code and icons, never whole working folders.

## Build installers

```sh
python -m pip install -r requirements-build.txt
python scripts/build_desktop.py
```

Run on the destination OS: PyInstaller does not cross-compile desktop executables.

- **Linux:** produces `.deb` and portable `.tar.gz` packages. CI builds on Ubuntu 22.04 x86_64 (glibc 2.35+). Install the `.deb` with `sudo apt install ./dist/PasswordGenie-*.deb`; launch from the application menu. For the tarball, extract and run `PasswordGenie/PasswordGenie`; install the shared libraries listed in `scripts/build_desktop.py` if needed. Local builds require glibc at least as new as their build host.
- **Windows x64:** install Inno Setup 6 before building. Produces a per-user setup `.exe` with uninstall support. The user vault remains outside the installation directory.
- **macOS:** produces an `.app` in a `.dmg` with an Applications shortcut. CI builds the architecture of `macos-14`; artifact names identify it. The current installer is not Developer ID signed or notarized.
- **Android 8.0+:** native Java app, JDK 17, Android SDK 36/build tools 35.0.0, Gradle 8.13. In `android/`, run `gradle testDebugUnitTest lintDebug assembleDebug`. The installable debug APK is for testing. Release APKs require your persistent signing key. Do not distribute a newly generated debug key as a stable release.

## Workflows and releases

[Build installers](.github/workflows/build.yml) runs desktop tests/builds and Android unit tests/lint/APK builds for pushes, pull requests, and manual dispatch. Artifacts are downloadable from the workflow run. A `v2.1.0` tag additionally builds a signed Android APK and creates a **draft** GitHub release with all installers and SHA-256 checksums only after every build succeeds. It never overwrites an existing release.

Configure repository Actions secrets `ANDROID_KEYSTORE_BASE64`, `ANDROID_STORE_PASSWORD`, `ANDROID_KEY_ALIAS`, and `ANDROID_KEY_PASSWORD` using a persistent release keystore. Missing secrets fail the release job instead of publishing an unsigned APK. Keep the keystore and passwords out of the repository. Windows Authenticode signing and macOS Developer ID signing/notarization still need configuration before a fully signed public release.

Before tagging: update `vault_core.VERSION`, Android `versionName`/`versionCode`, and release notes; verify the installers on each platform, including an Android device/emulator. The release tag must match the source version. Review and publish the draft after installation tests pass. See [reconciliation notes](RECONCILIATION.md) and [release notes](RELEASE_NOTES.md).

## Tests

```sh
QT_QPA_PLATFORM=offscreen python -m unittest discover -s tests -v
python scripts/check_private_files.py
# after a Linux build
python scripts/smoke_frozen.py
```

Tests use temporary vaults and synthetic credentials. They never open a real user vault. Android crypto tests include a Python-produced fixture with Unicode and a binary salt containing `:` to guard legacy compatibility.

[Security policy](SECURITY.md) · [Contributing](CONTRIBUTING.md) · [Issue policy](ISSUE_REPORTING_POLICY.md)
