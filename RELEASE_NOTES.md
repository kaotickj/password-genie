# Password Genie 2.1.0

- Reconcile the newer dark Qt desktop app with the public repository.
- Build Linux .deb/portable archives, Windows setup installers, macOS DMGs, and a native Android APK in GitHub Actions.
- Create an empty per-user vault on first run; preserve existing portable vaults and schema-1 encryption compatibility.
- Fix retrieval for salts containing colons, lock on passkey edits, preserve password whitespace, and verify passkeys for each storage operation.
- Exclude private databases, backups, signing keys, and unrelated sensitive documents from source and packages.

Release candidates require installation testing. Desktop installers are currently unsigned; macOS is not notarized. Android release builds require the repository owner's persistent signing key. No vault migration or automatic device synchronization is included. Back up existing vaults before upgrading. SHA-256 checksums verify download integrity and do not replace publisher signatures.
