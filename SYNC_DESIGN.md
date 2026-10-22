# Cross-device and remote vault access

Status: design only. Synchronization is not enabled in this build, and no server or private data has been deployed or uploaded.

## Preserve existing vaults

Desktop and Android retain schema 1 and compatible password encryption. Existing local vaults should remain usable without conversion. Platform names, usernames, and the master-password verifier are stored unencrypted in SQLite; only the password values are currently encrypted. Do not upload raw `vault.db` or use its stored verifier as a synchronization key.

The native Android app currently has no import/export or synchronization UI. Sharing requires new app functionality on both platforms, even though their vault formats are compatible.

## Recommended first version: encrypted snapshots

Keep an independent local vault on each device and offer an explicit **Sync now** action:

1. Create a consistent SQLite snapshot using the backup API, without copying a live database file by ordinary filesystem operations. See the [SQLite backup documentation](https://www.sqlite.org/backup.html).
2. Encrypt the entire snapshot on the device in a new authenticated, versioned envelope. Preserve the existing encryption inside the snapshot. Use an independently generated sync key with a reviewed pairing/recovery mechanism; never send the master passkey or plaintext snapshot to the server.
3. Upload only the encrypted envelope over authenticated HTTPS to a private endpoint, such as [Nextcloud WebDAV](https://docs.nextcloud.com/server/latest/developer_manual/client_apis/WebDAV/basic.html). A small private service on the owner's server is another option. Server authentication tokens and encryption keys remain separate.
4. Record the downloaded revision and require a matching strong ETag on upload. HTTP [If-Match](https://www.rfc-editor.org/rfc/rfc9110.html#name-if-match) makes stale uploads fail instead of overwriting newer data. Use create-only preconditions for the first upload.
5. If two devices edited offline, preserve both encrypted versions and ask the user to resolve the conflict. Do not silently choose the latest timestamp. A file lock alone cannot solve independent offline edits.
6. Before replacing a local vault, verify the envelope authentication, SQLite integrity/schema, and master-passkey unlock. Close database handles, atomically replace the local file, retain a private rollback version, then reopen. Reject snapshots with unsupported formats or inconsistent vault identity.

Sync keys need an explicit recovery story. Pair new devices through a trusted channel, store keys using platform-provided protected storage, and define what happens when a device is lost or revoked. Authentication revocation cannot make a previously downloaded vault disappear from another device. Existing vaults must remain accessible if sync is disabled or the service is unavailable.

## Avoid a live network database

Do not point the app directly at a vault on SMB/NFS or treat a cloud-synced folder as a concurrently writable SQLite database. Network filesystem locking can be unreliable, and independent file replication can lose changes or separate a database from its journal. See [SQLite's network-use guidance](https://www.sqlite.org/useovernet.html). HTTPS provides transport protection; client-side encryption is still needed to hide the vault metadata from the storage service.

## Later: automatic record merging

Reliable automatic merging needs stable record identifiers, per-record revisions, deletion tracking, and rules for competing edits and master-password changes. That should be a separately versioned design with compatibility tests and recovery tools. Do not retrofit it by modifying schema-1 records in place during an ordinary GUI/build update.

## Acceptance checks for a future implementation

Use synthetic data to test Windows/Linux/Android interchange, offline access, two-device conflicts, interrupted uploads, wrong keys, corrupted snapshots, replayed old revisions, expired authentication, device revocation, and recovery. Existing real vaults must never appear in fixtures, logs, Git, or build packages.
