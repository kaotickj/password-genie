# Android release signing

Password Genie can use the existing K-Tunes release signing key without copying
the keystore or its passwords out of GitHub Actions.

The signing workflow runs in
[`kaotickj/Python-Music-Player`](https://github.com/kaotickj/Python-Music-Player/tree/signing/password-genie)
on its dedicated `signing/password-genie` branch, where these existing secrets
are available:

- `KTUNES_RELEASE_KEYSTORE_BASE64`
- `KTUNES_KEYSTORE_PASSWORD`
- `KTUNES_KEY_ALIAS`
- `KTUNES_KEY_PASSWORD`

The workflow's maintained copy is [ci/password-genie-signing.yml](ci/password-genie-signing.yml).
Its active path in the key repository is
`.github/workflows/password-genie-signing.yml`. It does not change the K-Tunes
app or its main branch. A reusable workflow called from Password Genie would
not automatically receive the key repository's secrets.

## Build or rebuild

1. Review the desired Password Genie source revision and set `SOURCE_SHA` in
   the workflow to its full immutable commit SHA. The initial build pins
   `616fcccbdf91e953f3c665ca378ee440b429a36b`, the working 2.1.0 app on `dev`.
2. Keep the expected app ID, version, output filenames, and certificate digest
   consistent with that revision. The certificate SHA-256 pin is
   `6f289ade4d7c49f94390c1a791b880d941ad72a86fda9079f216506dea616794`,
   verified against the signed K-Tunes APK from run `39243840614`.
3. Commit the reviewed workflow to its dedicated branch in the key repository.
   A push that changes that workflow starts the build. To rebuild an unchanged
   revision, use **Re-run all jobs** on the existing Actions run. This branch
   workflow does not require a release tag or publish a public release.
4. Download the `password-genie-android-signed-release` artifact from the
   successful run. It contains the release APK, `SHA256SUMS.txt`, and
   `build-verification.json` with the source revision and public certificate
   digest.

The build job has no signing credentials. It checks tracked files, runs Android
release unit tests and lint, builds an unsigned APK, and checks its contents.
A fresh signing runner independently checks the APK's app ID, version,
non-debuggable status, and absence of private database/document/key files.
It then aligns the APK, loads the key into a temporary file, signs using
password environment references, removes the key, and verifies the signature,
alignment, and pinned certificate. No Gradle build or application scripts run
with the key present. Only the APK and safe verification metadata are exported.

User vaults and signing keys must remain outside Git and every build package.
This workflow checks out only tracked app source; it never opens a local vault.
Future tagged multi-platform draft releases in Password Genie's own repository
still require the `ANDROID_*` secrets described in the README, or an explicit
integration with this separate signing workflow.

Android requires the same signing certificate for updates to an existing app.
A prior debug-signed Password Genie APK cannot be updated in place with this
release key. Because uninstalling deletes Android's app-private vault, do not
uninstall a populated Android installation without a separate usable backup.
