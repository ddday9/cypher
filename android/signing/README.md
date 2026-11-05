# Signing the APK

Android only installs an update over an app signed with the same key. No
key is stored in this repository: whoever has the key can publish APKs that
install over nevio.

**Releases (GitHub Actions)** are signed with the key from these repository
secrets (Settings → Secrets and variables → Actions):

| Secret | Value |
|---|---|
| `NEVIO_KEYSTORE_B64` | the keystore file, `base64 -w0 release.keystore` |
| `NEVIO_KEYSTORE_PASSWORD` | keystore password |
| `NEVIO_KEY_ALIAS` | key alias, e.g. `nevio` |
| `NEVIO_KEY_PASSWORD` | key password |

Create the key once, on your own computer, and keep a backup: without it
you cannot publish updates that install over the previous version.

```bash
keytool -genkeypair -keystore release.keystore -alias nevio -keyalg RSA -keysize 3072 -validity 20000
```

Without the secrets the release APK is signed with the runner's temporary
debug key: it installs fine, but every release has a different key, so an
update needs the old version removed first (its settings are lost).

**Local builds:** put `keystore.properties` into `android/` (it is ignored by git):

```
storeFile=/path/to/release.keystore
storePassword=…
keyAlias=nevio
keyPassword=…
```
