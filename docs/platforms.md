---
layout: default
title: Platforms
nav_order: 7
---

# Platforms and apps

Status matches what the code on `master` does today.

## Platforms

| Status | Platform | Store paths (as used in code) | Operations |
|--------|----------|-------------------------------|------------|
| **Supported** | Linux (Debian/Ubuntu/Alpine/Gentoo layout) | CA dir `/usr/share/ca-certificates`; add dir `/usr/local/share/ca-certificates` (created on add if missing; Gentoo often omits it); bundle `/etc/ssl/certs/ca-certificates.crt`; refresh `/usr/sbin/update-ca-certificates`. See [Gentoo wiki Certificates](https://wiki.gentoo.org/wiki/Certificates). | list, add, allowlist (Remove), backup, restore |
| **Supported** | Linux (Fedora/RHEL/CentOS/Rocky layout) | CA dir `/etc/pki/ca-trust/source`; add dir `/etc/pki/ca-trust/source/anchors`; bundle `/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem`; allowlist writes distrust PEMs to `/etc/pki/ca-trust/source/blocklist`; refresh `/usr/bin/update-ca-trust` | same |
| **Supported** | Linux (Arch layout) | CA dir `/etc/ca-certificates/trust-source`; add dir `/etc/ca-certificates/trust-source/anchors`; bundle `/etc/ca-certificates/extracted/tls-ca-bundle.pem`; allowlist writes distrust PEMs to `/etc/ca-certificates/trust-source/blocklist`; refresh `/usr/bin/update-ca-trust` | same |
| **Partial** | Darwin / macOS | System roots `/System/Library/Keychains/SystemRootCertificates.keychain` (SIP-protected); system keychain `/Library/Keychains/System.keychain`; login `~/Library/Keychains/login.keychain` (or `login.keychain-db`). CLI PEM bundle is a separate store: `--app ssl` → `/etc/ssl/cert.pem` (see Applications). | list, add, allowlist, backup, restore; system roots are not rewritten; restore honors `--backup` for the login-keychain backup path |
| **List-only** | Windows | Machine stores via PowerShell: `Cert:\LocalMachine\My`, `Root`, `Trust`, `CA`, `AuthRoot` | `list` only; Add, Backup, Remove (allowlist), and Restore are no-ops |
| **Stub (CI)** | FreeBSD | No system CA dir probe yet. `Platform()` is a stub: list returns empty; live add/allowlist/backup/restore return "not implemented". CI runs unit/CLI tests in a FreeBSD guest with an empty HOME so nothing touches guest system trust. | compile + test only; no platform mutations |

Linux picks the first `cadir` whose bundle file exists, in this order: Fedora/RHEL/Rocky, Arch, then Debian/Ubuntu/Alpine/Gentoo. Fedora and Arch also ship `/etc/ssl/certs/ca-certificates.crt` as a compatibility symlink, so their unique bundle paths are checked first. Backups of the Linux CA **directory** go under `~/.trustprune/linux/<unix-timestamp>/`. Refresh (`update-ca-certificates` / `update-ca-trust`) and root-owned file copies escalate with `sudo` when present on `PATH`, otherwise `su`; already-root processes run the command directly (issue #134).

## Applications

| Status | App (`--app`) | Store paths | Operations |
|--------|--------------|-------------|------------|
| **Supported** | `certifi` | Python certifi CA bundle. Discovery: `--store <cacert.pem>` override on list/backup/connect/restore/add/allowlist; then for each interpreter (`python3` then `python`; on Windows `python` then `python3` then `py`) try `import certifi; print(certifi.where())` and, before the next interpreter, that same interpreter's `pip._vendor.certifi`; then common `site-packages/certifi/cacert.pem` fallbacks. Distro-patched certifi may point at the system CA bundle. Backups record the bundle path; restore into a different path is refused unless `--force`. | list, add, allowlist (Remove), backup, restore, `--dry-run`; atomic sibling-temp install shared with `--app ssl`/`openssl` (refuse leftover `.restore-old`, refuse empty bundle, exclusive backup dirs under `certifi/<timestamp>/cacert.pem` plus a `source` file) |
| **Supported** | `java` | `cacerts` under `JAVA_HOME` (`lib/security/cacerts` or `jre/lib/security/cacerts`). Linux also probes `/usr/bin/java`, `/etc/alternatives/java`, `/usr/lib/jvm/default-jvm`. Darwin uses `/usr/libexec/java_home`, each `*/Contents/Home` under `/Library/Java/JavaVirtualMachines/`, and Homebrew OpenJDK prefixes. Windows requires a usable `JAVA_HOME` (no extra install-path probes). `--app java --store <cacerts>` overrides search for list, backup, connect, restore, add, and allowlist. A missing `cacerts` file, a directory where that file should be, or a wrong keystore password (`Keystore was tampered with, or password was incorrect`) fails immediately with a distinct error; `keytool` is invoked non-interactively (`-noprompt`, storepass via `-storepass` for the default `changeit` or `-storepass:env` for a custom `TRUSTPRUNE_JAVA_STOREPASS`) with a timeout and no stdin. Custom passwords are not placed on the keytool or sudo command line (JDK 6+ `-storepass:env`, with `sudo --preserve-env` when escalating). The keystore password defaults to `changeit`; set `TRUSTPRUNE_JAVA_STOREPASS` to override (value is trimmed; whitespace-only falls back to `changeit`; no other passwords are tried). Backups record the keystore path; restore into a different path is refused unless `--force`. | list, add, allowlist, backup, restore |
| **Partial** | `chrome` | **Linux:** NSS DB at `~/.pki/nssdb`. **Darwin / Windows:** wraps the platform store (Chrome uses the OS trust store). | Full NSS ops on Linux when the DB exists; otherwise platform behavior |
| **Partial** | `firefox` | NSS profile dirs matching `~/.mozilla/firefox/*.default` (Linux) or `~/Library/Application Support/Firefox/Profiles/*.default` (Darwin). Uses `cert9.db` or legacy `cert8.db`. | list/add/allowlist/backup/restore via NSS when a profile is found |
| **Supported** | `openssl` | First existing path wins: `SSL_CERT_FILE`, `CURL_CA_BUNDLE`, then `/etc/ssl/certs/ca-certificates.crt`, `/etc/pki/tls/certs/ca-bundle.crt`, Homebrew OpenSSL cert dirs (`/usr/local/etc/openssl/certs`, `/opt/homebrew/etc/openssl/certs`, and `openssl@3` / `openssl@1.1` variants), then `git config --get http.sslCAInfo` (best-effort). Darwin `/etc/ssl/cert.pem` is **not** an openssl default (use `--app ssl`). `--bundle <pem>` is an explicit PEM file and skips this search. Rehash: `c_rehash` when present (`/usr/bin/c_rehash`, Homebrew openssl prefixes). | list, add, allowlist (Remove), backup, restore, `--dry-run` for both PEM **files** (atomic sibling-temp install, refuse empty bundle) and OpenSSL **cert directories** (`*.pem`/`*.crt`, directory swap, `c_rehash` after add; rehash after remove/restore if available). `restore` / `restore --dry-run` with no backup exits 1 with `ERROR: no backup for openssl in …; run: trustprune backup --app openssl` (not a silent no-op). `--bundle <pem>` overrides discovery for list, backup, restore, and allowlist and must be an existing PEM file (cert directories stay on `--app openssl` without `--bundle`). PEM backups record that path in `source`. `--bundle` restore uses the newest backup recorded for that file and refuses a different path unless `--force`. Discovery restore (no `--bundle`) follows the discovered PEM (legacy backups with no `source` still match) and refuses a backup recorded for a different bundle unless `--force` |
| **Supported (Darwin)** | `ssl` | `/etc/ssl/cert.pem` — the PEM bundle curl, git, python3, ruby, perl, and openssl CLI tools read on macOS. Apple's keychain blocks do not apply here ([eMudhra / HT149555](https://support.apple.com/en-us/149555)). Not available as a store on Linux/Windows. | list, add, allowlist (Remove), backup, restore, `--dry-run`; atomic sibling-temp install (copy aside to `.restore-old`, refuse leftover aside, exclusive backup dirs); list/add/allowlist parse negative-serial certs via a cryptobyte fallback (no GODEBUG); other unparsable PEM blocks get a stderr warning and are kept in original order on rewrite; warns when the live file differs from the last trustprune write (typical after a macOS update restores Apple's copy) |

### NSS profile files

For Chrome (Linux) and Firefox, backups copy the matching profile set from the certdb directory:

| DB style | Files |
|----------|-------|
| Shared DB (`cert9.db`) | `cert9.db`, `key4.db`, `pkcs11.txt` |
| Legacy (`cert8.db`) | `cert8.db`, `key3.db`, `secmod.db` |

NSS modifications use Mozilla `certutil`: Darwin probes `/usr/local/opt/nss/bin/certutil`; Linux probes `/usr/bin/certutil`; FreeBSD probes `/usr/local/bin/certutil`. The `-d` argument uses the `sql:` prefix when `cert9.db` is present (shared DB) and `dbm:` for legacy `cert8.db`-only profiles. After changes to a `cert8.db` profile, the tool may print a restart hint for that app.

## Backup parent directories

| OS | Parent directory |
|----|------------------|
| Linux / Windows / FreeBSD | `~/.trustprune/` (read-only fallback `~/.cert-manage/`) |
| Darwin | `~/Library/trustprune/` (read-only fallback `~/Library/cert-manage/`) |

Per-store subfolders include `linux/`, `darwin/`, `java/`, `chrome/`, `firefox/`, `ssl/`, `openssl/`, `certifi/`.

## Future stores

Researched but not yet supported:

- Container images
- Thunderbird and Chromium browsers on NSS
- FreeBSD system CA store (platform stub + CI only today)
- Node
- Registry CAs
- .NET
- Android
- Kubernetes
- iOS

[← Home](index.md)
