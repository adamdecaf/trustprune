---
layout: default
title: Platforms and apps
---

# Platforms and apps

Status matches what the code on `master` does today.

## Platforms

| Status | Platform | Store paths (as used in code) | Operations |
|--------|----------|-------------------------------|------------|
| **Supported** | Linux (Debian/Ubuntu/Alpine/Gentoo layout) | CA dir `/usr/share/ca-certificates`; add dir `/usr/local/share/ca-certificates`; bundle `/etc/ssl/certs/ca-certificates.crt`; refresh `/usr/sbin/update-ca-certificates` | list, add, allowlist (Remove), backup, restore |
| **Supported** | Linux (Fedora/RHEL/CentOS layout) | Anchors `/etc/pki/ca-trust/source/anchors`; bundle `/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem`; refresh `/usr/bin/update-ca-trust` | same |
| **Partial** | Darwin / macOS | System roots `/System/Library/Keychains/SystemRootCertificates.keychain` (SIP-protected); system keychain `/Library/Keychains/System.keychain`; login `~/Library/Keychains/login.keychain` (or `login.keychain-db`). CLI PEM bundle is a separate store: `-app ssl` → `/etc/ssl/cert.pem` (see Applications). | list, add, allowlist, backup, restore; system roots are not rewritten; restore `-file` / `where` is incomplete (always uses latest backup) |
| **List-only** | Windows | Machine stores via PowerShell: `Cert:\LocalMachine\My`, `Root`, `Trust`, `CA`, `AuthRoot` | `list` only; Add, Backup, Remove (allowlist), and Restore are no-ops |

Linux picks the first `cadir` whose bundle file exists. Backups of the Linux CA **directory** go under `~/.trustprune/linux/<unix-timestamp>/`.

## Applications

| Status | App (`-app`) | Store paths | Operations |
|--------|--------------|-------------|------------|
| **Supported** | `java` | `cacerts` under `JAVA_HOME` (`lib/security/cacerts` or `jre/lib/security/cacerts`). Linux also probes `/usr/bin/java`, `/etc/alternatives/java`, `/usr/lib/jvm/default-jvm`. Darwin uses `java_home` / `/Library/Java/JavaVirtualMachines/`. Windows requires a usable `JAVA_HOME` (no extra install-path probes). | list, add, allowlist, backup, restore |
| **Partial** | `chrome` | **Linux:** NSS DB at `~/.pki/nssdb`. **Darwin / Windows:** wraps the platform store (Chrome uses the OS trust store). | Full NSS ops on Linux when the DB exists; otherwise platform behavior |
| **Partial** | `firefox` | NSS profile dirs matching `~/.mozilla/firefox/*.default` (Linux) or `~/Library/Application Support/Firefox/Profiles/*.default` (Darwin). Uses `cert9.db` or legacy `cert8.db`. | list/add/allowlist/backup/restore via NSS when a profile is found |
| **Stub** | `openssl` | Cert paths probed: `/etc/ssl/certs/ca-certificates.crt`, `/usr/local/etc/openssl/certs`. Rehash: `/usr/bin/c_rehash`, `/usr/local/opt/openssl/bin/c_rehash`. | **Add** (write + `c_rehash`) only; List, Backup, Remove, and Restore return empty / no-op |
| **Supported (Darwin)** | `ssl` | `/etc/ssl/cert.pem` — the PEM bundle curl, git, python3, ruby, perl, and openssl CLI tools read on macOS. Apple's keychain blocks do not apply here ([eMudhra / HT149555](https://support.apple.com/en-us/149555)). Not available as a store on Linux/Windows. | list, add, allowlist (Remove), backup, restore, `-dry-run`; atomic temp-then-copy writes; list skips unparsable PEM certificates with a stderr warning (e.g. negative serials); add/allowlist refuse to rewrite if any certificate was skipped; warns when the live file differs from the last trustprune write (typical after a macOS update restores Apple's copy) |

### NSS profile files

For Chrome (Linux) and Firefox, backups copy the matching profile set from the certdb directory:

| DB style | Files |
|----------|-------|
| Shared DB (`cert9.db`) | `cert9.db`, `key4.db`, `pkcs11.txt` |
| Legacy (`cert8.db`) | `cert8.db`, `key3.db`, `secmod.db` |

NSS modifications use Mozilla `certutil`: Darwin probes `/usr/local/opt/nss/bin/certutil`; Linux probes `/usr/bin/certutil`. After changes to a `cert8.db` profile, the tool may print a restart hint for that app.

## Backup parent directories

| OS | Parent directory |
|----|------------------|
| Linux / Windows | `~/.trustprune/` (read-only fallback `~/.cert-manage/`) |
| Darwin | `~/Library/trustprune/` (read-only fallback `~/Library/cert-manage/`) |

Per-store subfolders include `linux/`, `darwin/`, `java/`, `chrome/`, `firefox/`, `ssl/`.

[← Home](index.md)
