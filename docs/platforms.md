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
| **Partial** | `chrome` | **Linux:** NSS DB at `~/.pki/nssdb`. **Darwin / Windows:** wraps the platform store (Chrome uses the OS trust store). | Full NSS ops on Linux when the DB exists, including the recorded-profile restore guard (a different path, or a backup with no recorded profile, is refused unless `--force`); otherwise platform behavior |
| **Partial** | `firefox` | The newest NSS profile whose name contains `default` (such as `*.default-release`) under `$XDG_CONFIG_HOME/mozilla/firefox` or `~/.mozilla/firefox` (Linux; `MOZ_LEGACY_HOME=1` checks the legacy dir first), `~/Library/Application Support/Firefox/Profiles` (Darwin), or `%APPDATA%\Mozilla\Firefox\Profiles` (Windows). Uses `cert9.db` or legacy `cert8.db`. | backup/restore of the profile files when a profile is found; the backup records that profile path and restore into a different path, or from a backup with no recorded path, is refused unless `--force`; list/add/allowlist via Mozilla certutil when a probe path exists (see NSS section) |
| **Partial** | `poppler` | NSS DB for pdfsig / poppler. `--store <dir>` is `-nssdir` and skips discovery. Otherwise the same lookup as poppler: the newest Firefox profile whose name contains `default` and has a regular non-empty `cert9.db` (cert8-only profiles are skipped) when `certutil -L -d sql:<dir>` succeeds, or when certutil cannot be found or run; a profile that fails that probe falls back to `~/.pki/nssdb` (a failed Firefox open does not try `/etc/pki/nssdb`); with no cert9 profile, `/etc/pki/nssdb` when it contains a regular non-empty `cert9.db` and that probe succeeds or certutil cannot be found or run, otherwise `~/.pki/nssdb`. Profile roots match Firefox (`$XDG_CONFIG_HOME` / `~/.config`, `MOZ_LEGACY_HOME`, `~/.mozilla/firefox`, Darwin `~/Library/Application Support/Firefox/Profiles`, Windows `%APPDATA%\Mozilla\Firefox\Profiles`). `apps` shows the chosen path only when that directory contains a regular non-empty `cert9.db`. `list` uses the same path. Built-in `libnssckbi` roots are not enumerated yet. | list, add, allowlist, backup, restore through the same NSS store as firefox; `--store` overrides the directory on list, backup, connect, restore, add, and allowlist. Allowlist refuses when this directory has no backup of its own and the newest backup was recorded for a different directory, unless `--force`. A root that exists only in `libnssckbi` is not listed and is not distrusted |
| **Supported** | `openssl` | First existing path wins: `SSL_CERT_FILE`, `CURL_CA_BUNDLE`, then `/etc/ssl/certs/ca-certificates.crt`, `/etc/pki/tls/certs/ca-bundle.crt`, Homebrew OpenSSL cert dirs (`/usr/local/etc/openssl/certs`, `/opt/homebrew/etc/openssl/certs`, and `openssl@3` / `openssl@1.1` variants), then `git config --get http.sslCAInfo` (best-effort). Darwin `/etc/ssl/cert.pem` is **not** an openssl default (use `--app ssl`). `--bundle <pem>` is an explicit PEM file and skips this search. Rehash: `c_rehash` when present (`/usr/bin/c_rehash`, Homebrew openssl prefixes). | list, add, allowlist (Remove), backup, restore, `--dry-run` for both PEM **files** (atomic sibling-temp install, refuse empty bundle) and OpenSSL **cert directories** (`*.pem`/`*.crt`, directory swap, `c_rehash` after add; rehash after remove/restore if available). `restore` / `restore --dry-run` with no backup exits 1 with `ERROR: no backup for openssl in …; run: trustprune backup --app openssl` (not a silent no-op). `--bundle <pem>` overrides discovery for list, backup, restore, and allowlist and must be an existing PEM file (cert directories stay on `--app openssl` without `--bundle`). PEM backups record that path in `source`. `--bundle` restore uses the newest backup recorded for that file and refuses a different path unless `--force`. Discovery restore (no `--bundle`) follows the discovered PEM (legacy backups with no `source` still match) and refuses a backup recorded for a different bundle unless `--force` |
| **Supported (Darwin)** | `ssl` | `/etc/ssl/cert.pem` — the PEM bundle curl, git, python3, ruby, perl, and openssl CLI tools read on macOS. Apple's keychain blocks do not apply here ([eMudhra / HT149555](https://support.apple.com/en-us/149555)). Not available as a store on Linux/Windows. | list, add, allowlist (Remove), backup, restore, `--dry-run`; atomic sibling-temp install (copy aside to `.restore-old`, refuse leftover aside, exclusive backup dirs); list/add/allowlist parse negative-serial certs via a cryptobyte fallback (no GODEBUG); other unparsable PEM blocks get a stderr warning and are kept in original order on rewrite; warns when the live file differs from the last trustprune write (typical after a macOS update restores Apple's copy) |
| **Guide only** | `foxit` | Windows and macOS install of Foxit PDF Editor or Foxit PDF Reader (older PhantomPDF and Foxit Reader names too). `apps` PATH is that install. The Trusted Certificates file is **unverified**, so it is not a store path. Linux is not probed. | `apps` reports `guide only` when an install is found. `list`, `add`, `allowlist`, `backup`, `restore`, and `connect` print the pruning guide and exit 1. They do not read or write Foxit trust data. `--dry-run` does not plan a change. `--store` is rejected |

### Foxit

`--app foxit` detects Foxit PDF Editor and Foxit PDF Reader so `trustprune apps` can report the install. PDF signature trust in Foxit is separate from the OS TLS store. trustprune prints where that trust comes from and how to change it in the app. It does not list, back up, or prune Foxit.

`apps` shows `guide only` when an install is found, with the executable or `.app` bundle in PATH. JSON adds `"guideOnly": true`. A machine with no install shows `not-found`. On Linux and other systems the row is `not-found`: a current Foxit build for Linux is **unverified**, and those systems are not probed.

#### Where trust comes from

Foxit keeps a local Trusted Certificates list. The [Windows Trusted Certificates page](https://www.foxit.com/resource-hub/user-guide/foxit-pdf-editor-for-windows/trusted-certificates/) says **Protect > Sign & Certify > Trusted Certificates** opens the Trust Certificates window, where a certificate can be added, exported, viewed, deleted, or given a trust level. Trust levels on the certificate viewer are "Use this certificate as a trusted root" and trusting it for validating signatures or certified documents.

The [Foxit Approved Trust List (FATL)](https://www.foxit.com/blog/how-to-automatically-trust-digital-ids-for-digital-signatures/) downloads into that same local list. **File > Preferences > Trust Manager**, group **Automatic Foxit Approved Trust List updates**, option **Load trusted certificates from Foxit server**. It is selected by default. Foxit downloads new or updated roots every 28 days, and when a signed PDF's certificate has never been checked or was last checked more than 28 days ago.

On Mac, the same preferences also download the European Union Trusted Lists (EUTL) into that list. The [Mac Protect PDF guide](https://help.foxit.com/manuals/pdf-editor/mac/en-us/2025.3.0/Protect_PDF_Files.html) puts this under **File > Preferences > Trust Manager** (or **Foxit PDF Editor > Preferences > Trust Manager**), groups **Automatic Foxit Approved Trust Lists (FATL) updates** and **Automatic European Union Trusted Lists (EUTL) updates**, option **Load trusted certificates from Foxit FATL / EUTL server**. That option is selected by default, on the same 28-day schedule.

On Windows, [Signature preferences](https://www.foxit.com/resource-hub/user-guide/foxit-pdf-editor-for-windows/signature/) include **Windows Integration**: whether to trust all root certificates in the Windows Certificate Store when validating signatures and certified documents. **File > Preferences > Signature**. With Windows Integration on, a root removed from the Windows store drops out of that path. The FATL copy in Trusted Certificates stays.

#### Remove a root and turn off FATL

1. Open Foxit PDF Editor or Foxit PDF Reader.
2. Choose **Protect > Sign & Certify > Trusted Certificates**.
3. Select the certificate and delete it, or clear its trust for signatures and certified documents.
4. Turn off the download that would add it back. **File > Preferences > Trust Manager**. On Windows, clear **Load trusted certificates from Foxit server**. On Mac, clear **Load trusted certificates from Foxit FATL / EUTL server** in both the FATL and EUTL groups.
5. On Windows, open **File > Preferences > Signature** and clear the Windows Integration options that trust Windows certificate store roots. Do this when the root should also stop being trusted through the Windows store.

An administrator can set the same FATL download from policy. The [Foxit PDF Editor Deployment and Configuration 2026.2](https://cdn01.foxitsoftware.com/pub/foxit/manual/phantom/en_us/pdf-editor-deployment-and-configuration-2026.2.pdf) guide calls the setting "Load trusted certificates from Foxit server", with **Disable**, **Enable & Ask before updating**, and **Enable & Install silently**. It is written under `HKEY_CURRENT_USER\Software\Policies\Foxit\PDFEditor` or `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Foxit\PDFEditor`. The value names are **unverified**.

#### On-disk store

The Trusted Certificates list's file path and format are **unverified**. The Windows user guide describes the Trust Certificates window, and the 2026.2 deployment guide describes the FATL policy, and neither gives a path. trustprune does not try to list or back up that list. `list`, `add`, `allowlist`, `backup`, `restore`, and `connect` with `--app foxit` print this guide and exit 1, including under `--dry-run`.

#### Install detection

The first existing install wins. PATH in `apps` is that file or bundle.

Windows searches `%ProgramFiles%`, then `%ProgramFiles(x86)%`. When the variable is unset, those default to `C:\Program Files` and `C:\Program Files (x86)`. A hit is a regular file at:

| Product | Path under the Program Files root | Source |
|---------|-----------------------------------|--------|
| Foxit PDF Editor | `Foxit Software\Foxit PDF Editor\FoxitPDFEditor.exe` | The [2026.2 deployment guide](https://cdn01.foxitsoftware.com/pub/foxit/manual/phantom/en_us/pdf-editor-deployment-and-configuration-2026.2.pdf) uses `C:\Program Files\Foxit Software\Foxit PDF Editor` as the install folder. It does not name the executable. |
| Foxit PDF Reader | `Foxit Software\Foxit PDF Reader\FoxitPDFReader.exe` | Current product name. The default directory is **unverified**. |
| Foxit PhantomPDF | `Foxit Software\Foxit PhantomPDF\FoxitPhantomPDF.exe` | Older Editor name. The path is **unverified**. |
| Foxit Reader | `Foxit Software\Foxit Reader\FoxitReader.exe` | Older Reader name. The path is **unverified**. |

A product folder with no executable is not an install. Per-user install directories are **unverified** and are not probed.

macOS searches `/Applications`, then `~/Applications`. A hit is a bundle whose `Contents/Info.plist` is a regular file. PATH is the `.app` bundle. The names are `Foxit PDF Editor.app`, `Foxit PDF Reader.app`, `Foxit PhantomPDF.app`, and `Foxit Reader.app`, in that order inside each folder. The Mac user guide does not state an install path. These are the product names in the default application folders.

### NSS profile files

For Chrome (Linux), Firefox, and poppler (pdfsig), backups copy the matching profile set from the certdb directory:

| DB style | Files |
|----------|-------|
| Shared DB (`cert9.db`) | `cert9.db`, `key4.db`, `pkcs11.txt` |
| Legacy (`cert8.db`) | `cert8.db`, `key3.db`, `secmod.db` |

Each backup directory also contains a `source` file recording the resolved profile directory the files were copied from (symlinks are followed). That file is not part of the profile set and is not restored onto the live profile. Restore into a different directory than the recorded profile is refused before any write unless `--force`. A backup with no `source` file (from an older release, or a legacy single file) is refused the same way unless `--force`. Allowlist refuses when this directory has no backup of its own and the newest backup was recorded for a different directory, unless `--force`. The error tells you to run `trustprune backup` for this store. Latest-backup selection never treats `source` or a `*.source` sidecar as a backup.

NSS modifications use Mozilla `certutil`: Darwin probes `/usr/local/opt/nss/bin/certutil`; Linux probes `/usr/bin/certutil`; FreeBSD probes `/usr/local/bin/certutil`. There is no Windows certutil probe yet, so list, add, and allowlist are not available for a Windows Firefox profile. Backup and restore still copy the profile files. The `-d` argument uses the `sql:` prefix when `cert9.db` is present (shared DB) and `dbm:` for legacy `cert8.db`-only profiles. After changes to a `cert8.db` profile, the tool may print a restart hint for that app.

## Backup parent directories

| OS | Parent directory |
|----|------------------|
| Linux / Windows / FreeBSD | `~/.trustprune/` (read-only fallback `~/.cert-manage/`) |
| Darwin | `~/Library/trustprune/` (read-only fallback `~/Library/cert-manage/`) |

Per-store subfolders include `linux/`, `darwin/`, `java/`, `chrome/`, `firefox/`, `poppler/`, `ssl/`, `openssl/`, `certifi/`.

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
- PDF reader document-signing trust other than pdfsig's NSS DB (`--app poppler`): Adobe, Okular's custom DB, poppler's GPG backend, and Evince/Papers. See the [research note](research/pdf-readers.md). Foxit install detection and the pruning guide are in [Foxit](#foxit)

[← Home](index.md)
