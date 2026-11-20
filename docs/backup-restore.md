---
layout: default
title: Backup and restore
nav_order: 6
---

# Backup and restore
{: .no_toc }

<details open markdown="block">
  <summary>Table of contents</summary>
  {: .text-delta }
1. TOC
{:toc}
</details>

Certificate-store edits can break HTTPS for browsers, package managers, and language runtimes. Treat every change as privileged.

## Best practices

1. **Backup first.** Allowlisting without a prior backup fails on purpose. Run `trustprune backup` (and `--app …` when targeting an app) before any allowlist.
2. **Prefer temp or container stores** when experimenting. Do not point destructive tests at real `/etc` or `/usr` CA paths.
3. **Verify after changes** with `trustprune list` and `trustprune connect https://…`.
4. **Keep a known-good backup** until you confirm the machine still reaches the sites and tools you need.

Add `--dry-run` to `backup` or `restore` to see exactly which files would be written or copied, without touching the store.

## Where backups are stored

Parent directory (created as needed):

| OS | Path |
|----|------|
| Linux, Windows | `~/.trustprune/` (legacy read-only fallback: `~/.cert-manage/`) |
| Darwin | `~/Library/trustprune/` (legacy read-only fallback: `~/Library/cert-manage/`) |

| Store | Layout under the parent |
|-------|-------------------------|
| Linux platform | `linux/<unix-timestamp>/` — mirror of the live CA **directory** (`/usr/share/ca-certificates`, Fedora/RHEL/Rocky `/etc/pki/ca-trust/source`, or Arch `/etc/ca-certificates/trust-source`) |
| Darwin platform | `darwin/<unix-timestamp>/login.keychain/<sha256>.crt` — PEM exports of login-keychain certs |
| Java | `java/cacerts-<unix-timestamp>.bck` plus a `.source` sidecar recording the keystore path |
| Chrome / Firefox / poppler / okular (NSS) | `chrome/<unix-timestamp>/`, `firefox/<unix-timestamp>/`, `poppler/<unix-timestamp>/`, or `okular/<unix-timestamp>/` — full profile file set plus a `source` file recording the profile directory (see below) |
| OpenSSL | `openssl/<unix-timestamp>/` — PEM bundle saved as `ca-bundle.pem` plus a `source` file recording the path, or a mirror of a hashed cert directory |
| Darwin `--app ssl` | `ssl/<unix-timestamp>/cert.pem` — copy of `/etc/ssl/cert.pem` |
| Python `--app certifi` | `certifi/<unix-timestamp>/cacert.pem` plus a `source` file recording the bundle path |
| Acrobat `--app acrobat` | `acrobat/<unix-timestamp>/addressbook.acrodata` plus a `source` file recording the live path. The bytes are copied unchanged |

`GetLatestBackup` picks the lexicographically largest entry in that store’s folder (timestamped names sort correctly). Files named `source` or ending in `.source` are source sidecars, not backups, and are skipped.

## Restore or allowlist with no backup

When no backup exists for a store, `restore` refuses before any filesystem write (dry-run included), prints `ERROR: no backup for <store> in <dir>; run: trustprune backup` (app stores such as firefox, chrome, ssl, openssl, and certifi suggest `trustprune backup --app <name>`), and exits 1. There is no fallback to a system default state.

`allowlist` does the same: with no backup for the target store it refuses before any filesystem write (dry-run included, so no plan is printed), prints the same `ERROR: no backup for <store> in <dir>; run: trustprune backup` message (or `trustprune backup --app <name>` for `--app` stores, including java, ssl, openssl, and certifi), and exits 1.

## Linux: temp-dir swap and rollback

`linuxStore.Restore` does **not** delete the live CA directory before copying. It:

1. Mirrors the backup into a sibling temp directory (`<ca.dir>.restore-tmp`).
2. Renames the live directory aside to `<ca.dir>.restore-old`. It always uses that fixed path, so an operator can find it even after a crash; restore prints the path only when a failure leaves `<ca.dir>.restore-old` in place.
3. Renames the temp directory into place as the live CA dir.
4. Runs `update-ca-certificates` / `update-ca-trust` (via `sudo` unless already root).
5. On refresh failure, moves the failed tree to `<ca.dir>.restore-failed` and renames the aside directory back.
6. On success, removes the aside directory. If that removal fails, restore still succeeds and prints a warning naming `<ca.dir>.restore-old` (remaining contents may be incomplete).

If the swap rename itself fails after the live tree was moved aside, the previous directory is renamed back. A failed mirror leaves the live directory untouched.

`Restore` honors an explicit backup path (`trustprune restore --backup …`). Empty `where` uses the latest backup under `~/.trustprune/linux/` or the legacy `~/.cert-manage/linux/`; the primary path wins for duplicate basenames.

## NSS: full file set

NSS backups for Chrome (Linux), Firefox, poppler, and okular copy whichever members of the profile set exist:

| Style | Files |
|-------|-------|
| `cert9.db` present | `cert9.db`, `key4.db`, `pkcs11.txt` |
| else `cert8.db` | `cert8.db`, `key3.db`, `secmod.db` |

### Temp-dir swap and rollback

`nssStore.Restore` does **not** copy profile files straight onto the live paths. It:

1. Stages the backup set into a sibling temp directory (`<profile>.restore-tmp`).
2. Moves each existing live file aside under `<profile>.restore-old/`. It always uses that fixed path, so an operator can find it even after a crash; restore prints the path only when a failure leaves `<profile>.restore-old/` in place.
3. Renames each staged file into the live profile.
4. On any staging or swap failure, rolls live files back from the aside directory and removes the temp dirs.
5. On success, removes the temp and aside directories. If either cleanup fails, restore still succeeds and prints a warning naming the kept path (remaining contents may be incomplete), matching Linux restore behavior for `.restore-old`.

A failed stage leaves the live profile files untouched. Restore from a **legacy single file** uses the same stage-then-swap path onto `cert9.db` (or `cert8.db` if the backup basename contains `cert8`). Explicit `--backup` is honored.

Backup also writes a `source` file in the timestamp directory recording the resolved profile directory the files came from (symlinks are followed so a later retarget cannot silently match). That file is not part of the profile set and is not copied onto the live profile. Restore compares it to the profile being restored into and refuses a different directory before any write (dry-run included) unless `--force` is given. A backup with no `source` file — an older release, or a legacy single file — is refused the same way unless `--force`. Firefox profiles share one backup directory, so a source-less backup is not assumed to belong to the profile currently selected.

## Java

Backup copies the live `cacerts` file into `~/.trustprune/java/` (or `~/Library/trustprune/java/` on Darwin) and writes a `.source` sidecar recording the keystore path. Restore copies the chosen backup over the live keystore (`SudoCopyFile` when permissions require it).

`--app java --store <cacerts>` overrides trust-store search on `list`, `backup`, `connect`, `restore`, `add`, and `allowlist` (the keystore to operate on, not the backup). Use `--backup <path>` to restore a specific `.bck` file. Restore into a different path than the backup recorded is refused before any write unless `--force` is given. Latest-backup selection prefers the newest `.bck` whose recorded source matches the target keystore.

## Darwin notes

- System root keychain is SIP-protected and is not rewritten.
- Backup exports certificates from the **login** keychain only under `darwin/<unix-timestamp>/login.keychain/<sha256>.crt`.
- Restore clears “Never Trust” overrides for Apple system roots where applicable, then re-adds missing login-keychain certs from the chosen backup. Empty `where` uses the latest backup; `--backup` may be the timestamp directory or the `login.keychain` directory itself.

## Darwin `--app ssl` (`/etc/ssl/cert.pem`)

Backup copies the live PEM into `~/Library/trustprune/ssl/<unix-timestamp>/cert.pem`. Backup directories use exclusive `Mkdir` and bump the unix-second on collision so two backups in the same second never share a directory.

Restore and other writers install via a sibling temp directory:

1. Stage into `<dst>.restore-tmp` (a directory next to the live file).
2. **Copy** the live PEM aside to `<dst>.restore-old` (never move it), so the live path stays readable during the swap.
3. Rename the staged file over `dst`.
4. If `<dst>.restore-old` already exists before a restore, refuse with an error naming that path (do not delete it).
5. After a successful swap, a failed aside cleanup warns on stderr naming the kept path and still returns success.

Explicit `--backup` is honored (PEM file or backup directory containing `cert.pem`).


## Python certifi (`--app certifi`)

Backup copies the live certifi CA bundle into `~/.trustprune/certifi/<unix-timestamp>/cacert.pem` (or `~/Library/trustprune/certifi/...` on Darwin) and writes a `source` file in that directory recording the bundle path. Backup directories use exclusive `Mkdir` and bump the unix-second on collision.

Restore and other writers use the same atomic sibling-temp install as `--app ssl` (stage into `.restore-tmp`, copy the live file aside to `.restore-old`, rename over the destination; refuse a leftover `.restore-old`). An empty allowlist result is refused. Restore with no backup returns an error before any filesystem write (dry-run included). Restore into a different path than the backup recorded is refused before any write unless `--force` is given. Latest-backup selection prefers the newest directory whose recorded source matches the target bundle.

Path discovery matches `docs/usage.md`: `--store` overrides the bundle on `list`, `backup`, `connect`, `restore`, `add`, and `allowlist`. Then Python `certifi.where()`, pip's vendored certifi, then site-packages fallbacks. On `add` and `allowlist`, `--file` stays the certificate or allowlist file. For restore, `--backup` selects the backup source.

## OpenSSL (`--app openssl`)

Manages curl/git/OpenSSL and LibreSSL CA bundles and cert directories. Path resolution (first existing wins): `SSL_CERT_FILE`, `CURL_CA_BUNDLE`, LibreSSL locations when LibreSSL is present (Homebrew `.../etc/libressl/cert.pem` then `.../etc/libressl/certs` under `/usr/local` and `/opt/homebrew`, then OpenBSD/Alpine `/etc/ssl/cert.pem`), distro/Homebrew OpenSSL defaults, then `git config --get http.sslCAInfo`. LibreSSL is present when a Homebrew `libressl` `openssl` binary exists or `openssl version` starts with `LibreSSL`. Darwin `/usr/bin/openssl` does not count. Darwin `/etc/ssl/cert.pem` is never chosen as the openssl default; that file is `--app ssl`.

- **PEM file** (for example `/etc/ssl/certs/ca-certificates.crt`): backup copies into `openssl/<unix-timestamp>/ca-bundle.pem` and writes a `source` file recording the bundle path. Restore and other writers use the same atomic sibling-temp install as `--app ssl`. An empty allowlist result is refused.
- **Cert directory** (for example Homebrew `/usr/local/etc/openssl/certs` or LibreSSL `.../etc/libressl/certs`): backup mirrors the directory. Restore stages into `<dir>.restore-tmp`, moves the live dir aside to `<dir>.restore-old`, then swaps. Remove deletes cert files that do not match the allowlist, then rehashes. LibreSSL runs `<openssl> certhash <dir>`. Otherwise `c_rehash` runs when that binary is available. `--bundle` does not select a directory.

Restore with no backup refuses before any filesystem write (dry-run included). Explicit `--backup` is honored and still names the backup source.

`--bundle <pem>` on `list`, `backup`, `restore`, and `allowlist` uses that PEM and skips `SSL_CERT_FILE`, `CURL_CA_BUNDLE`, distro defaults, and git. On `allowlist`, `--file` remains the allowlist. On `restore`, `--backup` remains the backup source. With `--bundle` and no `--backup`, restore picks the newest backup whose `source` matches that PEM (backups with no `source` file are skipped). A backup recorded for a different path is refused before any write unless `--force`. Backups with no `source` file can still be applied with an explicit `--backup`. Discovery restore (no `--bundle`) of a PEM uses the newest backup recorded for that file and also accepts a legacy backup with no `source`; a backup recorded for a different bundle is refused unless `--force`. Allowlist uses the same selection. Automatic restore of a discovered cert directory ignores PEM backups that record a `source` and uses the newest remaining backup (directory mirrors have no `source` file). Restore into a cert directory refuses a PEM bundle backup (one that has a `source` file), including an explicit `--backup`. If discovery cannot resolve a path, only backups with no `source` file match.

## Acrobat (`--app acrobat`)

Backup copies the newest per-user `addressbook.acrodata` into `~/.trustprune/acrobat/<unix-timestamp>/addressbook.acrodata` (or `~/Library/trustprune/acrobat/...` on Darwin) and writes a `source` file in that directory recording the live path. The file is opaque: the copy is byte for byte, with no certificate parse. Backup directories use exclusive `Mkdir` and bump the unix-second on collision.

Restore writes that copy back with the same atomic sibling-temp install as `--app ssl` (stage into `.restore-tmp`, copy the live file aside to `.restore-old`, rename over the destination; refuse a leftover `.restore-old`). A backup recorded for a different path is refused before any write unless `--force`. Restore with no backup returns an error before any filesystem write (dry-run included). The live address book has to exist; a missing file is `addressbook.acrodata not found`.

Backup and restore refuse while a process image named Acrobat, AcroRd32, or AdobeReader is running. They do not create a backup directory in that case. `--dry-run` prints the copy plan and does not write, and it still refuses when one of those processes is running.

`list` prints a read-only report of the AATL, EUTL, and Windows store trust settings and does not parse the file. When Acrobat is not installed it prints `acrobat: not installed` and exits 0. Listing address book entries read-only was not attempted. The file is treated as opaque.

`allowlist` does not edit the file. With no backup it returns the usual no-backup error. With a backup it prints the pruning guide. See [Platforms](platforms.md#acrobat).

## Okular (`--app okular`)

When the effective signature backend is NSS, backups are the same NSS profile set as poppler, under `okular/<unix-timestamp>/`, with a `source` file recording the directory. Restore and allowlist use that recorded path the same way as firefox and poppler.

When the backend is GPG, `backup`, `restore`, and `allowlist` report the GPG backend and exit 1. They do not create a backup directory.

## Foxit (`--app foxit`)

Foxit is guide only. `backup`, `restore`, and `allowlist` print the pruning guide and exit 1. They do not create a backup directory. The Trusted Certificates file is **unverified**, so there is nothing to copy. See [Platforms](platforms.md#foxit).

## Windows

Platform Add, Backup, Remove, and Restore are unimplemented (return success with no work). Only `list` reads the machine certificate stores.

[← Home](index.md)
