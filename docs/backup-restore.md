---
layout: default
title: Backup and restore
---

# Backup and restore

Certificate-store edits can break HTTPS for browsers, package managers, and language runtimes. Treat every change as privileged.

## Best practices

1. **Backup first.** Allowlisting without a prior backup fails on purpose. Run `trustprune backup` (and `-app …` when targeting an app) before any allowlist.
2. **Prefer temp or container stores** when experimenting. Do not point destructive tests at real `/etc` or `/usr` CA paths.
3. **Verify after changes** with `trustprune list` and `trustprune connect https://…`.
4. **Keep a known-good backup** until you confirm the machine still reaches the sites and tools you need.

Add `-dry-run` to `backup` or `restore` to see exactly which files would be written or copied, without touching the store.

## Where backups are stored

Parent directory (created as needed):

| OS | Path |
|----|------|
| Linux, Windows | `~/.trustprune/` (legacy read-only fallback: `~/.cert-manage/`) |
| Darwin | `~/Library/trustprune/` (legacy read-only fallback: `~/Library/cert-manage/`) |

| Store | Layout under the parent |
|-------|-------------------------|
| Linux platform | `linux/<unix-timestamp>/` — mirror of the live CA **directory** (`/usr/share/ca-certificates` or Fedora anchors dir) |
| Darwin platform | `darwin/<unix-timestamp>/login.keychain/<sha256>.crt` — PEM exports of login-keychain certs |
| Java | `java/cacerts-<unix-timestamp>.bck` (filename taken from the keystore basename) |
| Chrome / Firefox (NSS) | `chrome/<unix-timestamp>/` or `firefox/<unix-timestamp>/` — full profile file set (see below) |
| OpenSSL | `openssl/<unix-timestamp>/` — PEM bundle saved as `ca-bundle.pem`, or a mirror of a hashed cert directory |

`GetLatestBackup` picks the lexicographically largest entry in that store’s folder (timestamped names sort correctly).

## Restore with no backup

When no backup exists for a store, `restore` refuses before any filesystem write (dry-run included), prints `ERROR: no backup for <store> in <dir>; run: trustprune backup` (app stores such as firefox, chrome, ssl, and openssl suggest `trustprune backup -app <name>`), and exits 1. There is no fallback to a system default state.

## Linux: temp-dir swap and rollback

`linuxStore.Restore` does **not** delete the live CA directory before copying. It:

1. Mirrors the backup into a sibling temp directory (`<ca.dir>.restore-tmp`).
2. Renames the live directory aside to `<ca.dir>.restore-old`. It always uses that fixed path, so an operator can find it even after a crash; restore prints the path only when a failure leaves `<ca.dir>.restore-old` in place.
3. Renames the temp directory into place as the live CA dir.
4. Runs `update-ca-certificates` / `update-ca-trust` (via `sudo` unless already root).
5. On refresh failure, moves the failed tree to `<ca.dir>.restore-failed` and renames the aside directory back.
6. On success, removes the aside directory. If that removal fails, restore still succeeds and prints a warning naming `<ca.dir>.restore-old` (remaining contents may be incomplete).

If the swap rename itself fails after the live tree was moved aside, the previous directory is renamed back. A failed mirror leaves the live directory untouched.

`Restore` honors an explicit path (`trustprune restore -file …` / the store `where` argument). Empty `where` uses the latest backup under `~/.trustprune/linux/` or the legacy `~/.cert-manage/linux/`; the primary path wins for duplicate basenames.

## NSS: full file set

NSS backups for Chrome (Linux) and Firefox copy whichever members of the profile set exist:

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

A failed stage leaves the live profile files untouched. Restore from a **legacy single file** uses the same stage-then-swap path onto `cert9.db` (or `cert8.db` if the backup basename contains `cert8`). Explicit `-file` / `where` is honored.

## Java

Backup copies the live `cacerts` file into `~/.trustprune/java/` (or `~/Library/trustprune/java/` on Darwin). Restore copies the chosen backup over the live keystore (`SudoCopyFile` when permissions require it). Explicit restore `-file` is honored as the backup source. For list/backup/connect, `-app java -file <cacerts>` overrides trust-store search and uses that keystore file instead of `JAVA_HOME` discovery.

## Darwin notes

- System root keychain is SIP-protected and is not rewritten.
- Backup exports certificates from the **login** keychain only under `darwin/<unix-timestamp>/login.keychain/<sha256>.crt`.
- Restore clears “Never Trust” overrides for Apple system roots where applicable, then re-adds missing login-keychain certs from the chosen backup. Empty `where` uses the latest backup; `-file` / `where` may be the timestamp directory or the `login.keychain` directory itself.

## Darwin `-app ssl` (`/etc/ssl/cert.pem`)

Backup copies the live PEM into `~/Library/trustprune/ssl/<unix-timestamp>/cert.pem`. Backup directories use exclusive `Mkdir` and bump the unix-second on collision so two backups in the same second never share a directory.

Restore and other writers install via a sibling temp directory:

1. Stage into `<dst>.restore-tmp` (a directory next to the live file).
2. **Copy** the live PEM aside to `<dst>.restore-old` (never move it), so the live path stays readable during the swap.
3. Rename the staged file over `dst`.
4. If `<dst>.restore-old` already exists before a restore, refuse with an error naming that path (do not delete it).
5. After a successful swap, a failed aside cleanup warns on stderr naming the kept path and still returns success.

Explicit `-file` / `where` is honored (PEM file or backup directory containing `cert.pem`).

## OpenSSL (`-app openssl`)

Manages curl/git/OpenSSL CA bundles and OpenSSL cert directories. Path resolution (first existing wins): `SSL_CERT_FILE`, `CURL_CA_BUNDLE`, distro/Homebrew defaults, then `git config --get http.sslCAInfo`. Darwin `/etc/ssl/cert.pem` is never chosen as the openssl default; that file is `-app ssl`.

- **PEM file** (for example `/etc/ssl/certs/ca-certificates.crt`): backup copies into `openssl/<unix-timestamp>/ca-bundle.pem`. Restore and other writers use the same atomic sibling-temp install as `-app ssl`. An empty allowlist result is refused.
- **Cert directory** (for example Homebrew `/usr/local/etc/openssl/certs`): backup mirrors the directory. Restore stages into `<dir>.restore-tmp`, moves the live dir aside to `<dir>.restore-old`, then swaps. Remove deletes cert files that do not match the allowlist, then runs `c_rehash` if that binary is available.

Restore with no backup refuses before any filesystem write (dry-run included). Explicit `-file` / `where` is honored.

## Windows

Platform Add, Backup, Remove, and Restore are unimplemented (return success with no work). Only `list` reads the machine certificate stores.

[← Home](index.md)
