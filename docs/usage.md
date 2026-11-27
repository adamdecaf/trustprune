---
layout: default
title: Usage
nav_order: 4
---

# Usage
{: .no_toc }

<details open markdown="block">
  <summary>Table of contents</summary>
  {: .text-delta }
1. TOC
{:toc}
</details>

Flags are per-command except `-v`/`--verbose`, which is accepted on every command and before the subcommand (`trustprune -v list …`). Root `-V` is an alias of `--version` (as is `-version`); `-v` is not a version alias. Only other flags a command actually uses are accepted (`trustprune apps --store x` is an unknown-flag usage error). Add `--dry-run` to `add`, `backup`, `restore`, or `allowlist` to print the planned changes without writing to any store. `add`, `backup`, and `restore` list files and certificates. `allowlist --dry-run` lists kept certificates and ends with kept, removed, and unmatched counts; `-v` adds per-certificate remove and keep details and lists unmatched fingerprints. A real allowlist ends with `N removed, M kept`, plus `, K unmatched` when fingerprints in the file matched nothing. `--count` prints only how many certificates were removed or untrusted. `create` reads a store, applies an allowlist, and writes a PEM bundle or a Java truststore. It leaves the store unchanged and has no `--dry-run` flag. `chain` prints a certificate chain from a local file or a URL (`--file`, `--url`, or one positional argument). `--url` implies a TLS lookup; a positional URL still needs `--remote`. It is read-only and has no `--dry-run` flag. `-v` on `chain` prints the full SHA-256 in the text table.

Both `-flag` and `--flag` work. These docs use `--flag`.

Supported `--app` values: `acrobat`, `android`, `certifi`, `chrome`, `firefox`, `foxit`, `java`, `okular`, `openssl`, `poppler`, `ssl` (Darwin `/etc/ssl/cert.pem`). `acrobat` copies `addressbook.acrodata` on backup and restore. `list` prints a read-only AATL, EUTL, and Windows store trust report, or `acrobat: not installed` (exit 0). `add`, `allowlist`, and `connect` print a pruning guide: see [Acrobat](#acrobat) below and [Platforms](platforms.md#acrobat). `android` is guide only: see [Android](#android) below and [Platforms](platforms.md#android). `foxit` is guide only: see [Foxit](#foxit) below and [Platforms](platforms.md#foxit). `okular` uses NSS when that is the effective signature backend and reports GPG without changes: see [Okular](#okular---app-okular). The OS name (`linux`, `darwin`, or `windows`) is accepted as `--app` and selects the platform store; `apps` lists application stores and does not show that name. `--store` with that name is rejected. An unknown `--app` value fails with exit 1 and an `ERROR:` that lists the valid apps, e.g. `ERROR: unknown app nope (apps: acrobat, android, certifi, chrome, firefox, foxit, java, okular, openssl, poppler, ssl)`.

Running `trustprune` with no subcommand prints the usage text and exits with status 0. `-h`, `--help`, `trustprune help`, and `trustprune <command> -h` also exit 0.

Usage errors (unknown flag, unknown command, stray positional args, missing required flag) exit 2. The message goes to stderr, starts with `ERROR:`, and the next line is a hint to run `--help` (that hint is not an `ERROR:` line). An unknown flag is echoed as typed: `-foo` is reported as `unknown flag -foo` and `--foo` as `unknown flag --foo`. Runtime errors stay on stdout, exit 1, and keep the `ERROR:` prefix. `diff` also exits 1 when the certificates differ; that report is the command output and has no `ERROR:` prefix.

```text
ERROR: unknown flag --foo
run 'trustprune list --help' for usage
```

Unexpected positional arguments are rejected with exit status 2 before any write (`unexpected argument(s): …`). Flags after a positional argument are still parsed, so `trustprune add --file x.pem extra --dry-run` is still a usage error and does not write. A shell glob that expands into multiple files can produce those extra arguments and is rejected the same way. `connect` accepts one optional positional URL (or `--url`, not both). `chain` accepts one optional positional target (an existing regular file is `--file`; anything else is `--url`; not together with `--file` or `--url`). `diff` accepts exactly two certificate paths.


## apps

List every supported application store. For each store, show whether it was found on this machine and the store path. Detection is read-only. Running `apps` also refreshes a 24-hour cache under the user cache directory so `--help` can list which apps were found without probing again.

```bash
trustprune apps
trustprune apps --format json
```

| Flag | Meaning |
|------|---------|
| `--format json` | Emit a JSON array of `{name, found, path}` objects (default is a header row then one aligned line per store). An installed guide-only app adds `guideOnly: true` (Foxit). |

Default terse output looks like:

```text
APP       STATUS     PATH
chrome    found      /home/you/.pki/nssdb
firefox   not-found  -
poppler   found      /home/you/.pki/nssdb
java      not-found  -
certifi   found      /path/to/site-packages/certifi/cacert.pem
openssl   found      /etc/ssl/certs/ca-certificates.crt
ssl       not-found  -
```

STATUS is `found`, `not-found`, or `guide only`. `guide only` means the app is installed and trustprune will not read or write its trust data. For Foxit, PATH is the install (the `.exe` or the `.app` bundle), not a certificate file. For Acrobat, PATH is `addressbook.acrodata` when that file is found. Acrobat backup and restore copy the file. `list` prints a read-only trust settings report. `add`, `allowlist`, and `connect` print a pruning guide.

## Acrobat

`--app acrobat` finds the newest per-user `addressbook.acrodata` on Windows and macOS. `trustprune apps` reports `found` and that path. `backup` and `restore` copy the file unchanged. They refuse while a process named Acrobat, AcroRd32, or AdobeReader is running. `list` prints a read-only report of the AATL download, the EUTL download, and Windows store trust (`iMSStoreTrusted`). It does not parse the address book. When no registry key, plist, or address book is found, `list` prints `acrobat: not installed` and exits 0. `add`, `allowlist`, and `connect` print where Acrobat trust comes from and do not edit the file. `--dry-run` on backup and restore prints the copy plan and does not write. `--store` is rejected.

The file lives under `%APPDATA%\Adobe\Acrobat\<ver>\Security` on Windows and `~/Library/Application Support/Adobe/Acrobat/<ver>/Security` on macOS. `DC` is newer than a numbered folder. A higher number is newer (`2024`, then `11.0`, then `10.0`). Linux is not probed.

Trusted Identities in that address book are where AATL and EUTL certificates are loaded. Remove a root in **Preferences > Signatures > Identities & Trusted Certificates > More > Trusted Certificates**. Turn off the AATL and EUTL downloads in Trust Manager so an update does not add it back. On Windows, Windows Integration can also trust the Windows certificate store. The address book format is **unverified**. Listing address book entries read-only was not attempted. The file is treated as opaque. `list` reads the settings from `HKCU\Software\Adobe\{Adobe Acrobat,Acrobat Reader}\<ver>\Security\cDigSig` on Windows and from `~/Library/Preferences/com.adobe.Acrobat.Pro.plist` or `com.adobe.Reader.plist` on macOS (`/usr/bin/defaults read`). It does not write the registry or a plist. Paths and the full steps are in [Platforms](platforms.md#acrobat).

## Android

`--app android` is guide only. `trustprune apps` always reports `guide only` (PATH is `-`). There is no host store to probe, and trustprune does not write to a device.

`list --app android --file <dir> --allowlist <path>` prints a disable report on a pulled cacerts directory: see [list](#list). `add`, `allowlist`, `backup`, `restore`, `create`, and `connect` print Settings and adb steps and exit 1. They do not write. `add`, `allowlist`, `backup`, and `restore` also accept `--dry-run` and print the same steps. `--store` is rejected.

To disable a system CA, open **Settings > Security > Encryption & credentials > Trusted credentials**, tap the certificate, and choose Disable. To uninstall a user CA, use the User tab and Uninstall. On a rooted device or emulator, `adb pull` can copy `/system/etc/security/cacerts` or `/apex/com.android.conscrypt/cacerts` for the list report. Paths, network security config, and remaining follow-up are in [Platforms](platforms.md#android) and the [research note](research/android.md).

## Foxit

`--app foxit` detects Foxit PDF Editor and Foxit PDF Reader on Windows and macOS. When one is installed, `trustprune apps` reports `guide only`. `list`, `add`, `allowlist`, `backup`, `restore`, and `connect` print where Foxit trust comes from and exit 1. They do not read or write a Foxit trust list, and `--dry-run` does not plan a change.

Trust comes from the local Trusted Certificates list (**Protect > Sign & Certify > Trusted Certificates**), from Foxit Approved Trust List (FATL) downloads into that list, from European Union Trusted Lists (EUTL) downloads on Mac, and on Windows from the Windows certificate store when Windows Integration is on.

To remove a root, delete it or clear its trust in Trusted Certificates, then turn the download off so the next update does not add it back: **File > Preferences > Trust Manager**, clear **Load trusted certificates from Foxit server** (on by default, about every 28 days). On Mac, clear **Load trusted certificates from Foxit FATL / EUTL server** for both FATL and EUTL. On Windows, **File > Preferences > Signature** > **Windows Integration** trusts Windows store roots for signatures and certified documents. Removing a root there leaves the FATL copy in place.

The on-disk Trusted Certificates list is **unverified**. Paths, the admin policy, and the full steps are in [Platforms](platforms.md#foxit).

## Environment

| Variable | Meaning |
|----------|---------|
| `TRUSTPRUNE_JAVA_STOREPASS` | When set (non-empty after trim), used as the keystore password for every `keytool` call under `--app java` and for `create --format jks` or `pkcs12`. Custom values are passed with keytool `-storepass:env` (trimmed value in the child environment; sudo uses `--preserve-env`) so the password never appears in keytool or sudo argv and is not logged; the default `changeit` still uses `-storepass changeit`. Requires keytool `-storepass:env` (JDK 6+). Leading/trailing whitespace is stripped; whitespace-only falls back to `changeit`. No other passwords are guessed. There is no CLI flag for this. |

## list

Show trusted certificates from the platform store, an app store, a local file, or a PEM or DER certificate bundle downloaded from a URL. `--url` downloads that bundle. It does not look up a live site.

```bash
trustprune list
trustprune list --count
trustprune list --app java
trustprune list --app java --store /path/to/cacerts
trustprune list --app certifi --store /path/to/venv/.../cacert.pem
trustprune list --app poppler
trustprune list --app poppler --store /path/to/nssdb
trustprune list --app okular
trustprune list --app openssl --bundle /path/to/ca-bundle.pem
trustprune list --file example.crt
trustprune list --file testdata/certdata.txt.gz
trustprune list --file /tmp/android-cacerts
trustprune list --app android --file /tmp/android-cacerts --allowlist allowlist.yaml
# Downloads a PEM or DER bundle (Mozilla certdata.txt also works). Not a live TLS lookup.
trustprune list --url https://raw.githubusercontent.com/mozilla-firefox/firefox/main/security/nss/lib/ckfw/builtins/certdata.txt
trustprune list --ui web --allowlist allowlist.json
trustprune list --ui web --allowlist https://trustprune.com/downloads/allowlists/mozilla-included.yaml
```

| Flag | Meaning |
|------|---------|
| `--app <name>` | List from an application store |
| `--store <path>` | With `--app java`, `--app certifi`, or `--app poppler`: read that keystore, `cacert.pem`, or NSS directory instead of discovery. `list` output shows the chosen path |
| `--file <path>` | Without `--app`: list certificates from a local file (PEM, DER, Mozilla `certdata.txt`, or a gzip-compressed `.gz` of those; a gzip magic header is also accepted), or from a pulled Android cacerts directory of `<hash>.0` PEM or DER files, including `.crt`/`.cer`/`.der` exports of user-installed CAs. A file that cannot be parsed is an error that names the path (exit 1), including with `--count`, and does not print `0`. Cannot be combined with `--app`, except `list --app android --file <dir> --allowlist <path>`. Use `--store` to override a java, certifi, or poppler path |
| `--bundle <path>` | With `--app openssl`: list that PEM CA bundle instead of discovery |
| `--url <endpoint>` | Download a PEM or DER certificate bundle and list it (not a TLS site lookup). Mozilla `certdata.txt` is also accepted. JSON sets `store` to `url` and `path` to that URL, with userinfo redacted. To see a site's certificate chain, run `trustprune chain <host> --remote` |
| `--count` | Print only the number of certificates |
| `--format <fmt>` | Output format: `table` (default), `long`, `json`, `openssl`, `observatory`. `long` is the multi-line dump. An unknown name is a usage error (exit 2) whose message lists the valid formats |
| `--out <path>` | Write the formatted output to `<path>` instead of stdout for every `--format` and for `--count`. Stdout stays empty |
| `-v`, `--verbose` | On the default table, show the full fingerprint, serial, source or store path (the URL for `list --url`, with userinfo redacted), and hyphenated `NOT-BEFORE` / `NOT-AFTER`. Columns fit the longest header or cell and are separated by two spaces. When every row has the same path, print `PATH: <path>` above the table and omit the PATH column; mixed paths keep the column. DAYS stays numeric (including negative when expired). Also accepted globally (`trustprune -v list …`) |
| `--ui <type>` | Presentation: `cli` (default) or `web` (local page) |
| `--allowlist <path>` | With `--ui web`: local allowlist JSON or YAML, or an https URL, the same allowlist `allowlist --file` reads. Certificates that allowlist would keep start checked. Also required with `list --app android` (no `--ui web` needed): the report lists certificates that allowlist would not keep, most important first, with a short reason for each |
| `--sha256 <hex>` | With `--allowlist`: SHA-256 of the allowlist file bytes (64 hex digits, any case, or `sha256sum` output). Checked before the allowlist is parsed. A mismatch is `sha256 mismatch: want <expected> got <actual>` |
| `--signature <url or path>` | With `--allowlist`: detached minisign signature of the allowlist file bytes (local path or https URL). Requires `--pubkey`. Checked before the allowlist is parsed |
| `--pubkey <path or key>` | With `--signature`: minisign public key (local file or the key itself, not a URL) |

`list --app android --file <dir> --allowlist <path>` is a guide-only report. It reads a pulled Android cacerts or `cacerts-added` directory the same way `list --file <dir>` does, prints the certificates that allowlist (and the built-in denylist) would not keep, most important first, with a short reason for each, and prints short Settings and adb steps. Denylist and blocklist hits (built-in denylist, then Chromium, Mozilla, Apple, and CCADB removed) come first, then certificates not in the allowlist. User CAs (`.crt`/`.cer`/`.der` exports, or files in a `cacerts-added` directory) rank above system CAs, then earlier expiry. Ties break by subject, then SHA-256 fingerprint. trustprune does not write to the device. `--out` writes that report to a file and leaves stdout empty, the same as other `list` output. `--count` and a non-default `--format` are usage errors (exit 2). `add`, `allowlist`, `backup`, `restore`, `create`, and `connect` with `--app android` print the Settings and adb steps and exit 1 without writing. `--store` is rejected.

`list --ui web` shows each certificate on a local page with a keep switch. A checked switch means keep. With no `--allowlist`, every certificate starts checked. With `--allowlist`, a certificate starts checked when that allowlist would keep it. `--allowlist` may be a local YAML or JSON file or an https URL. `--sha256` is the SHA-256 of those file bytes (64 hex digits, or `sha256sum` output) and is checked before the page is built. A mismatch is `sha256 mismatch: want <expected> got <actual>`. `--signature` and `--pubkey` verify a detached minisign signature of those same bytes before the page is built (`--pubkey` is a local key file or the key itself, not a URL). **Download allowlist** builds a JSON allowlist of the checked certificates in the browser. The page is read-only and leaves the trust store unchanged. Apply the downloaded file with `trustprune allowlist --file`.

The header counts kept and dropped certificates. Search matches subject, issuer, or SHA256. Filters cover kept, dropped, expired, expiring within 90 days, and self-signed rows. Sort is by subject, NotAfter, or issuer. Select all and Select none change the keep switch for rows that are currently shown. Validity badges (Valid, Expiring soon, Expired, Not yet valid) are decided when the page is rendered.

In non-verbose table output, the DAYS cell shows `expired` when `NotAfter` is before now, `N!` when 0 ≤ days left < 90, and the plain day count otherwise. `-v` keeps numeric days on that same table. `--format json` keeps numeric `days` and adds boolean `expired`. `--format long` prints one multi-line block per certificate. Every `list` format (table, long, json, and the others) uses the same order: subject (case-insensitive), then SHA-256 fingerprint.

## backup

Capture the current trust store so you can restore later. Allowlisting refuses to run without a prior backup for that store.

```bash
trustprune backup
trustprune backup --app java
trustprune backup --app java --store /path/to/cacerts   # Java keystore override; backup records its source keystore
trustprune backup --app certifi --store /path/to/venv/.../cacert.pem
trustprune backup --app chrome
trustprune backup --app firefox
trustprune backup --app poppler
trustprune backup --app poppler --store /path/to/nssdb
trustprune backup --app openssl
trustprune backup --app openssl --bundle /path/to/ca-bundle.pem
trustprune backup --app certifi
```

| Flag | Meaning |
|------|---------|
| `--app <name>` | Back up that application's store instead of the platform |
| `--store <path>` | Java: back up that keystore instead of searching `JAVA_HOME`. Certifi: back up that `cacert.pem` instead of discovery. Poppler: back up that NSS directory (`-nssdir`) instead of discovery |
| `--bundle <path>` | With `--app openssl`: back up that PEM CA bundle instead of discovery. The backup records the path |
| `--dry-run` | Print what would be backed up; creates nothing |

See [Backup and restore](backup-restore.md) for where files land.

## restore

Revert to a backup. With no `--backup`, uses the latest backup for that store.

If no backup exists, `restore` (and `restore --dry-run`) refuses before writing anything and exits 1, for example `ERROR: no backup for linux in ~/.trustprune/linux; run: trustprune backup`. For app stores the hint is `trustprune backup --app <name>`.

For **java**, **certifi**, and **poppler**, `--store` is the store to restore into — the same meaning as on `backup` / `list` / `connect`. `--backup` selects the backup source. Each backup records the store path it came from; restoring into a different path is refused before any write unless `--force` is given.

For **openssl**, `--bundle <pem>` is the live PEM to restore into. `--backup` stays the backup source; automatic selection runs only when `--backup` is not set. PEM backups record that path; restoring a backup into a different PEM is refused before any write unless `--force`. Without `--bundle`, automatic restore follows discovery. A discovered PEM uses the newest backup recorded for that file, or a legacy backup with no `source`; a backup recorded for a different PEM is refused unless `--force`. A discovered cert directory ignores PEM backups that record a `source` and uses the newest remaining backup. Restore into a cert directory refuses a PEM bundle backup (one that has a `source` file), including an explicit `--backup`.

For **firefox**, **poppler**, **okular**, and Linux **chrome** (NSS), backup records the profile directory in a `source` file inside the backup. Restoring into a different profile is refused before any write unless `--force`. A backup with no recorded profile (an older release, or a legacy single file) is refused the same way unless `--force`. The `source` file is not copied onto the live profile and is never selected as a backup.

```bash
trustprune restore
trustprune restore --backup /path/to/backup
trustprune restore --app java
trustprune restore --app java --store /path/to/cacerts
trustprune restore --app java --store /path/to/cacerts --backup /path/to/cacerts-<ts>.bck
trustprune restore --app certifi --store /path/to/venv/.../cacert.pem
trustprune restore --app poppler --store /path/to/nssdb
trustprune restore --app chrome
trustprune restore --app openssl
trustprune restore --app openssl --bundle /path/to/ca-bundle.pem
trustprune restore --app openssl --bundle /path/to/ca-bundle.pem --backup ~/.trustprune/openssl/<timestamp>
trustprune restore --app java --dry-run
```

| Flag | Meaning |
|------|---------|
| `--app <name>` | Restore that application's store |
| `--store <path>` | Java/certifi/poppler: store to restore into |
| `--backup <path>` | Explicit backup to restore from (directory or file, depending on the store) |
| `--bundle <path>` | With `--app openssl`: PEM CA bundle to restore into. `--backup` remains the backup source |
| `--force` | Allow restoring a backup into a different store path than it was taken from (java, certifi, poppler, openssl `--bundle`, and NSS firefox/chrome/okular). Also allows an NSS backup that has no recorded profile. |
| `--dry-run` | Print the plan without writing |


## Darwin `/etc/ssl/cert.pem` (`--app ssl`)

On macOS, CLI tools (curl, git, python3, …) trust `/etc/ssl/cert.pem` and ignore Apple keychain blocks. Manage that bundle with `--app ssl`:

```bash
trustprune list --app ssl
trustprune backup --app ssl
trustprune allowlist --app ssl --file allowlist.yaml --dry-run
trustprune allowlist --app ssl --file allowlist.yaml
trustprune restore --app ssl
trustprune restore --app ssl --backup ~/Library/trustprune/ssl/<timestamp>/cert.pem
```

Writes stage into a sibling temp dir, copy the live file aside to `.restore-old`, then rename over the destination (sudo when needed); a leftover `.restore-old` is refused rather than deleted. An empty allowlist result is refused. After a successful write, trustprune records a content hash; if a later macOS update restores Apple's copy, `list --app ssl` prints a one-line warning. Re-apply with `backup --app ssl` then `allowlist --app ssl --file …`, or `restore --app ssl` to put back your pruned backup.

PEM parsing uses Go's `x509.ParseCertificate`, then a `cryptobyte` fallback that reads subject, issuer, serial, and validity (so Apple's negative-serial roots list and allowlist like any other cert, without GODEBUG). Blocks that still cannot be read print a warning to stderr naming the PEM block and are skipped for list; `add` and `allowlist` write those raw PEM blocks back unchanged in their original order.


## Python certifi (`--app certifi`)

Python's [certifi](https://github.com/certifi/python-certifi) package ships a Mozilla CA bundle (`cacert.pem`) used by requests and many other libraries. Manage that bundle with `--app certifi`.

Path discovery (first existing wins):

1. `--store <cacert.pem>` on `list`, `backup`, `connect`, `restore`, `add`, and `allowlist` (one bundle per venv)
2. `python3 -c 'import certifi; print(certifi.where())'` (then `python`)
3. The same probe against `pip._vendor.certifi`
4. Common `site-packages/certifi/cacert.pem` fallbacks

On `add`, `--file` is the certificate to import. On `allowlist`, `--file` is the allowlist YAML/JSON. Pass `--store` to target a venv bundle for those commands. For `restore`, pass `--store` as the venv's `cacert.pem` (same as `backup` / `list`); use `--backup` to pick a specific backup.

Some Linux distros patch certifi so `where()` returns the system CA bundle (for example `/etc/ssl/certs/ca-certificates.crt`). That path is still managed as a PEM file. Upstream installs keep a dedicated `cacert.pem` beside the package.

```
trustprune list --app certifi
trustprune list --app certifi --store /path/to/venv/lib/python3.12/site-packages/certifi/cacert.pem
trustprune backup --app certifi
trustprune backup --app certifi --store /path/to/venv/lib/python3.12/site-packages/certifi/cacert.pem
trustprune add --file cert.pem --app certifi --store /path/to/cacert.pem
trustprune allowlist --app certifi --store /path/to/venv/.../cacert.pem --file allowlist.yaml --dry-run
trustprune allowlist --app certifi --store /path/to/venv/.../cacert.pem --file allowlist.yaml
trustprune restore --app certifi
trustprune restore --app certifi --store /path/to/venv/lib/python3.12/site-packages/certifi/cacert.pem
```

Writes reuse the same atomic sibling-temp install as `--app ssl` / `--app openssl` (copy aside to `.restore-old`, refuse a leftover aside, refuse an empty allowlist result). Restore with no backup refuses before any filesystem write.

## OpenSSL CA bundles (`--app openssl`)

curl, git, and the OpenSSL libraries read a PEM bundle or a hashed cert directory — not the Darwin keychain and not always the same file as the Linux platform store. Manage that location with `--app openssl`.

Path resolution uses the first existing of:

1. `SSL_CERT_FILE` (if set)
2. `CURL_CA_BUNDLE` (if set)
3. LibreSSL, when it is present, ahead of OpenSSL paths. Present means a Homebrew LibreSSL binary exists (`/usr/local/opt/libressl/bin/openssl` on Intel, `/opt/homebrew/opt/libressl/bin/openssl` on Apple Silicon) or `openssl version` starts with `LibreSSL`. Darwin `/usr/bin/openssl` is Apple's LibreSSL and does not count. Candidates, in order: `/usr/local/etc/libressl/cert.pem`, `/opt/homebrew/etc/libressl/cert.pem`, `/usr/local/etc/libressl/certs`, `/opt/homebrew/etc/libressl/certs`, then the OpenBSD/Alpine bundle `/etc/ssl/cert.pem`.
4. Distro/Homebrew OpenSSL defaults (`/etc/ssl/certs/ca-certificates.crt`, `/etc/pki/tls/certs/ca-bundle.crt`, Homebrew `.../etc/openssl/certs` and `openssl@3` / `openssl@1.1` variants)
5. `git config --get http.sslCAInfo` (best-effort; git errors are ignored)

Darwin `/etc/ssl/cert.pem` is **not** selected as an openssl default. Use `--app ssl` for that file.

```bash
trustprune list --app openssl
trustprune list --app openssl --bundle /path/to/ca-bundle.pem
trustprune chain --app openssl --bundle /path/to/ca-bundle.pem --file leaf.pem
trustprune chain --app openssl --bundle /path/to/ca-bundle.pem leaf.pem
trustprune backup --app openssl
trustprune backup --app openssl --bundle /path/to/ca-bundle.pem
trustprune allowlist --app openssl --file allowlist.yaml --dry-run
trustprune allowlist --app openssl --file allowlist.yaml
trustprune allowlist --app openssl --file allowlist.yaml --bundle /path/to/ca-bundle.pem
trustprune restore --app openssl
trustprune restore --app openssl --bundle /path/to/ca-bundle.pem
```

`--bundle <pem>` skips path discovery and must name an existing PEM file. It does not select a hashed cert directory. On allowlist, `--file` is still the allowlist. On restore, `--backup` is the backup source; a backup taken from a different PEM is refused unless `--force`.

A PEM file is rewritten like `--app ssl` (atomic install, refuse empty bundle). Backups of a PEM file record its path in `source`. A cert directory lists `*.pem`/`*.crt`, backups mirror the directory, remove deletes non-matching cert files, and rehash runs after add (required) and after remove/restore when a tool is present. LibreSSL runs `<openssl> certhash <dir>` with the binary above. Otherwise `c_rehash` is used (`/usr/bin/c_rehash`, Homebrew openssl prefixes). Pass the PEM file to `--bundle` when you want that file rather than the discovered directory.


## pdfsig / poppler (`--app poppler`)

pdfsig and other poppler NSS users trust an NSS database. `--app poppler` uses that database. `list` shows the chosen path (verbose table `PATH`, and JSON `path`). `apps` prints the same path in the PATH column.

`--store <dir>` is poppler's `-nssdir` and skips discovery. Otherwise the directory is chosen the same way as poppler's `NSSSignatureConfiguration::setNSSDir`: the newest Firefox profile whose name contains `default` and that has a regular non-empty `cert9.db` (a cert8-only profile is skipped) when `certutil -L -d sql:<dir>` succeeds, or when certutil cannot be found or run. A profile that fails that probe falls back to `~/.pki/nssdb` (a failed Firefox open does not try `/etc/pki/nssdb`). With no cert9 profile, `/etc/pki/nssdb` is used when it contains a regular non-empty `cert9.db` and the probe succeeds or certutil cannot be found or run; otherwise `~/.pki/nssdb`. `apps` marks poppler found only when that chosen directory contains `cert9.db`. `list` still shows the chosen path.

Backup, restore, add, and allowlist use the same NSS code as `--app firefox`. Allowlist refuses when this directory has no backup of its own and the newest backup was recorded for a different directory, unless `--force`. List includes built-in `libnssckbi` roots. A root that exists only in that module is distrusted with a `p,p,p` override on the internal token.

```bash
trustprune list --app poppler
trustprune list --app poppler -v
trustprune list --app poppler --store /path/to/nssdb
trustprune backup --app poppler
trustprune backup --app poppler --store /path/to/nssdb
trustprune allowlist --app poppler --store /path/to/nssdb --file allowlist.yaml --dry-run
```

### Evince and Papers

Evince and Papers are not `--app` values.

**Papers** ([pps-poppler.c](https://gitlab.gnome.org/GNOME/papers/-/blob/18958ac9397bed07bb6c9a1d62331422c9fc0d95/libdocument/backend/pdf/pps-poppler.c), checked at `18958ac9`) validates signatures with poppler and leaves the NSS directory unset. The effective backend is `POPPLER_SIGNATURE_BACKEND` when set, otherwise poppler's compile-time default (NSS when that backend was built first; [CryptoSignBackend.cc](https://gitlab.freedesktop.org/poppler/poppler/-/blob/master/poppler/CryptoSignBackend.cc)). When the effective backend is NSS, `--app poppler` is the host store Papers uses, including list, backup, allowlist, and restore. A sandboxed Papers install (for example Flatpak) can use a different `XDG_CONFIG_HOME` and therefore a different NSS database than host `--app poppler`; confirm that install's database path before relying on pruning. When the effective backend is GPG, Papers reads `$GNUPGHOME` (default `~/.gnupg`; [GPGMECryptoSignBackend.cc](https://gitlab.freedesktop.org/poppler/poppler/-/blob/master/poppler/GPGMECryptoSignBackend.cc)). That store is report-only, the same as poppler's GPG backend: trustprune does not list or prune `trustlist.txt`.

**Evince** ([ev-poppler.c](https://gitlab.gnome.org/GNOME/evince/-/blob/e822030005f22231052667d51398a84327004924/backend/pdf/ev-poppler.c) and [ev-form-field.c](https://gitlab.gnome.org/GNOME/evince/-/blob/e822030005f22231052667d51398a84327004924/libdocument/ev-form-field.c), `main` at `e822030`) maps signature form fields and has no signature-validation call ([bug 614929](https://bugzilla.gnome.org/show_bug.cgi?id=614929)). There is no trust store to prune. If Evince adds validation later, reopen [issue #391](https://github.com/adamdecaf/trustprune/issues/391).

The [platforms page](platforms.md) has the same coverage with the source links.

## Okular (`--app okular`)

Okular's poppler generator trusts an NSS database or a GPG (gpgsm) store. `--app okular` reads `okular-generator-popplerrc` group `[Signatures]`. It merges matching files from `$XDG_CONFIG_DIRS` (default `/etc/xdg` on Unix) with the user file last (`$XDG_CONFIG_HOME/okular-generator-popplerrc` when `XDG_CONFIG_HOME` is an absolute path, otherwise `~/.config/okular-generator-popplerrc`), so the user file overrides each key. That lookup follows KConfig convention. Flatpak, Snap, and other sandboxed config locations are **unverified**.

The effective signature backend is `SignatureBackend` if that key is set, otherwise `POPPLER_SIGNATURE_BACKEND`, otherwise NSS, which is poppler's usual compiled default (NSS is built first). A prebuilt trustprune binary cannot read the host poppler compile-time default; if that default is GPG, set `SignatureBackend` or `POPPLER_SIGNATURE_BACKEND`. Keys marked `[$e]` are environment-expanded; if `SignatureBackend` cannot be expanded to NSS or GPG, trustprune refuses NSS operations. `list` shows which DB or backend was used (verbose table `PATH`, JSON `path`; a GPG backend is reported in the error and as PATH `GPG`).

When the backend is **NSS**: `UseDefaultCertDB=false` uses `DBCertificatePath` as the NSS directory. A `file://` URL is converted to a filesystem path, including percent-encoded characters. Otherwise the directory is the same lookup as [`--app poppler`](#pdfsig--poppler---app-poppler). `apps` marks okular found only when that directory contains a regular non-empty `cert9.db`. Backup, restore, add, and allowlist use the same NSS code as poppler, including the recorded-profile restore and allowlist guards.

When the backend is **GPG**: `list`, `add`, `allowlist`, `backup`, `restore`, and `connect` report that the backend is GPG and exit 1 without reading or writing a gpgsm store. `apps` shows `guide only` with PATH `GPG`. `--dry-run` does not plan a change.

```bash
trustprune list --app okular
trustprune list --app okular -v
trustprune backup --app okular
trustprune allowlist --app okular --file allowlist.yaml --dry-run
```

## allowlist

Distrust certificates that are **not** on the allowlist. Requires `--file` and a prior backup. With no backup, `allowlist` (and `allowlist --dry-run`) refuses before writing anything and exits 1, for example `ERROR: no backup for openssl in ~/.trustprune/openssl; run: trustprune backup --app openssl` (platform stores suggest `trustprune backup`). For firefox, poppler, okular, and Linux chrome, a newest backup recorded for a different NSS directory does not count as a backup of this directory. The error tells you to run `trustprune backup` for this store. `--force` allows the allowlist anyway. Always applies Chromium's certificate blocklist, Mozilla's `certdata.txt` blocklist, the CCADB Mozilla Removed CA Certificate Report (except removals that are only expiry or a voluntary / CA-requested withdrawal), and a built-in denylist of known-distrusted roots and their public keys, including the compromised eMudhra G3 intermediates, so those CAs are never kept (cannot be disabled). `gen-allowlist` skips denylisted CAs and prints a `NOTE:` for each one.

Allowlist files are YAML or JSON with optional `fingerprints` (SHA-256) and `countries` (ISO 3166-1 alpha-2). `--file` may be a local path or an https URL. `http://` and any other scheme are rejected. The download is capped at 1 MiB and uses a 30 second timeout. Redirects are followed only when they stay on https. `--sha256` is optional and is the SHA-256 of the allowlist file bytes (64 hex digits, any case, or `sha256sum` output). A mismatch is an error (`sha256 mismatch: want <expected> got <actual>`) and the allowlist is not parsed. `--signature` is an optional detached minisign signature of those same bytes, as a local path or an https URL, and requires `--pubkey`, a local minisign public key file or the key itself (not a URL). A missing, mismatched, or invalid signature is an error and the allowlist is not parsed. Signature downloads use the same https rules, 30 second timeout, redaction, and 1 MiB cap as `--file`. `--signature` and `--pubkey` must both be set or both omitted.

```bash
trustprune allowlist --file allowlist.yaml
trustprune allowlist --file https://trustprune.com/downloads/allowlists/mozilla-included.yaml --dry-run
trustprune allowlist --file https://trustprune.com/downloads/allowlists/mozilla-included.yaml
trustprune allowlist --file allowlist.yaml --signature allowlist.yaml.minisig --pubkey minisign.pub
trustprune allowlist --file allowlist.json --app java
trustprune allowlist --app java --store /path/to/cacerts --file allowlist.yaml
trustprune allowlist --file allowlist.yaml --app openssl --bundle /path/to/ca-bundle.pem
trustprune allowlist --file allowlist.yaml --dry-run
trustprune allowlist --file allowlist.yaml --dry-run -v
trustprune allowlist --file allowlist.yaml --count
trustprune allowlist --file allowlist.yaml --dry-run --count
```

`--dry-run` prints the plan and does not change the store. Kept certificates are listed by subject and SHA-256. Unparsable PEM blocks that would be kept are listed too, as `unparsable PEM block (N bytes)`, and are not included in the counts. The output ends with `dry-run: no changes made` and `dry-run: N kept, M removed`, plus `, K unmatched` when fingerprints in the allowlist equal no certificate in the store. `-v` / `--verbose` adds per-certificate remove and keep lines after that list (`remove`, `distrust`, `remove … from <path>`, and `remove … (alias …)`, depending on the store) and lists those unmatched fingerprints under `Unmatched allowlist entries:`, in file order, once each. Those detail lines and the unmatched list are omitted by default. Every command accepts `-v`/`--verbose`; among dry-run commands, only `allowlist` uses it for extra details. `add`, `backup`, and `restore` keep their existing dry-run output.

Fingerprints in the allowlist that equal no certificate in the store are counted in that summary as `, K unmatched`. The count is omitted when every fingerprint matches. `-v` / `--verbose` also lists them under `Unmatched allowlist entries:`, in file order, once each. On a dry-run the list is printed above the closing lines, so the summary stays last. A real run prints `Allowlist completed successfully`, then that list when `-v` is set, then a final line `N removed, M kept` or `N removed, M kept, K unmatched`. `N` is how many certificates were removed or distrusted. `M` is how many were kept. Unparsable PEM blocks are in neither number.

`--count` prints only `N`, one integer on stdout. It does not print the plan, the unmatched list, or the success line. The allowlist is still applied unless `--dry-run` is set. Exit codes are unchanged. There is no `--format json` for `allowlist`.

```text
dry-run: would remove certificates from certifi at /tmp/cacert.pem
Kept:
  CN=Keep Me (SHA256 abcd...)
  CN=Also Keep (SHA256 efgh...)
  unparsable PEM block (12 bytes)
dry-run: no changes made
dry-run: 2 kept, 3 removed, 1 unmatched
```

```text
Allowlist completed successfully
3 removed, 2 kept, 1 unmatched
```

```text
3
```

| Flag | Meaning |
|------|---------|
| `--file <path>` | **Required.** Local allowlist YAML or JSON, or an https URL |
| `--sha256 <hex>` | SHA-256 of the allowlist file bytes (64 hex digits, any case, or `sha256sum` output). Checked before the allowlist is parsed. A mismatch is `sha256 mismatch: want <expected> got <actual>`. Requires `--file` |
| `--signature <url or path>` | Detached minisign signature of the allowlist file bytes, a local path or an https URL. Checked before the allowlist is parsed. Requires `--file` and `--pubkey` |
| `--pubkey <path or key>` | Minisign public key for `--signature`: a local file or the key itself, not a URL. Requires `--signature` |
| `--store <path>` | With `--app java`, `--app certifi`, or `--app poppler`: operate on that keystore, `cacert.pem`, or NSS directory. Independent of `--file` |
| `--app <name>` | Apply against an application store |
| `--bundle <path>` | With `--app openssl`: PEM CA bundle to edit instead of discovery. Requires a backup recorded for that file |
| `--dry-run` | Print the plan without writing. Lists kept certificates, then ends with `dry-run: no changes made` and `dry-run: N kept, M removed`, plus `, K unmatched` when fingerprints in the file matched nothing |
| `--count` | Print only the number of certificates removed or untrusted |
| `--force` | Allow an NSS allowlist when the latest backup was taken from a different directory and this directory has no backup of its own |
| `-v`, `--verbose` | With `--dry-run`, also print per-certificate remove and keep details and list unmatched fingerprints under `Unmatched allowlist entries:`. A real run lists unmatched fingerprints the same way. No effect with `--count` |

Example YAML:

```yaml
fingerprints:
  - "050cf9fa95e40e9bddedaeda6961f6168c1279c4660172479cdd51ab03cea62c"
countries:
  - "US"
  - "JP"
```

## gen-allowlist

Build an allowlist from hostnames, platform presets, browser history, and/or a URL list file. When generation runs, the default platform preset for this OS is included unless you pass `--no-presets` or an explicit `--presets` list. Target another OS with `--presets linux` (or `darwin` / `windows`). Apply the result with `trustprune allowlist --file …` (optionally `--app openssl --bundle` for a PEM bundle). To write a PEM bundle or Java truststore from a store and leave that store unchanged, use [`trustprune create`](#create). Generation verifies chains against the system trust store, not roots from a target PEM bundle; CAs present only in that bundle are not discovered.

The summary table uses headers `CA`, `SHA256-FINGERPRINT`, `COUNT`, and `EXAMPLE-DNS-NAMES`, with two-space column gaps, so a CA name that contains spaces stays in the CA column. The fingerprint column shows the first 16 characters; `-v` prints the full fingerprint. JSON allowlists use a lowercase `fingerprints` key. Files with the older `"Fingerprints"` key are still read. YAML uses `fingerprints` as well.

```bash
trustprune gen-allowlist --out allowlist.yaml --hosts example.com,api.example.com
trustprune gen-allowlist --out allowlist.yaml --hosts example.com --presets linux
trustprune gen-allowlist --out allowlist.yaml --presets linux
trustprune gen-allowlist --out allowlist.yaml --from firefox
trustprune gen-allowlist --out allowlist.yaml --hosts example.com --no-presets
trustprune gen-allowlist --out allowlist.yaml --from browsers
trustprune gen-allowlist --out allowlist.yaml --from chrome,firefox
trustprune gen-allowlist --out allowlist.yaml --file urls.txt
trustprune gen-allowlist --out allowlist.yaml --hosts example.com -v
trustprune gen-allowlist --out allowlist.yaml --hosts example.com --no-presets --stats
```

| Flag | Meaning |
|------|---------|
| `--out <path>` | **Required.** Where to write the allowlist. The extension picks the format: `.json` writes JSON, `.yaml` or `.yml` writes YAML |
| `--hosts <hosts>` | Comma-separated hostnames or https URLs to include (`example.com` becomes `https://example.com`) |
| `--presets <names>` | Comma-separated preset names to include (default: this OS platform preset). Names: `apple`, `apt`, `darwin`, `linux`, `macos`, `macos-update`, `windows`, `windows-update` |
| `--no-presets` | Do not include the default platform preset |
| `--from <types>` | Comma-separated sources: `browser` / `browsers`, `chrome`, `firefox`, `safari`, `file` |
| `--file <path>` | Newline- or comma-delimited URLs (plain text or gzip CSV-style “top N” lists) |
| `-v`, `--verbose` | Show full fingerprints in the summary table. The default prints the first 16 characters |
| `--stats` | Print connection and timing stats to stderr after hosts are dialed. The summary table is unchanged. The block lists URLs read, unique hosts, TLS attempts, successes, and failures (failed hosts, at most 20), hosts answered from a CA already recorded for that name, total and average DNS and connect+TLS times, unique roots, and wall time. Omitted when `--stats` is not set |

Without `--out`, `gen-allowlist` prints `ERROR: required flag --out not set` and exits with status 2. With `--out` but none of `--from`, `--file`, `--hosts`, or `--presets`, it prints usage and exits 0. `--stats` alone does not count as a source. `--presets` and `--no-presets` together are a usage error (exit 2).

## create

Write the trusted certificates that match an allowlist. The platform store is the default. `--app` selects an application store. `--store` overrides java, certifi, and poppler. `--bundle` with `--app openssl` reads that PEM. The command only reads that store: it does not add, remove, back up, or restore. Guide-only apps return their existing guide error and write nothing.

`--file` is the allowlist (YAML or JSON), a local path or an https URL, the same allowlist `allowlist --file` reads. `--sha256` is optional and is the SHA-256 of those file bytes (64 hex digits, or `sha256sum` output). It is checked before the allowlist is parsed. A mismatch is `sha256 mismatch: want <expected> got <actual>`. `--signature` is an optional detached minisign signature of those bytes (a local path or an https URL) and requires `--pubkey`, a local minisign public key file or the key itself (not a URL). Both are checked before the allowlist is parsed. Matching uses that file's fingerprints and countries, including the built-in denylist and the Chromium, Mozilla, Apple, and CCADB removed-CA blocklists, so a denied certificate is left out even when the file names it. `--format` accepts `pem` (the default), `jks`, or `pkcs12`. Any other value is a usage error (exit 2) that names those formats. Omit `--out` with `pem` to write the bundle to stdout. With `--out`, stdout stays empty and the file mode is `0644`. `jks` and `pkcs12` require `--out` (exit 2 if it is omitted). They write a Java truststore that contains exactly the matching certificates. `keytool` creates it (`JAVA_HOME/bin`, then `PATH`, then `~/.local/bin`). A missing `keytool` is an error (exit 1) and no file is written. Each alias is `sha256-` plus the certificate's SHA-256 fingerprint, so aliases are stable and unique. The truststore is written to a temp file in the destination directory and renamed into place. The source store is not modified.

The truststore password defaults to Java's `changeit`. Set `TRUSTPRUNE_JAVA_STOREPASS` to override it (trimmed; whitespace-only falls back to `changeit`). A custom password is passed to `keytool` with `-storepass:env`, not argv, and it is not logged. There is no password flag. `keytool` is non-interactive (`-noprompt`, no stdin) and each call has a timeout.

An allowlist that matches no trusted certificate fails with exit 1 (`no certificates matched the allowlist; refusing to write an empty output`) and creates no output file. That matches `allowlist` refusing to leave a bundle empty. `--out` set to the store path, or to a file inside a directory store, is refused before any write.

```bash
trustprune create --file allowlist.yaml
trustprune create --file https://trustprune.com/downloads/allowlists/mozilla-included.yaml --out mozilla-roots.pem
trustprune create --file allowlist.yaml --out ca-bundle.pem
trustprune create --file allowlist.yaml --format pem --out ca-bundle.pem
trustprune create --file allowlist.yaml --format jks --out trusted.jks
trustprune create --file allowlist.yaml --format pkcs12 --out trusted.p12
trustprune create --file allowlist.yaml --app java --out java-cas.pem
trustprune create --file allowlist.yaml --app certifi --store /path/to/cacert.pem --out kept.pem
trustprune create --file allowlist.yaml --app poppler --store /path/to/nssdb --out kept.pem
trustprune create --app openssl --file allowlist.yaml --bundle /path/to/ca-bundle.pem --out kept.pem
```

| Flag | Meaning |
|------|---------|
| `--file <path>` | **Required.** Local allowlist YAML or JSON, or an https URL |
| `--sha256 <hex>` | SHA-256 of the allowlist file bytes (64 hex digits, any case, or `sha256sum` output). Checked before the allowlist is parsed. A mismatch is `sha256 mismatch: want <expected> got <actual>`. Requires `--file` |
| `--signature <url or path>` | Detached minisign signature of the allowlist file bytes, a local path or an https URL. Checked before the allowlist is parsed. Requires `--file` and `--pubkey` |
| `--pubkey <path or key>` | Minisign public key for `--signature`: a local file or the key itself, not a URL. Requires `--signature` |
| `--app <name>` | Read an application store. Omit it to read the platform store |
| `--store <path>` | With `--app java`, `--app certifi`, or `--app poppler`: read that keystore, `cacert.pem`, or NSS directory |
| `--bundle <path>` | With `--app openssl`: read that PEM CA bundle. The file is left unchanged |
| `--format <name>` | Output format: `pem` (default), `jks`, or `pkcs12`. `jks` and `pkcs12` write a Java truststore through `keytool`. Another name is a usage error (exit 2) |
| `--out <path>` | Write the PEM bundle or Java truststore to this path (mode `0644`). Stdout stays empty. **Required** for `jks` and `pkcs12`. Omit it with `pem` to write the bundle to stdout |

## chain

Show the certificate chain for a local file or a URL. The selected store is only listed. Nothing is added, removed, or backed up.

`--file` is a PEM bundle or one DER certificate. Without `--url`, the leaf is chosen from that file (the certificate that does not sign another certificate in the file). `--url` is a host or `https` URL; a bare host is treated as `https`. Explicit `http://` is rejected. One positional argument replaces `--file` or `--url`. If it names an existing regular file, it is read like `--file`. Otherwise it is a host or URL, like `--url`. Combining that argument with `--file` or `--url` is a usage error (exit 2). More than one positional argument is a usage error. The leaf for a URL is the first certificate in the file or store that matches that host. `--url` implies `--remote`: it dials that host only when no local leaf is found. A positional URL still needs `--remote` to dial. The dial uses a 30 second timeout and does not treat the server as trusted.

The default table uses trusted, in-date certificates that are not on the offline Chromium, Mozilla, Apple, or CCADB removed-CA blocklists. Columns match `connect -v`: INDEX, SUBJECT, ISSUER, NOT-AFTER, SHA256, LABELS. SHA256 is the 16-character prefix. `-v` / `--verbose` prints the full 64-character SHA-256 in that table. JSON always uses the full fingerprint. SUBJECT is the display name only. LABELS is `-` when none apply. Several labels are joined with a comma and no spaces (`untrusted,expired`). The leaf is shown even when it is not in the store. On a `--remote` lookup, intermediates the server presents are included when they chain to a trusted root, and are not labeled `untrusted`. Other certificates outside the store, expired or not-yet-valid certificates, and blocklisted certificates are omitted unless `--untrusted`, `--expired`, or `--revoked` is set. `--all` is those three flags together. It does not enable `--remote`. Included certificates are labeled `untrusted`, `expired`, `not yet valid`, and/or `blocklisted`. `--expired` includes a certificate whose `NotAfter` is in the past and a certificate whose `NotBefore` is in the future. `--revoked` matches the embedded Chromium, Mozilla, Apple, and CCADB removed-CA blocklists. It does not use OCSP or CRLs.

An incomplete chain prints a note and names the flags that would include a skipped issuer. That note is text only.

`--format json` prints one object. `chain` is leaf-first. Each certificate has `index`, `subject` (the display name), `issuer`, `not_after` (UTC RFC 3339), the full `sha256` fingerprint, and `labels` (`untrusted`, `expired`, `not yet valid`, `blocklisted`). `labels` is an empty array when none apply. `complete` is always present: `true` when the chain reaches a self-signed certificate, `false` when it does not. When the walk stopped because no issuer was found, `missing_issuer` is the issuer name of the last certificate included (the same string as that certificate's `issuer`). Cycle and too-long chains omit `missing_issuer`. `stopped_at` is the display name of the last certificate found. It is set whenever `complete` is false and omitted when `complete` is true. JSON has no `incomplete` field.

Exit status is 0 when the chain is complete and 1 when `complete` is false. The report goes to stdout and is not an `ERROR:` line. A file that cannot be read, a bad URL, and other failures exit 1 with `ERROR:` on stdout.

```bash
trustprune chain --file leaf.pem --app openssl --bundle /path/to/ca-bundle.pem
trustprune chain leaf.pem --app openssl --bundle /path/to/ca-bundle.pem
trustprune chain --file leaf.pem --app openssl --bundle /path/to/ca-bundle.pem -v
trustprune chain --file leaf.pem --untrusted
trustprune chain --file leaf.pem --expired
trustprune chain --file leaf.pem --revoked
trustprune chain --file leaf.pem --all
trustprune chain --url example.com
trustprune chain example.com --remote
trustprune chain --url https://example.com --untrusted
trustprune chain --url example.com --format json
trustprune chain --app java --store /path/to/cacerts --file leaf.pem
trustprune chain --app java --store /path/to/cacerts leaf.pem
```

```text
INDEX  SUBJECT       ISSUER      NOT-AFTER   SHA256    LABELS
0      leaf.example  ca.example  2027-06-01  <16 hex>  -
1      ca.example    ca.example  2027-06-01  <16 hex>  -
```

```json
{
  "chain": [
    {"index": 0, "subject": "leaf.example", "issuer": "ca.example", "not_after": "2027-06-01T00:00:00Z", "sha256": "<64 hex>", "labels": []},
    {"index": 1, "subject": "ca.example", "issuer": "ca.example", "not_after": "2027-06-01T00:00:00Z", "sha256": "<64 hex>", "labels": []}
  ],
  "complete": true
}
```

| Flag | Meaning |
|------|---------|
| `--file <path>` | Certificate file (PEM or DER) to show a chain for, instead of a positional path |
| `--url <url>` | Host or URL to show a chain for, instead of a positional URL. A bare host is treated as `https`. Implies `--remote`. A positional URL still needs `--remote` to dial |
| `--app <name>` | Use that application's store to decide which certificates are trusted |
| `--store <path>` | With `--app java`, `--app certifi`, or `--app poppler`: load that store instead of discovery |
| `--bundle <path>` | With `--app openssl`: read that PEM CA bundle. The file is left unchanged |
| `--untrusted` | Include certificates that are not in the trusted store |
| `--expired` | Include expired and not-yet-valid certificates |
| `--revoked` | Include certificates on the offline Chromium, Mozilla, Apple, and CCADB removed-CA blocklists (labeled `blocklisted`; no OCSP or CRL) |
| `--all` | Include untrusted, expired, not-yet-valid, and blocklisted certificates |
| `--remote` | Look up the TLS chain when no local chain is found (30s timeout). Implied by `--url` |
| `--format` | `text` (default) or `json`. An unknown name is a usage error (exit 2) whose message lists `json` and `text` |
| `-v`, `--verbose` | Print the full 64-character SHA-256 in the text table. The default table uses a 16-character prefix. JSON is unchanged |

## add

Add certificate(s) from a file into the platform or an app store.

```bash
trustprune add --file cert.pem
trustprune add --file cert.pem --app java
trustprune add --file cert.pem --app certifi --store /path/to/cacert.pem
trustprune add --file cert.pem --app java --store /path/to/cacerts
trustprune add --file cert.pem --app poppler --store /path/to/nssdb
```

| Flag | Meaning |
|------|---------|
| `--file <path>` | **Required.** Certificate file to import. `--store` alone is not a certificate path |
| `--store <path>` | With `--app java`, `--app certifi`, or `--app poppler`: import into that keystore, `cacert.pem`, or NSS directory |
| `--app <name>` | Target an application store |
| `--dry-run` | Print the plan without writing |

## connect

Attempt an HTTPS connection using the platform store or an app store. Useful after allowlist or restore.

A bare host is accepted (`trustprune connect google.com` is `https://google.com`). An explicit `http://` URL is rejected.

```bash
trustprune connect google.com
trustprune connect https://example.com
trustprune connect -v https://example.com
trustprune connect --format json google.com
trustprune connect --app java https://example.com
trustprune connect --app java --store /path/to/cacerts https://example.com
trustprune connect --app certifi --store /path/to/venv/.../cacert.pem https://example.com
trustprune connect --app poppler --store /path/to/nssdb https://example.com
trustprune connect --url https://example.com
```

Text output (the default) is one line:

```text
ok https://google.com tls1.3 root=<name> sha256=<16 hex> leaf-expires=<YYYY-MM-DD>
```

`sha256` is the first 16 hex characters of the root. `leaf-expires` is the leaf certificate's `NotAfter` in UTC (`YYYY-MM-DD`). `-v` prints the verified chain after that line (INDEX, SUBJECT, ISSUER, NOT-AFTER, SHA256, LABELS). LABELS is `-` on every row of a verified chain. `--format json` prints one object and ignores `-v`:

```json
{
  "url": "https://google.com",
  "tls_version": "tls1.3",
  "verified": true,
  "root": {"subject": "<name>", "sha256": "<64 hex>"},
  "leaf": {"subject": "<leaf>", "not_after": "<RFC 3339 UTC>"},
  "chain": [
    {"subject": "<leaf>", "issuer": "<issuer>", "not_after": "<RFC 3339 UTC>", "sha256": "<64 hex>"}
  ]
}
```

`chain` is leaf-first and includes the trust anchor. JSON `sha256` values are the full fingerprint. `verified` is true after a successful handshake. `not_after` is UTC RFC 3339. Text `leaf-expires` and the table `NOT-AFTER` column stay `YYYY-MM-DD`.

A failure is still one short `ERROR:` line, and the exit status stays 1. `-v` also prints the chain the server presented when verification fails (unknown authority, an expired certificate, a hostname mismatch, and other certificate verification errors). The chain is taken from that failed handshake. If the error has no certificates, a second handshake may be tried; if that is also refused, `-v` prints only the `ERROR:` line. A refused connection or other dial error stays the short line only.

The presented chain is leaf first, taken from the server's TLS certificates. Columns match the success table: INDEX, SUBJECT, ISSUER, NOT-AFTER, SHA256, LABELS. SUBJECT is the display name only. A certificate whose SHA-256 is not in the selected store has `not in store` in LABELS. LABELS is `-` when the certificate is in the store. The add hint is printed only when verification fails with an unknown authority. It names `trustprune add --file` and the full SHA-256 of the last missing certificate (closest to the root). If connect was run with `--app` or `--store`, the hint includes those flags so the CA is added to the same store. `allowlist` only keeps or removes certificates already in the store; it does not add a missing CA. After the CA is in the store, include that SHA-256 under `fingerprints` in an allowlist file so a later allowlist run keeps it. An expired site certificate gets a short note that adding a root won't help. A certificate that is not yet valid gets a separate note and is not called expired. Other verification errors, such as a hostname mismatch, print the chain with no add hint and no expiry note.

```text
presented chain:
INDEX  SUBJECT       ISSUER      NOT-AFTER   SHA256    LABELS
0      leaf.example  ca.example  2030-01-01  <16 hex>  not in store
1      ca.example    ca.example  2031-03-04  <16 hex>  not in store
to add a missing CA, run: trustprune add --file <cert>
after it is in the store, include sha256 <64 hex> under fingerprints in an allowlist file so a later allowlist run keeps it
ERROR: https://untrusted.example: unknown authority
```

`--format json` on a verification failure prints one object before that `ERROR:` line. `verified` is false. `presented_chain` uses the same fields as `chain` (`subject`, `issuer`, `not_after`, full `sha256`) plus `in_store`. `-v` does not change the JSON. Success output does not include `presented_chain`.

```json
{
  "url": "https://untrusted.example",
  "tls_version": "tls1.3",
  "verified": false,
  "presented_chain": [
    {"subject": "leaf.example", "issuer": "ca.example", "not_after": "2030-01-01T00:00:00Z", "sha256": "<64 hex>", "in_store": false}
  ]
}
```

| Flag | Meaning |
|------|---------|
| `--app <name>` | Use that application's certificates for the TLS handshake |
| `--store <path>` | With `--app java`, `--app certifi`, or `--app poppler`: load that store instead of discovery (same override as `list` / `backup` / `restore`) |
| `--url <url>` | URL or bare host to connect to, instead of the positional argument (e.g. `--url https://example.com`) |
| `-v`, `--verbose` | Print the verified chain after the one-line summary. On a verification failure, print the chain the server presented. Ignored with `--format json` |
| `--format` | `text` (default) or `json`. An unknown name is a usage error (exit 2) whose message lists `json` and `text` |

## diff

Compare two certificate files. The first path is the left side and the second path is the right side. There is no network access. Each file is PEM or DER. Comments around a PEM `CERTIFICATE` block are ignored, as are other PEM block types. DER is one certificate. A file with no certificate is an error.

When both files contain one certificate, diff prints the fields that differ. When either file contains more than one certificate, diff compares the bundles by SHA-256 fingerprint. A certificate only in the left file is removed. A certificate only in the right file is added. Duplicates inside one file count once.

```bash
trustprune diff old.pem new.pem
trustprune diff --format json old.pem new.der
trustprune diff backup.pem live.pem
```

Exit status is 0 when the certificates match and 1 when a field differs or a bundle certificate was added or removed. The report goes to stdout and is not an `ERROR:` line. A file that cannot be read, or that contains no certificate, exits 1 with `ERROR:` on stdout. The wrong number of paths, or an unknown `--format`, is a usage error (exit 2) on stderr.

Text (the default) for one certificate prints one line per differing field. Values are quoted. Identical certificates print `identical`.

```text
subject: "CN=Old" != "CN=New"
serial: "1" != "2"
key: "RSA-2048" != "RSA-1024"
sha256: "<64 hex>" != "<64 hex>"
```

JSON for one certificate is one object. `differences` lists only fields that differ, in the same order as text. `sha256` is the full fingerprint. An empty `differences` array means the certificates match. Single-certificate JSON has no `mode` field.

```json
{
  "identical": false,
  "left": "old.pem",
  "right": "new.pem",
  "differences": [
    {"field": "subject", "left": "CN=Old", "right": "CN=New"}
  ]
}
```

| Field | Meaning |
|-------|---------|
| `subject` | Full distinguished name of the subject |
| `issuer` | Full distinguished name of the issuer |
| `serial` | Decimal serial number |
| `validity` | `NotBefore` and `NotAfter` in UTC RFC3339, joined by ` .. ` |
| `key` | Public key type and size, such as `RSA-2048` |
| `sans` | DNS names, email addresses, IP addresses, and URIs, in that order |
| `sha256` | Hex SHA-256 fingerprint of the certificate |
| `signature_algorithm` | Signature algorithm name, such as `SHA256-RSA` |

Bundle text prints one line per changed certificate, then a summary. A certificate only in the left file starts with `-`. A certificate only in the right file starts with `+`. Each line is the full SHA-256 fingerprint, then the subject. Removed lines come first, then added lines. Each group is sorted by subject, then fingerprint. A group with no certificates is left out of the change lines. The summary is `removed N added N unchanged N` and still names all three counts. Identical bundles print `identical`, the same word one certificate uses.

```text
- <64 hex> Old CA
+ <64 hex> New CA
removed 1 added 1 unchanged 2
```

```text
identical
```

`-v` or `--verbose` prints the two paths before that bundle text. It does not change JSON. Single-certificate text does not print paths.

```text
left: backup.pem
right: live.pem
- <64 hex> Old CA
+ <64 hex> New CA
removed 1 added 1 unchanged 2
```

Bundle JSON sets `mode` to `bundle`. `removed` and `added` are arrays of `subject` and `sha256`, and they are empty arrays when nothing changed.

```json
{
  "identical": false,
  "left": "backup.pem",
  "right": "live.pem",
  "mode": "bundle",
  "removed": [
    {"subject": "Old CA", "sha256": "<64 hex>"}
  ],
  "added": [
    {"subject": "New CA", "sha256": "<64 hex>"}
  ],
  "unchanged": 2
}
```

| Flag | Meaning |
|------|---------|
| `--format` | `text` (default) or `json`. An unknown name is a usage error (exit 2) whose message lists `json` and `text` |
| `-v`, `--verbose` | Print `left:` and `right:` paths before bundle text. Ignored with `--format json`. Single-certificate text does not print paths |

## version

```bash
trustprune version
trustprune --version
trustprune -V
```

Prints the tool version and Go runtime version. `trustprune --version` is an alias of `trustprune version` and prints the same output. It is a root flag (`-version` and `-V` work the same way). Subcommands do not accept it (`trustprune list --version` is an unknown flag, and `trustprune list -V` reports `unknown flag -V`). `-v` is not a version alias; `-v`/`--verbose` is verbose on every command and before the subcommand (`trustprune -v list …`).

## Debugging

Environment variables (not CLI flags):

| Variable | Effect |
|----------|--------|
| `DEBUG=1` | Debug logging (`GODEBUG=x509roots=1` also enables Go root debugging) |
| `TRACE=<path>` | Write a binary execution trace to `<path>` |

[← Home](index.md)
