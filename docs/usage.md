---
layout: default
title: Usage
nav_order: 4
---

# Usage

Flags are per-command. Only flags a command actually uses are accepted (`trustprune apps --store x` is an unknown-flag usage error). Add `--dry-run` to `add`, `backup`, `restore`, or `allowlist` to print the planned changes without writing to any store. `add`, `backup`, and `restore` list files and certificates. `allowlist --dry-run` lists kept certificates and ends with kept and removed counts; `-v` adds per-certificate remove and keep details.

Both `-flag` and `--flag` work. These docs use `--flag`.

Supported `--app` values: `certifi`, `chrome`, `firefox`, `foxit`, `java`, `okular`, `openssl`, `poppler`, `ssl` (Darwin `/etc/ssl/cert.pem`). `foxit` is guide only: see [Foxit](#foxit) below and [Platforms](platforms.md#foxit). `okular` uses NSS when that is the effective signature backend and reports GPG without changes: see [Okular](#okular---app-okular). The OS name shown by `apps` (`linux`, `darwin`, or `windows`) is also accepted as `--app` and selects the platform store; it is left off the apps list on purpose. `--store` with that name is rejected. An unknown `--app` value fails with exit 1 and an `ERROR:` that lists the valid apps, e.g. `ERROR: unknown app nope (apps: certifi, chrome, firefox, foxit, java, okular, openssl, poppler, ssl)`.

Running `trustprune` with no subcommand prints the usage text and exits with status 0. `-h`, `--help`, `trustprune help`, and `trustprune <command> -h` also exit 0.

Usage errors (unknown flag, unknown command, stray positional args, missing required flag) exit 2. The message goes to stderr, starts with `ERROR:`, and the next line is a hint to run `--help` (that hint is not an `ERROR:` line). Runtime errors stay on stdout, exit 1, and keep the `ERROR:` prefix. `diff` also exits 1 when the certificates differ; that report is the command output and has no `ERROR:` prefix.

```text
ERROR: unknown flag --foo
run 'trustprune list --help' for usage
```

Unexpected positional arguments are rejected with exit status 2 before any write (`unexpected argument(s): …`). Flags after a positional argument are still parsed, so `trustprune add --file x.pem extra --dry-run` is still a usage error and does not write. A shell glob that expands into multiple files can produce those extra arguments and is rejected the same way. `connect` accepts one optional positional URL (or `--url`, not both). `diff` accepts exactly two certificate paths.


## apps

List every supported application store plus the system store. The system store is named for the OS (`linux`, `darwin`, or `windows`), matching backup paths under `~/.trustprune/<os>/` (or `~/Library/trustprune/<os>/` on Darwin). For each store, show whether it was found on this machine and the store path. Detection is read-only. Running `apps` also refreshes a 24-hour cache under the user cache directory so `--help` can list which apps were found without probing again.

```bash
trustprune apps
trustprune apps --format json
```

| Flag | Meaning |
|------|---------|
| `--format json` | Emit a JSON array of `{name, found, path}` objects (default is a header row then one aligned line per store). An installed guide-only app adds `guideOnly: true` (Foxit). JSON `name` for the system store is the OS name (`linux` / `darwin` / `windows`), not `platform`. |

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
linux     found      /etc/ssl/certs/ca-certificates.crt
```

STATUS is `found`, `not-found`, or `guide only`. `guide only` means the app is installed and trustprune will not read or write its trust data. For Foxit, PATH is the install (the `.exe` or the `.app` bundle), not a certificate file.

## Foxit

`--app foxit` detects Foxit PDF Editor and Foxit PDF Reader on Windows and macOS. When one is installed, `trustprune apps` reports `guide only`. `list`, `add`, `allowlist`, `backup`, `restore`, and `connect` print where Foxit trust comes from and exit 1. They do not read or write a Foxit trust list, and `--dry-run` does not plan a change.

Trust comes from the local Trusted Certificates list (**Protect > Sign & Certify > Trusted Certificates**), from Foxit Approved Trust List (FATL) downloads into that list, from European Union Trusted Lists (EUTL) downloads on Mac, and on Windows from the Windows certificate store when Windows Integration is on.

To remove a root, delete it or clear its trust in Trusted Certificates, then turn the download off so the next update does not add it back: **File > Preferences > Trust Manager**, clear **Load trusted certificates from Foxit server** (on by default, about every 28 days). On Mac, clear **Load trusted certificates from Foxit FATL / EUTL server** for both FATL and EUTL. On Windows, **File > Preferences > Signature** > **Windows Integration** trusts Windows store roots for signatures and certified documents. Removing a root there leaves the FATL copy in place.

The on-disk Trusted Certificates list is **unverified**. Paths, the admin policy, and the full steps are in [Platforms](platforms.md#foxit).

## Environment

| Variable | Meaning |
|----------|---------|
| `TRUSTPRUNE_JAVA_STOREPASS` | When set (non-empty after trim), used as the keystore password for every `keytool` call under `--app java`. Custom values are passed with keytool `-storepass:env` (trimmed value in the child environment; sudo uses `--preserve-env`) so the password never appears in keytool or sudo argv; the default `changeit` still uses `-storepass changeit`. Requires keytool `-storepass:env` (JDK 6+). Leading/trailing whitespace is stripped; whitespace-only falls back to `changeit`. No other passwords are guessed. There is no CLI flag for this. |

## list

Show trusted certificates from the platform store, an app store, a local file, or a remote URL.

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
trustprune list --url https://hg.mozilla.org/mozilla-central/raw-file/tip/security/nss/lib/ckfw/builtins/certdata.txt
```

| Flag | Meaning |
|------|---------|
| `--app <name>` | List from an application store |
| `--store <path>` | With `--app java`, `--app certifi`, or `--app poppler`: read that keystore, `cacert.pem`, or NSS directory instead of discovery. `list` output shows the chosen path |
| `--file <path>` | Without `--app`: list certificates from a local file (PEM or similar). Cannot be combined with `--app`; use `--store` to override a java, certifi, or poppler path |
| `--bundle <path>` | With `--app openssl`: list that PEM CA bundle instead of discovery |
| `--url <endpoint>` | Download and list (PEM or Mozilla `certdata.txt`) |
| `--count` | Print only the number of certificates |
| `--format <fmt>` | Output format: `table` (default), `long`, `json`, `openssl`, `observatory`. `long` is the multi-line dump. An unknown name is a usage error (exit 2) whose message lists the valid formats |
| `--out <path>` | Write the formatted output to `<path>` instead of stdout for every `--format` and for `--count`. Stdout stays empty |
| `-v` | On the default table, show the full fingerprint, serial, source or store path (`-` for URLs), and hyphenated `NOT-BEFORE` / `NOT-AFTER`. Columns fit the longest header or cell and are separated by two spaces. When every row has the same path, print `PATH: <path>` above the table and omit the PATH column; mixed paths keep the column. DAYS stays numeric (including negative when expired) |
| `--ui <type>` | Presentation: `cli` (default) or `web` (local page) |

In non-verbose table output, the DAYS cell shows `expired` when `NotAfter` is before now, `N!` when 0 ≤ days left < 90, and the plain day count otherwise. `-v` keeps numeric days on that same table. `--format json` keeps numeric `days` and adds boolean `expired`. `--format long` prints one multi-line block per certificate.

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
3. Distro/Homebrew defaults (`/etc/ssl/certs/ca-certificates.crt`, `/etc/pki/tls/certs/ca-bundle.crt`, Homebrew `.../etc/openssl/certs` and `openssl@3` / `openssl@1.1` variants)
4. `git config --get http.sslCAInfo` (best-effort; git errors are ignored)

Darwin `/etc/ssl/cert.pem` is **not** selected as an openssl default. Use `--app ssl` for that file.

```bash
trustprune list --app openssl
trustprune list --app openssl --bundle /path/to/ca-bundle.pem
trustprune backup --app openssl
trustprune backup --app openssl --bundle /path/to/ca-bundle.pem
trustprune allowlist --app openssl --file allowlist.yaml --dry-run
trustprune allowlist --app openssl --file allowlist.yaml
trustprune allowlist --app openssl --file allowlist.yaml --bundle /path/to/ca-bundle.pem
trustprune restore --app openssl
trustprune restore --app openssl --bundle /path/to/ca-bundle.pem
```

`--bundle <pem>` skips path discovery and must name an existing PEM file. It does not select a hashed cert directory. On allowlist, `--file` is still the allowlist. On restore, `--backup` is the backup source; a backup taken from a different PEM is refused unless `--force`.

A PEM file is rewritten like `--app ssl` (atomic install, refuse empty bundle). Backups of a PEM file record its path in `source`. A cert directory lists `*.pem`/`*.crt`, backups mirror the directory, remove deletes non-matching cert files, and `c_rehash` runs after add (required) and after remove/restore when the binary is present. Directory rehash is unchanged; pass the PEM file to `--bundle` when you want that file rather than the discovered directory.


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

Distrust certificates that are **not** on the allowlist. Requires `--file` and a prior backup. With no backup, `allowlist` (and `allowlist --dry-run`) refuses before writing anything and exits 1, for example `ERROR: no backup for openssl in ~/.trustprune/openssl; run: trustprune backup --app openssl` (platform stores suggest `trustprune backup`). For firefox, poppler, okular, and Linux chrome, a newest backup recorded for a different NSS directory does not count as a backup of this directory. The error tells you to run `trustprune backup` for this store. `--force` allows the allowlist anyway. Always applies Chromium's certificate blocklist and a built-in denylist of known-distrusted roots and their public keys, so those CAs are never kept (cannot be disabled). `gen-allowlist` skips denylisted CAs and prints a `NOTE:` for each one.

Allowlist files are YAML or JSON with optional `fingerprints` (SHA-256) and `countries` (ISO 3166-1 alpha-2).

```bash
trustprune allowlist --file allowlist.yaml
trustprune allowlist --file allowlist.json --app java
trustprune allowlist --app java --store /path/to/cacerts --file allowlist.yaml
trustprune allowlist --file allowlist.yaml --app openssl --bundle /path/to/ca-bundle.pem
trustprune allowlist --file allowlist.yaml --dry-run
trustprune allowlist --file allowlist.yaml --dry-run -v
```

`--dry-run` prints the plan and does not change the store. Kept certificates are listed by subject and SHA-256. Unparsable PEM blocks that would be kept are listed too, as `unparsable PEM block (N bytes)`, and are not included in the counts. The output ends with `dry-run: no changes made` and `dry-run: N kept, M removed`. `-v` / `--v` adds per-certificate remove and keep lines after that list (`remove`, `distrust`, `remove … from <path>`, and `remove … (alias …)`, depending on the store). Those detail lines are omitted by default. Among dry-run commands, only `allowlist` accepts `-v`; `add`, `backup`, and `restore` keep their existing dry-run output.

```text
dry-run: would remove certificates from certifi at /tmp/cacert.pem
Kept:
  CN=Keep Me (SHA256 abcd...)
  CN=Also Keep (SHA256 efgh...)
  unparsable PEM block (12 bytes)
dry-run: no changes made
dry-run: 2 kept, 3 removed
```

| Flag | Meaning |
|------|---------|
| `--file <path>` | **Required.** Path to the allowlist |
| `--store <path>` | With `--app java`, `--app certifi`, or `--app poppler`: operate on that keystore, `cacert.pem`, or NSS directory. Independent of `--file` |
| `--app <name>` | Apply against an application store |
| `--bundle <path>` | With `--app openssl`: PEM CA bundle to edit instead of discovery. Requires a backup recorded for that file |
| `--dry-run` | Print the plan without writing. Lists kept certificates, then ends with `dry-run: no changes made` and `dry-run: N kept, M removed` |
| `--force` | Allow an NSS allowlist when the latest backup was taken from a different directory and this directory has no backup of its own |
| `-v`, `--v` | With `--dry-run`, also print per-certificate remove and keep details |

Example YAML:

```yaml
fingerprints:
  - "050cf9fa95e40e9bddedaeda6961f6168c1279c4660172479cdd51ab03cea62c"
countries:
  - "US"
  - "JP"
```

## gen-allowlist

Build an allowlist from hostnames, platform presets, browser history, and/or a URL list file. When generation runs, the default platform preset for this OS is included unless you pass `--no-presets` or an explicit `--presets` list. Target another OS with `--presets linux` (or `darwin` / `windows`). Apply the result with `trustprune allowlist --file …` (optionally `--app openssl --bundle` for a PEM bundle). Generation verifies chains against the system trust store, not roots from a target PEM bundle; CAs present only in that bundle are not discovered.

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
```

| Flag | Meaning |
|------|---------|
| `--out <path>` | **Required.** Where to write the allowlist. The extension picks the format: `.json` writes JSON, `.yaml` or `.yml` writes YAML |
| `--hosts <hosts>` | Comma-separated hostnames or https URLs to include (`example.com` becomes `https://example.com`) |
| `--presets <names>` | Comma-separated preset names to include (default: this OS platform preset). Names: `apple`, `apt`, `darwin`, `linux`, `macos`, `macos-update`, `windows`, `windows-update` |
| `--no-presets` | Do not include the default platform preset |
| `--from <types>` | Comma-separated sources: `browser` / `browsers`, `chrome`, `firefox`, `safari`, `file` |
| `--file <path>` | Newline- or comma-delimited URLs (plain text or gzip CSV-style “top N” lists) |
| `-v` | Show full fingerprints in the summary table. The default prints the first 16 characters |

Without `--out`, `gen-allowlist` prints `ERROR: required flag --out not set` and exits with status 2. With `--out` but none of `--from`, `--file`, `--hosts`, or `--presets`, it prints usage and exits 0. `--presets` and `--no-presets` together are a usage error (exit 2).

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

`sha256` is the first 16 hex characters of the root. `leaf-expires` is the leaf certificate's `NotAfter` in UTC (`YYYY-MM-DD`). `-v` prints the verified chain after that line (INDEX, SUBJECT, ISSUER, NOT-AFTER, SHA256). `--format json` prints one object and ignores `-v`:

```json
{
  "url": "https://google.com",
  "tls_version": "tls1.3",
  "verified": true,
  "root": {"subject": "<name>", "sha256": "<64 hex>"},
  "leaf": {"subject": "<leaf>", "not_after": "YYYY-MM-DD"},
  "chain": [
    {"subject": "<leaf>", "issuer": "<issuer>", "not_after": "YYYY-MM-DD", "sha256": "<64 hex>"}
  ]
}
```

`chain` is leaf-first and includes the trust anchor. JSON `sha256` values are the full fingerprint. `verified` is true after a successful handshake. `not_after` uses the same UTC date as the text line.

Failures are one short line:

```text
ERROR: https://expired.badssl.com: certificate expired 2015-04-12
```

| Flag | Meaning |
|------|---------|
| `--app <name>` | Use that application's certificates for the TLS handshake |
| `--store <path>` | With `--app java`, `--app certifi`, or `--app poppler`: load that store instead of discovery (same override as `list` / `backup` / `restore`) |
| `--url <url>` | URL or bare host to connect to, instead of the positional argument (e.g. `--url https://example.com`) |
| `-v`, `--verbose` | Print the verified chain after the one-line summary. Ignored with `--format json` |
| `--format` | `text` (default) or `json`. An unknown name is a usage error (exit 2) whose message lists `json` and `text` |

## diff

Compare two certificate files and print the fields that differ. Each file is PEM or DER and must contain exactly one certificate. Comments around a PEM `CERTIFICATE` block are ignored, as are other PEM block types. The first path is the left side and the second path is the right side. There is no network access.

```bash
trustprune diff old.pem new.pem
trustprune diff --format json old.pem new.der
```

Exit status is 0 when every compared field matches and 1 when any field differs. The report goes to stdout and is not an `ERROR:` line. A file that cannot be read, or that does not contain exactly one certificate, exits 1 with `ERROR:` on stdout. The wrong number of paths, or an unknown `--format`, is a usage error (exit 2) on stderr.

Text (the default) prints one line per differing field. Values are quoted. Identical certificates print `identical`.

```text
subject: "CN=Old" != "CN=New"
serial: "1" != "2"
key: "RSA-2048" != "RSA-1024"
sha256: "<64 hex>" != "<64 hex>"
```

JSON is one object. `differences` lists only fields that differ, in the same order as text. `sha256` is the full fingerprint. An empty `differences` array means the certificates match.

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

| Flag | Meaning |
|------|---------|
| `--format` | `text` (default) or `json`. An unknown name is a usage error (exit 2) whose message lists `json` and `text` |

## version

```bash
trustprune version
trustprune --version
```

Prints the tool version and Go runtime version. `trustprune --version` is an alias of `trustprune version` and prints the same output. It is a root flag (`-version` works the same way). Subcommands do not accept it (`trustprune list --version` is an unknown flag). `-v` is not a version alias; on `list`, `-v` means verbose.

## Debugging

Environment variables (not CLI flags):

| Variable | Effect |
|----------|--------|
| `DEBUG=1` | Debug logging (`GODEBUG=x509roots=1` also enables Go root debugging) |
| `TRACE=<path>` | Write a binary execution trace to `<path>` |

[← Home](index.md)
