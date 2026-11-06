---
layout: default
title: Usage
nav_order: 4
---

# Usage

Global flags work with the subcommands that accept them. Add `-dry-run` to `add`, `backup`, `restore`, or `allowlist` to print the planned changes (files, certificates by subject and SHA-256, refresh commands) without writing to any store.

Supported `-app` values: `certifi`, `chrome`, `firefox`, `java`, `openssl`, `ssl` (Darwin `/etc/ssl/cert.pem`). An unknown `-app` value fails with exit 1 and an `ERROR:` that lists the valid apps, e.g. `ERROR: unknown app nope (apps: certifi, chrome, firefox, java, openssl, ssl)`.

Running `trustprune` with no subcommand prints the usage text and exits with status 1.


## apps

List every supported application store plus the system store. The system store is named for the OS (`linux`, `darwin`, or `windows`), matching backup paths under `~/.trustprune/<os>/` (or `~/Library/trustprune/<os>/` on Darwin). For each store, show whether it was found on this machine and the store path. Detection is read-only. Running `apps` also refreshes a 24-hour cache under the user cache directory so `-help` can list which apps were found without probing again.

```bash
trustprune apps
trustprune apps -format json
```

| Flag | Meaning |
|------|---------|
| `-format json` | Emit a JSON array of `{name, found, path}` objects (default is a header row then one aligned line per store). JSON `name` for the system store is the OS name (`linux` / `darwin` / `windows`), not `platform`. |

Default terse output looks like:

```text
APP       STATUS     PATH
chrome    found      /home/you/.pki/nssdb
firefox   not-found  -
java      not-found  -
certifi   found      /path/to/site-packages/certifi/cacert.pem
openssl   found      /etc/ssl/certs/ca-certificates.crt
ssl       not-found  -
linux     found      /etc/ssl/certs/ca-certificates.crt
```

## Environment

| Variable | Meaning |
|----------|---------|
| `TRUSTPRUNE_JAVA_STOREPASS` | When set (non-empty after trim), used as the keystore password for every `keytool` call under `-app java`. Custom values are passed with keytool `-storepass:env` (trimmed value in the child environment; sudo uses `--preserve-env`) so the password never appears in keytool or sudo argv; the default `changeit` still uses `-storepass changeit`. Requires keytool `-storepass:env` (JDK 6+). Leading/trailing whitespace is stripped; whitespace-only falls back to `changeit`. No other passwords are guessed. There is no CLI flag for this. |

## list

Show trusted certificates from the platform store, an app store, a local file, or a remote URL.

```bash
trustprune list
trustprune list -count
trustprune list -app java
trustprune list -app java -file /path/to/cacerts
trustprune list -file example.crt
trustprune list -url https://hg.mozilla.org/mozilla-central/raw-file/tip/security/nss/lib/ckfw/builtins/certdata.txt
```

| Flag | Meaning |
|------|---------|
| `-app <name>` | List from an application store |
| `-file <path>` | List certificates from a local file (PEM or similar) |
| `-url <endpoint>` | Download and list (PEM or Mozilla `certdata.txt`) |
| `-count` | Print only the number of certificates |
| `-format <fmt>` | Output format: `short` (default), `table`, `json`, `openssl`, `observatory` |
| `-v` | In `table` output, show the full fingerprint, serial, source or store path (`-` for URLs), and NOT BEFORE / NOT AFTER. DAYS stays numeric (including negative when expired) |
| `-ui <type>` | Presentation: `cli` (default) or `web` (local page) |

In non-verbose `table` output, the DAYS cell shows `expired` when `NotAfter` is before now, `N!` when 0 ≤ days left < 90, and the plain day count otherwise. `-format json` keeps numeric `days` and adds boolean `expired`.

## backup

Capture the current trust store so you can restore later. Allowlisting refuses to run without a prior backup for that store.

```bash
trustprune backup
trustprune backup -app java
trustprune backup -app java -file /path/to/cacerts   # Java keystore override; backup records its source keystore
trustprune backup -app certifi -file /path/to/venv/.../cacert.pem
trustprune backup -app chrome
trustprune backup -app firefox
trustprune backup -app openssl
trustprune backup -app certifi
```

| Flag | Meaning |
|------|---------|
| `-app <name>` | Back up that application's store instead of the platform |
| `-file <path>` | Java: back up that keystore instead of searching `JAVA_HOME`. Certifi: back up that `cacert.pem` instead of discovery. |
| `-dry-run` | Print what would be backed up; creates nothing |

See [Backup and restore](backup-restore.md) for where files land.

## restore

Revert to a backup. With no `-backup` (and no `-file` on stores other than java/certifi), uses the latest backup for that store.

If no backup exists, `restore` (and `restore -dry-run`) refuses before writing anything and exits 1, for example `ERROR: no backup for linux in ~/.trustprune/linux; run: trustprune backup`. For app stores the hint is `trustprune backup -app <name>`.

For **java** and **certifi**, `-file` is the store to restore into — the same meaning as on `backup` / `list` / `connect`. `-backup` selects the backup source. Each backup records the store path it came from; restoring into a different path is refused before any write unless `-force` is given.

```bash
trustprune restore
trustprune restore -backup /path/to/backup
trustprune restore -file /path/to/backup          # platform, NSS, ssl, openssl: backup source
trustprune restore -app java
trustprune restore -app java -file /path/to/cacerts
trustprune restore -app java -file /path/to/cacerts -backup /path/to/cacerts-<ts>.bck
trustprune restore -app certifi -file /path/to/venv/.../cacert.pem
trustprune restore -app chrome
trustprune restore -app openssl
trustprune restore -app java -dry-run
```

| Flag | Meaning |
|------|---------|
| `-app <name>` | Restore that application's store |
| `-file <path>` | Java/certifi: store to restore into. Other stores: explicit backup path (directory or file) |
| `-backup <path>` | Explicit backup to restore from (directory or file, depending on the store) |
| `-force` | Allow restoring a backup into a different store path than it was taken from (java and certifi) |
| `-dry-run` | Print the plan without writing |


## Darwin `/etc/ssl/cert.pem` (`-app ssl`)

On macOS, CLI tools (curl, git, python3, …) trust `/etc/ssl/cert.pem` and ignore Apple keychain blocks. Manage that bundle with `-app ssl`:

```bash
trustprune list -app ssl
trustprune backup -app ssl
trustprune allowlist -app ssl -file allowlist.yaml -dry-run
trustprune allowlist -app ssl -file allowlist.yaml
trustprune restore -app ssl
trustprune restore -app ssl -backup ~/Library/trustprune/ssl/<timestamp>/cert.pem
trustprune restore -app ssl -file ~/Library/trustprune/ssl/<timestamp>/cert.pem
```

Writes stage into a sibling temp dir, copy the live file aside to `.restore-old`, then rename over the destination (sudo when needed); a leftover `.restore-old` is refused rather than deleted. An empty allowlist result is refused. After a successful write, trustprune records a content hash; if a later macOS update restores Apple's copy, `list -app ssl` prints a one-line warning. Re-apply with `backup -app ssl` then `allowlist -app ssl -file …`, or `restore -app ssl` to put back your pruned backup.

PEM parsing uses Go's `x509.ParseCertificate`, then a `cryptobyte` fallback that reads subject, issuer, serial, and validity (so Apple's negative-serial roots list and allowlist like any other cert, without GODEBUG). Blocks that still cannot be read print a warning to stderr naming the PEM block and are skipped for list; `add` and `allowlist` write those raw PEM blocks back unchanged in their original order.


## Python certifi (`-app certifi`)

Python's [certifi](https://github.com/certifi/python-certifi) package ships a Mozilla CA bundle (`cacert.pem`) used by requests and many other libraries. Manage that bundle with `-app certifi`.

Path discovery (first existing wins):

1. `-file <cacert.pem>` override on `list`, `backup`, `connect`, and `restore` (one bundle per venv)
2. `python3 -c 'import certifi; print(certifi.where())'` (then `python`)
3. The same probe against `pip._vendor.certifi`
4. Common `site-packages/certifi/cacert.pem` fallbacks

On `add` and `allowlist`, `-file` keeps its usual meaning (certificate to import, or allowlist YAML/JSON). To target a specific venv for those commands, put that venv's `python` first on `PATH` so discovery selects its certifi. For `restore`, pass `-file` as the venv's `cacert.pem` (same as `backup` / `list`); use `-backup` to pick a specific backup.

Some Linux distros patch certifi so `where()` returns the system CA bundle (for example `/etc/ssl/certs/ca-certificates.crt`). That path is still managed as a PEM file. Upstream installs keep a dedicated `cacert.pem` beside the package.

```
trustprune list -app certifi
trustprune list -app certifi -file /path/to/venv/lib/python3.12/site-packages/certifi/cacert.pem
trustprune backup -app certifi
trustprune backup -app certifi -file /path/to/venv/lib/python3.12/site-packages/certifi/cacert.pem
trustprune allowlist -app certifi -file allowlist.yaml -dry-run
trustprune allowlist -app certifi -file allowlist.yaml
trustprune restore -app certifi
trustprune restore -app certifi -file /path/to/venv/lib/python3.12/site-packages/certifi/cacert.pem
```

Writes reuse the same atomic sibling-temp install as `-app ssl` / `-app openssl` (copy aside to `.restore-old`, refuse a leftover aside, refuse an empty allowlist result). Restore with no backup refuses before any filesystem write.

## OpenSSL CA bundles (`-app openssl`)

curl, git, and the OpenSSL libraries read a PEM bundle or a hashed cert directory — not the Darwin keychain and not always the same file as the Linux platform store. Manage that location with `-app openssl`.

Path resolution uses the first existing of:

1. `SSL_CERT_FILE` (if set)
2. `CURL_CA_BUNDLE` (if set)
3. Distro/Homebrew defaults (`/etc/ssl/certs/ca-certificates.crt`, `/etc/pki/tls/certs/ca-bundle.crt`, Homebrew `.../etc/openssl/certs` and `openssl@3` / `openssl@1.1` variants)
4. `git config --get http.sslCAInfo` (best-effort; git errors are ignored)

Darwin `/etc/ssl/cert.pem` is **not** selected as an openssl default. Use `-app ssl` for that file.

```bash
trustprune list -app openssl
trustprune backup -app openssl
trustprune allowlist -app openssl -file allowlist.yaml -dry-run
trustprune allowlist -app openssl -file allowlist.yaml
trustprune restore -app openssl
```

A PEM file is rewritten like `-app ssl` (atomic install, refuse empty bundle). A cert directory lists `*.pem`/`*.crt`, backups mirror the directory, remove deletes non-matching cert files, and `c_rehash` runs after add (required) and after remove/restore when the binary is present.


## allowlist

Distrust certificates that are **not** on the allowlist. Requires `-file` and a prior backup. With no backup, `allowlist` (and `allowlist -dry-run`) refuses before writing anything and exits 1, for example `ERROR: no backup for openssl in ~/.trustprune/openssl; run: trustprune backup -app openssl` (platform stores suggest `trustprune backup`). Always applies Chromium's certificate blocklist so known-bad CAs are never kept (cannot be disabled). The older `whitelist` name remains as a hidden alias.

Allowlist files are YAML or JSON with optional `fingerprints` (SHA-256) and `countries` (ISO 3166-1 alpha-2).

```bash
trustprune allowlist -file allowlist.yaml
trustprune allowlist -file allowlist.json -app java
trustprune allowlist -file allowlist.yaml -dry-run
```

| Flag | Meaning |
|------|---------|
| `-file <path>` | **Required.** Path to the allowlist |
| `-app <name>` | Apply against an application store |
| `-dry-run` | Print the plan without writing |

Example YAML:

```yaml
fingerprints:
  - "050cf9fa95e40e9bddedaeda6961f6168c1279c4660172479cdd51ab03cea62c"
countries:
  - "US"
  - "JP"
```

## gen-allowlist

Build an allowlist from browser history and/or a URL list file. The older `gen-whitelist` name remains as a hidden alias.

```bash
trustprune gen-allowlist -out allowlist.yaml -from firefox
trustprune gen-allowlist -out allowlist.yaml -from browsers
trustprune gen-allowlist -out allowlist.yaml -from chrome,firefox
trustprune gen-allowlist -out allowlist.yaml -file urls.txt
```

| Flag | Meaning |
|------|---------|
| `-out <path>` | **Required.** Where to write the allowlist. The extension picks the format: `.json` writes JSON, `.yaml` or `.yml` writes YAML |
| `-from <types>` | Comma-separated sources: `browser` / `browsers`, `chrome`, `firefox`, `safari`, `file` |
| `-file <path>` | Newline- or comma-delimited URLs (plain text or gzip CSV-style “top N” lists) |

## add

Add certificate(s) from a file into the platform or an app store.

```bash
trustprune add -file cert.pem
trustprune add -file cert.pem -app java
```

| Flag | Meaning |
|------|---------|
| `-file <path>` | **Required.** Certificate file to import |
| `-app <name>` | Target an application store |
| `-dry-run` | Print the plan without writing |

## connect

Attempt an HTTPS connection using the platform store or an app store. Useful after allowlist or restore.

```bash
trustprune connect https://example.com
trustprune connect -app java https://example.com
trustprune connect -app java -file /path/to/cacerts https://example.com
trustprune connect -url https://example.com
```

| Flag | Meaning |
|------|---------|
| `-app <name>` | Use that application's certificates for the TLS handshake |
| `-file <keystore>` | With `-app java` or `-app certifi`: load that store instead of discovery (same override as `list` / `backup` / `restore`). Without `-app`, `-file` is ignored and connect uses the platform store |
| `-url <url>` | URL to connect to, instead of the positional argument (e.g. `-url https://example.com`) |

The URL must use the `https` scheme.

## version

```bash
trustprune version
```

Prints the tool version and Go runtime version.

## Debugging

Environment variables (not CLI flags):

| Variable | Effect |
|----------|--------|
| `DEBUG=1` | Debug logging (`GODEBUG=x509roots=1` also enables Go root debugging) |
| `TRACE=<path>` | Write a binary execution trace to `<path>` |

[← Home](index.md)
