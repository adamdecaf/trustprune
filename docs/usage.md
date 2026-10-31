---
layout: default
title: Usage
---

# Usage

Global flags work with the subcommands that accept them. Add `-dry-run` to `add`, `backup`, `restore`, or `allowlist` to print the planned changes (files, certificates by subject and SHA-256, refresh commands) without writing to any store.

Supported `-app` values: `chrome`, `firefox`, `java`, `openssl`, `ssl` (Darwin `/etc/ssl/cert.pem`).


## apps

List every supported application store plus the platform store. For each one, show whether it was found on this machine and the store path. Detection is read-only. Running `apps` also refreshes a 24-hour cache under the user cache directory so `-help` can list which apps were found without probing again.

```bash
trustprune apps
trustprune apps -format json
```

| Flag | Meaning |
|------|---------|
| `-format json` | Emit a JSON array of `{name, found, path}` objects (default is one aligned line per store) |

Default terse output looks like:

```text
chrome    found      /home/you/.pki/nssdb
firefox   not-found  -
java      not-found  -
openssl   found      /etc/ssl/certs/ca-certificates.crt
ssl       found      /etc/ssl/cert.pem
platform  found      /etc/ssl/certs/ca-certificates.crt
```

## list

Show trusted certificates from the platform store, an app store, a local file, or a remote URL.

```bash
trustprune list
trustprune list -count
trustprune list -app java
trustprune list -file example.crt
trustprune list -url https://hg.mozilla.org/mozilla-central/raw-file/tip/security/nss/lib/ckfw/builtins/certdata.txt
```

| Flag | Meaning |
|------|---------|
| `-app <name>` | List from an application store |
| `-file <path>` | List certificates from a local file (PEM or similar) |
| `-url <endpoint>` | Download and list (PEM or Mozilla `certdata.txt`) |
| `-count` | Print only the number of certificates |
| `-format <fmt>` | Output format: `short` (default), `table`, `openssl`, `observatory` |
| `-ui <type>` | Presentation: `cli` (default) or `web` (local page) |

## backup

Capture the current trust store so you can restore later. Allowlisting refuses to run without a prior backup for that store.

```bash
trustprune backup
trustprune backup -app java
trustprune backup -app chrome
trustprune backup -app firefox
```

| Flag | Meaning |
|------|---------|
| `-app <name>` | Back up that application's store instead of the platform |
| `-dry-run` | Print what would be backed up; creates nothing |

See [Backup and restore](backup-restore.md) for where files land.

## restore

Revert to a backup. With no `-file`, uses the latest backup for that store. With `-file`, passes that path into the store's `Restore` (honored on Linux, Java, NSS, and `-app ssl`; Darwin keychain platform restore currently ignores it — see platforms).

```bash
trustprune restore
trustprune restore -file /path/to/backup
trustprune restore -app java
trustprune restore -app java -file /path/to/cacerts.bck
trustprune restore -app chrome
trustprune restore -app java -dry-run
```

| Flag | Meaning |
|------|---------|
| `-app <name>` | Restore that application's store |
| `-file <path>` | Explicit backup path (directory or file, depending on the store) |
| `-dry-run` | Print the plan without writing |


## Darwin `/etc/ssl/cert.pem` (`-app ssl`)

On macOS, CLI tools (curl, git, python3, …) trust `/etc/ssl/cert.pem` and ignore Apple keychain blocks. Manage that bundle with `-app ssl`:

```bash
trustprune list -app ssl
trustprune backup -app ssl
trustprune allowlist -app ssl -file allowlist.yaml -dry-run
trustprune allowlist -app ssl -file allowlist.yaml
trustprune restore -app ssl
trustprune restore -app ssl -file ~/Library/trustprune/ssl/<timestamp>/cert.pem
```

Writes stage a temp PEM then install it (sudo when needed). An empty allowlist result is refused. After a successful write, trustprune records a content hash; if a later macOS update restores Apple's copy, `list -app ssl` prints a one-line warning. Re-apply with `backup -app ssl` then `allowlist -app ssl -file …`, or `restore -app ssl` to put back your pruned backup.

PEM parsing skips individual unparsable certificates (Apple's bundle can include negative serial numbers that Go rejects) and prints a warning to stderr naming the PEM block, then continues with the rest of the file. `list` still returns the parseable certificates. `add` and `allowlist` refuse to rewrite the live bundle if any certificate was skipped, so those entries are not deleted; backup or restore first.


## allowlist

Distrust certificates that are **not** on the allowlist. Requires `-file` and a prior backup. Always applies Chromium's certificate blocklist so known-bad CAs are never kept (cannot be disabled). The older `whitelist` name remains as a hidden alias.

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
| `-out <path>` | **Required.** Where to write the allowlist |
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
```

| Flag | Meaning |
|------|---------|
| `-app <name>` | Use that application's certificates for the TLS handshake |

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
