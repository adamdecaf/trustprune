---
layout: default
title: Allowlists
nav_order: 5
---

# Allowlists
{: .no_toc }

<details open markdown="block">
  <summary>Table of contents</summary>
  {: .text-delta }
1. TOC
{:toc}
</details>

## Allowlisting

### Configuration

Allowlists represent an operation which disables certificate trust in a certificate store. The filters presented for an allowlist are:

- `fingerprints`: The SHA256 fingerprint of a certificate (YAML and JSON). This value will be unique across certificates given their contents are unique.
- `Countries`: ISO 3166-1 two-letter country codes of certificates to keep. (e.g. `US` - United States and `JP` - Japan)

Allowlists are stored in yaml or json files. There is a basic structure to them which allows for multiple methods of allowlisting. The structure looks like:

```yaml
# Optional array of SHA256 certificate fingerprints
fingerprints:
 - "050cf9fa95e40e9bddedaeda6961f6168c1279c4660172479cdd51ab03cea62c"

# Optional array of ISO 3166-1 Country Codes
countries:
 - "US"
 - "JP"
```

```json
{
  "fingerprints": [
    "050cf9fa95e40e9bddedaeda6961f6168c1279c4660172479cdd51ab03cea62c"
  ],
  "Countries": [
    "GB"
  ]
}
```

Files that use the older `"Fingerprints"` key are still accepted.

To apply an allowlist against a platform:

```
$ trustprune allowlist --file wh.json
Allowlist completed successfully
128 removed, 40 kept
```

The last line is how many certificates were removed or distrusted, and how many were kept. Counts depend on the store. Fingerprints in the file that matched no certificate add `, K unmatched` to that line. `-v` / `--verbose` also lists them under `Unmatched allowlist entries:`. `--count` prints only the removed count.

You can also apply an allowlist against an application's certificate store:

```
$ trustprune allowlist --file wh.json --app java
Allowlist completed successfully
40 removed, 12 kept
```

`create` uses the same allowlist file to write a PEM bundle or a Java truststore (`--format jks` or `pkcs12`) and leaves the store unchanged. `--format` accepts `pem` (the default), `jks`, and `pkcs12`. `jks` and `pkcs12` require `--out` and `keytool`. An allowlist that matches nothing fails and writes no file. Full flags: [usage](usage.md#create).

```
$ trustprune create --file wh.json --out kept.pem
$ trustprune create --file wh.json --format jks --out trusted.jks
$ trustprune create --file wh.json --app java --out java-cas.pem
```

## Baseline allowlists

trustprune ships two starting baselines, both as SHA-256 fingerprints of Mozilla [certdata.txt](https://raw.githubusercontent.com/mozilla-firefox/firefox/main/security/nss/lib/ckfw/builtins/certdata.txt) roots trusted for TLS server authentication. Neither is a full top-1-million scan or a Censys observed list, and neither is a signed hosted list.

`--file` accepts these https URLs directly. `http://` and any other scheme are rejected. `--sha256` is optional and is the SHA-256 of the file bytes (64 hex digits, any case). It is checked before the allowlist is parsed. `curl` still saves a local copy.

`allowlist` still requires a prior backup. Applying either file still skips denylisted and blocklisted certificates. See [Blocklisted certificates](#blocklisted-certificates) and [Denylisted certificates](#denylisted-certificates).

### Mozilla included roots

The included-root baseline is every certdata.txt root trusted for server authentication.

Download it from the docs site: <https://trustprune.com/downloads/allowlists/mozilla-included.yaml>

The same file is in the repo at `docs/downloads/allowlists/mozilla-included.yaml`. Regenerate with `make allowlists` (offline, from `testdata/certdata.txt.gz`).

```
$ trustprune allowlist --file https://trustprune.com/downloads/allowlists/mozilla-included.yaml --dry-run
$ trustprune allowlist --file https://trustprune.com/downloads/allowlists/mozilla-included.yaml
$ trustprune create --file https://trustprune.com/downloads/allowlists/mozilla-included.yaml --out mozilla-roots.pem

$ curl -fsSL https://trustprune.com/downloads/allowlists/mozilla-included.yaml -o mozilla-included.yaml
$ trustprune allowlist --file mozilla-included.yaml --dry-run
```

### Web (top sites)

The web baseline is the subset of those Mozilla roots that actually anchored TLS chains of popular websites. The checked-in file was generated from a [Tranco](https://tranco-list.eu/) daily list (list ID, date window, sample size, success count, and per-root site counts are in the file header). It includes every Mozilla root that anchored at least one successful site in that sample. It is a large sample, not a full top-1-million scan.

Download it from the docs site: <https://trustprune.com/downloads/allowlists/web.yaml>

The same file is in the repo at `docs/downloads/allowlists/web.yaml`.

```
$ trustprune allowlist --file https://trustprune.com/downloads/allowlists/web.yaml --dry-run
$ trustprune allowlist --file https://trustprune.com/downloads/allowlists/web.yaml
$ trustprune create --file https://trustprune.com/downloads/allowlists/web.yaml --out web-roots.pem

$ curl -fsSL https://trustprune.com/downloads/allowlists/web.yaml -o web.yaml
$ trustprune allowlist --file web.yaml --dry-run
```

Regenerate with `make web-allowlist LIST=/path/to/tranco.csv` after downloading a local Tranco CSV. `LIST` is required. That target dials the network and is not part of `make allowlists` or `make generate`. The scanner verifies each handshake only against the pinned `testdata/certdata.txt.gz` roots; fingerprints that are not in that set are never written.

## Generating allowlists

`trustprune` generates allowlists by dialing HTTPS hosts and recording the CAs that signed them. Sources can be a few hostnames (`--hosts`), named platform presets (`--presets`), browser history (`--from`), and/or a URL list file (`--file`).

`--out` is required. Without it, `gen-allowlist` prints `ERROR: required flag --out not set` and exits with status 2. With `--out` but none of `--from`, `--file`, `--hosts`, or `--presets`, it prints usage and exits 0 (the same for `--out --no-presets`). The `--out` extension picks the format: `.json` writes JSON; `.yaml` or `.yml` writes YAML.

While it writes the file, `gen-allowlist` prints a summary table with headers `CA`, `SHA256-FINGERPRINT`, `COUNT`, and `EXAMPLE-DNS-NAMES`. Columns are separated by two spaces, so a CA name that contains spaces stays in the CA column. The fingerprint column shows the first 16 characters. `-v` / `--verbose` prints each full fingerprint. At most three example DNS names are shown; `COUNT` is the full number of names.

CAs on the built-in denylist are left out of that table and out of the file. Each one prints `NOTE: skipping denylisted certificate ...` first. See [Denylisted certificates](#denylisted-certificates).

### Stats

`--stats` prints a block to stderr after hosts are dialed. The summary table on stdout stays the same. Without `--stats`, that block is not printed.

It is printed when generation dialed hosts, including when no CA could be recorded. It is not printed when generation stops before any dial, for example when no URLs were found.

The block reports:

- URLs read from the input, before duplicate hosts are collapsed, and how many unique hosts that was
- TLS connections attempted, succeeded, and failed
- hosts answered from a CA already recorded for that name, without a new connection (`reused hosts`)
- total and average DNS lookup time, and how many lookups that was
- total and average connect and TLS handshake time (from the start of the TCP dial through the handshake, including a dial that fails)
- unique roots matched
- total wall time, including writing the allowlist file

Failed hosts are listed on a last line, at most 20, with a count of any left out (`(+N more)`). That line is omitted when every dial succeeded. IP addresses do not add DNS time. An example block:

```
stats:
urls: 3
unique hosts: 2
tls attempted: 2
tls succeeded: 2
tls failed: 0
reused hosts: 0
dns: total 18ms, avg 9ms, lookups 2
connect+tls: total 140ms, avg 70ms, handshakes 2
roots: 1
wall: 160ms
```

```
$ trustprune gen-allowlist --out allowlist.yaml --hosts example.com --no-presets --stats
```

The summary table is still printed on stdout. `--stats` only adds the block above on stderr.

### Platform presets

When generation actually runs, the default platform preset for this OS is merged in unless you pass `--no-presets` or an explicit `--presets` list:

- **darwin** (alias **macos**): Apple service hosts (`apple`) plus software-update hosts (`macos-update`)
- **linux**: Debian/Ubuntu apt HTTPS indexes, plus a couple of Fedora/Rocky package-index hosts (`apt`)
- **windows**: Microsoft update and download HTTPS hosts (`windows-update`)

OS time servers (for example `time.apple.com` and `time.windows.com`) speak NTP, not HTTPS, so they are not included. Generation only dials `https`.

To generate a Linux allowlist on a Mac (or any other OS), pass `--presets linux`. Unknown preset names are a usage error (exit 2).

```
$ trustprune gen-allowlist --out allowlist.yaml --presets linux
```

### Few hostnames

`--hosts` takes comma-separated hostnames or https URLs. Bare names become `https://` URLs. This is the easy path for a small server or a PEM bundle/store:

```
$ trustprune gen-allowlist --out allowlist.yaml --hosts example.com,api.example.com
$ trustprune gen-allowlist --out allowlist.yaml --hosts example.com --presets linux
$ trustprune gen-allowlist --out allowlist.yaml --hosts example.com --no-presets
```

Apply the result with the existing allowlist command. For a PEM bundle, pass `--app openssl --bundle`:

```
$ trustprune allowlist --file allowlist.yaml
$ trustprune allowlist --file allowlist.yaml --app openssl --bundle /path/to/ca-bundle.pem
```

Generation verifies chains against the system trust store, not against a PEM bundle you may later apply the allowlist to. CAs present only in that bundle are not discovered. `allowlist` still backs up the target store first.

### Browser history

Either all browsers `--from browser` or specific browsers `--from chrome`.

```
$ trustprune gen-allowlist --from browser --out wh.yaml
CA             SHA256-FINGERPRINT  COUNT  EXAMPLE-DNS-NAMES
GeoTrust Inc.  ff856a2d251dcd88    13     plus.google.com, accounts.google.com, hangouts.google.com
...

$ trustprune gen-allowlist --from chrome --out wh.yaml
CA             SHA256-FINGERPRINT  COUNT  EXAMPLE-DNS-NAMES
GeoTrust Inc.  ff856a2d251dcd88    13     plus.google.com, accounts.google.com, hangouts.google.com
...

$ trustprune gen-allowlist --out allowlist.yaml --from firefox
```

### Blocklisted certificates

`trustprune` includes the [Chromium certificate blocklist](https://chromium.googlesource.com/chromium/src/+/main/net/data/ssl/blocklist/) to never allowlist certificates which are generally regarded by the industry as untrusted. Certificate PEM files in that directory are matched by the SHA-256 of the certificate DER, including leaf and intermediate certificates, not only roots. Standalone public-key files (`.key`) are matched by the SHA-256 of the SubjectPublicKeyInfo, so any certificate that uses one of those keys is blocked. Hashes are computed from the file bytes, never from the filename.

It also includes a Mozilla blocklist generated from [certdata.txt](https://raw.githubusercontent.com/mozilla-firefox/firefox/main/security/nss/lib/ckfw/builtins/certdata.txt). That list matches the same way. It contains certificates marked `CKT_NSS_NOT_TRUSTED` for server authentication, and roots whose `CKA_NSS_SERVER_DISTRUST_AFTER` date has passed. The date is recorded on those entries. A root whose distrust-after date is still in the future is omitted until `make generate` runs again after that date.

It also includes an Apple blocklist generated from the [Blocked Certificates](https://support.apple.com/en-us/103255) table on Apple's "CA certificates with additional constraints" page. That list matches certificate SHA-256 fingerprints. Certificates Apple only constrains, rather than blocks, are left out. HT204132 is the earlier Apple support article that described these lists.

It also includes fingerprints from the [CCADB Mozilla Removed CA Certificate Report](https://ccadb.my.salesforce-sites.com/mozilla/RemovedCACertificateReportCSVFormat) (listed from [CA/Removed Certificates](https://wiki.mozilla.org/CA/Removed_Certificates)). That list matches the report's SHA-256 Fingerprint column. The report has no structured removal-reason column. Every row is included except those whose Comments indicate the removal is only expiry or a voluntary / CA-requested withdrawal. Empty comments are kept. `make denylists` refreshes this list from the checked-in CSV.

`make generate` refreshes the Chromium, Mozilla, and Apple lists, and the CCADB removed-CA list, from checked-in testdata. It does not download. The Chromium archive is `pkg/allowlist/testdata/chromium-ssl-blocklist.tar.gz`; its commit and date are recorded in `pkg/allowlist/blocklist.go`.

There is currently no way to disable this behavior.

### Denylisted certificates

A smaller denylist is always applied as well, including when an allowlist names the certificate by fingerprint or by country. It covers roots and intermediates that were publicly distrusted: DigiNotar, CNNIC, WoSign, StartCom, Symantec legacy roots (GeoTrust, thawte, and VeriSign roots removed from Mozilla NSS), the compromised eMudhra G3 intermediates, DYMO Root CA (for localhost), and the Sennheiser HeadSetup roots. The entries are committed in `pkg/allowlist/denylist.go`.

Each entry has two SHA-256 values: the certificate itself, and the certificate's SubjectPublicKeyInfo. A later certificate that reuses a denylisted key is rejected even though its own fingerprint is new. `gen-allowlist` skips these CAs and prints a `NOTE:` line. They are not written to the allowlist file. There is no flag to turn this off.

The list is hand-curated. `go generate ./pkg/allowlist` prints how to refresh it and does not download anything. Recompute a fingerprint from the source named on that entry before adding it, and leave it out when you are not sure. Tests do not use the network.

### Files

`trustprune` can also generate allowlists from a given file. This could be a text file with a url on each line, or a comma separated file with urls in one column per row.

##### Plain text files

```
$ cat urls.txt
https://google.com
https://yahoo.com
https://bing.com

$ trustprune gen-allowlist --out wh.yaml --file urls.txt
CA                              SHA256-FINGERPRINT  COUNT  EXAMPLE-DNS-NAMES
DigiCert Inc, www.digicert.com  7431e5f4c3c1ce46    1      yahoo.com
Baltimore, CyberTrust           16af57a9f676b0ab    1      bing.com
GeoTrust Inc.                   ff856a2d251dcd88    1      google.com

$ cat wh.yaml
fingerprints:
    - 7431e5f4c3c1ce4690774f0b61e05440883ba9a01ed00ba6abd7806ed3b118cf
    - 16af57a9f676b0ab126095aa5ebadef22ab31119d644ac95cd4b93dbf3f26aeb
    - ff856a2d251dcd88d36656f450126798cfabaade40799c722de4d2b5db36a73a
```


##### CSV files

There are several services which offer "Top N Domains" lists, such as the [Tranco list](https://tranco-list.eu/). These are usually `rank,domain` CSV files. `gen-allowlist --file` reads that format directly and prefixes `https://` onto each domain. Keep only the top N rows you want to scan (for example with `head`). The file may also be gzip-compressed. One `https://` URL per line still works.

```
$ unzip -p tranco.zip | head -n 1000 > top-sites.csv
$ trustprune gen-allowlist --out wh.yaml --file top-sites.csv
CA                              SHA256-FINGERPRINT  COUNT  EXAMPLE-DNS-NAMES
DigiCert Inc, www.digicert.com  7431e5f4c3c1ce46    1      yahoo.com
Baltimore, CyberTrust           16af57a9f676b0ab    1      bing.com
GeoTrust Inc.                   ff856a2d251dcd88    1      google.com
...
```

## Go library

`github.com/adamdecaf/trustprune/pkg/certpool` returns an `*x509.CertPool` with an allowlist applied.

`New` starts from the trusted certificates in the system store, the same platform store `trustprune list` reads. `FromFile` reads a PEM bundle from a path and skips blocks that are not `CERTIFICATE`. An unreadable file, a `CERTIFICATE` block that fails to parse, or a file with no certificates returns an error. `FromCertificates` starts from a `[]*x509.Certificate` the caller already has. A certificate is kept only when `Allowlist.Matches` accepts it: SHA-256 fingerprint, country code, and the built-in Chromium, Mozilla, Apple, and CCADB removed-CA blocklists and denylist. See [Blocklisted certificates](#blocklisted-certificates) and [Denylisted certificates](#denylisted-certificates).

The system store is only read. `New` lists certificates and returns a new pool. `FromFile` reads only the path you pass. An allowlist that matches nothing yields an empty pool. Set that pool as `tls.Config.RootCAs` so verification uses the kept certificates.

```go
package main

import (
	"crypto/tls"
	"log"
	"net/http"

	"github.com/adamdecaf/trustprune/pkg/allowlist"
	"github.com/adamdecaf/trustprune/pkg/certpool"
)

func main() {
	al, err := allowlist.FromFile("allowlist.yaml")
	if err != nil {
		log.Fatal(err)
	}

	pool, err := certpool.New(al)
	if err != nil {
		log.Fatal(err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				RootCAs:    pool,
			},
		},
	}
	resp, err := client.Get("https://example.com")
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
}
```

The same filter for certificates you already hold:

```go
pool := certpool.FromCertificates(al, certs)
```

The same filter for a PEM bundle on disk:

```go
pool, err := certpool.FromFile(al, "roots.pem")
if err != nil {
	log.Fatal(err)
}
```
