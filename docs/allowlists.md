---
layout: default
title: Allowlists
---

# Allowlists

## Allowlisting

### Configuration

Allowlists represent an operation which disables certificate trust in a certificate store. The filters presented for an allowlist are:

- `Fingerprints`: The SHA256 fingerprint of a certificate. This value will be unique across certificates given their contents are unique.
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
  "Fingerprints": [
    "050cf9fa95e40e9bddedaeda6961f6168c1279c4660172479cdd51ab03cea62c"
  ],
  "Countries": [
    "GB"
  ]
}
```

To apply an allowlist against a platform:

```
$ trustprune allowlist -file wh.json
Allowlist completed successfully
```

You can also apply an allowlist against an application's certificate store:

```
$ trustprune allowlist -file wh.json -app java
Allowlist completed successfully
```

The older `whitelist` command name remains as a hidden alias.


## Generating allowlists

`trustprune` supports generating allowlists from browser history. Either all browsers `-from browser` or specific browsers `-from chrome`.

`-out` is required. Without it, `gen-allowlist` prints `ERROR: -out is required` and exits with status 2. With `-out` but neither `-from` nor `-file`, it prints usage and exits 1. The `-out` extension picks the format: `.json` writes JSON; `.yaml` or `.yml` writes YAML.

```
$ trustprune gen-allowlist -from browser -out wh.yaml
CA                                             Fingerprint      Count Example DNSNames
GeoTrust Inc.                                  ff856a2d251dcd88 13    plus.google.com, accounts.google.com, hangouts.google.com
...

$ trustprune gen-allowlist -from chrome -out wh.yaml
CA                                             Fingerprint      Count Example DNSNames
GeoTrust Inc.                                  ff856a2d251dcd88 13    plus.google.com, accounts.google.com, hangouts.google.com
...
```

The older `gen-whitelist` command name remains as a hidden alias.

### Blocklisted certificates

`trustprune` includes the [Chromium certificate blocklist](https://chromium.googlesource.com/chromium/src/+/main/net/data/ssl/blocklist/) to never allowlist certificates which are generally regarded by the industry as untrusted.

There is currently no way to disable this behavior.

### Files

`trustprune` can also generate allowlists from a given file. This could be a text file with a url on each line, or a comma separated file with urls in one column per row.

##### Plain text files

```
$ cat urls.txt
https://google.com
https://yahoo.com
https://bing.com

$ trustprune gen-allowlist -out wh.yaml -file urls.txt
CA                             Fingerprint      Count Example DNSNames
DigiCert Inc, www.digicert.com 7431e5f4c3c1ce46 1     yahoo.com
Baltimore, CyberTrust          16af57a9f676b0ab 1     bing.com
GeoTrust Inc.                  ff856a2d251dcd88 1     google.com

$ cat wh.yaml
fingerprints:
    - 7431e5f4c3c1ce4690774f0b61e05440883ba9a01ed00ba6abd7806ed3b118cf
    - 16af57a9f676b0ab126095aa5ebadef22ab31119d644ac95cd4b93dbf3f26aeb
    - ff856a2d251dcd88d36656f450126798cfabaade40799c722de4d2b5db36a73a
```


##### CSV files

There are several services which offer "Top N Domains" lists, such as the [Tranco list](https://tranco-list.eu/). These are usually `rank,domain` CSV files. `gen-allowlist -file` reads that format directly and prefixes `https://` onto each domain. Keep only the top N rows you want to scan (for example with `head`). The file may also be gzip-compressed. One `https://` URL per line still works.

```
$ unzip -p tranco.zip | head -n 1000 > top-sites.csv
$ trustprune gen-allowlist -out wh.yaml -file top-sites.csv
CA                             Fingerprint      Count Example DNSNames
DigiCert Inc, www.digicert.com 7431e5f4c3c1ce46 1     yahoo.com
Baltimore, CyberTrust          16af57a9f676b0ab 1     bing.com
GeoTrust Inc.                  ff856a2d251dcd88 1     google.com
...
```
