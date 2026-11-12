---
layout: default
title: Basics
nav_order: 3
---

Subcommands other than `connect` accept only flags. An unexpected positional argument is rejected with exit status 2 before any write. Flags after a positional argument are still parsed, so a stray extra argument with `--dry-run` after it is still a usage error. A shell glob that expands into multiple files can cause that.

## Add

`trustprune` can add certificates into a given trust store with the `add` sub command.

```
$ trustprune add --file cert.pem

$ trustprune add --file cert.pem --app java

$ trustprune add --file cert.pem --app certifi --store /path/to/cacert.pem
```

`--file` is the certificate to import. `--store` selects a Java keystore or a certifi `cacert.pem`. `--store` alone is not the certificate file.

## Connect

The `connect` command allows you to verify connectivity with a remote host using the certificates from a given store. This allows you to quickly verify if applying an allowlist (or restoring) worked.

```
$ ./trustprune connect https://google.com
Connection to https://google.com passed!

$ ./trustprune connect --app java https://google.com
Connection to https://google.com passed!

$ ./trustprune connect --app java --store /path/to/cacerts https://google.com
Connection to https://google.com passed!

$ ./trustprune connect --url https://google.com
Connection to https://google.com passed!
```

| Flag | Meaning |
|------|---------|
| `--app <name>` | Use that application's certificates for the TLS handshake |
| `--store <path>` | With `--app java` or `--app certifi`: load that store instead of discovery (same override as `list` / `backup` / `restore`) |
| `--url <url>` | URL to connect to, instead of the positional argument |

## List

The cli sub-command `list` will output a list of certificates installed (and trusted) in the certificate store. This option defaults to the platform (Linux, OSX, or Windows), but can be switched to an application via the `--app` flag. `--out <path>` writes that formatted output to a file for every format and for `--count`. Stdout stays empty.

Show certificates installed in the platform. The default format is a table with uppercase headers SUBJECT, ISSUER, KEY, DAYS, and SHA256-FINGERPRINT (16-character preview). SUBJECT and ISSUER are capped at 40 characters and end with `…` when cut; ISSUER shows `=` when the full issuer name matches the subject (self-signed roots). DAYS shows `expired` when the certificate is past `NotAfter`, `N!` when fewer than 90 days remain, and the plain day count otherwise.

```
$ trustprune list
SUBJECT                                  ISSUER KEY       DAYS SHA256-FINGERPRINT
EE Certification Centre Root CA          =      RSA-2048  1811 3e84ba4342908516
Entrust Root Certification Authority     =      RSA-2048  330  73c176434f1bc6d5
Entrust Root Certification Authority - … =      ECDSA-384 4369 02ed0eb28c14da45
...
```

`-v` applies to that default table. It shows the full fingerprint, serial, source or store path (`-` for URLs), and the dates. DAYS stays numeric. Verbose headers are SHA256-FINGERPRINT, SERIAL, PATH, NOT-BEFORE, and NOT-AFTER.

```
$ trustprune list -v
SUBJECT                                  ISSUER KEY       DAYS SHA256-FINGERPRINT                                               SERIAL                                  PATH              NOT-BEFORE NOT-AFTER
EE Certification Centre Root CA          =      RSA-2048  1811 3e84ba4342908516e77573c0992f0979ca084e4685681ff195ccba8a229b8a76 112324828676200291871926431888494945866 testdata/lots.crt 2010-10-30 2030-12-17
...
```

`--format long` prints each certificate as a multi-line dump. Empty optional fields stay hidden.

```
$ trustprune list --format long
Certificate
  SHA256 Fingerprint: 6dc47172e01cbcb0bf62580d895fe2b8ac9ad4f873801e0c10b9c837d21eb177
  SerialNumber: 946069240
  Subject: Entrust.net Certification Authority (2048)
  Issuer: Entrust.net Certification Authority (2048)
  NotBefore: 1999-12-24 17:50:51 +0000 UTC | NotAfter: 2029-07-24 14:15:12 +0000 UTC
  KEY: RSA-2048
  DAYS: 1300
  IsCA: true
...
```

Show certificates installed for an application. The same default table is used.

```
$ trustprune list --app firefox
```

Point `--store` at a venv certifi bundle or a Java keystore:

```
$ trustprune list --app certifi --store /path/to/venv/.../cacert.pem
$ trustprune list --app java --store /path/to/cacerts
```

Without `--app`, `--file` lists certificates from a PEM file (`trustprune list --file lots.crt`). `--file` cannot be combined with `--app`; use `--store` to override a java or certifi path.

If openssl is installed you can output certificates in that format (via `--format openssl`).

```
$ trustprune list --app firefox --format openssl
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            f0:1d:4b:ee:7b:7c:a3:7b:3c:05:66:ac:05:97:24:58
        Signature Algorithm: sha384WithRSAEncryption
        Issuer: C=GB, ST=Greater Manchester, L=Salford, O=COMODO CA Limited, CN=COMODO RSA Certification Authority
        Validity
            Not Before: May 18 00:00:00 2015 GMT
            Not After : May 17 23:59:59 2025 GMT
        Subject: C=US, ST=TX, L=Houston, O=cPanel, Inc., CN=cPanel, Inc. Certification Authority
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
            RSA Public Key: (2048 bit)
                Modulus (2048 bit):
                    00:8b:5e:01:56:b9:ec:6b:11:ef:48:e9:43:9e:9b:
                    ...
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Authority Key Identifier:
                keyid:BB:AF:7E:02:3D:FA:A6:F1:3C:84:8E:AD:EE:38:98:EC:D9:32:32:D4

            X509v3 Subject Key Identifier:
                7E:03:5A:65:41:6B:A7:7E:0A:E1:B8:9D:08:EA:1D:8E:1D:6A:C7:65
            X509v3 Key Usage: critical
                Digital Signature, Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Extended Key Usage:
                TLS Web Server Authentication, TLS Web Client Authentication
            X509v3 Certificate Policies:
                Policy: 1.3.6.1.4.1.6449.1.2.2.52
                Policy: 2.23.140.1.2.1

            X509v3 CRL Distribution Points:
                URI:http://crl.comodoca.com/COMODORSACertificationAuthority.crl

            Authority Information Access:
                CA Issuers - URI:http://crt.comodoca.com/COMODORSAAddTrustCA.crt
                OCSP - URI:http://ocsp.comodoca.com

    Signature Algorithm: sha384WithRSAEncryption
        10:9f:a0:60:08:81:74:a1:a0:84:78:60:4c:39:39:da:64:77:
        ...
```

### URL

`trustprune` can list certificates from a given URL. Supported formats are PEM and [certdata.txt](https://wiki.mozilla.org/CA/Included_Certificates). Output uses the same formats as any other list (table by default).

```
$ trustprune list --url https://hg.mozilla.org/mozilla-central/raw-file/tip/security/nss/lib/ckfw/builtins/certdata.txt --format long
Certificate
  SHA256 Fingerprint: ebd41040e4bb3ec742c9e381d31ef2a41a48b6685c96e7cef3c1df6cd4331c99
  SerialNumber: 4835703278459707669005204
  Subject: GlobalSign Root CA
  Issuer: GlobalSign Root CA
  NotBefore: 1998-09-01 12:00:00 +0000 UTC | NotAfter: 2028-01-28 12:00:00 +0000 UTC
  IsCA: true
...
```

### TLS observatory

`trustprune` supports `--format observatory` which outputs certificates in a format supported by [nabla-c0d3/trust_stores_observatory](https://github.com/nabla-c0d3/trust_stores_observatory).

```
$ trustprune list --format observatory --app chrome
platform: Darwin (OSX)
version: 10.13.3
url: ""
date_fetched: 2018-02-13
trusted_certificates_count: 176
trusted_certificates:
- subject_name: AffirmTrust
  fingerprint: 0376ab1d54c5f9803ce4b2e201a0ee7eef7b57b636e8a93c9b8d4860c96f5fa7
...
```

`--out <path>` writes this report to a file. The same flag writes `table`, `long`, `json`, `openssl`, and `--count` output to a file. Stdout stays empty.

```
$ trustprune list --format observatory --out report.yaml
$ trustprune list --format json --out certs.json
```

### Web

`trustprune` can present certificates on a local web page with `--ui web` on `list` only (other commands ignore `--ui`). It prints the local URL (and still serves it) when a browser cannot be opened, such as on a headless host. Each certificate row shows Subject, Issuer, SHA256 fingerprint, serial, and validity dates; the full formatted dump stays behind Details.

```
$ trustprune list --app java --ui web
Web UI: http://127.0.0.1:12345/
```

<img src="./images/web.png" />

## Backup and Restore

It's important to be able to rollback changes to your certificate store. These changes can be dangerous if done incorrectly as many websites you visit might partially quit loading.

To capture a backup:

```
$ trustprune backup
Backup completed successfully: /home/you/.trustprune/linux/1513034181

$ trustprune backup --app java
Backup completed successfully: /home/you/.trustprune/java/cacerts-1513034181.bck
```

Backups can be used as restore points.

```
# Restore from the latest backup
$ trustprune restore --app chrome

# Java / certifi: --store is the store to restore into (same as backup/list).
$ trustprune restore --app java --store /path/to/cacerts
$ trustprune restore --app certifi --store /path/to/venv/.../cacert.pem

# Explicit backup path
$ trustprune restore --backup /path/to/backup
```
