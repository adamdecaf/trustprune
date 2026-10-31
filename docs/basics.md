---
layout: default
title: Basics
---

## Add

`trustprune` can add certificates into a given trust store with the `add` sub command.

```
$ trustprune add -file cert.pem

$ trustprune add -file cert.pem -app java
```

## Connect

The `connect` command allows you to verify connectivity with a remote host using the certificates from a given store. This allows you to quickly verify if applying an allowlist (or restoring) worked.

```
$ ./trustprune connect https://google.com
Connection to https://google.com passed!

$ ./trustprune connect -app java https://google.com
Connection to https://google.com passed!
```

## List

The cli sub-command `list` will output a list of certificates installed (and trusted) in the certificate store. This option defaults to the platform (Linux, OSX, or Windows), but can be switched to an application via the `-app` flag.

Show certificates installed in the platform:

```
$ trustprune list
Certificate
  SHA256 Fingerprint - 1a5174980a294a528a110726d5855650266c48d9883bea692b67b6d726da98c5
  SerialNumber: 26471149583208131559647911801012699958
  Subject: The USERTRUST Network
  Issuer: AddTrust AB, AddTrust External TTP Network
  NotBefore - 2000-05-30 10:48:38 +0000 UTC, NotAfter - 2020-05-30 10:48:38 +0000 UTC
  IsCA - true
  CRLDistributionPoints
    http://crl.usertrust.com/AddTrustExternalCARoot.crl
...
```

Show certificates installed for an application

```
$ trustprune list -app firefox
Certificate
  SHA256 Fingerprint - 1a5174980a294a528a110726d5855650266c48d9883bea692b67b6d726da98c5
  SerialNumber: 26471149583208131559647911801012699958
  Subject: The USERTRUST Network
  Issuer: AddTrust AB, AddTrust External TTP Network
  NotBefore - 2000-05-30 10:48:38 +0000 UTC, NotAfter - 2020-05-30 10:48:38 +0000 UTC
  IsCA - true
  CRLDistributionPoints
    http://crl.usertrust.com/AddTrustExternalCARoot.crl
...
```

`-format table` prints an aligned table. Columns are Subject, Issuer, KEY, DAYS, SHA256 Fingerprint (16-character preview), Not Before, and Not After. Pass `-v` for the full fingerprint, serial, and source or store path (`-` for URLs).

```
$ trustprune list -format table
Subject                                                                 Issuer                                                                  KEY       DAYS SHA256 Fingerprint Not Before Not After
AC RAIZ FNMT-RCM SERVIDORES SEGUROS                                     AC RAIZ FNMT-RCM SERVIDORES SEGUROS                                     ECDSA-384 6258 554153b13d2cf9dd   2018-12-20 2043-12-20
ACCVRAIZ1                                                               ACCVRAIZ1                                                               RSA-4096  1521 9a6ec012e1a7da9d   2011-05-05 2030-12-31
Actalis Authentication Root CA                                          Actalis Authentication Root CA                                          RSA-4096  1421 55926084ec963a64   2011-09-22 2030-09-22
...
```

If openssl is installed you can output certificates in that format (via `-format openssl`).

```
$ trustprune list -app firefox -format openssl
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

`trustprune` can list certificates from a given URL. Supported formats are PEM and [certdata.txt](https://wiki.mozilla.org/CA/Included_Certificates)

```
$ trustprune list -url https://hg.mozilla.org/mozilla-central/raw-file/tip/security/nss/lib/ckfw/builtins/certdata.txt
Certificate
  SHA256 Fingerprint - ebd41040e4bb3ec742c9e381d31ef2a41a48b6685c96e7cef3c1df6cd4331c99
  SerialNumber: 4835703278459707669005204
  Subject: GlobalSign Root CA
  Issuer: GlobalSign Root CA
  NotBefore - 1998-09-01 12:00:00 +0000 UTC, NotAfter - 2028-01-28 12:00:00 +0000 UTC
  IsCA - true
...
```

### TLS observatory

`trustprune` supports `-format observatory` which outputs certificates in a format supported by [nabla-c0d3/trust_stores_observatory](https://github.com/nabla-c0d3/trust_stores_observatory).

```
$ trustprune list -format observatory -app chrome
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

### Web

`trustprune` can present certificates on a local web page with `-ui web` passed to any command.

```
$ trustprune list -app java -ui web
```

<img src="./images/web.png" />

## Backup and Restore

It's important to be able to rollback changes to your certificate store. These changes can be dangerous if done incorrectly as many websites you visit might partially quit loading.

To capture a backup:

```
$ trustprune backup
Backup completed successfully

$ trustprune backup -app java
Backup completed successfully
```

Backups can be used as restore points.

```
# Restore from the latest backup
$ trustprune restore -app chrome
```
