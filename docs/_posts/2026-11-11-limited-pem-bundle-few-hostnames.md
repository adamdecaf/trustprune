---
layout: post
title: "A limited PEM bundle for a few hostnames"
date: 2026-11-11
nav_exclude: true
---

Default CA trust stores are large. On this machine, the OpenSSL bundle at `/etc/ssl/certs/ca-certificates.crt` holds 148 certificates and occupies 222,073 bytes. A small server that only talks to a few hostnames does not need all of them.

`trustprune gen-allowlist --hosts` builds an allowlist from those hostnames. `trustprune allowlist --app openssl --bundle` applies it to a PEM file. The walkthrough below uses a *copy* of the system bundle so the live store is left alone.

## Build the allowlist

Copy the bundle, then see how many CAs it has:

```bash
cp /etc/ssl/certs/ca-certificates.crt /tmp/service-ca-bundle.pem
trustprune list --app openssl --bundle /tmp/service-ca-bundle.pem --count
```

```
148
```

Suppose the service only needs `example.com`, `pypi.org`, and `github.com`. `--no-presets` skips the default platform hosts (apt repos on Linux, Apple or Windows update hosts on those OSes) so the allowlist is just those three:

```bash
trustprune gen-allowlist --out allowlist.yaml --hosts example.com,pypi.org,github.com --no-presets
```

```
CA                                            Fingerprint      Count Example DNSNames
SSL.com TLS ECC Root CA 2022                  c32ffd9f46f936d1 1     example.com
GlobalSign                                    cbb522d7b7f127ad 1     pypi.org
Sectigo Public Server Authentication Root E46 c90f26f0fb1b4018 1     github.com
```

`--out` is required. Without it, `gen-allowlist` prints `required flag --out not set` and exits 2. The file is a list of SHA-256 fingerprints, not hostnames:

```yaml
fingerprints:
    - c32ffd9f46f936d16c3673990959434b9ad60aafbb9e7cf33654f144cc1ba143
    - cbb522d7b7f127ad6a0113865bdf1cd4102e7d0759af635a7cf4720dc963c53b
    - c90f26f0fb1b4018b22227519b5ca2b53e2ca5b3be5cf18efe1bef47380c5383
```

Those CAs were observed on 11 November 2026. A host can rotate to a different root. Re-generate the allowlist periodically, and again if a needed site starts failing verification. Before applying the new allowlist, restore the original bundle: allowlisting only keeps CAs already in the file, so it cannot add a root that was removed. If the original bundle does not contain the new root, obtain a suitable trusted bundle first, then regenerate, apply, and verify the host.

## Apply it to the PEM copy

`allowlist` will not write without a backup for that store. Work on the copy, and preview first:

```bash
trustprune backup --app openssl --bundle /tmp/service-ca-bundle.pem --dry-run
```

```
dry-run: would backup openssl at /tmp/service-ca-bundle.pem
  copy /tmp/service-ca-bundle.pem into $HOME/.trustprune/openssl/<timestamp>/ca-bundle.pem
  record the bundle path in source
dry-run: no changes made
```

```bash
trustprune backup --app openssl --bundle /tmp/service-ca-bundle.pem
```

```
Backup completed successfully: $HOME/.trustprune/openssl/1794450129
```

Without that backup, allowlisting fails immediately:

```
ERROR: no backup for openssl in ~/.trustprune/openssl; run: trustprune backup --app openssl
```

Preview the removals, then apply:

```bash
trustprune allowlist --file allowlist.yaml --app openssl --bundle /tmp/service-ca-bundle.pem --dry-run
```

```
dry-run: would remove certificates from openssl at /tmp/service-ca-bundle.pem
  remove ACCVRAIZ1 (SHA256 9a6ec012e1a7da9dbe34194d478ad7c0db1822fb071df12981496ed104384113)
  remove FNMT-RCM, AC RAIZ FNMT-RCM (SHA256 ebc5570c29018c4d67b1aa127baf12f703b4611ebc17b7dab5573894179b93fa)
  ...
dry-run: no changes made
```

The dry-run lists every certificate that would be removed. That is a long list on a default bundle; only the first rows are shown here.

```bash
trustprune allowlist --file allowlist.yaml --app openssl --bundle /tmp/service-ca-bundle.pem
trustprune list --app openssl --bundle /tmp/service-ca-bundle.pem --count
```

```
Allowlist completed successfully
3
```

The copy is now 2,897 bytes. Chromium's certificate blocklist is applied as well, and cannot be turned off.

## Check the bundle, then restore

`trustprune connect` has no `--bundle` flag. Point the process that will use the PEM at the file. With curl 8.14.1 linked against OpenSSL, `--cacert` alone still loaded the default CA store, so other sites kept verifying. Passing an empty `--capath` directory isolates the bundle:

```bash
empty_capath=$(mktemp -d)
curl --cacert /tmp/service-ca-bundle.pem --capath "$empty_capath" -sS -o /dev/null --max-time 20 -w '%{http_code}\n' https://example.com/
curl --cacert /tmp/service-ca-bundle.pem --capath "$empty_capath" -sS -o /dev/null --max-time 20 -w '%{http_code}\n' https://www.wikipedia.org/
```

`https://example.com/` returned `200`. `https://www.wikipedia.org/` failed with curl exit 60:

```
curl: (60) SSL certificate problem: unable to get local issuer certificate
```

`openssl s_client -CAfile /tmp/service-ca-bundle.pem -verify_return_error` agreed: example.com verified; wikipedia.org chained to ISRG Root X2, which is not in the three-CA bundle.

The allowlist keeps CAs, not hostnames. Any other site that chains to one of those three roots will still verify. Sites that need a different root will fail. That is expected, and it is why a host rotating CAs means you restore the original bundle, re-generate, and apply again.

To put the copy back:

```bash
trustprune restore --app openssl --bundle /tmp/service-ca-bundle.pem --dry-run
trustprune restore --app openssl --bundle /tmp/service-ca-bundle.pem
trustprune list --app openssl --bundle /tmp/service-ca-bundle.pem --count
```

```
dry-run: would restore openssl at /tmp/service-ca-bundle.pem
  source $HOME/.trustprune/openssl/1794450129/ca-bundle.pem
  stage into /tmp/service-ca-bundle.pem.restore-tmp then swap over /tmp/service-ca-bundle.pem
dry-run: no changes made
Restore completed successfully: /tmp/service-ca-bundle.pem
148
```

## When to keep platform presets

Without `--no-presets`, generation also includes the default platform preset for this OS: apt HTTPS indexes on Linux, Apple service and software-update hosts on macOS, Windows update and download hosts on Windows. Pass `--presets linux` (or `darwin` / `windows`) to target another OS, for example when you build a Linux-server allowlist on a Mac.

The same three hosts plus `--presets linux` produced five CAs, not three. The extras were ISRG Root X1 (for hosts such as `deb.debian.org`, `security.debian.org`, and `download.rockylinux.org`) and DigiCert Global Root G3 (`download.fedoraproject.org`). Keep that preset if the machine still needs to talk to those package indexes.

There is no time-server preset. `gen-allowlist` only dials HTTPS, and the usual OS time servers speak NTP on UDP/123. Asking for one is a usage error:

```bash
trustprune gen-allowlist --out allowlist.yaml --presets time
```

```
unknown preset "time"
run 'trustprune gen-allowlist --help' for usage
```

That command exits 2. Adding NTP hostnames would not discover a CA.

## Caveats

Generation verifies chains against the system trust store, not against the PEM you may later allowlist. CAs that exist only in that target bundle are not discovered.

The allowlist is a set of CA fingerprints, so it is broader than "exactly these hostnames." Restore the original bundle, re-generate periodically and whenever a needed host changes CA, then apply and verify.

Always back up first. Prefer a copy of the bundle, `--dry-run`, and `restore` if something breaks.

See [Allowlists](/allowlists) and [Usage](/usage) for the full flag list.

Changing CA trust stores can break TLS, cut off access and reduce security, so back up first and proceed at your own risk. trustprune is provided as is, with no warranty, under the Apache License 2.0, and its authors and contributors accept no liability.
