# trustprune

[![CI](https://github.com/adamdecaf/trustprune/actions/workflows/ci.yml/badge.svg)](https://github.com/adamdecaf/trustprune/actions/workflows/ci.yml)

**Your machine trusts hundreds of Certificate Authorities by default. Most of them you have never heard of. One bad CA is enough to break HTTPS for everyone who trusts it.**

In October 2026, the private keys of eight [eMudhra](https://emudhra.com/en/post/certificate-security-incident) intermediate CAs were compromised. Six of them could issue TLS certificates for any website. [Apple blocked](https://support.apple.com/en-us/149555) those certificates in Safari and system frameworks starting 19 October 2026, and later blocked the emSign ECC Root CA - G3. Command-line tools that still read `/etc/ssl/cert.pem` (git, curl, python3, and others) kept trusting the compromised chains until users removed the roots by hand — and a subsequent macOS update can restore Apple's copy of that file. The pattern is old: DigiNotar, Symantec, WoSign, and many others. The CA system still ships with more trust than most people need, and removing it is still harder than it should be.

`trustprune` gives you a single CLI to **list**, **backup**, **allowlist** (distrust), and **restore** the CA trust stores on your platform and in apps such as Java, Chrome, and Firefox.

Trust should be earned, not defaulted.


## Renamed from cert-manage

This project was renamed from **cert-manage** to **trustprune**. The repository is now at [github.com/adamdecaf/trustprune](https://github.com/adamdecaf/trustprune) (old GitHub URLs redirect).

- The primary CLI binary is `trustprune`. A `cert-manage` alias remains through **0.2.x** and prints a short rename notice on stderr when invoked under that name.
- New backups are written under `~/.trustprune/` (or `~/Library/trustprune/` on Darwin). Existing backups under `~/.cert-manage/` or `~/Library/cert-manage/` are still discovered read-only for restore; nothing is moved, renamed, or deleted from the old tree. When both trees have entries, the newest basename wins (primary path preferred on ties). Prefer an explicit `restore --backup` path if you mix legacy NSS filename layouts.

## 30-second quickstart

```bash
# 1. See what you currently trust
trustprune list
trustprune list --count
trustprune list --app java
trustprune list --app java --store /path/to/cacerts          # skip JAVA_HOME search
trustprune list --app certifi --store /path/to/venv/.../cacert.pem

# 2. Always take a backup before changing trust
trustprune backup
trustprune backup --app java

# 3. Allowlist: keep only the CAs you want (requires a prior backup)
trustprune allowlist --file urls.yaml
trustprune allowlist --app java --file urls.yaml
trustprune allowlist --app java --store /path/to/cacerts --file allowlist.yaml

# 4. Roll back if something breaks
trustprune restore
trustprune restore --app java
```

Allowlist files are YAML or JSON. See [docs/allowlists.md](docs/allowlists.md) for fingerprints, country filters, and generating an allowlist from hostnames, platform presets, or browser history.

> **Safety first:** Prefer experimenting against temp or container stores when learning. Back up first, every time. See [Safety](#safety) and the [docs site](https://trustprune.com/).

## Features

| Command | What it does |
|---------|----------------|
| [list](docs/basics.md#list) | Show trusted certificates in a platform or app store (audit) |
| [backup](docs/basics.md#backup-and-restore) / [restore](docs/basics.md#backup-and-restore) | Capture and roll back CA trust |
| [allowlist](docs/allowlists.md#allowlisting) | Distrust certificates that are not on your allowlist |
| [add](docs/basics.md#add) | Add certificates to a store |
| [connect](docs/basics.md#connect) | Probe a remote HTTPS host using a chosen store |
| [gen-allowlist](docs/allowlists.md#generating-allowlists) | Build an allowlist from hostnames, platform presets, browser history, or URL lists |
| [apps](docs/usage.md#apps) | List supported app and OS stores with detection status and paths |
| [version](docs/usage.md#version) | Print the version |

Allowlisting also applies Chromium's certificate blocklist, so certificates in that bundled list are never kept. That behavior cannot be disabled today.

## Platform and application support

Honest status as of late October 2026. Levels match what the code does today.

### Platforms

| Level | Platform | Notes |
|-------|----------|--------|
| **Supported** | Linux (Alpine, Debian, Ubuntu, Rocky, Fedora/RHEL, Arch) | System CA dir list, add, allowlist, backup, restore (see Safety) |
| **Partial** | Darwin / macOS | Keychain-backed list/add/allowlist/backup/restore; system roots are SIP-protected; restore honors `--backup` for login-keychain backups |
| **List-only** | Windows | `list` works (PowerShell export of machine stores); add, backup, allowlist, and restore are not implemented yet |
| **Stub (CI)** | FreeBSD | Builds and runs unit/CLI tests under an empty HOME via `vmactions/freebsd-vm`; the platform store is a stub (list empty; live add/allowlist/backup/restore return "not implemented"). App stores (java/NSS/certifi/openssl) compile; no FreeBSD system CA backend yet |

### Applications

| Level | Application | Notes |
|-------|-------------|--------|
| **Supported** | Java (`cacerts`) | Paths differ by distro and JDK vendor; use `--app java`. Windows needs a usable `JAVA_HOME` / cacerts path. Missing `cacerts`, a directory in its place, or a wrong keystore password fails immediately. Keystore password defaults to `changeit`; set `TRUSTPRUNE_JAVA_STOREPASS` to override (custom values use `-storepass:env`, not argv; no CLI flag; no other passwords are guessed). |
| **Partial** | Chrome | Linux uses NSS (`~/.pki/nssdb`); Darwin/Windows wrap the platform store. |
| **Partial** | Firefox | NSS profile `cert8.db` / `cert9.db`. |
| **Supported** | Python certifi | Mozilla CA bundle used by requests and friends (`--app certifi`). Discovery via `certifi.where()`, pip vendored certifi, site-packages fallbacks; `--store` overrides the bundle on list/backup/connect/restore/add/allowlist. Restore records the bundle path and refuses a cross-path restore unless `--force`. |
| **Supported** | OpenSSL | CA bundle PEM files and OpenSSL cert directories (`--app openssl`): list/add/allowlist/backup/restore. Path order: `SSL_CERT_FILE`, `CURL_CA_BUNDLE`, distro/Homebrew defaults, then git `http.sslCAInfo`. `--bundle <pem>` selects an explicit PEM file for list, backup, restore, and allowlist and skips that discovery. PEM backups record the bundle path; restore into a different PEM (discovery or `--bundle`) is refused unless `--force`. Discovery allowlist accepts a backup recorded for the discovered PEM or a legacy backup with no `source` (a source-less backup may belong to another PEM and does not show the live file is recoverable). Hashed cert directories are not selected by `--bundle`. Darwin `/etc/ssl/cert.pem` stays `--app ssl`. |
| **Supported (Darwin)** | `ssl` (`/etc/ssl/cert.pem`) | list/add/allowlist/backup/restore for the CLI PEM bundle Apple keychain blocks do not cover; list uses a cryptobyte fallback for negative-serial certs Go rejects; truly unparsable PEM blocks stay skipped (stderr warning) and add/allowlist keep them when rewriting; see [platforms](https://trustprune.com/platforms) |



## Environment

| Variable | Meaning |
|----------|---------|
| `TRUSTPRUNE_JAVA_STOREPASS` | When set (non-empty after trim), used as the keystore password for every `keytool` call under `--app java`. Custom values are passed via keytool `-storepass:env` (child env + sudo --preserve-env) so the secret is not on the process or sudo command line; the default `changeit` still uses `-storepass changeit`. Requires keytool `-storepass:env` (JDK 6+). Leading/trailing whitespace is stripped; whitespace-only falls back to `changeit`. No other passwords are guessed; there is no CLI flag. Details: [usage](docs/usage.md#environment). |

## Safety

Certificate-store edits can break HTTPS for browsers, package managers, and language runtimes. Treat every change as privileged.

1. **Backup first.** Allowlisting without a prior backup fails on purpose. Run `trustprune backup` (and `--app …` when targeting an app) before any allowlist. `restore` (and `restore --dry-run`) with no backup for that store also refuses before any write and exits 1, for example `ERROR: no backup for openssl in ~/.trustprune/openssl; run: trustprune backup --app openssl`. Discovery-based OpenSSL restore (no `--bundle`) follows the discovered PEM: it uses a backup recorded for that file (a legacy backup with no `source` still matches) and refuses a backup recorded for a different bundle unless `--force`. Allowlist of a discovered PEM uses those same candidates, not merely the newest openssl backup. A legacy backup with no `source` may belong to another PEM and does not show the live file is recoverable. With `--bundle <pem>`, backup records that file and restore refuses a different path unless `--force`.
2. **Prefer temp or container stores** when experimenting. Do not point destructive tests at real `/etc` or `/usr` CA paths.
3. **Preview with `--dry-run`.** `add`, `backup`, `restore`, and `allowlist` accept `--dry-run` to print the plan without writing to any store. `allowlist --dry-run` lists kept certificates and ends with `dry-run: N kept, M removed`; `-v` adds per-certificate remove and keep lines.
4. **Elevation on Linux/unix.** CA refresh and root-owned file copies escalate with `sudo` when present on `PATH`, otherwise `su root -c …`. Already-root processes run the command directly. Password prompts use the controlling TTY; non-interactive hosts need cached credentials or a root shell.
5. **No stray positionals.** Commands other than `connect` accept only flags. An unexpected positional argument is rejected with exit 2 before any write (`unexpected argument(s): …`). Flags after a positional are still parsed, so `trustprune add --file x.pem extra --dry-run` is still a usage error and does not write. A shell glob that expands to more than one file can produce those extra arguments and is rejected the same way.

Linux restore uses a temp-dir-then-swap so a failed restore leaves the live CA directory intact. Explicit backup paths use `--backup`. For java and certifi, restore `--store` is the store to restore into, matching backup/list; a backup taken from a different path is refused unless `--force`. For openssl, `--bundle <pem>` is the live PEM for list, backup, restore, and allowlist; `--backup` is the backup source, and a backup recorded for a different PEM is refused unless `--force`. NSS backups copy `cert9.db` / `cert8.db` and related profile files. Darwin platform restore honors `--backup` for the login-keychain backup directory. Full detail: [Backup and restore](https://trustprune.com/backup-restore).

## Install

Download a binary from the [latest release](https://github.com/adamdecaf/trustprune/releases) (tagged `0.1.0` still ships `cert-manage` and predates `allowlist` / `apps` / `--dry-run`; module version on `master` is `0.1.1-dev`), or build from source (Go **1.27** required) for current commands:

```bash
git clone https://github.com/adamdecaf/trustprune.git
cd trustprune
make build          # produces ./trustprune (+ cert-manage symlink)
# or cross-compile:
make dist           # linux / osx / windows binaries under bin/
```

You can also install with the Go toolchain:

```bash
go install github.com/adamdecaf/trustprune@master
```

`@master` tracks current docs/commands (tagged `@latest` / `0.1.0` is still the pre-rename `cert-manage` release). That installs a binary named `trustprune` (Go uses the last path element). `make build` also creates a local `cert-manage` symlink alias (supported through 0.2.x).

### Usage examples

```bash
# Platform store
trustprune list
trustprune list --format table       # short (default), table, json, openssl, observatory
trustprune list --format openssl
trustprune list --format json --out certs.json          # --out writes every list format and --count; stdout stays empty
trustprune list --format observatory --out report.yaml
trustprune list --ui web             # cli (default) or web (prints URL if headless)

# Apps
trustprune list --app java
trustprune list --app chrome
trustprune list --app firefox

# From a file or Mozilla certdata URL
trustprune list --file example.crt
trustprune list --url https://hg.mozilla.org/mozilla-central/raw-file/tip/security/nss/lib/ckfw/builtins/certdata.txt

# Add
trustprune add --file cert.pem
trustprune add --file cert.pem --app java
trustprune add --file cert.pem --app certifi --store /path/to/cacert.pem

# Allowlist, backup, restore
trustprune backup
trustprune allowlist --file urls.yaml
trustprune restore                 # latest backup
trustprune restore --backup <path>  # explicit backup path
trustprune restore --app java --store /path/to/cacerts   # java/certifi: store to restore into

# Generate an allowlist
trustprune gen-allowlist --out allowlist.yaml --hosts example.com,api.example.com
trustprune gen-allowlist --out allowlist.yaml --hosts example.com --no-presets
trustprune gen-allowlist --out allowlist.yaml --presets linux
trustprune gen-allowlist --out allowlist.yaml --from firefox
trustprune gen-allowlist --out allowlist.yaml --from browsers
trustprune gen-allowlist --out allowlist.yaml --file urls.txt
# --out is required: without it, gen-allowlist prints "required flag --out not set" and exits with status 2
# Apply the result with the existing allowlist command (optionally a PEM bundle):
#   trustprune allowlist --file allowlist.yaml
#   trustprune allowlist --file allowlist.yaml --app openssl --bundle /path/to/ca-bundle.pem

# Verify connectivity after a change
trustprune connect https://example.com
trustprune connect --app java https://example.com

trustprune version
# No subcommand prints usage and exits 0; an unknown --app (e.g. --app nope) exits 1 and lists the valid apps
```

More detail: [docs/basics.md](docs/basics.md), [docs/allowlists.md](docs/allowlists.md).

## Building and testing

Go **1.27** is required (`go.mod`).

```bash
make build          # vet + unit tests + binary
make test           # full suite (uses Docker when available)
make coverage-floor # pkg/store >= 40%, pkg/cmd >= 35% (also run in CI)
MOCKED=true make test   # skip Docker-backed tests
```

Backup/restore tests use **temp directories only** and refuse paths under `/etc` or `/usr`. Do not point destructive tests at a real system CA directory.

Cross-platform binaries: `make linux`, `make osx`, `make win`, or `make dist`. CI cross-compiles `linux`/`darwin`/`windows` (`amd64`/`arm64`), runs unit tests on Ubuntu/macOS/Windows (including arm64 runners) and FreeBSD (via `vmactions/freebsd-vm` under an empty HOME), and runs Alpine/Debian/Ubuntu/Rocky/Fedora/Arch plus Firefox/Chrome Docker distro suites.

## Contributing

Help with docs, bugfixes, tests, and new or deeper store support is welcome. One focused PR at a time works best.

1. Fork and clone the repo.
2. Use Go 1.27; run `make build` and `make test` (or `MOCKED=true make test`) before opening a PR.
3. Prefer temp / container stores in tests — never point destructive tests at a real system CA directory.

This project follows the [Google Code of Conduct](https://opensource.google.com/conduct/).

## Why this matters

Research keeps showing that default trust stores are larger than most users need:

- [Analysis of the HTTPS Certificate Ecosystem](docs/papers/https-imc13.pdf) (2013) — more than **1,800 entities** able to issue certificates for any website; compromise of one intermediate would force ~26% of HTTPS sites to re-issue.
- [CAge — Taming Certificate Authorities by Inferring Restricted Scopes](docs/papers/cage-fc13.pdf) — simple inference rules cut attack surface nearly tenfold without blocking most CA activity.
- [You Won't Be Needing These Any More: On Removing Unused Certificates From Trust Stores](docs/papers/on-removing-unused-certs.pdf) — only about two-thirds of trusted roots were observed signing HTTPS certificates.

Incidents keep showing the same pattern: one bad or unwanted root is enough to break HTTPS for everyone who trusts it. Browsers and vendors react after the fact; a CLI that can **list**, **backup**, **allowlist**, and **restore** trust stores is how you take that control yourself. A non-exhaustive sample of cases that justify that tooling (not a complete history of CA failures):

- **[DigiNotar (2011)](https://www.mozilla.org/en-US/security/advisories/mfsa2011-34/):** After fraudulent certificates — including a `*.google.com` wildcard used in active MITM attacks — were issued from DigiNotar’s CA, Mozilla [removed the DigiNotar root](https://blog.mozilla.org/security/2011/09/02/diginotar-removal-follow-up/) from its products. Anyone still trusting that root in a local store remained exposed until they removed it.
- **[Lenovo Superfish (2015)](https://blog.mozilla.org/security/2015/02/27/getting-superfish-out-of-firefox/):** Preinstalled adware installed a shared root CA (with a recoverable private key) into Windows and Firefox trust stores, so anyone with that key could impersonate any HTTPS site on affected machines. Users had to find and remove a vendor-installed root that browsers had not shipped.
- **[Dell eDellRoot (2015)](https://www.kb.cert.org/vuls/id/870761):** Dell Foundation Services installed the `eDellRoot` certificate *and its private key* into the Windows Trusted Root store, enabling MITM and spoofing. Microsoft later marked it untrusted via CTL updates; operators still needed to remove the root and stop the component that reinstalled it.
- **[CNNIC / MCS intermediate (2015)](https://blog.mozilla.org/security/2015/03/23/revoking-trust-in-one-cnnic-intermediate-certificate/):** CNNIC issued an unconstrained intermediate that a customer loaded into an SSL-inspection firewall, which then minted certificates for domains it did not control. Mozilla pushed the intermediate into OneCRL; the episode showed how a single trusted intermediate can MITM any site.
- **[WoSign / StartCom (2016)](https://blog.mozilla.org/security/2016/10/24/distrusting-new-wosign-and-startcom-certificates/):** After backdated SHA-1 certificates, undisclosed ownership ties, and other failures, Mozilla and [Google](https://security.googleblog.com/2016/10/distrusting-wosign-and-startcom.html) stopped trusting new certificates from these CAs. Default trust had to be walked back in stages across every affected client store.
- **[Symantec legacy PKI (2017–2018)](https://security.googleblog.com/2017/09/chromes-plan-to-distrust-symantec.html):** Systemic mis-issuance and weak oversight led Chrome and Mozilla to phase out trust in Symantec’s legacy roots (Thawte, VeriSign, GeoTrust, RapidSSL, and related brands). Site operators had to re-issue; users depended on browser updates to stop trusting a long-defaulted hierarchy.
- **[Kazakhstan MITM root (2019)](https://blog.mozilla.org/security/2019/08/21/protecting-our-users-in-kazakhstan/):** ISPs directed users to install a government root so HTTPS could be intercepted. Mozilla and Google blocked that root even when users installed it manually — a reminder that “trusted because someone put it in my store” is not the same as trustworthy.
- **[TrustCor (2022)](https://groups.google.com/a/mozilla.org/g/dev-security-policy/c/oxX69KFvsm4):** After researchers documented close ties between TrustCor and a company that distributed a malware SDK, Mozilla set distrust-after dates on TrustCor’s roots and later removed them from NSS. No public TLS mis-issuance was required for browsers to decide the CA should not stay in default trust.
- **[e-Tugra (2023)](https://groups.google.com/a/mozilla.org/g/dev-security-policy/c/C-HrP1SEq1A):** Following a breach of non-CA systems, inadequate change control, and slow incident response, Mozilla removed e-Tugra’s roots from its store (Chrome did likewise). Another case where default inclusion outlasted confidence in the operator.
- **[Entrust (2024)](https://security.googleblog.com/2024/06/sustaining-digital-certificate-security.html):** After years of compliance failures and delayed remediations, Chrome stopped trusting new Entrust/AffirmTrust TLS certificates (SCT after 11 November 2024). Mozilla took parallel distrust action. Large, long-trusted CAs can still leave users waiting on vendor schedules unless they can audit and trim local stores themselves.

## Background: CA incidents

Incidents keep showing that "trusted by default" is not the same as "trustworthy." Beyond [eMudhra / Apple (October 2026)](https://support.apple.com/en-us/149555), a non-exhaustive historical sample:

- [DigiNotar](https://en.wikipedia.org/wiki/DigiNotar)
- [CNNIC](https://blog.mozilla.org/security/2015/03/23/revoking-trust-in-one-cnnic-intermediate-certificate/)
- [Symantec issues](https://wiki.mozilla.org/CA:Symantec_Issues)
- [WoSign / WoTrus](https://wiki.mozilla.org/CA:WoSign_Issues)
- [Trustico CEO emailing DigiCert ~23k private keys](https://groups.google.com/forum/#!topic/mozilla.dev.security.policy/wxX4Yv0E3Mk)
- StartCom ([StartEncrypt](https://www.computest.nl/blog/startencrypt-considered-harmful-today/)), GlobalSign cross-signing mistakes, vendor-installed roots (e.g. [DYMO](https://github.com/njh/dymo-root-ca-security-risk), [Savitech](https://www.kb.cert.org/vuls/id/446847))
- See Mozilla's [CA Incident Dashboard](https://wiki.mozilla.org/CA/Incident_Dashboard) and [dev-security-policy](https://groups.google.com/forum/#!forum/mozilla.dev.security.policy)

Vendors and browsers react after the fact. `trustprune` is for putting that control on your own machine before the next incident.

## Related projects

| Project | Description |
|---------|-------------|
| [drduh/macOS-Security-and-Privacy-Guide](https://github.com/drduh/macOS-Security-and-Privacy-Guide#certificate-authorities) | Community guide to hardening macOS, including a Certificate Authorities section. |
| [kirei/catt](https://github.com/kirei/catt) | Certification Authority Trust Tracker — scripts and data for which CAs root programs trust. |
| [mkcert.org](https://mkcert.org/) | API to build custom PEM trust stores from Mozilla’s root list (include or exclude by label). |
| [mozilla/tls-observatory](https://github.com/mozilla/tls-observatory) | Suite for scanning TLS configurations and inspecting X.509 certificates. |
| [MSylvia/CertTrustSetter](https://github.com/MSylvia/CertTrustSetter) | Tool for installing certificates and modifying trust settings on macOS. |
| [nabla-c0d3/trust_stores_observatory](https://github.com/nabla-c0d3/trust_stores_observatory) | Continuously monitors and records major platforms’ root certificate stores. |
| [ntkme/security-trust-settings-tools](https://github.com/ntkme/security-trust-settings-tools) | macOS Keychain trust-settings tools for blocking certificates by fingerprint. |
| [sebdeckers/tls-keygen](https://gitlab.com/sebdeckers/tls-keygen) | Generates a self-signed TLS certificate and adds it to the local trusted store. |

## Related reading

- [SSL and the Future of Authenticity](https://moxie.org/2011/04/11/ssl-and-the-future-of-authenticity.html)
- [Mozilla Certificate Policy](https://www.mozilla.org/en-US/about/governance/policies/security-group/certs/policy/)
- [Mozilla CA Incident Dashboard](https://wiki.mozilla.org/CA/Incident_Dashboard)
- [mozilla.dev.security.policy](https://groups.google.com/forum/#!forum/mozilla.dev.security.policy)
- [TLS Working Group](https://datatracker.ietf.org/wg/tls/charter/)
- Apple: [About the compromised eMudhra intermediate CAs](https://support.apple.com/en-us/149555)
- eMudhra: [Statement on certificate security incident](https://emudhra.com/en/post/certificate-security-incident)

## Disclaimer
Editing CA trust stores can break TLS for your system, browsers, package managers and other apps. It can lock you out of sites and services, and it can weaken your security if you remove, add or restore the wrong certificates. You use trustprune at your own risk. Run `backup` before every change, keep those backups somewhere safe, and test against a temporary or container store first.

trustprune is provided "AS IS", without warranties or conditions of any kind. To the fullest extent the law allows, the authors and contributors are not liable for any damage, data loss, outage or security issue that comes from using it. See [LICENSE](LICENSE) (Apache License 2.0, Sections 7 and 8) for the full terms.

trustprune is not affiliated with or endorsed by Apple, Google, Mozilla, Oracle or any CA.

## License

Apache License 2.0. See [LICENSE](LICENSE).
