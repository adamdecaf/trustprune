---
layout: post
title: "Apple told Mac admins to hand-edit a PEM file. That is a symptom."
date: 2026-10-28
nav_exclude: true
---

In October 2026, [Apple Support documented](https://support.apple.com/en-us/149555) the compromise of intermediate Certification Authorities operated by eMudhra and published Terminal steps that rewrite `/etc/ssl/cert.pem`. Safari and apps that use Apple's networking frameworks were blocked automatically. Command-line tools that read the system PEM bundle were not.

Apple's own summary of the gap is blunt:

> On Mac, some command-line tools included with macOS or the Xcode Command Line Tools (including curl, git, python3, ruby, perl, and openssl) check certificates against /etc/ssl/cert.pem. For certificates that chain to a root CA certificate in this file, these tools don't check Apple's block or whether the certificate has been revoked.

([About the compromised eMudhra intermediate CAs](https://support.apple.com/en-us/149555), published 23 October 2026.)

Apple says most people do not need to touch the file. For administrators who will not wait for a future macOS update, the same page publishes `awk` and `sudo install` commands that strip **emSign ECC Root CA - G3** and, optionally, **AAA Certificate Services** from that PEM bundle. Coverage of the same guidance and the lingering CLI gap appears in [heise online](https://www.heise.de/en/news/eMudhra-TLS-leak-Apple-leaves-macOS-command-line-issue-unresolved-11502949.html), [Macs Only!](https://macsonly.com/article/2026/follow-up-apple-says-a-future-macos-release-will-fix-cert-pem-for-emudhra), and [we-have-a-problem.com](https://emudhra.we-have-a-problem.com/apple.html). Those reports also note that a later macOS update can put the roots back, so the hand edit may need repeating.

Hand-editing a system PEM bundle is workable as an emergency one-liner. As an operations practice, it is fragile.

**There is no structured backup.** Apple's first step copies the file once to `cert.pem.orig`. That is better than nothing, and still a single static sibling with no inventory of which certificates you removed, when, or on which machines.

**It is easy to break the file or remove the wrong root.** A mistyped subject string in `awk` can leave the file untouched or remove an unintended matching CA. Apple warns that removing **AAA Certificate Services** can stop verification for sites that chain through unaffected intermediates. There is no dry-run that lists subjects and fingerprints before the write.

**It is not repeatable across a fleet.** Copy-pasting four Terminal commands onto every Mac, then again after every update that restores the file, does not scale. MDM can wrap the same script; the underlying model is still "rewrite the vendor file by hand."

**Updates silently undo the change.** Apple states that "A macOS software update can replace `/etc/ssl/cert.pem` with Apple's version." Reports after macOS 26.7.2 describe exactly that: both roots returned and curl accepted the test hosts again until the workaround was re-applied ([we-have-a-problem.com issue 157](https://github.com/galadran/we-have-a-problem.com/issues/157)).

**There is no audit trail.** Success is "the command shows nothing." You do not get a before/after list of SHA-256 fingerprints, a backup directory you can restore from, or a recorded plan of what would change.

That pattern—treating a PEM or CA directory as a text file to edit under stress—is why trustprune exists. It runs these operations on the platform and application stores that support them. The Windows platform store supports listing only, though the Java store works on Windows when `JAVA_HOME` is set. OpenSSL CA bundles and cert directories are managed with `-app openssl` (list, add, allowlist, backup, restore). On Darwin, the macOS platform store works through Keychain paths; the CLI PEM bundle is a separate store: `-app ssl` manages `/etc/ssl/cert.pem` directly (list, backup, allowlist, restore, `-dry-run`) — that path closed [issue #257](https://github.com/adamdecaf/trustprune/issues/257). The point is the workflow you should demand of any trust-store change, including the next incident that lands on Linux, Java, or a browser profile.

See which stores are actually on the machine:

```bash
trustprune apps
trustprune apps -format json
```

Preview before writing. `-dry-run` works on `add`, `backup`, `restore`, and `allowlist`:

```bash
trustprune backup -dry-run
trustprune allowlist -file allowlist.yaml -dry-run
trustprune restore -dry-run
```

Take a real backup first. Allowlisting refuses to run without one for that store:

```bash
trustprune backup
trustprune backup -app ssl
trustprune backup -app java
trustprune backup -app firefox
```

Remove trust for CAs that are not on your allowlist (Chromium's certificate blocklist is always applied as well):

```bash
trustprune allowlist -file allowlist.yaml
trustprune allowlist -app ssl -file allowlist.yaml
trustprune allowlist -file allowlist.yaml -app java
```

Roll back if HTTPS breaks for a tool you need:

```bash
trustprune restore
trustprune restore -app ssl
trustprune restore -app java
trustprune list -app ssl
trustprune connect -app ssl https://example.com
```

On Linux, that path covers the platform CA directory and refresh tools. On Darwin, it covers Keychain-oriented platform operations (restore honors `-backup` / `-file` for the login-keychain backup directory), the CLI PEM bundle via `-app ssl`, and app stores such as Java and Firefox when they are present. Across machines, the same commands and allowlist file are repeatable only for the operations each store supports. The Windows platform store does not support every operation. Stores that support backups write timestamped entries under `~/.trustprune/` or `~/Library/trustprune/` that you can restore from (older `~/.cert-manage/` / `~/Library/cert-manage/` backups remain readable). Darwin `-app ssl` backups land at `~/Library/trustprune/ssl/<timestamp>/cert.pem`.

Apple's PEM recipe is an honest interim for a real hole in macOS CLI trust. It also shows what "just edit the bundle" costs: silent reverts, brittle scripts, and no plan you can review before you write. Prefer a tool that dry-runs, backs up, restores, and applies the same policy on every store you actually use — including `-app ssl` for `/etc/ssl/cert.pem`. That is safer than hand-editing a PEM under pressure—not a guarantee that nothing will break.

Changing CA trust stores can break TLS, cut off access and reduce security, so back up first and proceed at your own risk. trustprune is provided as is, with no warranty, under the Apache License 2.0, and its authors and contributors accept no liability.
