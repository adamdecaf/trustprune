---
layout: default
title: trustprune
description: >-
  List, backup, allowlist, and restore CA trust stores on your platform and in
  apps such as Java, Chrome, and Firefox. Trust should be earned, not defaulted.
nav_order: 1
permalink: /
---

# trustprune

**Your machine trusts hundreds of Certificate Authorities by default. Most of them you have never heard of. One bad CA is enough to break HTTPS for everyone who trusts it.**

`trustprune` is a single CLI to **list**, **backup**, **allowlist** (distrust), and **restore** the CA trust stores on your platform and in apps such as Java, Chrome, and Firefox.

Trust should be earned, not defaulted.

## Quick start

```bash
# See what you currently trust
trustprune list
trustprune list --count
trustprune list --app java

# Always take a backup before changing trust
# Backups stored at `~/.trustprune/` or `~/Library/trustprune/` on Darwin
trustprune backup
trustprune backup --app java

# Keep only the CAs you want (requires a prior backup)
trustprune allowlist --file urls.yaml
trustprune allowlist --app java --file urls.yaml

# Roll back if something breaks
trustprune restore
trustprune restore --app java
```

## Pages

| Page | Contents |
|------|----------|
| [Install](install.md) | Release binaries, `go install`, build from source |
| [Usage](usage.md) | Every command and flag |
| [Platforms](platforms.md) | Platforms and apps, store paths, support status |
| [Backup and restore](backup-restore.md) | Where backups live, NSS file sets, safe swap/rollback |
| [Basics](basics.md) | Command walkthrough (list, add, backup/restore, connect) |
| [Allowlists](allowlists.md) | Allowlist format and generating from browser history |
| [Why this matters](why.md) | Research and CA incidents that motivate the tool |
| [Blog](blog.md) | Posts |
| [Papers](papers/) | Related research PDFs |

## Source

- [GitHub repository](https://github.com/adamdecaf/trustprune)
- [Releases](https://github.com/adamdecaf/trustprune/releases)
- License: [Apache 2.0](https://github.com/adamdecaf/trustprune/blob/master/LICENSE)
