---
layout: default
title: PDF readers (research)
nav_exclude: true
---

# PDF readers and document-signing trust

Research note for [#360](https://github.com/adamdecaf/trustprune/issues/360). Foxit install detection and the pruning guide are implemented ([#392](https://github.com/adamdecaf/trustprune/issues/392)); see [Platforms](../platforms.md#foxit). Acrobat address book backup and restore, and a read-only AATL, EUTL, and Windows store settings report, are implemented ([#390](https://github.com/adamdecaf/trustprune/issues/390)). Listing address book entries read-only was not attempted. The file is treated as opaque. See [Platforms](../platforms.md#acrobat). Papers on an NSS backend is the poppler store and Evince has no signature validation ([platforms](../platforms.md)). The other items on this page are not. Researched November 2026.

PDF readers validate signed PDFs against their own trust lists, separate from the TLS stores trustprune prunes today. A CA you remove from browser or OS TLS trust can still make a PDF signature show as valid. This page covers where each reader keeps that trust, and what trustprune could safely list, back up, or prune.

Anything marked **unverified** came from community sources, or could not be confirmed in vendor docs or source code. Don't build on it without checking it first.

## Summary

| Reader | Platforms | Trust data | Updated by | trustprune could | Main risk |
|--------|-----------|------------|------------|------------------|-----------|
| pdfsig / poppler (NSS backend) | Linux, also Windows builds | An NSS DB, chosen in this order: `-nssdir`, the newest Firefox `*default*` profile, `/etc/pki/nssdb`, `~/.pki/nssdb`. Built-in roots come from `libnssckbi` | Firefox / NSS packages, `certutil` | **list, backup, prune** with the existing NSS code (`p,p,p`) | Choosing a different DB than poppler does |
| pdfsig / poppler (GPG backend) | Linux | gpgsm keybox plus `trustlist.txt` in `$GNUPGHOME` (default `~/.gnupg`) | User / gpgsm | report only, at first | Text format that gpg-agent owns |
| Okular | Linux, Windows | Uses poppler. Can set its own NSS DB in `okular-generator-popplerrc` (`[Signatures]` `UseDefaultCertDB`, `DBCertificatePath`, `SignatureBackend`) | Same as poppler | **list, backup, prune** via NSS when the effective backend is NSS and the configured DB is resolved | A custom DB path, or a GPG backend, that trustprune doesn't treat as NSS |
| Evince / Papers | Linux | Evince: no signature validation found in current source. Papers: poppler's default NSS DB when the effective backend is NSS; poppler's GPG store when the effective backend is GPG | Same as poppler | Documented on the [platforms page](../platforms.md). Papers NSS is `--app poppler`. Papers GPG is report-only. Evince: nothing to prune | None for Evince |
| Adobe Acrobat / Reader | Windows, macOS | Per-user `addressbook.acrodata` (Trusted Identities, which AATL and EUTL download into). Windows store, if Windows Integration is on | AATL/EUTL download from Adobe; user or admin import | **backup and restore** the address book (implemented). **Report** AATL, EUTL, and Windows store settings (implemented, read only). Listing address book entries read-only was not attempted; the file is treated as opaque. Prune: **guide only** | AATL/EUTL updates re-adding roots; corrupting the address book |
| Foxit PDF Reader / Editor | Windows, macOS | A local trusted-certificate list (location **unverified**), plus FATL/EUTL downloads, plus the Windows store if Windows Integration is on | FATL/EUTL download from Foxit; user import | **guide only** (implemented): detect the install and print a pruning guide. No list or backup | Undocumented storage |

## pdfsig and poppler (NSS)

poppler is the PDF library behind `pdfsig`, Okular and Papers. It has two signature backends: NSS and GPG (gpgme, CMS). The backend is picked by `POPPLER_SIGNATURE_BACKEND`, then by the compile-time `DEFAULT_SIGNATURE_BACKEND`, which is the first one built, with NSS first ([CryptoSignBackend.cc](https://gitlab.freedesktop.org/poppler/poppler/-/blob/master/poppler/CryptoSignBackend.cc), [CMakeLists.txt](https://gitlab.freedesktop.org/poppler/poppler/-/blob/master/CMakeLists.txt)).

**Which NSS DB.** The [pdfsig(1) man page](https://gitlab.freedesktop.org/poppler/poppler/-/blob/master/utils/pdfsig.1) lists: `-nssdir`, then the default Firefox profile (`$HOME/.mozilla/firefox/*.default*`), then `/etc/pki/nssdb`, then `$HOME/.pki/nssdb`. The code in [NSSCryptoSignBackend.cc](https://gitlab.freedesktop.org/poppler/poppler/-/blob/master/poppler/NSSCryptoSignBackend.cc) (`getDefaultFirefoxCertDB`, `NSSSignatureConfiguration::setNSSDir`) is more specific:

- If a directory is given (`-nssdir`, or `Poppler::setNSSDir` from an app), only that one is used.
- Otherwise it looks for Firefox profiles. On Unix it first checks `$XDG_CONFIG_HOME/mozilla/firefox/` (or `~/.config/mozilla/firefox/`), skipped when `MOZ_LEGACY_HOME=1`, then `~/.mozilla/firefox/`. On Windows it checks `%APPDATA%/Mozilla/Firefox/Profiles/`. It takes any directory whose name contains `default` and has a `cert9.db`, and picks the one whose `cert9.db` was written most recently.
- If no profile is found, it opens `sql:/etc/pki/nssdb`.
- If that `NSS_Init` fails, or if a Firefox profile was found but its `NSS_Init` fails, it tries `$HOME/.pki/nssdb`. A failed Firefox init does not fall through to `/etc/pki/nssdb`.
- After init it always loads the `Root Certs` module (`libnssckbi.so`). Mozilla's built-in roots are trusted unless the DB overrides them.

**Usages checked.** poppler accepts a signer chain if it verifies for `certificateUsageEmailSigner`, `certificateUsageEmailRecipient` or `certificateUsageSSLClient`. A comment there says NSS has no "can sign PDF" usage. A distrust that only clears the TLS trust bits therefore doesn't stop PDF validation. trustprune's NSS `Remove` already sets `p,p,p` (SSL, email and object signing) through `certutil -M` (`pkg/store/nss.go`), which covers all three usages.

**Format and updates.** Standard NSS `cert9.db` / `key4.db` / `pkcs11.txt` (legacy `cert8.db`). The built-in list changes when NSS or Firefox is updated. Distrust entries in the DB survive those updates.

**What trustprune could do.** List, backup, prune and restore through `NssStore` in `pkg/store/nss.go`, the same code `--app firefox` and Linux `--app chrome` (`~/.pki/nssdb`) use. Today's `listCertsFromDB` runs `certutil -L` without `-h`, so it lists the internal token, not the built-in roots Poppler loads from `libnssckbi`. `Remove` therefore never applies `p,p,p` to a root present only in that module. The new work is resolving the same DB poppler uses, accepting `--store <dir>` for `-nssdir` users, and enumerating those built-in roots so distrust overrides are written into the DB.

**Risks.**
- **Profile mismatch.** `--app firefox` globs `~/.mozilla/firefox/*.default` (`pkg/store/firefox.go`). poppler prefers `~/.config/mozilla/firefox/`, accepts any name containing `default` (for example `*.default-release`), and picks the newest `cert9.db`. Pruning `--app firefox` can leave the profile poppler actually reads untouched.
- `/etc/pki/nssdb` is a system-wide DB and needs root. Changes there affect every NSS user on the host.
- The DB is shared with the browser, so a prune affects Firefox TLS too. That's usually what the user wants, but it has to be stated.

## pdfsig and poppler (GPG backend)

With `POPPLER_SIGNATURE_BACKEND=GPG`, or a build where it is the default, poppler uses gpgme in CMS mode ([GPGMECryptoSignBackend.cc](https://gitlab.freedesktop.org/poppler/poppler/-/blob/master/poppler/GPGMECryptoSignBackend.cc)). The man page says certificates come from `$GNUPGHOME`, defaulting to `$HOME/.gnupg`. Root trust for gpgsm is kept in `trustlist.txt`: one fingerprint per line followed by `S`, and a leading `!` marks a key as explicitly not trusted ([GnuPG agent configuration](https://www.gnupg.org/documentation/manuals/gnupg/Agent-Configuration.html)). trustprune could report this file and later prune it by adding `!` lines, but that's a separate store. It's left out of the first sub-issue.

## Okular

Okular's poppler generator reads `okular-generator-popplerrc`, group `[Signatures]`, keys `SignatureBackend`, `UseDefaultCertDB` (default `true`), `DBCertificatePath` and `CheckOCSPServers` ([conf/pdfsettings.kcfg](https://invent.kde.org/graphics/okular/-/blob/master/generators/poppler/conf/pdfsettings.kcfg)). When `UseDefaultCertDB` is false, it calls `Poppler::setNSSDir(DBCertificatePath)` before validating ([generator_pdf.cpp](https://invent.kde.org/graphics/okular/-/blob/master/generators/poppler/generator_pdf.cpp)). Otherwise it uses poppler's default order above. The KConfig file lives in the user's config dir (on Linux, normally `~/.config/okular-generator-popplerrc`; that path follows KConfig convention and is **unverified** for packaged builds such as Flatpak).

- **Platforms:** Linux; Okular also ships for Windows. On Windows, poppler's Firefox search uses `%APPDATA%`.
- **What trustprune could do:** read the rc file. Resolve the effective signature backend: the `SignatureBackend` setting if set, otherwise `POPPLER_SIGNATURE_BACKEND`, otherwise the compiled default. Select and inspect the NSS database only when that backend is NSS; if it is GPG, report it and stop. When the backend is NSS: if a custom NSS DB is set, run the NSS store against it; otherwise reuse the poppler resolution.
- **Risks:** Flatpak or Snap sandboxes may keep the config and NSS DB under the app's own home (**unverified**).

## Evince and Papers

- **Evince:** current `main` (checked at `e822030`, Oct 2026) maps signature form fields (`ev-poppler.c`, `ev-form-field.c`) but has no call to poppler's signature validation, so there's no trust store to prune ([GNOME/evince](https://gitlab.gnome.org/GNOME/evince)). Older work to show signatures stalled ([bug 614929](https://bugzilla.gnome.org/show_bug.cgi?id=614929)).
- **Papers** (GNOME's newer document viewer): validates with `poppler_form_field_signature_validate_sync` and sets only an NSS password callback, not an NSS dir (`libdocument/backend/pdf/pps-poppler.c` in [GNOME/papers](https://gitlab.gnome.org/GNOME/papers)). When the effective backend is NSS, it uses poppler's default DB order. When the effective backend is GPG, it follows poppler's GPG store instead. The [GNOME Discourse thread](https://discourse.gnome.org/t/digital-signature-in-papers/33495) imports user certificates into `~/.pki/nssdb`.
- **Coverage:** documented on the [platforms page](../platforms.md) ([#391](https://github.com/adamdecaf/trustprune/issues/391)). Papers follows `--app poppler` when the effective backend is NSS. When the effective backend is GPG, Papers is report-only, like poppler's GPG backend: trustprune does not list or prune `trustlist.txt`. Evince has no signature validation. If Evince adds validation later, reopen #391.

## Adobe Acrobat and Reader

**Platforms.** Windows and macOS. Adobe's preference reference also mentions Unix and Linux for these settings, but current Acrobat and Reader builds target Windows and macOS (Linux status **unverified**, believed discontinued).

**Trust data.**
- **Trusted Identities** are stored in `addressbook.acrodata` (the file name can be changed with `Security\cPubSec\tAddressBook`). Adobe documents the per-user folder as `C:\Users\<user>\AppData\Roaming\Adobe\Acrobat\DC\Security` on Windows and `/Users/<user>/Library/Application Support/Adobe/Acrobat/DC/Security` on macOS. Deleting the file removes manually trusted certificates, and Acrobat recreates it ([Adobe KB](https://helpx.adobe.com/reader/kb/error-opening-acrobat-reader-extended-pdfs.html)). Older versions use `11.0`, `10.0` and so on in place of `DC` ([PrefRef: Addressbook Import](https://www.adobe.com/devnet-docs/acrobatetk/tools/PrefRef/Windows/Security.html)).
- **Format:** Adobe-proprietary and not documented. The sibling `directories.acrodata` is shown as FDF in Adobe's guide ([DigSig planning](https://www.adobe.com/devnet-docs/acrobatetk/tools/DigSigDC/planning.html)). The address book format is **unverified**.
- **AATL and EUTL are not a separate cache.** Adobe says "both the AATL and EUTL features load certificates into the user's Acrobat Address Book (Acrobat Trust Store)" ([PrefRef: European Union Trust List](https://www.adobe.com/devnet-docs/acrobatetk/tools/PrefRef/Windows/Security.html)). The KB above also says AATL/EUTL certificates can be re-added from Trust Manager after the file is deleted.
- **Enterprise distribution:** `addressbook.acrodata` can be pre-seeded by copying it into the installer's `Replicate\Security` folder ([Customization Wizard: files and folders](https://www.adobe.com/devnet-docs/acrobatetk/tools/Wizard/filesfolders.html)), or by importing `.acrobatsecuritysettings` files, optionally polled from a server (`Security\cDigSig\cCustomDownload`).

**Updates.** By default, Acrobat and Reader download the AATL. PrefRef says every 14 days for 11 and DC; the DigSig guide says 30 days. The documents disagree, so treat the interval as **unverified**. EUTL support has existed since 11.0.06.

**Registry and plist keys** (all from [PrefRef: Security](https://www.adobe.com/devnet-docs/acrobatetk/tools/PrefRef/Windows/Security.html)). User keys live under `HKCU\Software\Adobe\(Adobe Acrobat | Acrobat Reader)\(version)\`. Locks live under `HKLM\SOFTWARE\Policies\Adobe\(product)\(version)\FeatureLockDown\` (`Wow6432Node` on 64-bit). On macOS, user prefs are in `~/Library/Preferences/com.adobe.(Acrobat.Pro | Reader).plist` and locks in `/Library/Preferences/com.adobe.(Acrobat.Pro | Reader).plist`, using the same key paths inside the `DC` hive ([PrefRef glossary](https://www.adobe.com/devnet-docs/acrobatetk/tools/Preferences_by_version/Macintosh/glossary.html), [Mac admin guide](https://www.adobe.com/devnet-docs/acrobatetk/tools/AdminGuide_Mac/predeployment_configuration_advanced.html)).

| Key (relative to the product/version root) | Meaning |
|--------------------------------------------|---------|
| `Security\cDigSig\cAdobeDownload\bLoadSettingsFromURL` | Periodically download AATL trust anchors (0 = off) |
| `Security\cDigSig\cAdobeDownload\bAskBeforeInstalling`, `iCheckEvery` | Prompt before installing; interval in seconds |
| `Security\cDigSig\cEUTLDownload\bLoadSettingsFromURL` (plus `bAskBeforeInstalling`, `iCheckEvery`) | Same for EUTL; documented as "Not lockable" |
| `Security\cASPKI\cMSCAPI_DirectoryProvider\iMSStoreTrusted` | Trust the Windows Certificate Store: `0x00` none, `0x60` signatures, `0x62` signatures and certified documents |
| `FeatureLockDown\cSecurity\cASPKI\cMSCAPI_DirectoryProvider\bMSStoreTrusted` (HKLM) | Locks `iMSStoreTrusted` (`0` = locked) |
| `Security\cASPKI\cSPIs\cDirectoryProvider` / `iDirectoryProvider` | Which trust sources validation uses: `AAB_DirectoryProvider` (Trusted Identities), `MSCAPI_DirectoryProvider` (Windows store), and others |
| `Security\cPubSec\tAddressBook` | Address book file name |

PrefRef doesn't give an HKLM lock path for the AATL `bLoadSettingsFromURL`. Whether the AATL download can be locked is **unverified**.

**Is OS store removal respected?**
- **Windows:** only when Windows Integration (`iMSStoreTrusted`) is on. Adobe's [verification preferences](https://helpx.adobe.com/acrobat/desktop/e-sign-documents/manage-digital-signatures/set-preferences.html) list it as "Windows only"; that it is off by default is **unverified** (community sources say so). Removing a root from the Windows store removes that trust path. It doesn't remove a copy that AATL, EUTL or the user put in `addressbook.acrodata`. Whether Acrobat honors the Windows `Disallowed` store is **unverified**.
- **macOS:** Adobe documents no Keychain trust integration for validation. The Keychain is used for signing identities only. So removing a root from the Keychain has no effect on Acrobat (Keychain for signing identities: Acrobat 9.1 notes in the [Acrobat 9 admin guide copy](https://manualzz.com/doc/8484298/adobe-9.0-acrobat-administration-guide); no trust integration: [community answer](https://stackoverflow.com/questions/7110606/verifying-digital-signatures-on-mac-adobe-reader), **unverified** in current Adobe docs).

**What trustprune does.** `--app acrobat` finds the newest `addressbook.acrodata` and copies it on backup and restore while Acrobat, AcroRd32, or AdobeReader is not running. `list` prints a read-only report of the AATL download (`cAdobeDownload` / `bLoadSettingsFromURL`), the EUTL download (`cEUTLDownload`), and `iMSStoreTrusted`. On Windows those values are read from `HKCU\Software\Adobe\(Adobe Acrobat|Acrobat Reader)\<ver>\Security\cDigSig` (and `iMSStoreTrusted` also from `cASPKI\cMSCAPI_DirectoryProvider` when it is not under `cDigSig`). On macOS the same keys are read from `~/Library/Preferences/com.adobe.Acrobat.Pro.plist` and `com.adobe.Reader.plist` with `/usr/bin/defaults read`. Linux is not probed. When no registry key, plist, or address book is found, `list` prints `acrobat: not installed` and exits 0. The registry and plist are not written. `add`, `allowlist`, and `connect` print a pruning guide. The address book is not parsed. See [Platforms](../platforms.md#acrobat).

**What trustprune does not do yet.**
- **List** entries. Listing address book entries read-only was not attempted. The file is treated as opaque.
- **Prune.** The guide points at Trust Manager / Trusted Certificates. An admin turns off AATL/EUTL downloads in the app. trustprune does not rewrite the file except to put a previous copy back on restore.

**Risks.** AATL and EUTL updates may re-add or re-trust a root that trustprune removed (**unverified**: whether an edited AATL entry's trust survives the next update). Rewriting an undocumented file can break Reader Extended PDFs, which is the failure in Adobe's KB. Changing policy keys is an admin and account-level change.

## Foxit PDF Reader and Editor

- **Platforms:** Windows and macOS for current products ([Windows guide](https://www.foxit.com/resource-hub/user-guide/foxit-pdf-editor-for-windows/signature/), [Mac guide](https://help.foxit.com/manuals/pdf-editor/mac/en-us/2025.3.0/Protect_PDF_Files.html)). Linux: **unverified**.
- **Trust data:**
  - A local "Trusted Certificates" list, managed under Protect > Sign & Certify > Trusted Certificates, where certificates can be added, exported, deleted, or have their trust changed ([Trusted Certificates](https://www.foxit.com/resource-hub/user-guide/foxit-pdf-editor-for-windows/trusted-certificates/)). Its on-disk location and format are **unverified**: not found in Foxit docs.
  - The Foxit Approved Trust List (FATL), and on Mac also EUTL, is downloaded into that local list. By default this is on, every 28 days, or when a signed PDF's certificate hasn't been checked recently ([Foxit blog](https://www.foxit.com/blog/how-to-automatically-trust-digital-ids-for-digital-signatures/)).
  - "Windows Integration" can trust all roots in the Windows Certificate Store for signatures and certified documents ([Signature preferences](https://www.foxit.com/resource-hub/user-guide/foxit-pdf-editor-for-windows/signature/)).
- **Admin:** the deployment guide has a GPO setting, "Load trusted certificates from Foxit server" (Disable / Ask / Silent), under `HKEY_CURRENT_USER\Software\Policies\Foxit\PDFEditor` or `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Foxit\PDFEditor` ([Foxit PDF Editor Deployment and Configuration 2026.2](https://cdn01.foxitsoftware.com/pub/foxit/manual/phantom/en_us/pdf-editor-deployment-and-configuration-2026.2.pdf)). The value names aren't given in the guide (**unverified**). Whether FATL includes AATL members is **unverified**.
- **Is OS store removal respected?** On Windows, only when Windows Integration is on. The FATL/EUTL copy isn't affected.
- **What trustprune does:** `--app foxit` detects an Editor or Reader install on Windows and macOS and `apps` reports it as `guide only`. `list`, `add`, `allowlist`, `backup`, `restore`, and `connect` print the pruning guide and do not read or write a trust store. The on-disk list is still **unverified**, so list and backup stay out until a path is documented. Steps and detection paths: [Platforms](../platforms.md#foxit).
- **Risks:** an undocumented store; FATL re-download.

## AATL and EUTL

The AATL is Adobe's own program for signing CAs and timestamp services ([AATL members](https://helpx.adobe.com/acrobat/kb/approved-trust-list1.html)). Adobe says its signatures also work with every qualified provider on the EU Trust List. It is run separately from the Mozilla, Apple and Microsoft root programs, so a TLS distrust there doesn't remove a CA from it. Acrobat and Foxit keep the EUTL as a separate download, but both land in the same local trust list as their own approved list.

## Proposed sub-issues

Ordered by user value and feasibility.

1. **poppler/pdfsig: NSS store that matches poppler's DB lookup**
   Scope: add a store (for example `--app poppler`) that resolves the DB the way `NSSSignatureConfiguration::setNSSDir` does: `--store` (for `-nssdir`); otherwise the newest `cert9.db` in a Firefox directory whose name contains `default`. On Unix, search `$XDG_CONFIG_HOME/mozilla/firefox/` when set, or `~/.config/mozilla/firefox/` otherwise, skipped when `MOZ_LEGACY_HOME=1`, then `~/.mozilla/firefox/`. On Windows, search `%APPDATA%/Mozilla/Firefox/Profiles`. If no profile is found, try `/etc/pki/nssdb`. If a discovered Firefox profile's `NSS_Init` fails, or if `/etc/pki/nssdb` fails to initialize, fall back to `~/.pki/nssdb` (do not try `/etc/pki/nssdb` after a failed Firefox init). Reuse `NssStore` for list, backup, allowlist and restore, and also enumerate built-in roots loaded from `libnssckbi` (today `listCertsFromDB` runs `certutil -L` without `-h` and only sees the internal token). `Remove` must apply `p,p,p` distrust overrides to roots present only in that module. Fix `--app firefox` discovery to match (`*.default-release`, XDG path, `XDG_CONFIG_HOME`, `MOZ_LEGACY_HOME`, and Windows `%APPDATA%`).
   Acceptance: no-network tests with temp profile trees pick the same DB as poppler, including `XDG_CONFIG_HOME`, `MOZ_LEGACY_HOME=1`, and Windows `%APPDATA%` layouts; a Firefox profile that fails `NSS_Init` falls back to `~/.pki/nssdb` and not `/etc/pki/nssdb`; allowlist sets `p,p,p`, including on a root present only in the built-in module; `pdfsig` on a test PDF signed by a pruned root reports an untrusted certificate. Docs updated.

2. **Okular: use the configured signature DB and backend**
   Scope: read `okular-generator-popplerrc` `[Signatures]`. Resolve the effective signature backend: the `SignatureBackend` setting if set, otherwise `POPPLER_SIGNATURE_BACKEND`, otherwise the compiled default. Select and inspect the NSS database only when that backend is NSS; if it is GPG, report it and exit without changes. When the backend is NSS: if `UseDefaultCertDB=false`, run the NSS store on `DBCertificatePath`; otherwise use sub-issue 1's lookup.
   Acceptance: tests for default, custom-path, explicit GPG, and GPG via `POPPLER_SIGNATURE_BACKEND` or the compiled default when `SignatureBackend` is absent; `list --app okular` shows which DB or backend it used; docs note Flatpak paths as unverified.

3. **Adobe Acrobat/Reader: back up the address book and report trust settings**
   Scope: find `addressbook.acrodata` per OS and back it up and restore it as an opaque file, refusing while Acrobat is running. Read and report the AATL/EUTL download settings and `iMSStoreTrusted` (registry on Windows, plist on macOS). Spike whether entries can be listed read-only. Pruning stays a printed guide.
   Acceptance: backup and restore round-trip on fixtures; a settings report on a Windows CI runner without Acrobat says "not installed"; no writes to registry, plist or the address book except restore.
   Status: backup and restore of `addressbook.acrodata` are implemented ([#390](https://github.com/adamdecaf/trustprune/issues/390), [Platforms](../platforms.md#acrobat)). `list --app acrobat` reports AATL, EUTL, and Windows store trust settings from the registry on Windows and the plist on macOS, read only. Listing address book entries read-only was not attempted. The file is treated as opaque. Pruning is a printed guide.

4. **Evince/Papers: document coverage through poppler**
   Scope: docs only. Papers validates with poppler's default NSS DB when the effective backend is NSS, so sub-issue 1 covers that case. If the effective backend is GPG, it is report-only, like poppler's GPG backend. Evince has no signature validation today. Add a row to the platforms page.
   Acceptance: the platforms page says so, with source links, and qualifies Papers coverage by the effective backend. If Evince adds validation later, reopen.
   Status: documented on the [platforms page](../platforms.md) ([#391](https://github.com/adamdecaf/trustprune/issues/391)).

5. **Foxit: detection and a pruning guide** (implemented, [#392](https://github.com/adamdecaf/trustprune/issues/392))
   Scope: detect Foxit PDF Reader/Editor on Windows and macOS, and print where trust comes from (local Trusted Certificates, FATL/EUTL downloads, Windows Integration) with steps to remove a root and turn off FATL. Find the on-disk store before attempting list or backup.
   Acceptance: guide text in the docs; `trustprune` reports Foxit as "guide only" when installed; the storage location is either documented with a source or left marked unverified. The storage location is still **unverified**.

Related, outside PDF readers: a gpgsm `trustlist.txt` store for poppler's GPG backend (`!` lines to distrust) can be filed separately if users ask for it.

[← Platforms](../platforms.md)
