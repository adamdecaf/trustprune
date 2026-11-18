---
layout: default
title: iOS (research)
nav_exclude: true
---

# iOS trusted roots

Research note for [#364](https://github.com/adamdecaf/trustprune/issues/364). Nothing on this page is implemented. Researched November 2026.

iOS keeps a preinstalled root store in the OS. On a stock iPhone, Apple documents no Settings control and no configuration-profile payload that removes or distrusts one of those roots. trustprune can compare an allowlist with the list Apple publishes, and it can print the taps that turn off a root the user installed. It cannot change the phone from the computer.

Anything marked **unverified** was not confirmed on the Apple pages cited here.

## System trust store

The [Apple Root Certificate Program](https://www.apple.com/certificateauthority/ca_program.html) page now points at the [Apple Root Program Policy](https://github.com/apple/apple-root-program/blob/main/policy.md). That policy (version 2.0, effective 2026-08-01) is what CAs have to meet to be included. Apple operating systems then ship one shared store of those roots.

[Available root certificates for Apple operating systems](https://support.apple.com/en-us/103272) is the index. The roots are preinstalled. Since iOS 12, macOS 10.14, tvOS 12, and watchOS 5, those systems share one store, and Apple archives each version as it is replaced. The current article, [roots for iOS 26 and the matching releases](https://support.apple.com/en-us/126047), is trust store version **2025082000**. The [iOS 18 article](https://support.apple.com/en-us/121672) is version **2024051500**. Each article is a table of included roots with a SHA-256 fingerprint. The [iOS 16 article](https://support.apple.com/en-us/103100) (version **2022070700**) also splits the store into trusted, always ask, and blocked certificates. The iOS 18 and iOS 26 articles do not repeat those three headings.

To see which version an iPhone or iPad has, Apple's current articles say: **Settings > General > About**, scroll to the bottom, tap **Certificate Trust Settings**. They do not say which corner of that screen shows the number. On a Mac the same shared store is `TrustStore.html` at `/System/Library/Security/Certificates.bundle/Contents/Resources/TrustStore.html`, and the version is in the upper-right of that file. The Mac's version and the phone's version can differ until both have the same update.

The full-trust list on that screen is only for additional certificates. If **Enable full trust for root certificates** is absent, no additional certificate is installed ([Trust manually installed certificate profiles](https://support.apple.com/en-us/102390)). Preinstalled roots are not in that list. The [Restrictions payload](https://developer.apple.com/documentation/devicemanagement/restrictions) has no key that names a system root and turns it off. That was checked against Apple's published [`com.apple.applicationaccess` schema](https://github.com/apple/device-management/blob/release/mdm/profiles/com.apple.applicationaccess.yaml). When a preinstalled root is compromised, Apple can push a wireless trust-store update ([Intro to certificate management](https://support.apple.com/sq-al/guide/deployment/depb5eff8914/web)). That update is Apple's.

## User-installed roots

An extra root arrives in a configuration profile. A profile from the web or from Mail is installed in Settings, and iOS deletes it if it is still uninstalled after 8 minutes ([Install a configuration profile](https://support.apple.com/en-us/102400)). On an unsupervised device the install warning says the certificate is not trusted for websites until Certificate Trust Settings enables it.

The switch is **Settings > General > About > Certificate Trust Settings**, under **Enable full trust for root certificates**:

- It turns TLS trust on or off for that additional root. Off leaves the certificate installed and untrusted for TLS.
- It lists additional roots only.
- On a supervised device, and for a root a device-management service installed, Apple turns off the option to change those trust settings.
- A root is already fully trusted when Apple Configurator installs it with the same supervision identity as the device, when a device-management service installs it, or when it is in an enrollment profile ([Certificates payload](https://support.apple.com/en-za/guide/deployment/dep91d2eb26/1/web/1.0)). The support article above states the shorter rule: Configurator, MDM, and an enrollment profile are trusted for SSL automatically.

Removing the root means deleting its profile. Profiles are listed at **Settings > General > VPN & Device Management**. Deleting a profile deletes the settings and information that came with it ([Review and delete configuration profiles](https://support.apple.com/en-mn/guide/personal-safety/ips327569a75/web)). A profile the user installed can be deleted there. A profile from device management often cannot. The administrator removes that one.

## MDM and configuration profiles

The Certificates payload adds certificates and identities. On iPhone and iPad the identifiers are `com.apple.security.pem`, `com.apple.security.pkcs1`, `com.apple.security.pkcs12`, and `com.apple.security.root` ([payload list](https://support.apple.com/guide/deployment/payload-list-for-iphone-and-ipad-depdca795ebd/web)). The [root payload](https://developer.apple.com/documentation/devicemanagement/certificateroot) carries the certificate bytes in `PayloadContent`. Supervision is not required, manual install is allowed, and user enrollment may include it. The payload adds a trust anchor.

No restriction can distrust a system root. `com.apple.applicationaccess` has no key for that. Nearby keys do other jobs:

- `allowOTAPKIUpdates` (default true). Set to false, over-the-air PKI updates stop. CRL and OCSP checks keep running. The deployment guide calls this "Allow automatic updates to certificate trust settings." The schema does not mark the key as supervised. User enrollment cannot set it.
- `allowUntrustedTLSPrompt` (default true). Set to false, untrusted HTTPS certificates are rejected with no prompt. A root the store already trusts stays trusted.
- `allowUIConfigurationProfileInstallation` (default true, supervised only). Set to false, the user cannot install configuration profiles or certificates from the UI.
- `allowEnterpriseAppTrust` hides **Trust Enterprise Developer**. That is app provisioning, not CA roots.

The [Certificate Revocation payload](https://developer.apple.com/documentation/devicemanagement/certificaterevocation) (`com.apple.security.certificaterevocation`, iOS 14.2) turns on revocation checking for certificates named by the SHA-256 hash of `subjectPublicKeyInfo`. Apple's schema says trusted roots are already included, so the payload does not ask you to list them. It does not mark a root untrusted.

Supervision decides who may install a profile and who may flip the switch. On an unsupervised device, Apple Configurator asks the person to confirm, and a root installed by hand needs the full-trust switch. On a supervised device, Configurator installs the profile with no prompt ([Add or remove configuration profiles](https://support.apple.com/guide/apple-configurator-mac/add-or-remove-configuration-profiles-cadb67fcd4f/2.16/mac/12.4)), and the trust switch for those roots is off. `allowUIConfigurationProfileInstallation` can also block the user from adding any profile.

## Reading the trust state

On the phone, Apple's current articles send you to Certificate Trust Settings to read the store version. That screen's full-trust switches are the additional roots. **VPN & Device Management** shows installed profiles and the certificates inside them. The full-trust bit is the other screen. Neither screen is a list of the preinstalled roots.

Apple Configurator can add and remove profiles. A backup taken there contains the configuration profiles. Restoring onto the same device keeps them. Restoring onto a different device puts them back and then removes them ([Back up and restore devices](https://support.apple.com/guide/apple-configurator-mac/back-up-and-restore-devices-cadbf9b61c/2.16/mac/12.4)). The backup also includes settings that can be changed on the device, including certificates ([Restore from backup](https://support.apple.com/guide/apple-configurator-mac/restore-from-backup-cad4bd2f08/mac)). Those are certificates a person or a profile set. Configurator does not document an export of the preinstalled root store.

A Finder, Apple Devices, or iTunes backup holds almost all of the device's data and settings ([Backup methods](https://support.apple.com/en-us/108771)). An encrypted backup also includes saved passwords, Wi-Fi settings, website history, Health data, and call history, and encryption is what includes keychain data ([About encrypted backups](https://support.apple.com/en-us/108353)). Apple does not document the preinstalled root store as a file in that backup. The roots ship with the OS. Whether the full-trust flags sit inside an encrypted backup's keychain is **unverified**. Apple documents no way to read them back out.

An app on the phone cannot list the store either. The system trusts the roots packaged with the OS. `SecTrustSetAnchorCertificates` changes one evaluation inside the calling app. Other evaluations on the device stay as they were ([Configuring a trust](https://developer.apple.com/documentation/security/configuring-a-trust)).

## What trustprune can do

**Audit against the published list.** Take a trust-store version, the number from Certificate Trust Settings or a version the user names, and list that article's roots: name and SHA-256 fingerprint. Diff an allowlist against that set. The output is Apple's published list for that version, and the command should say so. It is a description of a published article, not a dump of a phone. The articles are HTML tables. Apple does not document a machine-readable feed of the same table. Whether `Certificates.bundle` holds anything beyond the documented `TrustStore.html` is **unverified**. The version in a Mac's `TrustStore.html` is that Mac's copy of the shared store. It can be a different version from the phone.

**A guide for roots the user installed.** Print the steps and do not write anything:

1. Open **Settings > General > VPN & Device Management**. Delete a profile you installed. That removes its certificates.
2. Open **Settings > General > About > Certificate Trust Settings**. Turn off **Enable full trust for root certificates** for a root you installed by hand. TLS trust drops. The profile stays until you delete it.
3. If the switch is missing, or the profile will not delete, the device is supervised or a device-management service owns the profile. The administrator removes it.

**What cannot be automated on a stock iPhone:**

- Removing or distrusting a preinstalled root.
- Building a profile that distrusts one. No payload does that.
- Flipping Certificate Trust Settings, or confirming a profile install, from software on a computer.
- Reading the live system store from a backup, from Apple Configurator, or from an app.
- Installing or removing a profile with no prompt on an unsupervised device.
- Holding a root out of the next store Apple ships. `allowOTAPKIUpdates` can stop over-the-air PKI updates on a managed device. It leaves the current roots in place. Whether a later full OS update still replaces the store was not checked, and is **unverified**.

## Proposed follow-up

1. **Guide only.** A command such as `trustprune list --app ios` prints the two Settings paths. `add`, `allowlist`, `backup`, and `restore` print the same guide and exit non-zero. No device I/O.
2. **Published-list audit.** Given a trust-store version, print Apple's roots for that version and the diff against an allowlist. Vendor a snapshot of the table, and record the article URL and the version string. Label the output as the published list.
3. **Mac version string.** On Darwin, read the version out of `TrustStore.html` and print it as that Mac's shared-store version. Do not present it as the phone's version.
4. **Out of scope.** A profile that adds a private root, speaking MDM, parsing backups, and any jailbreak path.

[← Platforms](../platforms.md)
