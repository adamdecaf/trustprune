---
layout: default
title: Android (research)
nav_exclude: true
---

# Android trusted roots
{: .no_toc }

<details open markdown="block">
  <summary>Table of contents</summary>
  {: .text-delta }
1. TOC
{:toc}
</details>

Research note. No Android store is implemented. The list commands in the audit section are existing flags, pointed at a copy pulled with adb. Researched November 2026.

Android keeps a preinstalled root store on the device. On a stock phone, Settings can turn one system root off for the current user, and it can install a user CA. trustprune can list a pulled copy of the system store. It cannot change the phone from the computer.

Anything marked **unverified** was not confirmed from Android's published behavior or from the AOSP layout described here. Menu paths and the set of roots vary by vendor and version.

## System trust store

System roots are one file per certificate. The file name is `<subject_hash_old>.0`. That hash is OpenSSL's legacy subject hash (`openssl x509 -subject_hash_old -noout`): eight hex digits. A second certificate with the same hash is `<subject_hash_old>.1`, then `.2`. On AOSP the body is a PEM certificate followed by the OpenSSL text form of that same certificate (issuer, subject, validity, extensions, and a fingerprint). One PEM block per file.

Android 13 (API 33) and earlier keep the directory at `/system/etc/security/cacerts`.

Android 14 (API 34) moved it into the updatable Conscrypt module at `/apex/com.android.conscrypt/cacerts`. Conscrypt is a [mainline module](https://source.android.com/docs/core/ota/modular-system), so on a device that receives Google Play system updates the module, including this directory, can be replaced without a full OS update. A device without Play system updates receives the directory in the system image. A later release or a vendor image can put the files somewhere else. List the directory on the device before relying on it.

`adb shell getprop ro.build.version.sdk` prints the API level. Vendors rewrite `ro.build.version.release`, so the SDK integer is the check for API 34.

On AOSP and on typical retail builds both directories are world-readable. A non-root `adb shell` can list them, and `adb pull` can copy them. The system partition and the APEX are mounted read-only, so a stock `adb push` into either path fails.

The directory is the full system set shipped on that device. OEMs add and drop roots. User-installed CAs and the per-user disable list live elsewhere, in the directories in the next section. Android 14 and later also build a per-process view of the store for apps, described there. `adb shell` lists the APEX or system directory, which is the module's full set.

If `/apex/com.android.conscrypt/cacerts` is missing, list `/system/etc/security/cacerts`. Some images have both paths. When both exist, do not treat them as the same set. On Android 14 and later the Conscrypt path is the store the module ships.

## User-added CAs and disabled system roots

User-installed CAs for one Android user are files in `/data/misc/user/<userid>/cacerts-added`. System roots that user has turned off are files in `/data/misc/user/<userid>/cacerts-removed`. The names are the same `<subject_hash_old>.0` form.

The primary user on a normal phone is userid `0`. A work profile is another user. `adb shell pm list users` prints the ids when adb is allowed. The system assigns the work-profile id. With one work profile that id is often `10`. Confirm it on the device.

`/data/misc` is not readable by the shell user. `adb pull` of either directory fails on a stock device. `adb root` works on `userdebug` and `eng` builds and is refused on a production `user` build. Reading these directories on a retail phone takes root.

Turning a system root off records that certificate in `cacerts-removed` for that user, under the same hash name. The file in the system directory stays. On AOSP, trust evaluation for that user skips a system certificate when `cacerts-removed` holds that same certificate. The store looks up the entry by hash and then compares certificate contents across the `.0`, `.1`, ... suffixes, That is Conscrypt's store. The Android 14 framework system certificate source (`SystemCertificateSource`) is different: it filters by file name only. When two system roots share a subject hash, a `cacerts-removed` entry whose suffix does not match the system file name can drop a different root from that source and leave the intended one in place. Treat a disable of a root with a hash collision as **unverified** until the result is checked on the device. Turning the root back on removes the `cacerts-removed` entry. A user CA is a certificate file in `cacerts-added` under the same kind of name. AOSP writes the files in `cacerts-added` and `cacerts-removed` as DER, not PEM with OpenSSL text like the system image. trustprune reads PEM, so convert each file before listing it (see the audit section).

This note did not check, on a device, whether a `cacerts-removed` entry still matches after a Conscrypt update or an OS update replaces the system file. That match is **unverified**.

Android keeps user anchors separate from the system store. The system source is the Conscrypt (or older system) directory, filtered against that user's `cacerts-removed`. The user source is that user's `cacerts-added`. An app's network security config selects which sources it trusts, so a new user CA does not reach an app that uses the default configuration for API 24 and later. On Android 14 and later the Conscrypt directory itself is mounted into app namespaces; that mount carries the system roots, not a merged set with user CAs. Trust code caches certificates it has loaded, so a running process may not see a change until it reloads or restarts. The on-disk record of a disable is still `cacerts-removed`.

## Installing a user CA

On AOSP the path is **Settings > Security > Encryption & credentials > Install a certificate > CA certificate**. Pixel and other vendors often nest those labels under **Security & privacy**, and they rename the intermediate screens. The choice that installs a trust anchor is **CA certificate**. Neighboring choices install a client or Wi-Fi credential.

The system warns that the CA can inspect encrypted traffic, and a notification that the network may be monitored stays up afterward. The wording changes with the version.

Since Android 11 an app cannot open this flow for a CA. [`KeyChain.createInstallIntent`](https://developer.android.com/reference/android/security/KeyChain) no longer installs a CA certificate. The intent can still install a client credential (a PKCS#12). The person installs the CA from Settings. The restriction is in the platform on Android 11 and later. It is not limited to apps whose target SDK is 30.

A CA installed here is a user CA. It is stored in `cacerts-added` for the user who installed it. It does not join the system directory. Most apps ignore it, as described in the network security config section.

## Turning off a system root

On AOSP: **Settings > Security > Encryption & credentials > Trusted credentials > System**, tap the certificate, **Turn off**. Older builds label the button **Disable**. Vendors move this screen the same way they move certificate install.

The switch writes that certificate into `cacerts-removed` for the current user. It leaves the system file in place. **Turn on** removes the `cacerts-removed` entry. The User tab lists `cacerts-added`. Removing an entry there deletes that user CA. It leaves system roots as they are.

Android does not document an `adb` command that flips this switch on a stock, non-root device. `settings` and `cmd` have no documented system-root toggle.

A device owner or a profile owner can install and remove user CAs with [`DevicePolicyManager`](https://developer.android.com/reference/android/app/admin/DevicePolicyManager) `installCaCert` and `uninstallCaCert`. Those methods write the user store of the user that admin manages. Disabling a system root has no public device-policy API.

## Root and Magisk-module overlays

With root, a Magisk module or another systemless overlay can replace `/system/etc/security/cacerts`, which is the directory Android 13 and earlier read.

Android 14 and later read `/apex/com.android.conscrypt/cacerts`, and each app process receives that store through its own mount namespace. An overlay of `/system/etc/security/cacerts` leaves those apps on the APEX store. A module has to bind-mount over the APEX path inside the namespaces the apps use. A Play system update can replace the Conscrypt module, and an OS update can replace the mount setup. Either one drops the overlay.

Verified boot signs the system and APEX contents. An overlay presents a different set of roots. It voids the stock security model. It is out of scope for automation by default. This note does not describe how to build one.

## Work profile and MDM

A work profile is a separate Android user, with its own `cacerts-added` and `cacerts-removed`. A system root turned off in the personal profile stays trusted in the work profile until that profile has its own `cacerts-removed` entry. A user CA installed in one profile is absent from the other.

Android Enterprise uses a device owner on a fully managed device and a profile owner on a work profile. Either can push a user CA with `installCaCert` and remove that CA with `uninstallCaCert`. The certificate is still a user CA, so an app that targets API 24 or higher and does not opt in to user anchors does not trust it. MDM consoles sometimes label the payload a managed configuration. On the device the public API is `DevicePolicyManager`. The per-app managed-configuration bundle ([`RestrictionsManager`](https://developer.android.com/reference/android/content/RestrictionsManager)) does not change CA trust.

System-root distrust is not an MDM policy on stock Android. No public restriction names a preinstalled root and turns it off. Some OEM enterprise stacks add their own certificate APIs. What those accept is **unverified** and out of scope here.

## App network security config

Since Android 7.0 (API 24), the default follows the app's `targetSdkVersion`. An app that targets API 24 or higher trusts system CAs only. An app that targets API 23 or lower trusts system CAs and user CAs. A network security config in the app replaces that default. The device's Android version leaves the app's target in place. The rules are the [network security configuration](https://developer.android.com/privacy-and-security/security-config).

The manifest selects the file with `android:networkSecurityConfig` on `<application>`. The usual path is `res/xml/network_security_config.xml`. The API 24 default trusts `src="system"` only.

An app can add user CAs (`<certificates src="user" />`), trust only a certificate shipped inside the app (`src="@raw/..."`), or pin keys with a `<pin-set>`. A `debug-overrides` block can trust user CAs when `android:debuggable` is true. Other builds ignore that block.

A user-store change and a system-root disable reach different apps:

- A CA in `cacerts-added` is trusted by apps that trust user anchors: apps still targeting API 23 or lower, and apps that opt in. A typical app that targets API 24 or higher and leaves the default in place ignores the user store. Removing the user CA drops it for the apps that did trust it.
- A system root turned off drops out of the system anchors for that Android user. Apps that trust those anchors, including the API 24 default, stop trusting chains under that root.
- An app that trusts only a bundled anchor, or uses its own TrustManager or TLS stack with independent anchors, follows its own anchors. Key pinning alone is not one of these: an app that trusts system anchors and pins a key still fails chain validation when its only system root is turned off, before the pin is checked.

WebView in an app uses that app's network security config. Whether current Chrome on Android verifies public sites with the Chrome Root Store, the Android system store, or both was not checked for this note and is **unverified**.

## Audit/list (first deliverable)

Pull the system directory and list the copy. This needs no root. trustprune has no `--app android`. `--store` overrides Java, certifi, and poppler only. On `list`, `--file` is a local certificate file or a pulled Android cacerts directory, and cannot be combined with `--app`.

API 34 and later:

```bash
adb shell ls /apex/com.android.conscrypt/cacerts
adb pull /apex/com.android.conscrypt/cacerts /tmp/android-cacerts
```

API 33 and earlier: use `/system/etc/security/cacerts` in both commands. If the APEX listing fails, try the older path.

`adb pull` of a directory copies that directory. It sometimes nests an extra `cacerts` folder; pass the directory that actually contains the `<hash>.0` files (`*.1`, `*.2`, and so on when a subject hash collided):

```bash
trustprune list --file /tmp/android-cacerts
trustprune list --file /tmp/android-cacerts --count
```

`list --file` on that directory reads each `<hash>.<n>` PEM file and skips the OpenSSL text after the certificate. `--format` and allowlist/denylist marking work the same as for other `list` sources. A single `.0` file, or a concatenated PEM bundle, can still be passed as a regular file.

`trustprune list --app openssl --bundle` still requires a regular PEM file. A directory is rejected. Without `--bundle`, `--app openssl` discovers the computer's own OpenSSL store. When that store is a directory, only `*.pem` and `*.crt` are read, not `<hash>.0`.

`allowlist --file` is an allowlist document, not this bundle.

The result is the system set as shipped on the device. `cacerts-added` and `cacerts-removed` are not in it. With a root shell those directories can be pulled too, but their files are DER, so concatenating them as-is does not produce a PEM bundle (`list` reports `no certificates to display`, and `--count` prints zero). Convert each non-empty file to PEM first:

```bash
#!/bin/sh
# Run as a script. It stops instead of listing a partial bundle.
: > /tmp/android-user-cas.pem
for f in /tmp/android-cacerts-added/*.[0-9]*; do
  [ -s "$f" ] || continue
  openssl x509 -inform DER -in "$f" -outform PEM >> /tmp/android-user-cas.pem \
    || { echo "cannot convert $f; stopping" >&2; exit 1; }
done
trustprune list --file /tmp/android-user-cas.pem
```

A stock `user` build cannot do that read.

## Guided distrust plan

These are taps on the phone. The computer does not write the store.

1. To turn off a preinstalled root, open **Settings > Security > Encryption & credentials > Trusted credentials > System**, tap the certificate, and choose **Turn off**. Confirm the root shows as off and that a site chaining to it now fails; when another system root shares its subject hash, Android may have dropped the wrong one (see the user-CA section). The system file stays, and **Turn on** restores it. Apps that trust system anchors see the change, including apps that also pin a key. Apps that ship independent anchors or do their own trust validation keep them. Another user, including a work profile, is unchanged.
2. To remove a CA installed by hand, open **Trusted credentials > User**, tap it, and remove it. That deletes the user CA. System roots stay as they are. Apps that do not trust user CAs are unchanged.
3. To add a CA, open **Install a certificate > CA certificate** and accept the warning. Since Android 11 an app cannot open that screen for a CA. The new certificate is a user CA, and most apps will not trust it.
4. If a user CA cannot be removed from the User tab, a device owner or profile owner likely installed it. That administrator removes it with `uninstallCaCert` or the MDM console.

There is no stock `adb` command for steps 1–3. The screen names move on vendor skins. **Trusted credentials**, **System**, **User**, and **CA certificate** are the AOSP labels.

## What could be automated (only on rooted or managed devices)

Not the default, and not implemented.

On a rooted phone, or on a `userdebug` image where `adb root` is accepted:

- Read `cacerts-added` and `cacerts-removed`, convert each DER file to PEM, concatenate them, and list them with `trustprune list --file`.
- Write the system certificate into `cacerts-removed` under the same file name as the system file (same hash and suffix, so name-only and content matching agree) to match **Turn off**, or delete that entry to match **Turn on**. On Android 14 and later an app process can keep the mounted view it started with until it starts again.
- Overlay `/system/etc/security/cacerts` on Android 13 and earlier, or bind-mount the Conscrypt APEX path inside app namespaces on Android 14 and later. Updates drop that overlay, and the overlay voids the stock security model. Out of scope for automation by default.

On a managed device, a device-owner or profile-owner app can install a user CA with `DevicePolicyManager.installCaCert` and remove it with `uninstallCaCert`, for the user that admin manages. It cannot turn off a preinstalled root through device policy. The supported step for a system root is still the Settings toggle, which the policy cannot flip.

## Cannot automate on stock devices

- Turning a system root off or on. Someone has to use Settings. No stock `adb` command does it, and no public API does it.
- Installing a CA from an app with `KeyChain.createInstallIntent`. Android 11 and later do not install a CA certificate from that intent. The user installs it from Settings.
- Reading `cacerts-added` or `cacerts-removed` on a production `user` build. `adb root` is refused, and the shell user cannot read `/data/misc`.
- Reading the user's disables out of the world-readable system or APEX directory. That directory is the full system set.
- Writing the system store with `adb push`. The system partition and the Conscrypt APEX are read-only.
- Distrusting a system root with device policy. `installCaCert` and `uninstallCaCert` handle user CAs only.
- Causing an app that targets API 24 or higher to trust a user CA. That app's network security config, or a trust manager it supplies, decides. The user store does not.
- Holding a root out of the next Conscrypt module update or OS update. The update can ship a new system store. Whether an existing `cacerts-removed` file still matches is **unverified**.
- Changing another user's store, including the work profile, from the personal profile's Settings toggles.

## Proposed follow-up

`trustprune list --file <dir>` lists a pulled Android system cacerts directory of `<hash>.0` PEM files. That is offline analysis of a copy the user already pulled; it does not talk to the device.

1. **Guide only.** A command such as `trustprune list --app android` would print the Settings path and the `adb pull` lines above. `add`, `allowlist`, `backup`, and `restore` would print the same guide and exit non-zero. No device I/O. `--app android` is not a supported app today.
2. **Out of scope.** Magisk and bind-mount automation, an MDM client, and writing `cacerts-removed` from the host.

[← Platforms](../platforms.md)
