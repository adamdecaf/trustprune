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

Research note for [#97](https://github.com/adamdecaf/trustprune/issues/97). No Android store is implemented. The list commands in the audit section are existing flags, pointed at a copy pulled with adb. Researched November 2026. Official Android documentation and AOSP sources cited here were fetched and checked on 2026-11-26.

Android keeps a preinstalled root store on the device. On a stock phone, Settings can turn one system root off for the current user, and it can install a user CA. trustprune can list a pulled copy of the system store. It cannot change the phone from the computer.

Anything marked **unverified** was not confirmed from Android's published behavior or from the AOSP layout described here. Menu paths and the set of roots vary by vendor and version.

## System trust store

System roots are one file per certificate. The file name is `<hash>.<n>`. [Conscrypt's cacerts README](https://android.googlesource.com/platform/external/conscrypt/+/master/apex/ca-certificates/README.cacerts) says the hash is OpenSSL's legacy subject hash (`openssl x509 -subject_hash_old -in filename`): eight hex digits. `n` starts at `0`. A second certificate with the same hash is `<hash>.1`, then `.2`. See OpenSSL's `c_rehash` for that collision rule. On AOSP the body is a PEM certificate followed by the OpenSSL text form of that same certificate (issuer, subject, validity, extensions, and a fingerprint). One PEM block per file.

On Android 13 and earlier, the on-device directory is `$ANDROID_ROOT/etc/security/cacerts`, which is `/system/etc/security/cacerts` when `ANDROID_ROOT` is `/system`. That path is what [SystemCertificateSource](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/core/java/android/security/net/config/SystemCertificateSource.java) and [TrustedCertificateStore](https://android.googlesource.com/platform/external/conscrypt/+/master/platform/src/main/java/org/conscrypt/TrustedCertificateStore.java) use as the fallback. The AOSP source tree that builds those files is `system/ca-certificates`; [the Conscrypt module page](https://source.android.com/docs/core/ota/modular-system/conscrypt) still refers to that tree as `system/ca-certificates`.

[Android 14 introduced an updatable root trust store in the Conscrypt module](https://source.android.com/docs/core/ota/modular-system/conscrypt). Starting in Android 14, those roots are stored in the Conscrypt APEX and in the system partition. The runtime path the AOSP classes look at first is `/apex/com.android.conscrypt/cacerts`. They use it when the directory exists and is not empty, and when the SDK level is 34 or higher (`TrustedCertificateStore.shouldUseApex`). Otherwise they fall back to `$ANDROID_ROOT/etc/security/cacerts`. The `system.certs.enabled=true` system property forces the older path. Conscrypt is a [mainline module](https://source.android.com/docs/core/ota/modular-system) (`com.android.conscrypt`), so on a device that receives Google Play system updates the module, including this directory, can be replaced without a full OS update. A device without Play system updates receives the directory in the system image. A later release or a vendor image can put the files somewhere else. List the directory on the device before relying on it.

`adb shell getprop ro.build.version.sdk` prints the API level. Vendors rewrite `ro.build.version.release`, so the SDK integer is the check for API 34.

On AOSP and on typical retail builds both directories are world-readable. A non-root `adb shell` can list them, and `adb pull` can copy them. The system partition and the APEX are mounted read-only, so a stock `adb push` into either path fails.

The directory is the full system set shipped on that device. OEMs add and drop roots. User-installed CAs and the per-user disable list live elsewhere, in the directories in the next section. Android 14 and later also build a per-process view of the store for apps, described there. `adb shell` lists the APEX or system directory, which is the module's full set.

If `/apex/com.android.conscrypt/cacerts` is missing, list `/system/etc/security/cacerts`. Some images have both paths. When both exist, do not treat them as the same set. On Android 14 and later the Conscrypt path is the store the module ships, when `shouldUseApex` accepts it.

## User-added CAs and disabled system roots

User-installed CAs for one Android user are files in `/data/misc/user/<userid>/cacerts-added`. System roots that user has turned off are files in `/data/misc/user/<userid>/cacerts-removed`. The names are the same `<hash>.<n>` form.

Those paths come from [`Environment.getUserConfigDirectory`](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/core/java/android/os/Environment.java), which returns `/data/misc/user/<userid>` (`getDataDirectory()` plus `misc/user/<id>`). [UserCertificateSource](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/core/java/android/security/net/config/UserCertificateSource.java) opens `cacerts-added` in that directory. `SystemCertificateSource` opens `cacerts-removed` there. `TrustedCertificateStore`'s compiled default is `$ANDROID_DATA/misc/keychain` (`cacerts-added` and `cacerts-removed` under that directory, created in `init.rc`). On a running app or Settings process, [`ActivityThread`](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/core/java/android/app/ActivityThread.java) calls `TrustedCertificateStore.setDefaultUserDirectory` with `getUserConfigDirectory` for the current user, so the per-user directories are the ones that matter. The primary user on a normal phone is userid `0`. A work profile is another user. `adb shell pm list users` prints the ids when adb is allowed. The system assigns the work-profile id. With one work profile that id is often `10`. Confirm it on the device.

`/data/misc` is not readable by the shell user. `adb pull` of either directory fails on a stock device. `adb root` works on `userdebug` and `eng` builds and is refused on a production `user` build. Reading these directories on a retail phone takes root.

Turning a system root off records that certificate in `cacerts-removed` for that user, under the same hash name. The file in the system directory stays. [TrustedCertificateStore](https://android.googlesource.com/platform/external/conscrypt/+/master/platform/src/main/java/org/conscrypt/TrustedCertificateStore.java) does this by writing an exact copy of the CA into the removed directory. Lookup there uses the subject hash and then compares certificate contents (`X509Certificate.equals`, based on the encoded form) across the `.0`, `.1`, … suffixes. That is Conscrypt's store. The framework [SystemCertificateSource](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/core/java/android/security/net/config/SystemCertificateSource.java) is different: `isCertMarkedAsRemoved` only checks whether a file with the same name exists in `cacerts-removed`. [DirectoryCertificateSource](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/core/java/android/security/net/config/DirectoryCertificateSource.java) then skips that file name. When two system roots share a subject hash, a `cacerts-removed` entry whose suffix does not match the system file name can drop a different root from that source and leave the intended one in place. Treat a disable of a root with a hash collision as **unverified** until the result is checked on the device. Turning the root back on removes the `cacerts-removed` entry. A user CA is a certificate file in `cacerts-added` under the same kind of name. AOSP writes the files in `cacerts-added` and `cacerts-removed` as DER (`TrustedCertificateStore.writeCertificate` writes `cert.getEncoded()`), not PEM with OpenSSL text like the system image. trustprune reads PEM, so convert each file before listing it (see the audit section).

`TrustedCertificateStore` says those deletions are intended to persist across upgrades, and are not intended to mask a CA that has a matching name or public key but is otherwise reissued in a system update. This note did not check, on a device, whether a `cacerts-removed` entry still matches after a Conscrypt update or an OS update replaces the system file. That on-device match is **unverified**.

Android keeps user anchors separate from the system store. The system source is the Conscrypt (or older system) directory, filtered against that user's `cacerts-removed`. The user source is that user's `cacerts-added`. An app's network security config selects which sources it trusts, so a new user CA does not reach an app that uses the default configuration for API 24 and later. On Android 14 and later the Conscrypt directory itself is mounted into app namespaces; that mount carries the system roots, not a merged set with user CAs. Trust code caches certificates it has loaded, so a running process may not see a change until it reloads or restarts (`DirectoryCertificateSource` keeps a cache until `handleTrustStorageUpdate`). The on-disk record of a disable is still `cacerts-removed`.

## Installing a user CA

On AOSP the path is **Settings > Security > Encryption & credentials > Install a certificate > CA certificate**. Those labels are the current AOSP [Settings strings](https://android.googlesource.com/platform/packages/apps/Settings/+/refs/heads/main/res/values/strings.xml) (`security_settings_title`, `encryption_and_credential_settings_title`, `credentials_install`, `ca_certificate`). Pixel documents a vendor path: **Settings > Security & privacy > More security settings > Encryption & credentials > Install a certificate**, and the help page walked through a Wi-Fi certificate when it was fetched ([Add & remove certificates](https://support.google.com/pixelphone/answer/2844832)). Other vendors rename the intermediate screens. The AOSP choice that installs a trust anchor is **CA certificate**. Neighboring choices install a client or Wi-Fi credential.

The system shows a warning before install (`ca_certificate_warning_title` / `ca_certificate_warning_description`; current AOSP title is "Your data won't be private"), and a notification labeled **Network may be monitored** (`ssl_ca_cert_warning`) stays up afterward. The wording changes with the version.

Since Android 11 (API 30, `Build.VERSION_CODES.R`) an app cannot open this flow for a CA. [`KeyChain.createInstallIntent`](https://developer.android.com/reference/android/security/KeyChain#createInstallIntent%28%29) no longer installs a CA certificate. The documentation says CA certificates can only be installed via Settings, and the app should give the user a file (for example by writing it to `MediaStore.Downloads`). The intent can still install a client credential (a PKCS#12). The restriction is in the platform on Android 11 and later. It is not limited to apps whose target SDK is 30.

A CA installed here is a user CA. It is stored in `cacerts-added` for the user who installed it. It does not join the system directory. Most apps ignore it, as described in the network security config section. Pixel's help states that removing certificates you installed does not remove the permanent system certificates.

## Turning off a system root

On AOSP: **Settings > Security > Encryption & credentials > Trusted credentials > System**, tap the certificate, **Disable**. The current AOSP Settings strings use **Disable** and **Enable** for a system CA, and **Uninstall** for a user CA (`trusted_credentials_disable_label`, `trusted_credentials_enable_label`, `trusted_credentials_remove_label`). Vendors move this screen the same way they move certificate install, and they may relabel the button (some use **Turn off**).

The switch writes that certificate into `cacerts-removed` for the current user. It leaves the system file in place. **Enable** removes the `cacerts-removed` entry. The User tab lists `cacerts-added`. Removing an entry there uninstalls that user CA. It leaves system roots as they are.

Android does not document an `adb` command that flips this switch on a stock, non-root device. `settings` and `cmd` have no documented system-root toggle.

A device owner or a profile owner can install and remove user CAs with [`DevicePolicyManager`](https://developer.android.com/reference/android/app/admin/DevicePolicyManager#installCaCert%28android.content.ComponentName,%20byte[]%29) `installCaCert` and `uninstallCaCert`. The documentation describes `installCaCert` as installing the given certificate as a user CA. Those methods write the user store of the user that admin manages. Disabling a system root has no public device-policy API.

## Root and Magisk-module overlays

With root, a Magisk module or another systemless overlay can replace `/system/etc/security/cacerts`, which is the directory Android 13 and earlier read.

Android 14 and later read `/apex/com.android.conscrypt/cacerts`, and each app process receives that store through its own mount namespace. An overlay of `/system/etc/security/cacerts` leaves those apps on the APEX store. A module has to bind-mount over the APEX path inside the namespaces the apps use. A Play system update can replace the Conscrypt module, and an OS update can replace the mount setup. Either one drops the overlay.

Verified boot signs the system and APEX contents. An overlay presents a different set of roots. It voids the stock security model. It is out of scope for automation by default. This note does not describe how to build one.

## Work profile and MDM

A work profile is a separate Android user, with its own `cacerts-added` and `cacerts-removed`. A system root turned off in the personal profile stays trusted in the work profile until that profile has its own `cacerts-removed` entry. A user CA installed in one profile is absent from the other.

Android Enterprise uses a device owner on a fully managed device and a profile owner on a work profile. Either can push a user CA with `installCaCert` and remove that CA with `uninstallCaCert`. The certificate is still a user CA, so an app that targets API 24 or higher and does not opt in to user anchors does not trust it. MDM consoles sometimes label the payload a managed configuration. On the device the public API is `DevicePolicyManager`. The per-app managed-configuration bundle ([`RestrictionsManager`](https://developer.android.com/reference/android/content/RestrictionsManager)) does not change CA trust.

System-root distrust is not an MDM policy on stock Android. No public restriction names a preinstalled root and turns it off. Some OEM enterprise stacks add their own certificate APIs. What those accept is **unverified** and out of scope here.

## App network security config

Since Android 7.0 (API 24), the default follows the app's `targetSdkVersion`. The rules are the [network security configuration](https://developer.android.com/privacy-and-security/security-config). An app that targets API 24 or higher trusts system CAs only (`<certificates src="system" />` in the documented default `base-config`). An app that targets API 23 or lower trusts system CAs and user CAs (`src="system"` and `src="user"`). A network security config in the app replaces that default. The device's Android version leaves the app's target in place. The [Conscrypt module page](https://source.android.com/docs/core/ota/modular-system/conscrypt) also notes that apps can still choose their own certificates and modify certificate behavior with `NetworkSecurityConfig`.

The manifest selects the file with `android:networkSecurityConfig` on `<application>`. The usual path is `res/xml/network_security_config.xml`.

An app can add user CAs (`<certificates src="user" />`), trust only a certificate shipped inside the app (`src="@raw/..."`), or pin keys with a `<pin-set>`. A `debug-overrides` block can trust user CAs when `android:debuggable` is true. Other builds ignore that block. App stores do not accept apps marked debuggable.

A user-store change and a system-root disable reach different apps:

- A CA in `cacerts-added` is trusted by apps that trust user anchors: apps still targeting API 23 or lower, and apps that opt in. A typical app that targets API 24 or higher and leaves the default in place ignores the user store. Removing the user CA drops it for the apps that did trust it.
- A system root turned off drops out of the system anchors for that Android user. Apps that trust those anchors, including the API 24 default, stop trusting chains under that root.
- An app that trusts only a bundled anchor, or uses its own TrustManager or TLS stack with independent anchors, follows its own anchors. Key pinning alone is not one of these: an app that trusts system anchors and pins a key still fails chain validation when its only system root is turned off, before the pin is checked.

WebView in an app uses that app's network security config. Whether current Chrome on Android verifies public sites with the Chrome Root Store, the Android system store, or both was not checked for this note and is **unverified**.

## Audit/list (first deliverable)

Pull the system directory and list the copy. This needs no root. `--app android` is a guide-only app: `list --app android --file <dir> --allowlist <path>` prints a disable report on that copy, and mutating commands print the Settings and adb steps without writing. `--store` overrides Java, certifi, and poppler only. On `list`, `--file` is a local certificate file or a pulled Android cacerts directory. It cannot be combined with `--app` except for `list --app android --file <dir> --allowlist <path>`.

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

`list --file` on that directory reads each `<hash>.<n>` PEM or DER file and skips the OpenSSL text after a PEM certificate. It also reads `.crt`, `.cer`, and `.der` exports of user-installed CAs. `--format` and allowlist/denylist marking work the same as for other `list` sources. A single `.0` file, or a concatenated PEM bundle, can still be passed as a regular file.

`trustprune list --app openssl --bundle` still requires a regular PEM file. A directory is rejected. Without `--bundle`, `--app openssl` discovers the computer's own OpenSSL store. When that store is a directory, only `*.pem` and `*.crt` are read, not `<hash>.0`.

`allowlist --file` is an allowlist document, not this bundle. `list --app android --file <dir> --allowlist <path>` prints a compact ranked table of the certificates that allowlist (and the built-in denylist) would not keep, with REASON, DAYS, LABELS, and a `N to disable of M` footer. A recorded Mozilla distrust-after date is shown in REASON. Settings and adb steps print only with `-v`. `--format json` and `--count` are supported. Denylist and blocklist hits come first, then certificates not in the allowlist, with user CAs (`.crt`/`.cer`/`.der`, or files in a `cacerts-added` directory) above system CAs, then earlier expiry. `add`, `allowlist`, `backup`, `restore`, and `create` with `--app android` print those same steps and exit non-zero without writing.

The result is the system set as shipped on the device. `cacerts-added` and `cacerts-removed` are not in it. With a root shell those directories can be pulled too. `list --file` on the pulled directory reads the DER `<hash>.<n>` files directly. Concatenating them as-is still does not produce a PEM bundle (`list` on that file reports `no certificates to display`, and `--count` prints zero). To build a PEM bundle, convert each non-empty file first:

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

1. To turn off a preinstalled root, open **Settings > Security > Encryption & credentials > Trusted credentials > System**, tap the certificate, and choose **Disable** (AOSP's current label; a vendor skin may say **Turn off**). Confirm the root shows as disabled and that a site chaining to it now fails; when another system root shares its subject hash, Android may have dropped the wrong one (see the user-CA section). The system file stays, and **Enable** restores it. Apps that trust system anchors see the change, including apps that also pin a key. Apps that ship independent anchors or do their own trust validation keep them. Another user, including a work profile, is unchanged.
2. To remove a CA installed by hand, open **Trusted credentials > User**, tap it, and **Uninstall** it. That deletes the user CA. System roots stay as they are. Apps that do not trust user CAs are unchanged.
3. To add a CA, open **Install a certificate > CA certificate** and accept the warning. Since Android 11 an app cannot open that screen for a CA. The new certificate is a user CA, and most apps will not trust it.
4. If a user CA cannot be removed from the User tab, a device owner or profile owner likely installed it. That administrator removes it with `uninstallCaCert` or the MDM console.

There is no stock `adb` command for steps 1–3. The screen names move on vendor skins. **Trusted credentials**, **System**, **User**, and **CA certificate** are the AOSP labels.

## What could be automated (only on rooted or managed devices)

Not the default, and not implemented.

On a rooted phone, or on a `userdebug` image where `adb root` is accepted:

- Read `cacerts-added` and `cacerts-removed`, convert each DER file to PEM, concatenate them, and list them with `trustprune list --file`.
- Write the system certificate into `cacerts-removed` under the same file name as the system file (same hash and suffix, so name-only and content matching agree) to match **Disable**, or delete that entry to match **Enable**. On Android 14 and later an app process can keep the mounted view it started with until it starts again.
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
- Holding a root out of the next Conscrypt module update or OS update. The update can ship a new system store. AOSP intends a `cacerts-removed` copy to persist across upgrades, and not to mask a reissued CA with a matching name or public key. Whether an existing file still matches on a device after such an update is **unverified**.
- Changing another user's store, including the work profile, from the personal profile's Settings toggles.

## Proposed follow-up

`trustprune list --file <dir>` lists a pulled Android system cacerts directory of `<hash>.0` PEM or DER files, and `.crt`/`.cer`/`.der` exports of user-installed CAs. That is offline analysis of a copy the user already pulled; it does not talk to the device.

`trustprune list --app android --file <dir> --allowlist <path>` is a guide-only report on that same pulled directory: a compact ranked table of the certificates the allowlist (and built-in denylist) would not keep, with REASON, DAYS, LABELS, and a `N to disable of M` footer. A recorded Mozilla distrust-after date is shown in REASON. Settings and adb steps print only with `-v`. `--format json` and `--count` are supported. Denylist and blocklist hits come first, then certificates not in the allowlist, with user CAs above system CAs, then earlier expiry. It does not write to the device. `--app android` is a registered guide-only app: `apps` lists it, and `add`, `allowlist`, `backup`, `restore`, and `create` print the Settings and adb steps and exit non-zero without writing.

1. **Future work, outside this issue.** An interactive companion that walks the user through the Settings toggle (or asks an MDM admin to install or remove a user CA). It still cannot write the system store on a stock device. The list report already ranks which certificates to disable first.
2. **Out of scope.** Magisk and bind-mount automation, an MDM client, and writing `cacerts-removed` from the host.

[← Platforms](../platforms.md)
