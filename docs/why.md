---
layout: default
title: Why
nav_order: 8
---

# Why this matters

Your machine trusts hundreds of Certificate Authorities by default. Most of them you have never heard of. One bad CA is enough to break HTTPS for everyone who trusts it.

In October 2026, the private keys of eight [eMudhra](https://emudhra.com/en/post/certificate-security-incident) intermediate CAs were compromised. Six of them could issue TLS certificates for any website. [Apple blocked](https://support.apple.com/en-us/149555) those certificates in Safari and system frameworks starting 19 October 2026, and later blocked the emSign ECC Root CA - G3. Command-line tools that still read `/etc/ssl/cert.pem` (git, curl, python3, and others) kept trusting the compromised chains until users removed the roots by hand — and a subsequent macOS update can restore Apple's copy of that file. The pattern is old: DigiNotar, Symantec, WoSign, and many others. The CA system still ships with more trust than most people need, and removing it is still harder than it should be.

## Research

- [Analysis of the HTTPS Certificate Ecosystem](papers/https-imc13.pdf) (2013) — more than **1,800 entities** able to issue certificates for any website; compromise of one intermediate would force ~26% of HTTPS sites to re-issue.
- [CAge — Taming Certificate Authorities by Inferring Restricted Scopes](papers/cage-fc13.pdf) — simple inference rules cut attack surface nearly tenfold without blocking most CA activity.
- [You Won't Be Needing These Any More: On Removing Unused Certificates From Trust Stores](papers/on-removing-unused-certs.pdf) — only about two-thirds of trusted roots were observed signing HTTPS certificates.


## Incidents

Incidents keep showing the same pattern: one bad or unwanted root is enough to break HTTPS for everyone who trusts it. Browsers and vendors react after the fact; a CLI that can **list**, **backup**, **allowlist**, and **restore** trust stores is how you take that control yourself. A non-exhaustive sample (not a complete history of CA failures):

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

## Further reading

- [Mozilla CA Incident Dashboard](https://wiki.mozilla.org/CA/Incident_Dashboard)
- [mozilla.dev.security.policy](https://groups.google.com/forum/#!forum/mozilla.dev.security.policy)
- Apple: [About the compromised eMudhra intermediate CAs](https://support.apple.com/en-us/149555)
- eMudhra: [Statement on certificate security incident](https://emudhra.com/en/post/certificate-security-incident)

[← Home](index.md)
