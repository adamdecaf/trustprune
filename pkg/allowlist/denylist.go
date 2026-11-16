// Copyright 2026 Adam Shannon
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package allowlist

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"

	"github.com/adamdecaf/trustprune/pkg/certutil"
)

// The denylist is a small, committed set of known-distrusted roots and
// intermediates. Builds and tests do not use the network. It is separate
// from the generated Chromium fingerprint blocklist in blocklist.go: each
// entry here records both the certificate SHA-256 and the SHA-256 of the
// SubjectPublicKeyInfo, so a re-issued certificate that reused the key is
// still rejected.
//
// To refresh this list, run:
//
//	go generate ./pkg/allowlist
//
// That prints the reminder below and does not download anything. Then:
//
//  1. Re-read a certificate you can recompute. DigiNotar, CNNIC, WoSign, and
//     StartCom entries come from the PEM files in Chromium's
//     net/data/ssl/blocklist (the archive blocklist_gen.go downloads).
//     Symantec legacy roots come from Mozilla's Removed CA Certificate
//     Report (bugs 1670769 and 1686854), checked against that report's PEM.
//  2. Record the lowercase hex SHA-256 of the certificate DER and of
//     cert.RawSubjectPublicKeyInfo. The certificate hash must match the
//     source. Leave the entry out if you are not sure.
//  3. Put the source in a comment above the entry and commit the file.
//
//go:generate echo pkg/allowlist/denylist.go is hand-curated. Recompute certificate and SubjectPublicKeyInfo SHA-256 fingerprints from the sources named in this file, then commit them. Do not fetch during tests.

// deniedCert is one known-distrusted certificate. fingerprint is the hex
// SHA-256 of the certificate DER. spki is the hex SHA-256 of the
// SubjectPublicKeyInfo DER. Either field may be empty. A match on either
// rejects the certificate, including a later certificate that reused the key.
type deniedCert struct {
	name        string
	fingerprint string
	spki        string
}

// deniedCerts is the built-in denylist. Fingerprints are lowercase hex.
// Several historical certificates share one SPKI; each certificate is listed
// so the exact certificate matches, and the shared SPKI matches a re-issue.
var deniedCerts = []deniedCert{
	// DigiNotar (2011 CA compromise). SHA-256 of the Chromium
	// net/data/ssl/blocklist PEMs, which match the fingerprints already
	// recorded in blocklist.go. Three DigiNotar Root CA certificates share
	// SPKI a903af8c… and the DigiNotar Cyber CA certificates share SPKI
	// d34b255b…. Chromium's blocklist README says these certificates and
	// their keys are revoked.
	{
		name:        "DigiNotar Root CA",
		fingerprint: "0d136e439f0ab6e97f3a02a540da9f0641aa554e1d66ea51ae2920d51b2f7217",
		spki:        "a903af8c07bb91b0d9e3f3a30c6d53339fc5bd47e5d6bdb476598860c068a024",
	},
	{
		name:        "DigiNotar Root CA G2",
		fingerprint: "294f55ef3bd7244c6ff8a68ab797e9186ec27582751a791515e3292e48372d61",
		spki:        "455b87e96f1cea2f8b6dae0808ec24738fd92b7fd306757198bf389d755c0b6c",
	},
	{
		name:        "DigiNotar PKIoverheid CA Overheid",
		fingerprint: "31c8fd37db9b56e708b03d1f01848b068c6da66f36fb5d82c008c6040fa3e133",
		spki:        "f034f642ca1d9e88e9efeafcb15c7c937aa19e04b080f27335e1da70d1ca1201",
	},
	{
		name:        "DigiNotar PKIoverheid CA Overheid en Bedrijven",
		fingerprint: "3946901f46b0071e90d78279e82fababca177231a704be72c5b0e8918566ea66",
		spki:        "dd3eeb779bee07f9efdac382408b28d142fa842c78e8bc0e33348d57b92f0583",
	},
	{
		name:        "DigiNotar Services 1024 CA",
		fingerprint: "450f1b421bb05c8609854884559c323319619e8b06b001ea2dcbb74a23aa3be2",
		spki:        "93ca2d436cae7f68d2b4256ca175c985ce39926dc9f7eeaeecf2f8970fb97802",
	},
	{
		name:        "DigiNotar Root CA",
		fingerprint: "4fee0163686ecbd65db968e7494f55d84b25486d438e9de558d629d28cd4d176",
		spki:        "a903af8c07bb91b0d9e3f3a30c6d53339fc5bd47e5d6bdb476598860c068a024",
	},
	{
		name:        "DigiNotar Root CA",
		fingerprint: "8a1bd21661c60015065212cc98b1abb50dfd14c872a208e66bae890f25c448af",
		spki:        "a903af8c07bb91b0d9e3f3a30c6d53339fc5bd47e5d6bdb476598860c068a024",
	},
	{
		name:        "DigiNotar Cyber CA",
		fingerprint: "9ed8f9b0e8e42a1656b8e1dd18f42ba42dc06fe52686173ba2fc70e756f207dc",
		spki:        "d34b255b2fe7d1a09656cbab6409f73c796ec7d66af73653ecc39af978297310",
	},
	{
		name:        "DigiNotar Cyber CA",
		fingerprint: "a686fee577c88ab664d0787ecdfff035f4806f3de418dc9e4d516324fff02083",
		spki:        "d34b255b2fe7d1a09656cbab6409f73c796ec7d66af73653ecc39af978297310",
	},
	{
		name:        "DigiNotar PKIoverheid CA Organisatie - G2",
		fingerprint: "b8686723e415534bc0dbd16326f9486f85b0b0799bf6639334e61daae67f36cd",
		spki:        "7e7058ea35ad4359654159973f560187f16d19c514b939c5055672d1d2a518ac",
	},
	{
		name:        "DigiNotar Cyber CA",
		fingerprint: "fdedb5bdfcb67411513a61aee5cb5b5d7c52af06028efc996cc1b05b1d6cea2b",
		spki:        "d34b255b2fe7d1a09656cbab6409f73c796ec7d66af73653ecc39af978297310",
	},

	// CNNIC roots, distrusted after the 2015 unconstrained intermediate.
	// Source: Chromium net/data/ssl/blocklist PEMs 1c01c6f4….pem and
	// e2839377….pem, and Mozilla removal bug 1380868.
	{
		name:        "China Internet Network Information Center EV Certificates Root",
		fingerprint: "1c01c6f4dbb2fefc22558b2bca32563f49844acfc32b7be4b0ff599f9e8c7af7",
		spki:        "9dd55fc573f546cb6a3831d1112d8710a6f4f82dc87f5fae9d3a1a028dd36e4b",
	},
	{
		name:        "CNNIC ROOT",
		fingerprint: "e28393773da845a679f2080cc7fb44a3b7a1c3792cb7eb7729fdcb6a8d99aea7",
		spki:        "1f4224cec84fc99ced881ff6fcfd3e21f8c519c547aa6a5dd3de247302ce50d1",
	},

	// WoSign roots, distrusted in 2016. Source: Chromium
	// net/data/ssl/blocklist PEMs and Mozilla removal bug 1387260.
	{
		name:        "Certification Authority of WoSign",
		fingerprint: "4b22d5a6aec99f3cdb79aa5ec06838479cd5ecba7164f7f22dc1d65f63d85708",
		spki:        "d6a18443d348db994f934ccd8e635d833a27ac1e56f8afaf7c97cb4f43eab68b",
	},
	{
		name:        "CA WoSign ECC Root",
		fingerprint: "8b45da1c06f791eb0cabf26be588f5fb23165c2e614bf885562d0dce50b29b02",
		spki:        "7aedddf36b18f8acb7379fe1ce183212b2350d0788abe0e82457be9badad6d54",
	},
	{
		name:        "Certification Authority of WoSign G2",
		fingerprint: "d487a56f83b07482e85e963394c1ecc2c9e51d0903ee946b02c301581ed99e16",
		spki:        "381a3fc7a8b082fa28613a4d07f2c7553f4e1918ee07caa9e8b7cede5a9ca06a",
	},
	{
		name:        "CA 沃通根证书",
		fingerprint: "d6f034bd94aa233f0297eca4245b283973e447aa590f310c77f48fdf83112254",
		spki:        "db15c0062b520f318a19dacfecd64f9e7a3fbe609fd586796f20ae028e8e3058",
	},

	// StartCom roots, distrusted in 2016. Source: Chromium
	// net/data/ssl/blocklist PEMs and Mozilla removal bug 1392849.
	// The two StartCom Certification Authority certificates share one key.
	{
		name:        "StartCom Certification Authority",
		fingerprint: "c766a9bef2d4071c863a31aa4920e813b2d198608cb7b7cfe21143b836df09ea",
		spki:        "e42f24bd4d37f4aa2e56b979d83d1e65219fe0e9e3a382a1b3cb66c93955de75",
	},
	{
		name:        "StartCom Certification Authority G2",
		fingerprint: "c7ba6567de93a798ae1faa791e712d378fae1f93c4397fea441bb7cbe6fd5995",
		spki:        "1528397da212890a830b0b95a59968cef234773779df5181cf10fa647534bb65",
	},
	{
		name:        "StartCom Certification Authority",
		fingerprint: "e17890ee09a3fbf4f48b9c414a17d637b7a50647e9bc752322727fcc1742a911",
		spki:        "e42f24bd4d37f4aa2e56b979d83d1e65219fe0e9e3a382a1b3cb66c93955de75",
	},

	// Symantec legacy roots (GeoTrust, thawte, VeriSign) removed from
	// Mozilla NSS after the public Symantec distrust. Fingerprints are the
	// SHA-256 column of Mozilla's Removed CA Certificate Report; SPKI is
	// SHA-256 of SubjectPublicKeyInfo from that report's PEM. Bugs 1670769
	// and 1686854. Checked on 2026-11-16 against Mozilla's included CA
	// report: none of these SPKIs were still included.
	{
		name:        "GeoTrust Primary Certification Authority",
		fingerprint: "37d51006c512eaab626421f1ec8c92013fc5f82ae98ee533eb4619b8deb4d06c",
		spki:        "4905466623ab4178be92ac5cbd6584f7a1e17f27652d5a85af89504ea239aaaa",
	},
	{
		name:        "GeoTrust Primary Certification Authority - G2",
		fingerprint: "5edb7ac43b82a06a8761e8d7be4979ebf2611f7dd79bf91c1c6b566a219ed766",
		spki:        "bcfb44aab9ad021015706b4121ea761c81c9e88967590f6f94ae744dc88b78fb",
	},
	{
		name:        "GeoTrust Primary Certification Authority - G3",
		fingerprint: "b478b812250df878635c2aa7ec7d155eaa625ee82916e2cd294361886cd1fbd4",
		spki:        "ab98495276adf1ecaff28f35c53048781e5c1718dab9c8e67a504f4f6a51328f",
	},
	{
		name:        "GeoTrust Universal CA",
		fingerprint: "a0459b9f63b22559f5fa5d4c6db3f9f72ff19342033578f073bf1d1b46cbb912",
		spki:        "9699225c5de52e56cdd32df2e96d1cfea5aa3ca0bb52cd8933c23b5c27443820",
	},
	{
		name:        "GeoTrust Universal CA 2",
		fingerprint: "a0234f3bc8527ca5628eec81ad5d69895da5680dc91d1cb8477f33f878b95b0b",
		spki:        "7caa03465124590c601e567e52148e952c0cffe89000530fe0d95b6d50eaae41",
	},
	{
		name:        "thawte Primary Root CA",
		fingerprint: "8d722f81a9c113c0791df136a2966db26c950a971db46b4199f4ea54b78bfb9f",
		spki:        "1d75d0831b9e0885394d32c7a1bfdb3dbc1c28e2b0e8391fb135981dbc5ba936",
	},
	{
		name:        "thawte Primary Root CA - G2",
		fingerprint: "a4310d50af18a6447190372a86afaf8b951ffb431d837f1e5688b45971ed1557",
		spki:        "67dc4f32fa10e7d01a79a073aa0c9e0212ec2ffc3d779e0aa7f9c0f0e1c2c893",
	},
	{
		name:        "thawte Primary Root CA - G3",
		fingerprint: "4b03f45807ad70f21bfc2cae71c9fde4604c064cf5ffb686bae5dbaad7fdd34c",
		spki:        "1906c6124dbb438578d00e066d5054c6c37f0fa6028c05545e0994eddaec8629",
	},
	{
		name:        "VeriSign Class 3 Public Primary Certification Authority - G4",
		fingerprint: "69ddd7ea90bb57c93e135dc85ea6fcd5480b603239bdc454fc758b2a26cf7f79",
		spki:        "5192438ec369d7ee0ce71f5c6db75f941efbf72e58441715e99eab04c2c8acee",
	},
	{
		name:        "VeriSign Class 3 Public Primary Certification Authority - G5",
		fingerprint: "9acfab7e43c8d880d06b262a94deeee4b4659989c3d0caf19baf6405e41ab7df",
		spki:        "25b41b506e4930952823a6eb9f1d31def645ea38a5c6c6a96d71957e384df058",
	},
	{
		name:        "VeriSign Universal Root Certification Authority",
		fingerprint: "2399561127a57125de8cefea610ddf2fa078b5c8067f4e828290bfb860e84b3c",
		spki:        "967b0cd93fcef7f27ce2c245767ae9b05a776b0649f9965b6290968469686872",
	},
}

// Denied reports whether cert is on the built-in denylist. A certificate
// matches when its SHA-256 fingerprint matches, or when the SHA-256 of its
// SubjectPublicKeyInfo matches. name is a short label for the matching entry.
func Denied(cert *x509.Certificate) (denied bool, name string) {
	if cert == nil {
		return false, ""
	}
	fp := certutil.GetHexSHA256Fingerprint(*cert)
	spkiFP := spkiSHA256(cert)
	for i := range deniedCerts {
		e := &deniedCerts[i]
		if sameHex(e.fingerprint, fp) || (spkiFP != "" && sameHex(e.spki, spkiFP)) {
			return true, e.name
		}
	}
	return false, ""
}

// AddDeniedForTest appends one denylist entry until the returned function
// runs. It is for tests. Do not call it from parallel tests.
func AddDeniedForTest(name, fingerprint, spki string) func() {
	prev := deniedCerts
	deniedCerts = append(append([]deniedCert{}, deniedCerts...), deniedCert{
		name:        name,
		fingerprint: fingerprint,
		spki:        spki,
	})
	return func() { deniedCerts = prev }
}

func spkiSHA256(cert *x509.Certificate) string {
	if cert == nil || len(cert.RawSubjectPublicKeyInfo) == 0 {
		return ""
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// sameHex reports whether a and b are the same SHA-256 hex digest. Colons,
// spaces, and case are ignored. Anything that is not 64 hex digits does not
// match, so a short or empty field never rejects a certificate.
func sameHex(a, b string) bool {
	na := normHex(a)
	nb := normHex(b)
	return na != "" && na == nb
}

func normHex(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == ':' || c == ' ' || c == '\t':
			continue
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f':
			out = append(out, c)
		case c >= 'A' && c <= 'F':
			out = append(out, c-'A'+'a')
		default:
			return ""
		}
	}
	if len(out) != sha256.Size*2 {
		return ""
	}
	return string(out)
}
