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
	"bytes"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/adamdecaf/trustprune/pkg/certutil"
)

const appleBlockedFixture = "testdata/apple-blocked-certificates.html"

// affirmTrustCommercial is a SHA-256 Apple published in the TLS constrained
// table on the same page, not in Blocked Certificates. The fixture includes
// this row so the parser can be checked against leaking constrained certs.
const affirmTrustCommercial = "0376ab1d54c5f9803ce4b2e201a0ee7eef7b57b636e8a93c9b8d4860c96f5fa7"

func TestParseAppleBlockedCertificates_fixture(t *testing.T) {
	t.Parallel()
	f, err := os.Open(appleBlockedFixture)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := f.Close(); err != nil {
			t.Error(err)
		}
	})
	certs, err := ParseAppleBlockedCertificates(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 66 {
		t.Fatalf("got %d blocked certificates, want 66", len(certs))
	}

	want := make([]string, 0, len(certs))
	seen := make(map[string]string, len(certs))
	for _, c := range certs {
		if !hexFingerprint(c.Fingerprint) {
			t.Fatalf("invalid fingerprint %q (%q)", c.Fingerprint, c.Name)
		}
		if c.Name == "" {
			t.Fatalf("empty name for %s", c.Fingerprint)
		}
		if prev, ok := seen[c.Fingerprint]; ok {
			t.Fatalf("duplicate %s (%q and %q)", c.Fingerprint, prev, c.Name)
		}
		seen[c.Fingerprint] = c.Name
		want = append(want, c.Fingerprint)
	}
	if _, ok := seen[affirmTrustCommercial]; ok {
		t.Fatal("constrained AffirmTrust Commercial fingerprint leaked into the blocked list")
	}

	got := append([]string(nil), appleBlocklistedFingerprints...)
	sort.Strings(want)
	if len(got) != len(want) {
		t.Fatalf("generated list has %d fingerprints, fixture has %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("generated list does not match fixture at %d: got %s, want %s", i, got[i], want[i])
		}
	}
}

func TestParseAppleBlockedCertificates_ignoresConstrained(t *testing.T) {
	t.Parallel()
	const doc = `<html><body>
<h2>Blocked Certificates</h2>
<table>
<tr><th>Certificate SHA256 Fingerprint</th><th>Certificate Name</th></tr>
<tr><td>0d136e439f0ab6e97f3a02a540da9f0641aa554e1d66ea51ae2920d51b2f7217</td><td>DigiNotar Root CA</td></tr>
</table>
<h2>Constrained Certificates</h2>
<table>
<tr><th>Certificate SHA256 Fingerprint</th><th>Certificate Name</th></tr>
<tr><td>0376ab1d54c5f9803ce4b2e201a0ee7eef7b57b636e8a93c9b8d4860c96f5fa7</td><td>AffirmTrust Commercial</td></tr>
</table>
</body></html>`
	certs, err := ParseAppleBlockedCertificates(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 1 || certs[0].Fingerprint != "0d136e439f0ab6e97f3a02a540da9f0641aa554e1d66ea51ae2920d51b2f7217" {
		t.Fatalf("got %#v", certs)
	}
	if certs[0].Name != "DigiNotar Root CA" {
		t.Fatalf("name %q", certs[0].Name)
	}
}

func TestParseAppleBlockedCertificates_errors(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		doc  string
	}{
		{name: "empty", doc: ""},
		{name: "no heading", doc: "<html><table><tr><td>0d136e439f0ab6e97f3a02a540da9f0641aa554e1d66ea51ae2920d51b2f7217</td><td>DigiNotar Root CA</td></tr></table></html>"},
		{name: "no table", doc: "<html><h2>Blocked Certificates</h2><p>none</p></html>"},
		{name: "invalid fingerprint", doc: `<html><h2>Blocked Certificates</h2><table><tr><td>not-a-fingerprint</td><td>Bad</td></tr></table></html>`},
		{name: "duplicate", doc: `<html><h2>Blocked Certificates</h2><table>
<tr><td>0d136e439f0ab6e97f3a02a540da9f0641aa554e1d66ea51ae2920d51b2f7217</td><td>One</td></tr>
<tr><td>0d136e439f0ab6e97f3a02a540da9f0641aa554e1d66ea51ae2920d51b2f7217</td><td>Two</td></tr>
</table></html>`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := ParseAppleBlockedCertificates(strings.NewReader(tc.doc)); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestAllowlist_appleBlocklistedFingerprintsLoad(t *testing.T) {
	if len(appleBlocklistedFingerprints) != 66 {
		t.Fatalf("appleBlocklistedFingerprints has %d entries, want 66", len(appleBlocklistedFingerprints))
	}
	if !sort.StringsAreSorted(appleBlocklistedFingerprints) {
		t.Fatal("appleBlocklistedFingerprints is not sorted")
	}
	seen := make(map[string]struct{}, len(appleBlocklistedFingerprints))
	for _, fp := range appleBlocklistedFingerprints {
		if !hexFingerprint(fp) {
			t.Fatalf("fingerprint %q is not lowercase hex SHA-256", fp)
		}
		if _, ok := seen[fp]; ok {
			t.Fatalf("duplicate fingerprint %s", fp)
		}
		seen[fp] = struct{}{}
	}
	if _, ok := seen[affirmTrustCommercial]; ok {
		t.Fatal("constrained AffirmTrust Commercial fingerprint is on the Apple blocklist")
	}

	src, err := os.ReadFile("apple_blocklist.go")
	if err != nil {
		t.Fatal(err)
	}
	const sourceURL = "https://support.apple.com/en-us/103255"
	if !bytes.Contains(src, []byte(sourceURL)) {
		t.Fatal("generated file is missing the Apple support URL")
	}
	if !bytes.Contains(src, []byte("Blocked Certificates")) {
		t.Fatal("generated file does not cite the Blocked Certificates table")
	}
	if !bytes.Contains(src, []byte("Constrained certificates on that page are not included")) {
		t.Fatal("generated file does not say constrained certificates are omitted")
	}

	// Independently verified: these Apple-published SHA-256 values match
	// denylist entries whose fingerprints were recomputed from the source
	// PEMs named in denylist.go.
	verified := []struct {
		name string
		fp   string
	}{
		{"CNNIC ROOT", "e28393773da845a679f2080cc7fb44a3b7a1c3792cb7eb7729fdcb6a8d99aea7"},
		{"DigiNotar Root CA", "0d136e439f0ab6e97f3a02a540da9f0641aa554e1d66ea51ae2920d51b2f7217"},
		{"DigiNotar Root CA G2", "294f55ef3bd7244c6ff8a68ab797e9186ec27582751a791515e3292e48372d61"},
		{"GeoTrust Primary Certification Authority", "37d51006c512eaab626421f1ec8c92013fc5f82ae98ee533eb4619b8deb4d06c"},
		{"GeoTrust Primary Certification Authority - G3", "b478b812250df878635c2aa7ec7d155eaa625ee82916e2cd294361886cd1fbd4"},
		{"SenncomRootCA", "91e5cc32910686c5cac25c18cc805696c7b33868c280caf0c72844a2a8eb91e2"},
		{"StartCom Certification Authority", "c766a9bef2d4071c863a31aa4920e813b2d198608cb7b7cfe21143b836df09ea"},
		{"StartCom Certification Authority", "e17890ee09a3fbf4f48b9c414a17d637b7a50647e9bc752322727fcc1742a911"},
		{"StartCom Certification Authority G2", "c7ba6567de93a798ae1faa791e712d378fae1f93c4397fea441bb7cbe6fd5995"},
		{"thawte Primary Root CA", "8d722f81a9c113c0791df136a2966db26c950a971db46b4199f4ea54b78bfb9f"},
		{"thawte Primary Root CA - G2", "a4310d50af18a6447190372a86afaf8b951ffb431d837f1e5688b45971ed1557"},
		{"thawte Primary Root CA - G3", "4b03f45807ad70f21bfc2cae71c9fde4604c064cf5ffb686bae5dbaad7fdd34c"},
		{"VeriSign Class 3 Public Primary Certification Authority - G4", "69ddd7ea90bb57c93e135dc85ea6fcd5480b603239bdc454fc758b2a26cf7f79"},
		{"VeriSign Universal Root Certification Authority", "2399561127a57125de8cefea610ddf2fa078b5c8067f4e828290bfb860e84b3c"},
	}
	deny := make(map[string]string)
	for _, d := range deniedCerts {
		if d.fingerprint != "" {
			deny[d.fingerprint] = d.name
		}
	}
	for _, v := range verified {
		if _, ok := seen[v.fp]; !ok {
			t.Errorf("verified fingerprint %s (%s) missing from Apple blocklist", v.fp, v.name)
		}
		if got := deny[v.fp]; got == "" {
			t.Errorf("verified fingerprint %s (%s) missing from denylist", v.fp, v.name)
		}
	}

	// Qaznet is on Chromium's blocklist and on Apple's published list.
	const qaznet = "00309c736dd661da6f1eb24173aa849944c168a43a15bffd192eecfdb6f8dbd2"
	if _, ok := seen[qaznet]; !ok {
		t.Errorf("Qaznet Trust Network fingerprint %s missing from Apple blocklist", qaznet)
	}
	foundChrome := false
	for _, fp := range blocklistedFingerprints {
		if fp == qaznet {
			foundChrome = true
			break
		}
	}
	if !foundChrome {
		t.Errorf("Qaznet Trust Network fingerprint %s missing from Chromium blocklist", qaznet)
	}
}

func TestAllowlist_appleBlocklistRejectsMatch(t *testing.T) {
	certs, err := certutil.FromFile("../../testdata/example.crt")
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) == 0 || certs[0] == nil {
		t.Fatal("expected example.crt")
	}
	fp := certutil.GetHexSHA256Fingerprint(*certs[0])

	orig := appleBlocklistedFingerprints
	t.Cleanup(func() { appleBlocklistedFingerprints = orig })
	appleBlocklistedFingerprints = append([]string{fp}, appleBlocklistedFingerprints...)

	al := Allowlist{Fingerprints: []string{fp}, Countries: []string{"US"}}
	if al.Matches(certs[0]) {
		t.Fatal("Apple blocklisted fingerprint should not match even if it is on the allowlist")
	}
}

func hexFingerprint(fp string) bool {
	if len(fp) != 64 {
		return false
	}
	for _, c := range fp {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
