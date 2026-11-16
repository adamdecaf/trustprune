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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/adamdecaf/trustprune/pkg/certutil"
)

func TestDenylist_committedEntries(t *testing.T) {
	if len(deniedCerts) == 0 {
		t.Fatal("denylist is empty")
	}
	hex64 := regexp.MustCompile(`^[0-9a-f]{64}$`)
	wantFP := []string{
		"0d136e439f0ab6e97f3a02a540da9f0641aa554e1d66ea51ae2920d51b2f7217", // DigiNotar Root CA
		"e28393773da845a679f2080cc7fb44a3b7a1c3792cb7eb7729fdcb6a8d99aea7", // CNNIC ROOT
		"4b22d5a6aec99f3cdb79aa5ec06838479cd5ecba7164f7f22dc1d65f63d85708", // WoSign
		"c766a9bef2d4071c863a31aa4920e813b2d198608cb7b7cfe21143b836df09ea", // StartCom
		"9acfab7e43c8d880d06b262a94deeee4b4659989c3d0caf19baf6405e41ab7df", // VeriSign Class 3 G5
	}
	byFP := make(map[string]deniedCert, len(deniedCerts))
	for _, e := range deniedCerts {
		if e.name == "" {
			t.Errorf("entry %s has an empty name", e.fingerprint)
		}
		if !hex64.MatchString(e.fingerprint) {
			t.Errorf("%s fingerprint %q is not lowercase sha256 hex", e.name, e.fingerprint)
		}
		if !hex64.MatchString(e.spki) {
			t.Errorf("%s spki %q is not lowercase sha256 hex", e.name, e.spki)
		}
		if prev, ok := byFP[e.fingerprint]; ok {
			t.Errorf("duplicate fingerprint %s (%s and %s)", e.fingerprint, prev.name, e.name)
		}
		byFP[e.fingerprint] = e
	}
	for _, fp := range wantFP {
		if _, ok := byFP[fp]; !ok {
			t.Errorf("missing denylisted fingerprint %s", fp)
		}
	}

	// Three DigiNotar Root CA certificates were re-issued on one key.
	shared := "a903af8c07bb91b0d9e3f3a30c6d53339fc5bd47e5d6bdb476598860c068a024"
	for _, fp := range []string{
		"0d136e439f0ab6e97f3a02a540da9f0641aa554e1d66ea51ae2920d51b2f7217",
		"4fee0163686ecbd65db968e7494f55d84b25486d438e9de558d629d28cd4d176",
		"8a1bd21661c60015065212cc98b1abb50dfd14c872a208e66bae890f25c448af",
	} {
		e, ok := byFP[fp]
		if !ok {
			t.Fatalf("missing DigiNotar Root CA %s", fp)
		}
		if e.spki != shared {
			t.Errorf("%s spki=%s, want shared DigiNotar Root CA key %s", fp, e.spki, shared)
		}
	}
}

func TestAllowlist_denylistRejectsNamedCert(t *testing.T) {
	cert := mustDeniedTestCert(t, nil, "Named Root", "US", 1)
	fp := certutil.GetHexSHA256Fingerprint(*cert)

	al := Allowlist{
		Fingerprints: []string{fp},
		Countries:    []string{"US"},
	}
	if !al.Matches(cert) {
		t.Fatal("certificate should match before it is denylisted")
	}

	// Upper case and colons still identify the certificate.
	var colon string
	for i := 0; i < len(fp); i += 2 {
		if i > 0 {
			colon += ":"
		}
		colon += fp[i : i+2]
	}
	t.Cleanup(AddDeniedForTest("fixture root", strings.ToUpper(colon), ""))

	if al.Matches(cert) {
		t.Fatal("denylisted certificate must not match even when the allowlist names it")
	}
	if denied, name := Denied(cert); !denied || name != "fixture root" {
		t.Fatalf("Denied=%v %q", denied, name)
	}
	if al.MatchesAll([]*x509.Certificate{cert}) {
		t.Fatal("MatchesAll must reject a denylisted certificate")
	}
}

func TestAllowlist_denylistSPKICatchesReissue(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	original := mustDeniedTestCert(t, key, "Original Root", "US", 1)
	reissued := mustDeniedTestCert(t, key, "Reissued Root", "US", 2)
	other := mustDeniedTestCert(t, nil, "Other Root", "US", 3)

	origFP := certutil.GetHexSHA256Fingerprint(*original)
	reFP := certutil.GetHexSHA256Fingerprint(*reissued)
	otherFP := certutil.GetHexSHA256Fingerprint(*other)
	if origFP == reFP {
		t.Fatal("re-issued certificate must have a different fingerprint")
	}
	if spkiSHA256(original) != spkiSHA256(reissued) {
		t.Fatal("re-issued certificate must keep the same SPKI")
	}
	if spkiSHA256(original) == spkiSHA256(other) {
		t.Fatal("unrelated certificate must not share the SPKI")
	}

	// Fingerprint-only entry rejects the original certificate and not the re-issue.
	t.Cleanup(AddDeniedForTest("fingerprint only", origFP, ""))
	alRe := Allowlist{Fingerprints: []string{reFP}, Countries: []string{"US"}}
	if !alRe.Matches(reissued) {
		t.Fatal("fingerprint denylist entry must not reject a re-issued certificate")
	}
	alOrig := Allowlist{Fingerprints: []string{origFP}, Countries: []string{"US"}}
	if alOrig.Matches(original) {
		t.Fatal("fingerprint denylist entry must reject the named certificate")
	}

	// SPKI entry rejects the re-issue even though the allowlist names it.
	t.Cleanup(AddDeniedForTest("shared key", "", spkiSHA256(original)))
	if alRe.Matches(reissued) {
		t.Fatal("SPKI denylist entry must reject a re-issued certificate named by the allowlist")
	}
	if alOrig.Matches(original) {
		t.Fatal("SPKI denylist entry must reject the original certificate")
	}
	if denied, name := Denied(reissued); !denied || name == "" {
		t.Fatalf("Denied(reissued)=%v %q", denied, name)
	}
	alOther := Allowlist{Fingerprints: []string{otherFP}}
	if !alOther.Matches(other) {
		t.Fatal("unrelated certificate must still match")
	}
}

func TestDenied_nil(t *testing.T) {
	if denied, name := Denied(nil); denied || name != "" {
		t.Fatalf("Denied(nil)=%v %q", denied, name)
	}
}

func mustDeniedTestCert(t *testing.T, key *ecdsa.PrivateKey, cn, country string, serial int64) *x509.Certificate {
	t.Helper()
	var err error
	if key == nil {
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject: pkix.Name{
			CommonName: cn,
			Country:    []string{country},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
