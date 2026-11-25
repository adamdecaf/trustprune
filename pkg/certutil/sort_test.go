// Copyright 2018 Adam Shannon
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

package certutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func TestCertUtil__sort(t *testing.T) {
	certs, err := FromFile("../../testdata/lots.crt")
	if err != nil {
		t.Fatal(err)
	}
	Sort(certs)

	answers := []string{
		"EE Certification Centre Root CA",
		"Entrust Root Certification Authority",
		"Entrust Root Certification Authority - EC1",
		"Entrust Root Certification Authority - G2",
		"Entrust.net Certification Authority (2048)",
	}

	for i := range certs {
		sub := StringifyPKIXName(certs[i].Subject)
		if sub != answers[i] {
			t.Errorf("idx %d got %q", i, sub)
		}
		if i > 0 && Less(certs[i], certs[i-1]) {
			t.Errorf("idx %d sorts before idx %d", i, i-1)
		}
	}
}

func TestCertUtil__sortNil(t *testing.T) {
	named := mustSortCert(t, "Bravo", 1)
	bare := &x509.Certificate{Subject: pkix.Name{CommonName: "Alpha"}}
	certs := []*x509.Certificate{named, nil, bare, nil}
	Sort(certs)
	if certs[0] != nil || certs[1] != nil {
		t.Fatalf("nil certificates should sort first: %#v", certs)
	}
	// Subjects decide: Alpha before Bravo. The bare certificate has no raw
	// encoding; sorting it must not panic.
	if certs[2] != bare || certs[3] != named {
		t.Fatalf("got %q then %q", StringifyPKIXName(certs[2].Subject), StringifyPKIXName(certs[3].Subject))
	}
	if Less(named, nil) || !Less(nil, named) || Less(nil, nil) {
		t.Fatal("nil Less mismatch")
	}
	bareSame := &x509.Certificate{Subject: named.Subject}
	if StringifyPKIXName(bareSame.Subject) != StringifyPKIXName(named.Subject) {
		t.Fatalf("same subject required for fingerprint tie-break: %q vs %q", StringifyPKIXName(bareSame.Subject), StringifyPKIXName(named.Subject))
	}
	same := []*x509.Certificate{named, bareSame}
	Sort(same)
	if same[0] != bareSame || same[1] != named {
		t.Fatal("empty fingerprint should sort before a real fingerprint")
	}
	Sort(nil)
	Sort([]*x509.Certificate{})
}

func TestCertUtil__sortCaseAndFingerprint(t *testing.T) {
	alpha := mustSortCert(t, "alpha", 1)
	beta := mustSortCert(t, "Beta", 1)
	shared1 := mustSortCert(t, "Shared", 1)
	shared2 := mustSortCert(t, "Shared", 2)

	fp1 := GetHexSHA256Fingerprint(*shared1)
	fp2 := GetHexSHA256Fingerprint(*shared2)
	if fp1 == fp2 {
		t.Fatal("shared subjects should have distinct fingerprints")
	}
	low, high := shared1, shared2
	if fp2 < fp1 {
		low, high = shared2, shared1
	}

	// Reverse of subject order, with the equal-subject pair reversed too.
	// Case-sensitive order would put "Beta" before "alpha".
	certs := []*x509.Certificate{high, beta, low, alpha}
	Sort(certs)

	if certs[0] != alpha || certs[1] != beta {
		t.Fatalf("case-insensitive subject order: got %q, %q",
			StringifyPKIXName(certs[0].Subject), StringifyPKIXName(certs[1].Subject))
	}
	if certs[2] != low || certs[3] != high {
		t.Fatalf("fingerprint tiebreaker: got %s then %s",
			GetHexSHA256Fingerprint(*certs[2]), GetHexSHA256Fingerprint(*certs[3]))
	}
}

func mustSortCert(t *testing.T, subject string, serial int64) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: subject},
		NotBefore:    time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA:         true,
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
