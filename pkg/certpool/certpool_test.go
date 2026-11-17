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

package certpool_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"reflect"
	"testing"
	"time"

	"github.com/adamdecaf/trustprune/pkg/allowlist"
	"github.com/adamdecaf/trustprune/pkg/certpool"
	"github.com/adamdecaf/trustprune/pkg/certutil"
)

func TestFromCertificates_keepsMatches(t *testing.T) {
	keepFP := mustCert(t, "Keep By Fingerprint", "US", 1)
	keepCountry := mustCert(t, "Keep By Country", "JP", 2)
	drop := mustCert(t, "Drop", "DE", 3)

	al := allowlist.Allowlist{
		Fingerprints: []string{certutil.GetHexSHA256Fingerprint(*keepFP)},
		Countries:    []string{"jp"},
	}
	in := []*x509.Certificate{keepFP, nil, drop, keepCountry, keepFP}
	before := append([]*x509.Certificate(nil), in...)

	got := certpool.FromCertificates(al, in)
	if got == nil {
		t.Fatal("nil pool")
	}
	if !reflect.DeepEqual(in, before) {
		t.Fatal("input certificates were modified")
	}

	want := x509.NewCertPool()
	want.AddCert(keepFP)
	want.AddCert(keepCountry)
	if !got.Equal(want) {
		t.Fatal("allowlist filter did not keep the fingerprint match and the JP certificate")
	}

	withDrop := x509.NewCertPool()
	withDrop.AddCert(keepFP)
	withDrop.AddCert(keepCountry)
	withDrop.AddCert(drop)
	if got.Equal(withDrop) {
		t.Fatal("dropped certificate was kept")
	}
}

func TestFromCertificates_empty(t *testing.T) {
	got := certpool.FromCertificates(allowlist.Allowlist{}, nil)
	if got == nil {
		t.Fatal("nil pool")
	}
	if !got.Equal(x509.NewCertPool()) {
		t.Fatal("nil certificate list should yield an empty pool")
	}

	drop := mustCert(t, "Drop", "US", 4)
	got = certpool.FromCertificates(allowlist.Allowlist{}, []*x509.Certificate{drop, nil})
	if !got.Equal(x509.NewCertPool()) {
		t.Fatal("empty allowlist should keep nothing")
	}
}

func mustCert(t *testing.T, cn, country string, serial int64) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
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
