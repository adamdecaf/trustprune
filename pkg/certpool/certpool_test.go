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
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/adamdecaf/trustprune/pkg/allowlist"
	"github.com/adamdecaf/trustprune/pkg/certpool"
	"github.com/adamdecaf/trustprune/pkg/certutil"
)

func TestFromFile_matching(t *testing.T) {
	keepFP := mustCert(t, "Keep By Fingerprint", "US", 11)
	keepCountry := mustCert(t, "Keep By Country", "JP", 12)
	drop := mustCert(t, "Drop", "DE", 13)
	al := allowlist.Allowlist{
		Fingerprints: []string{certutil.GetHexSHA256Fingerprint(*keepFP)},
		Countries:    []string{"jp"},
	}
	path := writePEM(t, "roots.pem", []*pem.Block{
		{Type: "PRIVATE KEY", Bytes: []byte("not-a-key")},
		pemCert(keepFP),
		pemCert(drop),
		pemCert(keepCountry),
	})

	got, err := certpool.FromFile(al, path)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("nil pool")
	}
	want := certpool.FromCertificates(al, []*x509.Certificate{keepFP, drop, keepCountry})
	if !got.Equal(want) {
		t.Fatal("FromFile pool did not match FromCertificates")
	}

	withDrop := x509.NewCertPool()
	withDrop.AddCert(keepFP)
	withDrop.AddCert(keepCountry)
	withDrop.AddCert(drop)
	if got.Equal(withDrop) {
		t.Fatal("dropped certificate was kept")
	}
}

func TestFromFile_nonMatching(t *testing.T) {
	drop := mustCert(t, "Drop", "DE", 14)
	al := allowlist.Allowlist{
		Fingerprints: []string{"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
		Countries:    []string{"jp"},
	}
	path := writePEM(t, "roots.pem", []*pem.Block{pemCert(drop)})

	got, err := certpool.FromFile(al, path)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("nil pool")
	}
	if !got.Equal(x509.NewCertPool()) {
		t.Fatal("non-matching certificates should yield an empty pool")
	}
}

func TestFromFile_empty(t *testing.T) {
	al := allowlist.Allowlist{Countries: []string{"US"}}
	dir := t.TempDir()

	empty := filepath.Join(dir, "empty.pem")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	assertFromFileError(t, al, empty, "no certificates")

	onlyKey := writePEMIn(t, dir, "key.pem", []*pem.Block{
		{Type: "PRIVATE KEY", Bytes: []byte("not-a-key")},
	})
	assertFromFileError(t, al, onlyKey, "no certificates")
}

func TestFromFile_invalid(t *testing.T) {
	al := allowlist.Allowlist{Countries: []string{"US"}}
	dir := t.TempDir()

	bad := filepath.Join(dir, "bad.pem")
	garbage := []byte("-----BEGIN CERTIFICATE-----\nQQ==\n-----END CERTIFICATE-----\n")
	if err := os.WriteFile(bad, garbage, 0o600); err != nil {
		t.Fatal(err)
	}
	assertFromFileError(t, al, bad, "certificate block")

	keep := mustCert(t, "Keep", "US", 15)
	mixedBody := append(encodePEM(t, []*pem.Block{pemCert(keep)}), garbage...)
	mixed := filepath.Join(dir, "mixed.pem")
	if err := os.WriteFile(mixed, mixedBody, 0o600); err != nil {
		t.Fatal(err)
	}
	assertFromFileError(t, al, mixed, "certificate block")
}

func TestFromFile_missing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.pem")
	pool, err := certpool.FromFile(allowlist.Allowlist{}, path)
	if err == nil {
		t.Fatal("expected an error for a missing file")
	}
	if pool != nil {
		t.Fatal("pool should be nil when the file cannot be read")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("got %v", err)
	}
}

func assertFromFileError(t *testing.T, al allowlist.Allowlist, path, want string) {
	t.Helper()
	pool, err := certpool.FromFile(al, path)
	if err == nil {
		t.Fatalf("%s: expected an error containing %q", path, want)
	}
	if pool != nil {
		t.Fatalf("%s: pool should be nil on error", path)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("%s: got %v", path, err)
	}
}

func pemCert(c *x509.Certificate) *pem.Block {
	return &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}
}

func writePEM(t *testing.T, name string, blocks []*pem.Block) string {
	t.Helper()
	return writePEMIn(t, t.TempDir(), name, blocks)
}

func writePEMIn(t *testing.T, dir, name string, blocks []*pem.Block) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, encodePEM(t, blocks), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func encodePEM(t *testing.T, blocks []*pem.Block) []byte {
	t.Helper()
	var buf []byte
	for i := range blocks {
		encoded := pem.EncodeToMemory(blocks[i])
		if len(encoded) == 0 {
			t.Fatalf("encode PEM block %d", i)
		}
		buf = append(buf, encoded...)
	}
	return buf
}

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
