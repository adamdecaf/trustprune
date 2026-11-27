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
	"testing"
	"time"

	"github.com/adamdecaf/trustprune/pkg/certutil"
)

func TestBlocklistNames(t *testing.T) {
	cert := mintBlocklistCA(t, "Blocklist Fixture", 1)
	fp := certutil.GetHexSHA256Fingerprint(*cert)
	if names := BlocklistNames(cert); len(names) != 0 {
		t.Fatalf("unlisted cert: %v", names)
	}

	t.Cleanup(AddBlocklistedForTest("chromium", fp))
	t.Cleanup(AddBlocklistedForTest("ccadb", fp))
	got := BlocklistNames(cert)
	want := []string{BlocklistChromium, BlocklistCCADB}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("got %v, want %v", got, want)
	}
	if !Blocklisted(cert) {
		t.Fatal("expected Blocklisted")
	}
	al := Allowlist{Fingerprints: []string{fp}}
	if al.Matches(cert) {
		t.Fatal("blocklisted cert should not match an allowlist")
	}
}

func mintBlocklistCA(t *testing.T, cn string, serial int64) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
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
