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

package cmd

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/adamdecaf/trustprune/pkg/allowlist"
	"github.com/adamdecaf/trustprune/pkg/allowlist/gen"
	"github.com/adamdecaf/trustprune/pkg/certutil"
)

func TestDropDenylisted_skipsReissuedKeyWithNote(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	original := mustGenCACert(t, key, "Original Distrusted", 1)
	reissued := mustGenCACert(t, key, "Reissued Distrusted", 2)
	keptCert := mustGenCACert(t, nil, "Keep Me", 3)

	sum := sha256.Sum256(original.RawSubjectPublicKeyInfo)
	t.Cleanup(allowlist.AddDeniedForTest("shared key", "", hex.EncodeToString(sum[:])))

	reFP := certutil.GetHexSHA256Fingerprint(*reissued)
	var buf bytes.Buffer
	kept, err := dropDenylisted(&buf, []*gen.CA{
		{Certificate: reissued, Fingerprint: reFP, DNSNames: []string{"bad.example"}},
		{Certificate: keptCert, Fingerprint: certutil.GetHexSHA256Fingerprint(*keptCert), DNSNames: []string{"ok.example"}},
		nil,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(kept) != 1 || kept[0].Certificate != keptCert {
		t.Fatalf("kept %#v, want only the unrelated CA", kept)
	}
	note := buf.String()
	if !strings.Contains(note, "NOTE: skipping denylisted certificate Reissued Distrusted") {
		t.Fatalf("note = %q", note)
	}
	if !strings.Contains(note, "sha256="+reFP) || !strings.Contains(note, "(shared key)") {
		t.Fatalf("note = %q", note)
	}
	al := allowlist.FromCertificates([]*x509.Certificate{kept[0].Certificate})
	for _, fp := range al.Fingerprints {
		if fp == reFP {
			t.Fatal("generated allowlist contains the denylisted re-issued certificate")
		}
	}
}

func mustGenCACert(t *testing.T, key *ecdsa.PrivateKey, cn string, serial int64) *x509.Certificate {
	t.Helper()
	var err error
	if key == nil {
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: cn},
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
