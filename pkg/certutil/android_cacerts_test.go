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

package certutil

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFromAndroidDir(t *testing.T) {
	dir := t.TempDir()
	a := mintAndroidCA(t, "Android Test Root A", 1)
	b := mintAndroidCA(t, "Android Test Root B", 2)
	writeAndroidPEM(t, dir, "aaaaaaaa.0", a)
	writeAndroidPEM(t, dir, "aaaaaaaa.1", b) // collision suffix
	if err := os.WriteFile(filepath.Join(dir, "README"), []byte("not a cert\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ignored.pem"), pemBytes(t, a), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "bbbbbbbb.0"), 0o755); err != nil {
		t.Fatal(err)
	}

	certs, err := FromAndroidDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 2 {
		t.Fatalf("got %d certs, want 2", len(certs))
	}
	got := map[string]struct{}{
		GetHexSHA256Fingerprint(*certs[0]): {},
		GetHexSHA256Fingerprint(*certs[1]): {},
	}
	wantA := GetHexSHA256Fingerprint(*a)
	wantB := GetHexSHA256Fingerprint(*b)
	if _, ok := got[wantA]; !ok {
		t.Fatalf("missing fingerprint for A %s in %v", wantA, got)
	}
	if _, ok := got[wantB]; !ok {
		t.Fatalf("missing fingerprint for B %s in %v", wantB, got)
	}
}

func TestFromAndroidDir_empty(t *testing.T) {
	dir := t.TempDir()
	if _, err := FromAndroidDir(dir); err == nil {
		t.Fatal("expected error for an empty directory")
	}
	if err := os.WriteFile(filepath.Join(dir, "cccccccc.0"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := FromAndroidDir(dir); err == nil {
		t.Fatal("expected error when matching files are empty")
	}
}

func TestFromAndroidDir_notPEM(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dddddddd.0")
	if err := os.WriteFile(path, []byte("not a certificate\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := FromAndroidDir(dir); err == nil {
		t.Fatal("expected error for a non-PEM hash-named file")
	}
}

func TestFromAndroidDir_notDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := FromAndroidDir(path); err == nil {
		t.Fatal("expected error for a regular file")
	}
}

func mintAndroidCA(t *testing.T, cn string, serial int64) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"trustprune test"}},
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

func pemBytes(t *testing.T, cert *x509.Certificate) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func writeAndroidPEM(t *testing.T, dir, name string, cert *x509.Certificate) {
	t.Helper()
	var buf bytes.Buffer
	if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
		t.Fatal(err)
	}
	// Android layout: PEM first, then the OpenSSL text form of that certificate.
	fmt.Fprintf(&buf, "Certificate:\n    Data:\n        Issuer: CN=%s\n        Subject: CN=%s\n        SHA256 Fingerprint=%s\n",
		cert.Subject.CommonName, cert.Subject.CommonName, GetHexSHA256Fingerprint(*cert))
	if err := os.WriteFile(filepath.Join(dir, name), buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}
