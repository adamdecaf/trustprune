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

package main

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
	"strings"
	"testing"
	"time"

	"github.com/adamdecaf/trustprune/pkg/certutil"
)

func TestListFileAndroidCacertsDir(t *testing.T) {
	bin := cliBinary(t)
	home := t.TempDir()
	dir := t.TempDir()

	a := mintListAndroidCA(t, "Android List Root A", 1)
	b := mintListAndroidCA(t, "Android List Root B", 2)
	writeListAndroidPEM(t, dir, "aaaaaaaa.0", a)
	writeListAndroidPEM(t, dir, "bbbbbbbb.0", b)
	if err := os.WriteFile(filepath.Join(dir, "README"), []byte("ignore\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	fpA := certutil.GetHexSHA256Fingerprint(*a)
	fpB := certutil.GetHexSHA256Fingerprint(*b)

	count := runCLI(t, bin, home, "list", "--file", dir, "--count")
	if count.code != 0 {
		t.Fatalf("count: code=%d\nstdout=%s\nstderr=%s", count.code, count.stdout, count.stderr)
	}
	if strings.TrimSpace(count.stdout) != "2" {
		t.Fatalf("count = %q, want 2", count.stdout)
	}

	for _, format := range []string{"table", "json", "long"} {
		res := runCLI(t, bin, home, "list", "--file", dir, "--format", format)
		if res.code != 0 {
			t.Fatalf("%s: code=%d\nstdout=%s\nstderr=%s", format, res.code, res.stdout, res.stderr)
		}
		wantA, wantB := fpA, fpB
		if format == "table" {
			wantA, wantB = fpA[:16], fpB[:16]
		}
		if !strings.Contains(res.stdout, wantA) {
			t.Fatalf("%s output missing fingerprint %s\n%s", format, wantA, res.stdout)
		}
		if !strings.Contains(res.stdout, wantB) {
			t.Fatalf("%s output missing fingerprint %s\n%s", format, wantB, res.stdout)
		}
	}

	empty := runCLI(t, bin, home, "list", "--file", t.TempDir())
	if empty.code == 0 {
		t.Fatalf("empty dir: code=0 stdout=%s", empty.stdout)
	}
}

func mintListAndroidCA(t *testing.T, cn string, serial int64) *x509.Certificate {
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

func writeListAndroidPEM(t *testing.T, dir, name string, cert *x509.Certificate) {
	t.Helper()
	var buf bytes.Buffer
	if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(&buf, "Certificate:\n    Subject: CN=%s\n", cert.Subject.CommonName)
	if err := os.WriteFile(filepath.Join(dir, name), buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}
