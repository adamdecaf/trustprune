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
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testPEMBundleWithNegativeSerial(t *testing.T) (blob []byte, wantFingerprints []string) {
	t.Helper()
	good, err := os.ReadFile("../../testdata/example.crt")
	if err != nil {
		t.Fatal(err)
	}
	neg, err := os.ReadFile("../../testdata/negative-serial.pem")
	if err != nil {
		t.Fatal(err)
	}
	lots, err := os.ReadFile("../../testdata/lots.crt")
	if err != nil {
		t.Fatal(err)
	}

	// Confirm this Go rejects the fixture the way Darwin /etc/ssl/cert.pem fails.
	block, _ := pem.Decode(neg)
	if block == nil {
		t.Fatal("negative-serial.pem: no PEM block")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err == nil {
		t.Skip("crypto/x509 accepted a negative serial; cannot test skip path (check GODEBUG)")
	} else if !strings.Contains(err.Error(), "negative serial") {
		t.Fatalf("expected negative serial parse error, got %v", err)
	}

	goodCerts, err := ParsePEM(good)
	if err != nil || len(goodCerts) != 1 {
		t.Fatalf("example.crt: len=%d err=%v", len(goodCerts), err)
	}
	lotsCerts, err := ParsePEM(lots)
	if err != nil || len(lotsCerts) != 5 {
		t.Fatalf("lots.crt: len=%d err=%v", len(lotsCerts), err)
	}
	for _, c := range append(goodCerts, lotsCerts...) {
		wantFingerprints = append(wantFingerprints, GetHexSHA256Fingerprint(*c))
	}

	var buf bytes.Buffer
	buf.Write(good)
	buf.Write(neg)
	buf.Write(lots)
	return buf.Bytes(), wantFingerprints
}

func TestParsePEM_skipsNegativeSerial(t *testing.T) {
	blob, want := testPEMBundleWithNegativeSerial(t)

	var warn bytes.Buffer
	old := pemParseWarn
	pemParseWarn = &warn
	t.Cleanup(func() { pemParseWarn = old })

	parsed := ParsePEMResult(blob)
	if parsed.Skipped != 1 {
		t.Fatalf("ParsePEMResult.Skipped=%d, want 1", parsed.Skipped)
	}
	certs := parsed.Certs
	if len(certs) != len(want) {
		t.Fatalf("got %d certs, want %d good certs (negative serial skipped)", len(certs), len(want))
	}
	for i := range certs {
		got := GetHexSHA256Fingerprint(*certs[i])
		if got != want[i] {
			t.Errorf("cert %d fingerprint %s, want %s", i, got, want[i])
		}
	}
	msg := warn.String()
	if !strings.Contains(msg, "PEM block 2") {
		t.Errorf("warning should identify PEM block 2, got %q", msg)
	}
	if !strings.Contains(msg, "negative serial") {
		t.Errorf("warning should mention negative serial, got %q", msg)
	}
}

func TestFromFile_skipsNegativeSerial(t *testing.T) {
	blob, want := testPEMBundleWithNegativeSerial(t)

	var warn bytes.Buffer
	old := pemParseWarn
	pemParseWarn = &warn
	t.Cleanup(func() { pemParseWarn = old })

	path := filepath.Join(t.TempDir(), "bundle.pem")
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		t.Fatal(err)
	}
	parsed, err := FromFileResult(path)
	if err != nil {
		t.Fatalf("FromFileResult: %v", err)
	}
	if parsed.Skipped != 1 {
		t.Fatalf("FromFileResult.Skipped=%d, want 1", parsed.Skipped)
	}
	certs, err := FromFile(path)
	if err != nil {
		t.Fatalf("FromFile: %v", err)
	}
	if len(certs) != len(parsed.Certs) {
		t.Fatalf("FromFile len=%d, FromFileResult len=%d", len(certs), len(parsed.Certs))
	}
	if len(certs) != len(want) {
		t.Fatalf("got %d certs, want %d good certs (negative serial skipped)", len(certs), len(want))
	}
	for i := range certs {
		got := GetHexSHA256Fingerprint(*certs[i])
		if got != want[i] {
			t.Errorf("cert %d fingerprint %s, want %s", i, got, want[i])
		}
	}
}

func TestParsePEM_negativeSerialOnly(t *testing.T) {
	neg, err := os.ReadFile("../../testdata/negative-serial.pem")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(neg)
	if block == nil {
		t.Fatal("negative-serial.pem: no PEM block")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err == nil {
		t.Skip("crypto/x509 accepted a negative serial; cannot test skip path (check GODEBUG)")
	}

	var warn bytes.Buffer
	old := pemParseWarn
	pemParseWarn = &warn
	t.Cleanup(func() { pemParseWarn = old })

	certs, err := ParsePEM(neg)
	if err != nil {
		t.Fatalf("ParsePEM: %v", err)
	}
	if len(certs) != 0 {
		t.Fatalf("got %d certs, want 0", len(certs))
	}
	if !strings.Contains(warn.String(), "PEM block 1") {
		t.Errorf("warning should identify PEM block 1, got %q", warn.String())
	}
}

func TestParsePEM_skipsMalformedCertificateBlock(t *testing.T) {
	good, err := os.ReadFile("../../testdata/example.crt")
	if err != nil {
		t.Fatal(err)
	}
	garbage := []byte("-----BEGIN CERTIFICATE-----\nQQ==\n-----END CERTIFICATE-----\n")

	var warn bytes.Buffer
	old := pemParseWarn
	pemParseWarn = &warn
	t.Cleanup(func() { pemParseWarn = old })

	certs, err := ParsePEM(append(append([]byte{}, good...), garbage...))
	if err != nil {
		t.Fatalf("ParsePEM: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("got %d certs, want 1 (malformed block skipped)", len(certs))
	}
	if !strings.Contains(warn.String(), "PEM block 2") {
		t.Errorf("warning should identify PEM block 2, got %q", warn.String())
	}
}
