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

const negativeSerialSHA256 = "e80df890f56250311212ef234fb4cda53018e6bf409674f77003735342076c2a"

func requireX509RejectsNegativeSerial(t *testing.T, der []byte) {
	t.Helper()
	if _, err := x509.ParseCertificate(der); err == nil {
		t.Skip("crypto/x509 accepted a negative serial; cannot exercise fallback on this toolchain")
	} else if !strings.Contains(err.Error(), "negative serial") {
		t.Fatalf("expected negative serial parse error, got %v", err)
	}
	if strings.Contains(os.Getenv("GODEBUG"), "x509negativeserial") {
		t.Fatal("GODEBUG must not enable x509negativeserial")
	}
}

func testPEMBundleWithNegativeSerial(t *testing.T) (blob []byte, goodFingerprints []string, negFP string) {
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

	block, _ := pem.Decode(neg)
	if block == nil {
		t.Fatal("negative-serial.pem: no PEM block")
	}
	requireX509RejectsNegativeSerial(t, block.Bytes)

	goodCerts, err := ParsePEM(good)
	if err != nil || len(goodCerts) != 1 {
		t.Fatalf("example.crt: len=%d err=%v", len(goodCerts), err)
	}
	lotsCerts, err := ParsePEM(lots)
	if err != nil || len(lotsCerts) != 5 {
		t.Fatalf("lots.crt: len=%d err=%v", len(lotsCerts), err)
	}
	for _, c := range append(goodCerts, lotsCerts...) {
		goodFingerprints = append(goodFingerprints, GetHexSHA256Fingerprint(*c))
	}

	var buf bytes.Buffer
	buf.Write(good)
	buf.Write(neg)
	buf.Write(lots)
	return buf.Bytes(), goodFingerprints, negativeSerialSHA256
}

func TestParsePEM_includesNegativeSerialViaFallback(t *testing.T) {
	blob, good, negFP := testPEMBundleWithNegativeSerial(t)

	var warn bytes.Buffer
	old := pemParseWarn
	pemParseWarn = &warn
	t.Cleanup(func() { pemParseWarn = old })

	parsed := ParsePEMResult(blob)
	if parsed.Skipped != 0 {
		t.Fatalf("ParsePEMResult.Skipped=%d, want 0 (fallback should parse negative serial)", parsed.Skipped)
	}
	if warn.Len() != 0 {
		t.Fatalf("unexpected skip warning: %q", warn.String())
	}
	wantLen := len(good) + 1
	if len(parsed.Certs) != wantLen {
		t.Fatalf("got %d certs, want %d (good + negative serial)", len(parsed.Certs), wantLen)
	}
	if len(parsed.Entries) != wantLen {
		t.Fatalf("Entries=%d, want %d", len(parsed.Entries), wantLen)
	}
	for i := range parsed.Entries {
		if parsed.Entries[i].Cert == nil {
			t.Fatalf("entry %d should be a parsed cert", i)
		}
	}
	if GetHexSHA256Fingerprint(*parsed.Certs[0]) != good[0] {
		t.Fatal("first cert should remain example.crt")
	}
	if GetHexSHA256Fingerprint(*parsed.Certs[1]) != negFP {
		t.Fatalf("second cert fingerprint=%s, want negative-serial %s",
			GetHexSHA256Fingerprint(*parsed.Certs[1]), negFP)
	}
	if parsed.Certs[1].SerialNumber.Sign() >= 0 {
		t.Fatal("fallback cert serial should be negative")
	}
}


func TestParsePEMResult_KeepMatchingFallbackCert(t *testing.T) {
	blob, good, negFP := testPEMBundleWithNegativeSerial(t)
	parsed := ParsePEMResult(blob)
	if len(good) < 1 {
		t.Fatal("need at least one good cert")
	}
	kept, removed := parsed.KeepMatching(func(c *x509.Certificate) bool {
		fp := GetHexSHA256Fingerprint(*c)
		return fp == good[0] || fp == negFP
	})
	if len(kept.Certs) != 2 {
		t.Fatalf("kept=%d, want 2 (example + negative serial)", len(kept.Certs))
	}
	if len(removed) != len(good)-1 {
		t.Fatalf("removed=%d, want %d", len(removed), len(good)-1)
	}
	if kept.Skipped != 0 {
		t.Fatalf("kept.Skipped=%d, want 0", kept.Skipped)
	}

	encoded, err := EncodePEMEntries(kept.Entries)
	if err != nil {
		t.Fatal(err)
	}
	round := ParsePEMResult(encoded)
	if round.Skipped != 0 || len(round.Certs) != 2 {
		t.Fatalf("reparse Skipped=%d certs=%d, want 0/2", round.Skipped, len(round.Certs))
	}
	got := map[string]bool{}
	for _, c := range round.Certs {
		got[GetHexSHA256Fingerprint(*c)] = true
	}
	if !got[good[0]] || !got[negFP] {
		t.Fatalf("reparse fingerprints=%v", got)
	}
}

func TestFromFile_includesNegativeSerial(t *testing.T) {
	blob, good, negFP := testPEMBundleWithNegativeSerial(t)

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
	if parsed.Skipped != 0 {
		t.Fatalf("FromFileResult.Skipped=%d, want 0", parsed.Skipped)
	}
	certs, err := FromFile(path)
	if err != nil {
		t.Fatalf("FromFile: %v", err)
	}
	if len(certs) != len(good)+1 {
		t.Fatalf("got %d certs, want %d", len(certs), len(good)+1)
	}
	if GetHexSHA256Fingerprint(*certs[1]) != negFP {
		t.Fatal("FromFile should include negative-serial via fallback")
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
	requireX509RejectsNegativeSerial(t, block.Bytes)

	var warn bytes.Buffer
	old := pemParseWarn
	pemParseWarn = &warn
	t.Cleanup(func() { pemParseWarn = old })

	certs, err := ParsePEM(neg)
	if err != nil {
		t.Fatalf("ParsePEM: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("got %d certs, want 1", len(certs))
	}
	if warn.Len() != 0 {
		t.Fatalf("unexpected warning: %q", warn.String())
	}
	if GetHexSHA256Fingerprint(*certs[0]) != negativeSerialSHA256 {
		t.Fatalf("fp=%s", GetHexSHA256Fingerprint(*certs[0]))
	}
	if StringifyPKIXName(certs[0].Subject) != "negative-serial-test" {
		t.Fatalf("subject=%q", StringifyPKIXName(certs[0].Subject))
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
	parsed := ParsePEMResult(append(append([]byte{}, good...), garbage...))
	if parsed.Skipped != 1 {
		t.Fatalf("Skipped=%d, want 1", parsed.Skipped)
	}
	if len(parsed.Entries) != 2 || parsed.Entries[1].Cert != nil {
		t.Fatalf("want good cert then raw skip, entries=%d", len(parsed.Entries))
	}
	if !bytes.Contains(parsed.Entries[1].Raw, []byte("-----BEGIN CERTIFICATE-----")) {
		t.Fatal("raw skip should include PEM headers")
	}

	kept, _ := parsed.KeepMatching(func(c *x509.Certificate) bool { return true })
	if kept.Skipped != 1 || len(kept.Entries) != 2 {
		t.Fatalf("KeepMatching should retain raw skip: skipped=%d entries=%d", kept.Skipped, len(kept.Entries))
	}
	encoded, err := EncodePEMEntries(kept.Entries)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(encoded, garbage) {
		t.Fatal("rewrite dropped malformed PEM block")
	}
}
