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
	"strings"
	"testing"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

func TestParseCertificate_fallbackNegativeSerial(t *testing.T) {
	neg, err := os.ReadFile("../../testdata/negative-serial.pem")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(neg)
	if block == nil {
		t.Fatal("negative-serial.pem: no PEM block")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err == nil {
		t.Skip("crypto/x509 accepted a negative serial; cannot exercise fallback on this toolchain")
	} else if !strings.Contains(err.Error(), "negative serial") {
		t.Fatalf("expected negative serial parse error, got %v", err)
	}
	if strings.Contains(os.Getenv("GODEBUG"), "x509negativeserial") {
		t.Fatal("GODEBUG must not enable x509negativeserial; fallback should work without it")
	}

	cert, err := ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate fallback: %v", err)
	}
	if cert.SerialNumber == nil || cert.SerialNumber.Sign() >= 0 {
		t.Fatalf("serial=%v, want negative", cert.SerialNumber)
	}
	if got := StringifyPKIXName(cert.Subject); !strings.Contains(got, "negative-serial-test") {
		t.Fatalf("subject=%q, want CN negative-serial-test", got)
	}
	if got := StringifyPKIXName(cert.Issuer); !strings.Contains(got, "negative-serial-test") {
		t.Fatalf("issuer=%q, want CN negative-serial-test", got)
	}
	if cert.NotAfter.IsZero() || cert.NotBefore.IsZero() {
		t.Fatalf("validity unset: before=%v after=%v", cert.NotBefore, cert.NotAfter)
	}
	wantFP := "e80df890f56250311212ef234fb4cda53018e6bf409674f77003735342076c2a"
	if got := GetHexSHA256Fingerprint(*cert); got != wantFP {
		t.Fatalf("sha256=%s, want %s", got, wantFP)
	}
	if len(cert.Raw) == 0 || len(cert.Raw) != len(block.Bytes) {
		t.Fatalf("Raw len=%d, want %d", len(cert.Raw), len(block.Bytes))
	}
}

func TestParseCertificate_trailingBytesRejected(t *testing.T) {
	good, err := os.ReadFile("../../testdata/example.crt")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(good)
	if block == nil {
		t.Fatal("example.crt: no PEM block")
	}
	der := append(append([]byte{}, block.Bytes...), 0x00)
	if _, err := x509.ParseCertificate(der); err == nil {
		t.Fatal("expected x509.ParseCertificate to reject trailing data")
	}
	if _, err := parseCertificateFallback(der); err == nil {
		t.Fatal("fallback must reject trailing bytes after the certificate SEQUENCE")
	}
	if _, err := ParseCertificate(der); err == nil {
		t.Fatal("ParseCertificate must reject trailing-data input")
	}
}

func TestParseCertificate_nonNegativeFailureStaysError(t *testing.T) {
	good, err := os.ReadFile("../../testdata/example.crt")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(good)
	if block == nil {
		t.Fatal("example.crt: no PEM block")
	}
	der := mismatchOuterSignatureAlgorithm(t, block.Bytes)
	x509Err := mustX509ParseError(t, der)
	fb, fbErr := parseCertificateFallback(der)
	if fbErr != nil {
		t.Fatalf("fallback should still parse structurally: %v", fbErr)
	}
	if fb.SerialNumber == nil || fb.SerialNumber.Sign() < 0 {
		t.Fatalf("fallback serial=%v, want non-negative", fb.SerialNumber)
	}
	_, err = ParseCertificate(der)
	if err == nil {
		t.Fatal("ParseCertificate must not accept fallback for non-negative serial failures")
	}
	if err.Error() != x509Err.Error() {
		t.Fatalf("want original x509 error %q, got %q", x509Err, err)
	}
}

func mustX509ParseError(t *testing.T, der []byte) error {
	t.Helper()
	_, err := x509.ParseCertificate(der)
	if err == nil {
		t.Fatal("expected x509.ParseCertificate error")
	}
	return err
}

// mismatchOuterSignatureAlgorithm flips one byte in the outer signature
// AlgorithmIdentifier so crypto/x509 rejects the cert for algorithm mismatch,
// while the cryptobyte fallback still reads a complete positive-serial cert.
func mismatchOuterSignatureAlgorithm(t *testing.T, der []byte) []byte {
	t.Helper()
	out := append([]byte(nil), der...)
	input := cryptobyte.String(out)
	var certSeq cryptobyte.String
	if !input.ReadASN1Element(&certSeq, cryptobyte_asn1.SEQUENCE) || !input.Empty() {
		t.Fatal("expected one certificate SEQUENCE")
	}
	if !certSeq.ReadASN1(&certSeq, cryptobyte_asn1.SEQUENCE) {
		t.Fatal("unwrap certificate")
	}
	if !certSeq.SkipASN1(cryptobyte_asn1.SEQUENCE) { // TBS
		t.Fatal("skip TBS")
	}
	var alg cryptobyte.String
	if !certSeq.ReadASN1Element(&alg, cryptobyte_asn1.SEQUENCE) {
		t.Fatal("outer algorithm")
	}
	// alg includes tag+length; flip last content byte inside the element.
	if len(alg) < 3 {
		t.Fatal("algorithm element too short")
	}
	// Find alg offset in out by searching the exact element bytes.
	off := bytes.Index(out, alg)
	if off < 0 {
		t.Fatal("algorithm element not found in DER")
	}
	out[off+len(alg)-1] ^= 0x01
	return out
}

func TestParseCertificate_negativeSerialTrailingRejected(t *testing.T) {
	neg, err := os.ReadFile("../../testdata/negative-serial.pem")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(neg)
	if block == nil {
		t.Fatal("negative-serial.pem: no PEM block")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err == nil {
		t.Skip("crypto/x509 accepted a negative serial; cannot exercise fallback on this toolchain")
	}
	der := append(append([]byte{}, block.Bytes...), 0x00)
	if _, err := parseCertificateFallback(der); err == nil {
		t.Fatal("fallback must reject negative-serial DER with trailing bytes")
	}
	if _, err := ParseCertificate(der); err == nil {
		t.Fatal("ParseCertificate must not accept negative-serial DER with trailing bytes")
	}
}

func TestParseCertificate_garbageStaysError(t *testing.T) {
	_, err := ParseCertificate([]byte{0x30, 0x03, 0x01, 0x01, 0x00})
	if err == nil {
		t.Fatal("expected error for garbage DER")
	}
}
