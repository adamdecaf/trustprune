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
	"crypto/x509"
	"encoding/pem"
	"os"
	"strings"
	"testing"
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

func TestParseCertificate_fallbackRejectsGarbage(t *testing.T) {
	_, err := ParseCertificate([]byte{0x30, 0x03, 0x01, 0x01, 0x00})
	if err == nil {
		t.Fatal("expected error for garbage DER")
	}
}
