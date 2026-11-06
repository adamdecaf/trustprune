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

package ui

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/adamdecaf/trustprune/pkg/certutil"
)

func TestWritePrinterFailureIncludesClose(t *testing.T) {
	var buf bytes.Buffer
	writePrinterFailure(&buf, errors.New("openssl unavailable"))
	out := buf.String()
	if !strings.Contains(out, "ERROR: openssl unavailable") {
		t.Fatalf("missing error text:\n%s", out)
	}
	if !strings.Contains(out, `href="/done"`) || !strings.Contains(out, "Close") {
		t.Fatalf("missing Close action:\n%s", out)
	}
}

func TestWebTitleUsesTrustprune(t *testing.T) {
	var buf bytes.Buffer
	if err := write(&buf, head, struct{ Operation string }{Operation: "list certificates"}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "<title>trustprune list certificates</title>") {
		t.Fatalf("expected trustprune title, got:\n%s", out)
	}
	if strings.Contains(out, "cert-mange") || strings.Contains(out, "cert-manage") {
		t.Fatalf("legacy/typo title still present:\n%s", out)
	}
}

func TestWebCertSummaryFields(t *testing.T) {
	cert := mustTestCert(t)
	view := webCertFromX509(cert, "RAW DUMP")
	var buf bytes.Buffer
	if err := write(&buf, list, struct{ Certificates []webCert }{Certificates: []webCert{view}}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	wantSubject := certutil.StringifyPKIXName(cert.Subject)
	wantIssuer := certutil.StringifyPKIXName(cert.Issuer)
	wantFP := certutil.GetHexSHA256Fingerprint(*cert)
	for _, want := range []string{
		"Subject: " + wantSubject,
		"Issuer: " + wantIssuer,
		"SHA256: " + wantFP,
		"Serial: " + cert.SerialNumber.String(),
		"NotBefore: " + cert.NotBefore.UTC().Format("2006-01-02"),
		"NotAfter: " + cert.NotAfter.UTC().Format("2006-01-02"),
		"RAW DUMP",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
}

func mustTestCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "web-ui-test"},
		Issuer:       pkix.Name{CommonName: "web-ui-issuer"},
		NotBefore:    time.Date(2020, 1, 2, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2030, 3, 4, 0, 0, 0, 0, time.UTC),
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
