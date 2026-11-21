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
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/adamdecaf/trustprune/pkg/certutil"
)

func TestNormalizeDiffFormat(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in      string
		want    string
		wantErr string
	}{
		{in: "", want: "text"},
		{in: "text", want: "text"},
		{in: "TEXT", want: "text"},
		{in: " json ", want: "json"},
		{in: "JSON", want: "json"},
		{in: "table", wantErr: `unknown format "table" (formats: json, text)`},
		{in: "Short", wantErr: `unknown format "Short" (formats: json, text)`},
		{in: "nope", wantErr: `unknown format "nope" (formats: json, text)`},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()
			got, err := NormalizeDiffFormat(tc.in)
			if tc.wantErr != "" {
				if err == nil || err.Error() != tc.wantErr {
					t.Fatalf("NormalizeDiffFormat(%q) error = %v, want %q", tc.in, err, tc.wantErr)
				}
				if got != "" {
					t.Fatalf("NormalizeDiffFormat(%q) = %q, want empty", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeDiffFormat(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("NormalizeDiffFormat(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestDiffSameFixtureIdentical(t *testing.T) {
	t.Parallel()

	path := diffTestdata(t, "example.crt")
	var buf bytes.Buffer
	if err := diffCertificates(&buf, path, path, DiffOptions{}); err != nil {
		t.Fatal(err)
	}
	if buf.String() != "identical\n" {
		t.Fatalf("stdout = %q", buf.String())
	}

	buf.Reset()
	if err := diffCertificates(&buf, path, path, DiffOptions{Format: "JSON"}); err != nil {
		t.Fatal(err)
	}
	doc := decodeDiffJSON(t, buf.String())
	if !doc.Identical || len(doc.Differences) != 0 {
		t.Fatalf("json = %#v", doc)
	}
	if doc.Left != path || doc.Right != path {
		t.Fatalf("paths = %q %q", doc.Left, doc.Right)
	}
	if !strings.Contains(buf.String(), `"differences": []`) {
		t.Fatalf("missing empty differences:\n%s", buf.String())
	}
	if strings.Contains(buf.String(), `"mode"`) {
		t.Fatalf("single-cert json includes mode:\n%s", buf.String())
	}
}

func TestDiffPEMAndDERIdentical(t *testing.T) {
	t.Parallel()

	pemPath := diffTestdata(t, "example.crt")
	certs, err := readCertificates(pemPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 1 {
		t.Fatalf("certs = %d", len(certs))
	}
	cert := certs[0]
	derPath := filepath.Join(t.TempDir(), "example.der")
	if err := os.WriteFile(derPath, cert.Raw, 0o600); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := diffCertificates(&buf, pemPath, derPath, DiffOptions{Format: "text"}); err != nil {
		t.Fatal(err)
	}
	if buf.String() != "identical\n" {
		t.Fatalf("stdout = %q", buf.String())
	}
}

func TestDiffNegativeSerialIdentical(t *testing.T) {
	t.Parallel()

	path := diffTestdata(t, "negative-serial.pem")
	var buf bytes.Buffer
	if err := diffCertificates(&buf, path, path, DiffOptions{}); err != nil {
		t.Fatalf("negative serial: %v", err)
	}
	if buf.String() != "identical\n" {
		t.Fatalf("stdout = %q", buf.String())
	}
}

func TestDiffExampleAndLocalCert(t *testing.T) {
	t.Parallel()

	leftPath := diffTestdata(t, "example.crt")
	rightPath := diffTestdata(t, "localcert.pem")
	var buf bytes.Buffer
	err := diffCertificates(&buf, leftPath, rightPath, DiffOptions{})
	if !errors.Is(err, ErrCertificatesDiffer) {
		t.Fatalf("err = %v", err)
	}
	text := buf.String()
	if strings.Contains(text, "ERROR:") || strings.Contains(text, "identical") {
		t.Fatalf("text =\n%s", text)
	}

	changes := textChanges(t, text)
	fields := map[string]diffChange{}
	var order []string
	for _, ch := range changes {
		fields[ch.Field] = ch
		order = append(order, ch.Field)
	}
	for _, name := range []string{"subject", "issuer", "serial", "validity", "key", "sans", "sha256", "signature_algorithm"} {
		ch, ok := fields[name]
		if !ok {
			t.Errorf("missing %s in %v", name, order)
			continue
		}
		if ch.Left == ch.Right {
			t.Errorf("%s values are equal: %q", name, ch.Left)
		}
	}
	if !strings.Contains(fields["subject"].Left, "Starfield") {
		t.Errorf("subject left = %q", fields["subject"].Left)
	}
	if !strings.Contains(fields["sans"].Right, "example.com") || !strings.Contains(fields["sans"].Right, "127.0.0.1") {
		t.Errorf("sans right = %q", fields["sans"].Right)
	}
	sig := fields["signature_algorithm"]
	if sig.Left != "SHA1-RSA" || sig.Right != "SHA256-RSA" {
		t.Errorf("signature = %#v", sig)
	}
	if fields["key"].Left != "RSA-2048" || fields["key"].Right != "RSA-1024" {
		t.Errorf("key = %#v", fields["key"])
	}
	wantSig := "signature_algorithm: " + strconv.Quote("SHA1-RSA") + " != " + strconv.Quote("SHA256-RSA") + "\n"
	if !strings.Contains(text, wantSig) {
		t.Fatalf("text missing %q\n%s", wantSig, text)
	}
	assertCanonicalDiffOrder(t, order)

	buf.Reset()
	err = diffCertificates(&buf, leftPath, rightPath, DiffOptions{Format: "json"})
	if !errors.Is(err, ErrCertificatesDiffer) {
		t.Fatalf("json err = %v", err)
	}
	doc := decodeDiffJSON(t, buf.String())
	if doc.Identical || doc.Left != leftPath || doc.Right != rightPath {
		t.Fatalf("json = %#v", doc)
	}
	if len(doc.Differences) != len(changes) {
		t.Fatalf("json fields %d, text fields %d", len(doc.Differences), len(changes))
	}
	for i, ch := range changes {
		got := doc.Differences[i]
		if got.Field != ch.Field || got.Left != ch.Left || got.Right != ch.Right {
			t.Fatalf("json[%d] = %#v, text = %#v", i, got, ch)
		}
	}
	if strings.Contains(buf.String(), `"mode"`) {
		t.Fatalf("single-cert json includes mode:\n%s", buf.String())
	}
}

func TestDiffRejectsBadFiles(t *testing.T) {
	t.Parallel()

	good := diffTestdata(t, "example.crt")
	dir := t.TempDir()

	t.Run("missing", func(t *testing.T) {
		t.Parallel()
		missing := filepath.Join(dir, "missing.pem")
		err := diffCertificates(&bytes.Buffer{}, missing, good, DiffOptions{})
		if err == nil || !strings.Contains(err.Error(), "does not exist") {
			t.Fatalf("err = %v", err)
		}
		if errors.Is(err, ErrCertificatesDiffer) {
			t.Fatal("missing file reported as a difference")
		}
	})

	t.Run("empty", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(dir, "empty.pem")
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		err := diffCertificates(&bytes.Buffer{}, path, good, DiffOptions{})
		if err == nil || !strings.Contains(err.Error(), "no certificate") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("garbage", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(dir, "garbage.bin")
		if err := os.WriteFile(path, []byte("not a certificate\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		err := diffCertificates(&bytes.Buffer{}, path, good, DiffOptions{})
		if err == nil || !strings.Contains(err.Error(), "not a PEM or DER certificate") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("bad pem block", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(dir, "bad.pem")
		body := "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		err := diffCertificates(&bytes.Buffer{}, path, good, DiffOptions{})
		if err == nil || !strings.Contains(err.Error(), "certificate 1:") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("private key only", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(dir, "key.pem")
		body := "-----BEGIN PRIVATE KEY-----\nYQ==\n-----END PRIVATE KEY-----\n"
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		err := diffCertificates(&bytes.Buffer{}, path, good, DiffOptions{})
		if err == nil || !strings.Contains(err.Error(), "no certificate") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("format before read", func(t *testing.T) {
		t.Parallel()
		missing := filepath.Join(dir, "also-missing.pem")
		err := diffCertificates(&bytes.Buffer{}, missing, missing, DiffOptions{Format: "nope"})
		if err == nil || err.Error() != `unknown format "nope" (formats: json, text)` {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestDiffIgnoresNonCertificatePEM(t *testing.T) {
	t.Parallel()

	pemPath := diffTestdata(t, "localcert.pem")
	body, err := os.ReadFile(pemPath)
	if err != nil {
		t.Fatal(err)
	}
	wrapped := filepath.Join(t.TempDir(), "wrapped.pem")
	prefix := []byte("-----BEGIN PRIVATE KEY-----\nYQ==\n-----END PRIVATE KEY-----\n")
	if err := os.WriteFile(wrapped, append(prefix, body...), 0o600); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := diffCertificates(&buf, pemPath, wrapped, DiffOptions{}); err != nil {
		t.Fatal(err)
	}
	if buf.String() != "identical\n" {
		t.Fatalf("stdout = %q", buf.String())
	}
}

func TestCompareCertFields(t *testing.T) {
	t.Parallel()

	left := baseDiffCert()
	right := cloneDiffCert(left)
	if changes := compareCerts(left, right); len(changes) != 0 {
		t.Fatalf("clone differs: %#v", changes)
	}

	// Equal instants in different zones are the same validity.
	right = cloneDiffCert(left)
	right.NotBefore = time.Date(2020, 1, 2, 12, 4, 5, 0, time.FixedZone("EAST", 9*60*60))
	right.NotAfter = time.Date(2030, 1, 2, 12, 4, 5, 0, time.FixedZone("EAST", 9*60*60))
	if changes := compareCerts(left, right); len(changes) != 0 {
		t.Fatalf("equal instants differ: %#v", changes)
	}

	t.Run("serial", func(t *testing.T) {
		t.Parallel()
		right := cloneDiffCert(left)
		right.SerialNumber = big.NewInt(8)
		changes := compareCerts(left, right)
		if len(changes) != 1 || changes[0].Field != "serial" || changes[0].Left != "7" || changes[0].Right != "8" {
			t.Fatalf("changes = %#v", changes)
		}
		got := formatDiffText(changes)
		want := "serial: \"7\" != \"8\"\n"
		if got != want {
			t.Fatalf("text = %q, want %q", got, want)
		}
	})

	t.Run("key size", func(t *testing.T) {
		t.Parallel()
		right := cloneDiffCert(left)
		right.PublicKey = rsaKey(1024)
		changes := compareCerts(left, right)
		if len(changes) != 1 || changes[0].Field != "key" || changes[0].Left != "RSA-2048" || changes[0].Right != "RSA-1024" {
			t.Fatalf("changes = %#v", changes)
		}
	})

	t.Run("key type", func(t *testing.T) {
		t.Parallel()
		right := cloneDiffCert(left)
		right.PublicKeyAlgorithm = x509.ECDSA
		right.PublicKey = &ecdsa.PublicKey{}
		changes := compareCerts(left, right)
		if len(changes) != 1 || changes[0].Field != "key" || changes[0].Left != "RSA-2048" || changes[0].Right != "ECDSA" {
			t.Fatalf("changes = %#v", changes)
		}
	})

	t.Run("sans kinds", func(t *testing.T) {
		t.Parallel()
		withURI := cloneDiffCert(left)
		withURI.URIs = []*url.URL{mustDiffURL(t, "https://example.com/a")}
		withURI.EmailAddresses = []string{"a@example.com"}
		withURI.IPAddresses = []net.IP{net.ParseIP("2001:db8::1")}
		if got := formatSANs(withURI); got != "a.example, a@example.com, 2001:db8::1, https://example.com/a" {
			t.Fatalf("sans = %q", got)
		}
		cleared := cloneDiffCert(left)
		cleared.DNSNames = nil
		changes := compareCerts(left, cleared)
		if len(changes) != 1 || changes[0].Field != "sans" || changes[0].Left != "a.example" || changes[0].Right != "" {
			t.Fatalf("changes = %#v", changes)
		}
	})

	t.Run("all fields", func(t *testing.T) {
		t.Parallel()
		right := cloneDiffCert(left)
		right.Subject = pkix.Name{CommonName: "other"}
		right.Issuer = pkix.Name{CommonName: "other-issuer"}
		right.SerialNumber = big.NewInt(9)
		right.NotAfter = left.NotAfter.Add(time.Hour)
		right.PublicKeyAlgorithm = x509.ECDSA
		right.PublicKey = &ecdsa.PublicKey{}
		right.DNSNames = []string{"b.example"}
		right.Raw = []byte{0x09, 0x09}
		right.SignatureAlgorithm = x509.SHA384WithRSA

		changes := compareCerts(left, right)
		want := []string{"subject", "issuer", "serial", "validity", "key", "sans", "sha256", "signature_algorithm"}
		if len(changes) != len(want) {
			t.Fatalf("changes = %#v", changes)
		}
		for i, name := range want {
			if changes[i].Field != name || changes[i].Left == changes[i].Right {
				t.Fatalf("field %d = %#v", i, changes[i])
			}
		}
		if changes[7].Left != x509.SHA256WithRSA.String() || changes[7].Right != x509.SHA384WithRSA.String() {
			t.Fatalf("signature = %#v", changes[7])
		}
	})
}

func TestFormatSANsOrder(t *testing.T) {
	t.Parallel()

	c := &x509.Certificate{
		DNSNames:       []string{"b.example", "a.example"},
		EmailAddresses: []string{"z@example.com"},
		IPAddresses:    []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		URIs:           []*url.URL{mustDiffURL(t, "https://example.com/a")},
	}
	got := formatSANs(c)
	want := "b.example, a.example, z@example.com, 127.0.0.1, ::1, https://example.com/a"
	if got != want {
		t.Fatalf("got %q", got)
	}
}

func baseDiffCert() *x509.Certificate {
	return &x509.Certificate{
		Raw:                []byte{0x01, 0x02, 0x03},
		Subject:            pkix.Name{CommonName: "subject"},
		Issuer:             pkix.Name{CommonName: "issuer"},
		SerialNumber:       big.NewInt(7),
		NotBefore:          time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC),
		NotAfter:           time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC),
		PublicKeyAlgorithm: x509.RSA,
		PublicKey:          rsaKey(2048),
		DNSNames:           []string{"a.example"},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
}

func cloneDiffCert(c *x509.Certificate) *x509.Certificate {
	cp := *c
	return &cp
}

func rsaKey(bits int) *rsa.PublicKey {
	return &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), uint(bits-1)), E: 65537}
}

func mustDiffURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func diffTestdata(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join("..", "..", "testdata", name)
}

func decodeDiffJSON(t *testing.T, raw string) diffJSON {
	t.Helper()
	var doc diffJSON
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatalf("json: %v\n%s", err, raw)
	}
	if !strings.HasSuffix(raw, "\n") {
		t.Fatal("json missing trailing newline")
	}
	return doc
}

func textChanges(t *testing.T, text string) []diffChange {
	t.Helper()
	var out []diffChange
	for _, line := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
		field, rest, ok := strings.Cut(line, ": ")
		if !ok {
			t.Fatalf("line %q", line)
		}
		leftQuoted, rightQuoted, ok := strings.Cut(rest, " != ")
		if !ok {
			t.Fatalf("line %q", line)
		}
		left, err := strconv.Unquote(leftQuoted)
		if err != nil {
			t.Fatalf("left %q: %v", leftQuoted, err)
		}
		right, err := strconv.Unquote(rightQuoted)
		if err != nil {
			t.Fatalf("right %q: %v", rightQuoted, err)
		}
		out = append(out, diffChange{Field: field, Left: left, Right: right})
	}
	return out
}

func assertCanonicalDiffOrder(t *testing.T, got []string) {
	t.Helper()
	canon := []string{"subject", "issuer", "serial", "validity", "key", "sans", "sha256", "signature_algorithm"}
	i := 0
	for _, name := range got {
		for i < len(canon) && canon[i] != name {
			i++
		}
		if i == len(canon) {
			t.Fatalf("order %v is not canonical", got)
		}
		i++
	}
}

func TestDiffBundleText(t *testing.T) {
	t.Parallel()

	notBefore, notAfter := diffBundleWindow()
	alpha, _ := mintCA(t, "a.example", notBefore, notAfter)
	mid, _ := mintCA(t, "m.example", notBefore, notAfter)
	zeta, _ := mintCA(t, "z.example", notBefore, notAfter)
	beta, _ := mintCA(t, "b.example", notBefore, notAfter)

	// File order is not the report order. alpha is duplicated.
	leftPath := writeDiffPEM(t, "left.pem", zeta, mid, alpha, alpha)
	rightPath := writeDiffPEM(t, "right.pem", beta, mid)

	var buf bytes.Buffer
	err := diffCertificates(&buf, leftPath, rightPath, DiffOptions{})
	if !errors.Is(err, ErrCertificatesDiffer) {
		t.Fatalf("err = %v", err)
	}
	want := "left: " + leftPath + "\n" +
		"right: " + rightPath + "\n" +
		"Removed (2):\n" +
		bundleLine(alpha) + "\n" +
		bundleLine(zeta) + "\n" +
		"Added (1):\n" +
		bundleLine(beta) + "\n" +
		"Unchanged: 1\n"
	if buf.String() != want {
		t.Fatalf("text =\n%s\nwant =\n%s", buf.String(), want)
	}
}

func TestDiffBundleIdentical(t *testing.T) {
	t.Parallel()

	notBefore, notAfter := diffBundleWindow()
	alpha, _ := mintCA(t, "a.example", notBefore, notAfter)
	beta, _ := mintCA(t, "b.example", notBefore, notAfter)
	leftPath := writeDiffPEM(t, "left.pem", alpha, beta, alpha)
	rightPath := writeDiffPEM(t, "right.pem", beta, alpha, beta)

	var buf bytes.Buffer
	if err := diffCertificates(&buf, leftPath, rightPath, DiffOptions{}); err != nil {
		t.Fatal(err)
	}
	want := "left: " + leftPath + "\n" +
		"right: " + rightPath + "\n" +
		"Unchanged: 2\n" +
		bundleSameCertificates + "\n"
	if buf.String() != want {
		t.Fatalf("text =\n%s\nwant =\n%s", buf.String(), want)
	}
}

func TestDiffBundleDuplicates(t *testing.T) {
	t.Parallel()

	notBefore, notAfter := diffBundleWindow()
	alpha, _ := mintCA(t, "a.example", notBefore, notAfter)
	leftPath := writeDiffPEM(t, "left.pem", alpha, alpha)
	rightPath := writeDiffPEM(t, "right.pem", alpha)

	var buf bytes.Buffer
	if err := diffCertificates(&buf, leftPath, rightPath, DiffOptions{}); err != nil {
		t.Fatalf("err = %v", err)
	}
	want := "left: " + leftPath + "\n" +
		"right: " + rightPath + "\n" +
		"Unchanged: 1\n" +
		bundleSameCertificates + "\n"
	if buf.String() != want {
		t.Fatalf("text =\n%s\nwant =\n%s", buf.String(), want)
	}
}

func TestDiffBundleOneVsMany(t *testing.T) {
	t.Parallel()

	notBefore, notAfter := diffBundleWindow()
	alpha, _ := mintCA(t, "a.example", notBefore, notAfter)
	beta, _ := mintCA(t, "b.example", notBefore, notAfter)

	t.Run("pem", func(t *testing.T) {
		t.Parallel()
		leftPath := writeDiffPEM(t, "one.pem", alpha)
		rightPath := writeDiffPEM(t, "many.pem", alpha, beta)
		var buf bytes.Buffer
		err := diffCertificates(&buf, leftPath, rightPath, DiffOptions{})
		if !errors.Is(err, ErrCertificatesDiffer) {
			t.Fatalf("err = %v", err)
		}
		want := "left: " + leftPath + "\n" +
			"right: " + rightPath + "\n" +
			"Added (1):\n" +
			bundleLine(beta) + "\n" +
			"Unchanged: 1\n"
		if buf.String() != want {
			t.Fatalf("text =\n%s\nwant =\n%s", buf.String(), want)
		}
	})

	t.Run("der", func(t *testing.T) {
		t.Parallel()
		leftPath := writeDiffDER(t, "one.der", alpha)
		rightPath := writeDiffPEM(t, "many.pem", beta, alpha)
		var buf bytes.Buffer
		err := diffCertificates(&buf, leftPath, rightPath, DiffOptions{})
		if !errors.Is(err, ErrCertificatesDiffer) {
			t.Fatalf("err = %v", err)
		}
		text := buf.String()
		if strings.Contains(text, "Removed (") || strings.Contains(text, " != ") {
			t.Fatalf("text =\n%s", text)
		}
		if !strings.Contains(text, "Added (1):\n"+bundleLine(beta)+"\n") || !strings.Contains(text, "Unchanged: 1\n") {
			t.Fatalf("text =\n%s", text)
		}
	})
}

func TestDiffBundleSameSubjectOrder(t *testing.T) {
	t.Parallel()

	notBefore, notAfter := diffBundleWindow()
	first, _ := mintCA(t, "same.example", notBefore, notAfter)
	second, _ := mintCA(t, "same.example", notBefore, notAfter)
	other, _ := mintCA(t, "other.example", notBefore, notAfter)
	if formatSHA256(first) == formatSHA256(second) {
		t.Fatal("minted certificates share a fingerprint")
	}
	leftPath := writeDiffPEM(t, "left.pem", second, first)
	rightPath := writeDiffPEM(t, "right.pem", other)

	var buf bytes.Buffer
	err := diffCertificates(&buf, leftPath, rightPath, DiffOptions{})
	if !errors.Is(err, ErrCertificatesDiffer) {
		t.Fatalf("err = %v", err)
	}
	ordered := []string{bundleLine(first), bundleLine(second)}
	if formatSHA256(second) < formatSHA256(first) {
		ordered = []string{bundleLine(second), bundleLine(first)}
	}
	want := "left: " + leftPath + "\n" +
		"right: " + rightPath + "\n" +
		"Removed (2):\n" +
		ordered[0] + "\n" +
		ordered[1] + "\n" +
		"Added (1):\n" +
		bundleLine(other) + "\n" +
		"Unchanged: 0\n"
	if buf.String() != want {
		t.Fatalf("text =\n%s\nwant =\n%s", buf.String(), want)
	}
}

func TestDiffBundleJSON(t *testing.T) {
	t.Parallel()

	notBefore, notAfter := diffBundleWindow()
	alpha, _ := mintCA(t, "a.example", notBefore, notAfter)
	beta, _ := mintCA(t, "b.example", notBefore, notAfter)
	gamma, _ := mintCA(t, "g.example", notBefore, notAfter)
	leftPath := writeDiffPEM(t, "left.pem", alpha, beta)
	rightPath := writeDiffPEM(t, "right.pem", beta, gamma)

	var buf bytes.Buffer
	err := diffCertificates(&buf, leftPath, rightPath, DiffOptions{Format: "json"})
	if !errors.Is(err, ErrCertificatesDiffer) {
		t.Fatalf("err = %v", err)
	}
	raw := buf.String()
	doc := decodeBundleDiffJSON(t, raw)
	if doc.Identical || doc.Mode != "bundle" || doc.Left != leftPath || doc.Right != rightPath || doc.Unchanged != 1 {
		t.Fatalf("json = %#v", doc)
	}
	if len(doc.Removed) != 1 || doc.Removed[0] != bundleEntry(alpha) {
		t.Fatalf("removed = %#v", doc.Removed)
	}
	if len(doc.Added) != 1 || doc.Added[0] != bundleEntry(gamma) {
		t.Fatalf("added = %#v", doc.Added)
	}
	assertJSONKeyOrder(t, raw, []string{"identical", "left", "right", "mode", "removed", "added", "unchanged"})

	buf.Reset()
	sameRight := writeDiffPEM(t, "same.pem", alpha, beta, beta)
	if err := diffCertificates(&buf, leftPath, sameRight, DiffOptions{Format: "JSON"}); err != nil {
		t.Fatal(err)
	}
	raw = buf.String()
	if !strings.Contains(raw, `"removed": []`) || !strings.Contains(raw, `"added": []`) {
		t.Fatalf("empty arrays missing:\n%s", raw)
	}
	if strings.Contains(raw, "null") {
		t.Fatalf("null in json:\n%s", raw)
	}
	doc = decodeBundleDiffJSON(t, raw)
	if !doc.Identical || doc.Mode != "bundle" || doc.Unchanged != 2 || len(doc.Removed) != 0 || len(doc.Added) != 0 {
		t.Fatalf("json = %#v", doc)
	}
}

func TestDiffBundleDisplayName(t *testing.T) {
	t.Parallel()

	// localcert has no common name. The bundle line uses the list subject
	// ("Acme Co"), not the raw subject "O=Acme Co".
	localCerts, err := readCertificates(diffTestdata(t, "localcert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	exampleCerts, err := readCertificates(diffTestdata(t, "example.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if len(localCerts) != 1 || len(exampleCerts) != 1 {
		t.Fatalf("certs = %d %d", len(localCerts), len(exampleCerts))
	}
	if got := bundleSubject(localCerts[0]); got != "Acme Co" {
		t.Fatalf("subject = %q", got)
	}
	leftPath := writeDiffPEM(t, "left.pem", exampleCerts[0], localCerts[0])
	var buf bytes.Buffer
	err = diffCertificates(&buf, leftPath, diffTestdata(t, "example.crt"), DiffOptions{})
	if !errors.Is(err, ErrCertificatesDiffer) {
		t.Fatalf("err = %v", err)
	}
	text := buf.String()
	if strings.Contains(text, "O=Acme Co") || strings.Contains(text, "Added (") {
		t.Fatalf("text =\n%s", text)
	}
	wantLine := "Acme Co " + formatSHA256(localCerts[0])
	if !strings.Contains(text, "Removed (1):\n"+wantLine+"\n") || !strings.Contains(text, "Unchanged: 1\n") {
		t.Fatalf("text =\n%s", text)
	}
}

func TestDiffTwoDERStaySingle(t *testing.T) {
	t.Parallel()

	notBefore, notAfter := diffBundleWindow()
	alpha, _ := mintCA(t, "a.example", notBefore, notAfter)
	beta, _ := mintCA(t, "b.example", notBefore, notAfter)
	leftPath := writeDiffDER(t, "left.der", alpha)
	rightPath := writeDiffDER(t, "right.der", beta)

	var buf bytes.Buffer
	err := diffCertificates(&buf, leftPath, rightPath, DiffOptions{Format: "json"})
	if !errors.Is(err, ErrCertificatesDiffer) {
		t.Fatalf("err = %v", err)
	}
	raw := buf.String()
	if strings.Contains(raw, `"mode"`) || strings.Contains(raw, `"removed"`) {
		t.Fatalf("der pair used bundle json:\n%s", raw)
	}
	doc := decodeDiffJSON(t, raw)
	if doc.Identical || len(doc.Differences) == 0 {
		t.Fatalf("json = %#v", doc)
	}
}

func diffBundleWindow() (time.Time, time.Time) {
	start := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)
	return start, start.Add(365 * 24 * time.Hour)
}

func writeDiffPEM(t *testing.T, name string, certs ...*x509.Certificate) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := certutil.ToFile(path, certs); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeDiffDER(t *testing.T, name string, cert *x509.Certificate) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, cert.Raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func bundleLine(c *x509.Certificate) string {
	return bundleSubject(c) + " " + formatSHA256(c)
}

func bundleEntry(c *x509.Certificate) bundleCert {
	return bundleCert{Subject: bundleSubject(c), SHA256: formatSHA256(c)}
}

func decodeBundleDiffJSON(t *testing.T, raw string) bundleDiffJSON {
	t.Helper()
	var doc bundleDiffJSON
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatalf("json: %v\n%s", err, raw)
	}
	if !strings.HasSuffix(raw, "\n") {
		t.Fatal("json missing trailing newline")
	}
	return doc
}

func assertJSONKeyOrder(t *testing.T, raw string, keys []string) {
	t.Helper()
	prev := -1
	for _, k := range keys {
		i := strings.Index(raw, `"`+k+`"`)
		if i < 0 || i <= prev {
			t.Fatalf("key %s order in\n%s", k, raw)
		}
		prev = i
	}
}
