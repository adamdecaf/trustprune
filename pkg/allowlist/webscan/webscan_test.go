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

package webscan

import (
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/adamdecaf/trustprune/pkg/certutil"
)

func TestVerifiedRootAndThresholdYAML(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)
	rootA, keyA := mintCAWithKey(t, "Test Root A", 1, now.Add(10*365*24*time.Hour))
	rootB, keyB := mintCAWithKey(t, "Test Root B", 2, now.Add(10*365*24*time.Hour))
	rootC, keyC := mintCAWithKey(t, "Unlisted Root", 3, now.Add(10*365*24*time.Hour))

	leafA1 := mintIssued(t, "a1.example", 21, now.Add(24*time.Hour), rootA, keyA, false, "a1.example")
	leafA2 := mintIssued(t, "a2.example", 22, now.Add(24*time.Hour), rootA, keyA, false, "a2.example")
	leafA3 := mintIssued(t, "a3.example", 23, now.Add(24*time.Hour), rootA, keyA, false, "a3.example")
	leafB := mintIssued(t, "b.example", 24, now.Add(24*time.Hour), rootB, keyB, false, "b.example")
	leafC := mintIssued(t, "c.example", 25, now.Add(24*time.Hour), rootC, keyC, false, "c.example")

	pool := x509.NewCertPool()
	pool.AddCert(rootA)
	pool.AddCert(rootB)
	known := map[string]*Root{
		fpOf(rootA): {Cert: rootA, SHA256: fpOf(rootA), Subject: certutil.StringifyPKIXName(rootA.Subject)},
		fpOf(rootB): {Cert: rootB, SHA256: fpOf(rootB), Subject: certutil.StringifyPKIXName(rootB.Subject)},
	}

	if got := VerifiedRoot(leafA1, nil, "a1.example", pool, known); got == nil || got.SHA256 != fpOf(rootA) {
		t.Fatalf("leafA1 root = %+v", got)
	}
	if got := VerifiedRoot(leafB, nil, "b.example", pool, known); got == nil || got.SHA256 != fpOf(rootB) {
		t.Fatalf("leafB root = %+v", got)
	}
	// Wrong DNS name must not count.
	if got := VerifiedRoot(leafA1, nil, "other.example", pool, known); got != nil {
		t.Fatalf("wrong DNS accepted: %+v", got)
	}
	// A real chain anchored by a CA that is not in the Mozilla set is ignored.
	if got := VerifiedRoot(leafC, nil, "c.example", pool, known); got != nil {
		t.Fatalf("unlisted root was accepted: %+v", got)
	}

	counts := NewCounts()
	for _, item := range []struct {
		leaf *x509.Certificate
		dns  string
	}{
		{leafA1, "a1.example"},
		{leafA2, "a2.example"},
		{leafA3, "a3.example"},
		{leafB, "b.example"},
		{leafC, "c.example"},
	} {
		counts.Add(VerifiedRoot(item.leaf, nil, item.dns, pool, known))
	}
	if counts.Sites(fpOf(rootA)) != 3 || counts.Sites(fpOf(rootB)) != 1 || counts.Sites(fpOf(rootC)) != 0 {
		t.Fatalf("counts A=%d B=%d C=%d", counts.Sites(fpOf(rootA)), counts.Sites(fpOf(rootB)), counts.Sites(fpOf(rootC)))
	}

	kept := counts.Above(2)
	if len(kept) != 1 || kept[0].SHA256 != fpOf(rootA) || kept[0].Sites != 3 {
		t.Fatalf("Above(2) = %+v", kept)
	}
	if len(counts.Above(1)) != 2 {
		t.Fatalf("Above(1) = %+v", counts.Above(1))
	}
	if len(counts.Above(4)) != 0 {
		t.Fatalf("Above(4) = %+v", counts.Above(4))
	}

	rep := Report{
		ListName:       "Tranco",
		ListID:         "TESTID",
		ListURL:        "https://tranco-list.eu/download/TESTID/4",
		ListDate:       "2026-11-27",
		CertdataSource: "testdata/certdata.txt.gz",
		N:              5,
		Success:        4,
		Threshold:      2,
		Roots:          kept,
		Observed:       counts.All(),
	}
	out := string(rep.YAML())
	if !strings.Contains(out, "Source list: Tranco TESTID") {
		t.Fatalf("missing source list:\n%s", out)
	}
	if !strings.Contains(out, "List date: 2026-11-27") || !strings.Contains(out, "Sites scanned: 5") {
		t.Fatalf("missing provenance:\n%s", out)
	}
	if !strings.Contains(out, "Successful verifications: 4") || !strings.Contains(out, "Success rate: 80.0%") {
		t.Fatalf("missing success stats:\n%s", out)
	}
	if !strings.Contains(out, "not a full top-1-million scan") {
		t.Fatalf("missing sample caveat:\n%s", out)
	}
	if !strings.Contains(out, "Cite: https://tranco-list.eu/") {
		t.Fatalf("missing Tranco cite:\n%s", out)
	}
	if !strings.Contains(out, "Threshold: roots that anchored at least 2 successful sites") {
		t.Fatalf("missing threshold:\n%s", out)
	}
	if !strings.Contains(out, "fingerprints:\n  - \""+fpOf(rootA)+"\"\n") {
		t.Fatalf("missing kept fingerprint:\n%s", out)
	}
	if strings.Contains(out, fpOf(rootB)+"\"") && strings.Contains(out, "  - \""+fpOf(rootB)+"\"") {
		t.Fatalf("root B should not be in fingerprints:\n%s", out)
	}
	if !strings.Contains(out, fpOf(rootA)+"       3") || !strings.Contains(out, fpOf(rootB)+"       1") {
		t.Fatalf("missing per-root counts:\n%s", out)
	}
	if strings.Contains(out, fpOf(rootC)) {
		t.Fatalf("invented unlisted fingerprint:\n%s", out)
	}
	if strings.HasPrefix(out, "---") {
		t.Fatal("YAML has Jekyll front matter")
	}
}

func TestParseTopSitesCSV(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", "..", "testdata", "tranco-sample.csv")
	bs, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	hosts, err := ParseTopSitesCSV(bytes.NewReader(bs), 0)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"google.com", "youtube.com", "facebook.com", "example.com"}
	if len(hosts) != len(want) {
		t.Fatalf("hosts=%v want %v", hosts, want)
	}
	for i := range want {
		if hosts[i] != want[i] {
			t.Fatalf("hosts=%v want %v", hosts, want)
		}
	}
	limited, err := ParseTopSitesCSV(bytes.NewReader(bs), 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(limited) != 2 || limited[0] != "google.com" || limited[1] != "youtube.com" {
		t.Fatalf("limit 2: %v", limited)
	}
	if _, err := ParseTopSitesCSV(strings.NewReader("not-a-row\n"), 0); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestLoadMozillaRootsFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", "..", "testdata", "certdata.txt.gz")
	pool, known, err := LoadMozillaRootsFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if pool == nil || len(known) < 100 {
		t.Fatalf("loaded %d mozilla roots", len(known))
	}
	for fp, root := range known {
		if len(fp) != 64 || root == nil || root.SHA256 != fp || root.Cert == nil {
			t.Fatalf("bad root entry %q: %+v", fp, root)
		}
		for _, c := range fp {
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				t.Fatalf("fingerprint %q is not lowercase hex", fp)
			}
		}
	}
	// A self-minted CA is not a Mozilla root, so it must not verify.
	now := time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)
	unknown, key := mintCAWithKey(t, "Unknown Root", 99, now.Add(365*24*time.Hour))
	leaf := mintIssued(t, "evil.example", 100, now.Add(24*time.Hour), unknown, key, false, "evil.example")
	if got := VerifiedRoot(leaf, nil, "evil.example", pool, known); got != nil {
		t.Fatalf("unknown root accepted: %+v", got)
	}
}

func TestVerifiedRootIntermediate(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)
	root, rootKey := mintCAWithKey(t, "Test Root A", 1, now.Add(10*365*24*time.Hour))
	intCA, intKey := mintIssuedWithKey(t, "Test Int A", 11, now.Add(5*365*24*time.Hour), root, rootKey, true)
	leaf := mintIssued(t, "via-int.example", 21, now.Add(24*time.Hour), intCA, intKey, false, "via-int.example")

	pool := x509.NewCertPool()
	pool.AddCert(root)
	known := map[string]*Root{
		fpOf(root): {Cert: root, SHA256: fpOf(root), Subject: certutil.StringifyPKIXName(root.Subject)},
	}
	if got := VerifiedRoot(leaf, nil, "via-int.example", pool, known); got != nil {
		t.Fatal("verified without presenting the intermediate")
	}
	if got := VerifiedRoot(leaf, []*x509.Certificate{intCA}, "via-int.example", pool, known); got == nil || got.SHA256 != fpOf(root) {
		t.Fatalf("intermediate chain: %+v", got)
	}
}

func TestGunzipIfNeededCap(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(bytes.Repeat([]byte("A"), 64)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := gunzipIfNeeded("certdata.txt.gz", buf.Bytes(), 16); err == nil {
		t.Fatal("expected size cap error")
	} else if !strings.Contains(err.Error(), "certdata.txt.gz") || !strings.Contains(err.Error(), "16") {
		t.Fatalf("error = %v", err)
	}
}

func fpOf(c *x509.Certificate) string {
	return certutil.GetHexSHA256Fingerprint(*c)
}

func mintCAWithKey(t *testing.T, cn string, serial int64, notAfter time.Time) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"trustprune test"}},
		NotBefore:             time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
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
	return cert, key
}

func mintIssued(t *testing.T, cn string, serial int64, notAfter time.Time, issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey, isCA bool, dnsNames ...string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"trustprune test"}},
		NotBefore:             time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              notAfter,
		DNSNames:              dnsNames,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}
	if isCA {
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		tmpl.ExtKeyUsage = nil
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, &key.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func mintIssuedWithKey(t *testing.T, cn string, serial int64, notAfter time.Time, issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey, isCA bool, dnsNames ...string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"trustprune test"}},
		NotBefore:             time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              notAfter,
		DNSNames:              dnsNames,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}
	if isCA {
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		tmpl.ExtKeyUsage = nil
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, &key.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}
