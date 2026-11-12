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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"flag"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/adamdecaf/trustprune/pkg/certutil"
)

func TestGetFormatsSorted(t *testing.T) {
	got := GetFormats()
	want := append([]string(nil), got...)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("GetFormats not sorted: %v", got)
	}
	joined := "," + strings.Join(got, ",") + ","
	for _, name := range []string{"json", "observatory", "openssl", "long", "table"} {
		if !strings.Contains(joined, ","+name+",") {
			t.Fatalf("GetFormats missing %s: %v", name, got)
		}
	}
	if strings.Contains(joined, ",short,") {
		t.Fatalf("GetFormats still contains short: %v", got)
	}
	if DefaultFormat() != "table" {
		t.Fatalf("DefaultFormat()=%q, want table", DefaultFormat())
	}
}

func TestShowCertsOnCliUnknownFormat(t *testing.T) {
	certs := testListCerts(t)
	err := showCertsOnCli(certs[:1], &Config{Format: "short"})
	if err == nil {
		t.Fatal("expected error")
	}
	const want = `unknown format "short" (formats: json, long, observatory, openssl, table)`
	if err.Error() != want {
		t.Fatalf("err=%q", err.Error())
	}
	err = showCertsOnCli(certs[:1], &Config{Format: "nope"})
	if err == nil || err.Error() != `unknown format "nope" (formats: json, long, observatory, openssl, table)` {
		t.Fatalf("err=%v", err)
	}
	if !KnownFormat("TABLE") || !KnownFormat("Long") || !KnownFormat("Observatory") {
		t.Fatal("known formats should match case-insensitively")
	}
	if KnownFormat("short") || KnownFormat("SHORT") || KnownFormat("") || KnownFormat("nope") {
		t.Fatal("unknown format treated as known")
	}
}

func TestLongPrinterIsMultilineDump(t *testing.T) {
	certs := testListCerts(t)
	var buf bytes.Buffer
	if err := (longPrinter{}).write(&buf, certs[:1]); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.HasPrefix(out, "Certificate\n") || !strings.Contains(out, "  SHA256 Fingerprint: ") {
		t.Fatalf("long output:\n%s", out)
	}
	if _, ok := getPrinter("short"); ok {
		t.Fatal("short is still a printer")
	}
	if _, ok := getPrinter("LONG"); !ok {
		t.Fatal("long printer is not case-insensitive")
	}
}

func TestListCertificatesJSON(t *testing.T) {
	bs, err := os.ReadFile(filepath.Join("..", "..", "testdata", "lots.crt"))
	if err != nil {
		t.Fatal(err)
	}
	certs, err := certutil.Decode(bs)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) < 1 {
		t.Fatal("no certs")
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	cfg := &Config{Format: "json", SourcePath: "testdata/lots.crt"}
	err = showCertsOnCliWithPrinter(certs[:1], cfg, jsonPrinter{meta: Meta{Name: "file"}, cfg: cfg})
	_ = w.Close()
	os.Stdout = old
	if err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(r)
	_ = r.Close()
	if err != nil {
		t.Fatal(err)
	}

	var rows []jsonCert
	if err := json.Unmarshal(out, &rows); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows", len(rows))
	}
	row := rows[0]
	wantFP := certutil.GetHexSHA256Fingerprint(*certs[0])
	if row.SHA256 != wantFP {
		t.Fatalf("sha256=%q want %q", row.SHA256, wantFP)
	}
	if row.Subject == "" || row.Issuer == "" {
		t.Fatalf("missing subject/issuer: %+v", row)
	}
	if row.Serial != certs[0].SerialNumber.String() {
		t.Fatalf("serial=%q", row.Serial)
	}
	if row.KeyType != "RSA" || row.KeyBits != 2048 {
		t.Fatalf("key=%s/%d", row.KeyType, row.KeyBits)
	}
	if !row.IsCA {
		t.Fatal("expected is_ca")
	}
	if row.Store != "file" || row.Path != "testdata/lots.crt" {
		t.Fatalf("store/path = %q %q", row.Store, row.Path)
	}
	if row.NotBefore == "" || row.NotAfter == "" {
		t.Fatalf("missing dates: %+v", row)
	}
}

func TestTablePrinterIncludesKeyAndDays(t *testing.T) {
	bs, err := os.ReadFile(filepath.Join("..", "..", "testdata", "example.crt"))
	if err != nil {
		t.Fatal(err)
	}
	certs, err := certutil.Decode(bs)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := (tablePrinter{}).write(&buf, certs); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "KEY") || !strings.Contains(out, "DAYS") {
		t.Fatalf("missing KEY/DAYS headers:\n%s", out)
	}
	if !strings.Contains(out, "SHA256-FINGERPRINT") {
		t.Fatalf("missing SHA256-FINGERPRINT header:\n%s", out)
	}
	if strings.Contains(out, "SHA256 FINGERPRINT") {
		t.Fatalf("old SHA256 FINGERPRINT header still present:\n%s", out)
	}
	if !strings.Contains(out, "RSA-") {
		t.Fatalf("missing KEY value:\n%s", out)
	}
}

const (
	tableGoldenPath        = "testdata/table.golden"
	tableVerboseGoldenPath = "testdata/table-verbose.golden"
	longGoldenPath         = "testdata/long.golden"
)

// goldenNow is the frozen clock for list goldens (lots.crt).
var goldenNow = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

var updateGolden = flag.Bool("update", false, "rewrite golden files")

func lotsCerts(t *testing.T) []*x509.Certificate {
	t.Helper()
	bs, err := os.ReadFile(filepath.Join("..", "..", "testdata", "lots.crt"))
	if err != nil {
		t.Fatal(err)
	}
	certs, err := certutil.Decode(bs)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) == 0 {
		t.Fatal("no certs in lots.crt")
	}
	return certs
}

func compareGolden(t *testing.T, path, out string) {
	t.Helper()
	if *updateGolden {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(out), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// #nosec G304 -- path is a testdata golden selected by the test
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if out != strings.ReplaceAll(string(want), "\r\n", "\n") {
		t.Fatalf("output differs from %s (run with -update):\n%s", path, out)
	}
}

func TestTablePrinterGoldenWidth(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	var buf bytes.Buffer
	p := tablePrinter{now: goldenNow}
	if err := p.write(&buf, lotsCerts(t)); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	compareGolden(t, tableGoldenPath, out)

	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if !strings.HasPrefix(lines[0], "SUBJECT ") || !strings.Contains(lines[0], "ISSUER") || !strings.Contains(lines[0], "SHA256-FINGERPRINT") {
		t.Fatalf("headers: %q", lines[0])
	}
	if strings.Contains(lines[0], "SHA256 FINGERPRINT") {
		t.Fatalf("old fingerprint header: %q", lines[0])
	}
	for i, line := range lines {
		if n := utf8.RuneCountInString(strings.TrimRight(line, " ")); n > tableMaxLineWidth {
			t.Errorf("line %d is %d wide (max %d): %q", i, n, tableMaxLineWidth, line)
		}
	}
}

func TestTablePrinterVerboseGolden(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	certs := lotsCerts(t)
	var buf bytes.Buffer
	p := tablePrinter{verbose: true, path: "testdata/lots.crt", now: goldenNow}
	if err := p.write(&buf, certs); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	compareGolden(t, tableVerboseGoldenPath, out)

	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	header := lines[0]
	for _, name := range []string{"SUBJECT", "ISSUER", "KEY", "DAYS", "SHA256-FINGERPRINT", "SERIAL", "PATH", "NOT-BEFORE", "NOT-AFTER"} {
		if !strings.Contains(header, name) {
			t.Errorf("header missing %s: %q", name, header)
		}
	}
	if strings.Contains(header, "SHA256 FINGERPRINT") || strings.Contains(header, "NOT BEFORE") || strings.Contains(header, "NOT AFTER") {
		t.Fatalf("old verbose header spacing: %q", header)
	}
	if strings.Contains(out, "!") || strings.Contains(out, "expired") {
		t.Fatalf("verbose DAYS should be numeric:\n%s", out)
	}
	if !strings.Contains(out, "testdata/lots.crt") {
		t.Fatalf("missing fixed path:\n%s", out)
	}
	wider := false
	for _, line := range lines {
		if utf8.RuneCountInString(strings.TrimRight(line, " ")) > tableMaxLineWidth {
			wider = true
			break
		}
	}
	if !wider {
		t.Fatal("verbose lines should exceed the non-verbose width cap")
	}
	for _, cert := range certs {
		fp := certutil.GetHexSHA256Fingerprint(*cert)
		if len(fp) < 32 || !strings.Contains(out, fp) {
			t.Fatalf("missing full fingerprint %s", fp)
		}
	}
}

func TestLongPrinterGolden(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	certs := lotsCerts(t)
	var buf bytes.Buffer
	if err := (longPrinter{now: goldenNow}).write(&buf, certs); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	compareGolden(t, longGoldenPath, out)

	if !strings.HasPrefix(out, "Certificate\n") {
		t.Fatalf("long dump should start with Certificate:\n%s", out)
	}
	if !strings.Contains(out, "  SHA256 Fingerprint: ") || !strings.Contains(out, "  Subject: ") {
		t.Fatalf("missing fingerprint or subject lines:\n%s", out)
	}
	withEmail, withIP, withPerm, withDNS, withCRL := 0, 0, 0, 0, 0
	for _, cert := range certs {
		if len(cert.EmailAddresses) > 0 {
			withEmail++
		}
		if len(cert.IPAddresses) > 0 {
			withIP++
		}
		if len(cert.PermittedDNSDomains) > 0 {
			withPerm++
		}
		if len(cert.DNSNames) > 0 {
			withDNS++
		}
		if len(cert.CRLDistributionPoints) > 0 {
			withCRL++
		}
	}
	if withEmail >= len(certs) || withIP >= len(certs) {
		t.Fatal("lots.crt has no certificate with an empty optional field")
	}
	checks := []struct {
		label string
		want  int
	}{
		{"EmailAddresses:", withEmail},
		{"IPAddresses:", withIP},
		{"PermittedDNSDomains:", withPerm},
		{"DNSNames:", withDNS},
		{"CRLDistributionPoints:", withCRL},
	}
	for _, check := range checks {
		if got := strings.Count(out, "\n  "+check.label+"\n"); got != check.want {
			t.Errorf("%s sections=%d want %d (empty fields must stay hidden)", check.label, got, check.want)
		}
	}
}

func TestTruncateColumn(t *testing.T) {
	if got := truncateColumn("short", 40); got != "short" {
		t.Errorf("got %q", got)
	}
	long := strings.Repeat("a", 50)
	got := truncateColumn(long, 40)
	if utf8.RuneCountInString(got) != 40 || !strings.HasSuffix(got, "…") {
		t.Errorf("got %q", got)
	}
}

func TestFormatTableDays(t *testing.T) {
	cases := []struct {
		days int
		want string
	}{
		{-100, "expired"},
		{-1, "expired"},
		{0, "0!"},
		{1, "1!"},
		{42, "42!"},
		{89, "89!"},
		{90, "90"},
		{91, "91"},
		{1811, "1811"},
	}
	for _, tc := range cases {
		if got := formatTableDays(tc.days); got != tc.want {
			t.Errorf("formatTableDays(%d)=%q want %q", tc.days, got, tc.want)
		}
	}
}

func mustTestCertWithExpiry(t *testing.T, subject string, notAfter time.Time) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: subject},
		NotBefore:    notAfter.Add(-365 * 24 * time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageCertSign,
		IsCA:         true,
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

func TestTablePrinterDaysMarkers(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	certs := []*x509.Certificate{
		mustTestCertWithExpiry(t, "Expired Root", now.Add(-48*time.Hour)),
		mustTestCertWithExpiry(t, "Soon Root", now.Add(42*24*time.Hour)),
		mustTestCertWithExpiry(t, "Far Root", now.Add(200*24*time.Hour)),
		mustTestCertWithExpiry(t, "Boundary Soon", now.Add(89*24*time.Hour)),
		mustTestCertWithExpiry(t, "Boundary OK", now.Add(90*24*time.Hour)),
	}

	var buf bytes.Buffer
	if err := (tablePrinter{now: now}).write(&buf, certs); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) < 6 {
		t.Fatalf("expected header + 5 rows:\n%s", out)
	}
	// Find DAYS column by splitting on runs of spaces after tabwriter
	wantSubstr := map[string]string{
		"Expired Root":  "expired",
		"Soon Root":     "42!",
		"Far Root":      "200",
		"Boundary Soon": "89!",
		"Boundary OK":   "90",
	}
	for _, line := range lines[1:] {
		matched := false
		for subj, days := range wantSubstr {
			if strings.Contains(line, subj) {
				matched = true
				fields := strings.Fields(line)
				// SUBJECT may be multi-token; DAYS is immediately before fingerprint (hex)
				// Layout: SUBJECT ... ISSUER KEY DAYS FINGERPRINT
				// With self-signed ISSUER is "=".
				if len(fields) < 5 {
					t.Fatalf("short line: %q", line)
				}
				gotDays := fields[len(fields)-2]
				if gotDays != days {
					t.Errorf("%s: DAYS=%q want %q\nline=%q", subj, gotDays, days, line)
				}
				delete(wantSubstr, subj)
				break
			}
		}
		if !matched {
			t.Errorf("unexpected line: %q", line)
		}
	}
	if len(wantSubstr) != 0 {
		t.Fatalf("missing rows: %v\n%s", wantSubstr, out)
	}

	// Verbose keeps numeric days (including negative), no "expired" / "!" markers.
	buf.Reset()
	if err := (tablePrinter{now: now, verbose: true}).write(&buf, certs); err != nil {
		t.Fatal(err)
	}
	vout := buf.String()
	if strings.Contains(vout, "expired") || strings.Contains(vout, "42!") {
		t.Fatalf("verbose table should keep numeric days:\n%s", vout)
	}
	if !strings.Contains(vout, "SHA256-FINGERPRINT") || !strings.Contains(vout, "NOT-BEFORE") || !strings.Contains(vout, "NOT-AFTER") || !strings.Contains(vout, "SERIAL") || !strings.Contains(vout, "PATH") {
		t.Fatalf("verbose headers:\n%s", vout)
	}
	if strings.Contains(vout, "SHA256 FINGERPRINT") || strings.Contains(vout, "NOT BEFORE") || strings.Contains(vout, "NOT AFTER") {
		t.Fatalf("old verbose headers still present:\n%s", vout)
	}
	if !strings.Contains(vout, "\t-2\t") && !strings.Contains(vout, " -2 ") {
		// tabwriter may use spaces; look for the expired cert's day count
		found := false
		for _, line := range strings.Split(vout, "\n") {
			if strings.Contains(line, "Expired Root") && strings.Contains(line, "-2") {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("verbose missing numeric -2 for expired:\n%s", vout)
		}
	}
}

func TestJSONCertDaysAndExpired(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	certs := []*x509.Certificate{
		mustTestCertWithExpiry(t, "Expired Root", now.Add(-24*time.Hour)),
		mustTestCertWithExpiry(t, "Soon Root", now.Add(10*24*time.Hour)),
		mustTestCertWithExpiry(t, "Far Root", now.Add(120*24*time.Hour)),
	}
	var buf bytes.Buffer
	cfg := &Config{Format: "json", SourcePath: "test"}
	p := jsonPrinter{meta: Meta{Name: "file"}, cfg: cfg, now: now}
	if err := p.write(&buf, certs); err != nil {
		t.Fatal(err)
	}
	var rows []jsonCert
	if err := json.Unmarshal(buf.Bytes(), &rows); err != nil {
		t.Fatalf("json: %v\n%s", err, buf.Bytes())
	}
	if len(rows) != 3 {
		t.Fatalf("got %d rows", len(rows))
	}
	bySubj := map[string]jsonCert{}
	for _, r := range rows {
		bySubj[r.Subject] = r
	}
	ex := bySubj["Expired Root"]
	if ex.Days >= 0 || !ex.Expired {
		t.Fatalf("expired row: days=%d expired=%v", ex.Days, ex.Expired)
	}
	soon := bySubj["Soon Root"]
	if soon.Days != 10 || soon.Expired {
		t.Fatalf("soon row: days=%d expired=%v", soon.Days, soon.Expired)
	}
	far := bySubj["Far Root"]
	if far.Days != 120 || far.Expired {
		t.Fatalf("far row: days=%d expired=%v", far.Days, far.Expired)
	}
}
