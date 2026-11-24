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
	"fmt"
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

func TestLongPrinterTimestampsRFC3339UTC(t *testing.T) {
	east := time.FixedZone("EAST", 9*60*60)
	// 18:37:37 in EAST (+09:00) is 09:37:37 UTC.
	notBefore := time.Date(2011, 5, 5, 18, 37, 37, 0, east)
	notAfter := time.Date(2030, 12, 31, 18, 37, 37, 0, east)
	cert := mustTestCertWithExpiry(t, "Example", time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
	cert.NotBefore = notBefore
	cert.NotAfter = notAfter

	var buf bytes.Buffer
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := (longPrinter{now: now}).write(&buf, []*x509.Certificate{cert}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	const want = "  NotBefore: 2011-05-05T09:37:37Z | NotAfter: 2030-12-31T09:37:37Z\n"
	if !strings.Contains(out, want) {
		t.Fatalf("long timestamps:\n%s\nwant line %s", out, want)
	}
	if strings.Contains(out, "+0000") || strings.Contains(out, " UTC") || strings.Contains(out, "EAST") {
		t.Fatalf("default time.Time string still present:\n%s", out)
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
	if lines[0] != "PATH: testdata/lots.crt" {
		t.Fatalf("shared path line: %q", lines[0])
	}
	header := lines[1]
	for _, name := range []string{"SUBJECT", "ISSUER", "KEY", "DAYS", "SHA256-FINGERPRINT", "SERIAL", "NOT-BEFORE", "NOT-AFTER"} {
		if !strings.Contains(header, name) {
			t.Errorf("header missing %s: %q", name, header)
		}
	}
	if strings.Contains(header, "PATH") {
		t.Fatalf("shared path kept the PATH column: %q", header)
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
	if strings.Contains(out, "+0000 UTC") {
		t.Fatalf("long format still uses time.Time.String():\n%s", out)
	}
	for _, cert := range certs {
		line := fmt.Sprintf("  NotBefore: %s | NotAfter: %s\n",
			cert.NotBefore.UTC().Format(time.RFC3339),
			cert.NotAfter.UTC().Format(time.RFC3339))
		if !strings.Contains(out, line) {
			t.Errorf("missing RFC3339 UTC validity line %q\n%s", strings.TrimRight(line, "\n"), out)
		}
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
	// Find DAYS column by splitting on whitespace. Columns are separated by
	// two spaces; Fields collapses that padding.
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
	vlines := strings.Split(strings.TrimRight(vout, "\n"), "\n")
	if len(vlines) < 2 || vlines[0] != "PATH: -" {
		t.Fatalf("shared empty path line:\n%s", vout)
	}
	vheader := vlines[1]
	if strings.Contains(vheader, "PATH") {
		t.Fatalf("shared path kept the PATH column:\n%s", vout)
	}
	if !strings.Contains(vheader, "SHA256-FINGERPRINT") || !strings.Contains(vheader, "NOT-BEFORE") || !strings.Contains(vheader, "NOT-AFTER") || !strings.Contains(vheader, "SERIAL") {
		t.Fatalf("verbose headers:\n%s", vout)
	}
	if strings.Contains(vout, "SHA256 FINGERPRINT") || strings.Contains(vout, "NOT BEFORE") || strings.Contains(vout, "NOT AFTER") {
		t.Fatalf("old verbose headers still present:\n%s", vout)
	}
	found := false
	for _, line := range vlines {
		if strings.Contains(line, "Expired Root") && strings.Contains(line, "-2") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("verbose missing numeric -2 for expired:\n%s", vout)
	}
}

func TestTableColumnWidthsMatchContent(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	certs := []*x509.Certificate{
		mustTestCertWithExpiry(t, "Ab", now.Add(10*24*time.Hour)),
		mustTestCertWithExpiry(t, "Wider Subject", now.Add(200*24*time.Hour)),
		mustTestCertWithExpiry(t, "Expired Root", now.Add(-48*time.Hour)),
	}

	var buf bytes.Buffer
	if err := (tablePrinter{now: now}).write(&buf, certs); err != nil {
		t.Fatal(err)
	}
	headers := []string{"SUBJECT", "ISSUER", "KEY", "DAYS", "SHA256-FINGERPRINT"}
	rows := expectedTableRows(certs, now, false, nil)
	assertContentColumnWidths(t, buf.String(), headers, rows)

	// DAYS is "expired" (7), wider than the header and not a fixed 8.
	// SHA256-FINGERPRINT (19) is wider than the 16-character preview.
	daysWidth := utf8.RuneCountInString("expired")
	fpWidth := utf8.RuneCountInString("SHA256-FINGERPRINT")
	if got := contentWidth(headers, rows, 3); got != daysWidth {
		t.Fatalf("DAYS width=%d want %d", got, daysWidth)
	}
	if got := contentWidth(headers, rows, 4); got != fpWidth {
		t.Fatalf("fingerprint width=%d want %d", got, fpWidth)
	}
}

func TestVerboseTablePathColumn(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	certs := []*x509.Certificate{
		mustTestCertWithExpiry(t, "Alpha", now.Add(100*24*time.Hour)),
		mustTestCertWithExpiry(t, "Beta", now.Add(120*24*time.Hour)),
	}

	t.Run("shared path", func(t *testing.T) {
		var buf bytes.Buffer
		p := tablePrinter{verbose: true, paths: []string{"stores/one.pem", "stores/one.pem"}, now: now}
		if err := p.write(&buf, certs); err != nil {
			t.Fatal(err)
		}
		out := buf.String()
		lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
		if len(lines) < 2 || lines[0] != "PATH: stores/one.pem" {
			t.Fatalf("shared path line:\n%s", out)
		}
		if strings.Contains(lines[1], "PATH") {
			t.Fatalf("PATH column kept for one path:\n%s", out)
		}
		for _, line := range lines[1:] {
			if strings.Contains(line, "stores/one.pem") {
				t.Fatalf("path repeated in the table:\n%s", out)
			}
		}
		headers := []string{"SUBJECT", "ISSUER", "KEY", "DAYS", "SHA256-FINGERPRINT", "SERIAL", "NOT-BEFORE", "NOT-AFTER"}
		rows := expectedTableRows(certs, now, true, []string{"stores/one.pem", "stores/one.pem"})
		rows = dropPathCells(rows)
		assertContentColumnWidths(t, strings.Join(lines[1:], "\n")+"\n", headers, rows)
		// SERIAL is the header (6), not a fixed 48. DAYS is the header (4), not 8.
		if got := contentWidth(headers, rows, 3); got != len("DAYS") {
			t.Fatalf("verbose DAYS width=%d want %d", got, len("DAYS"))
		}
		if got := contentWidth(headers, rows, 5); got != len("SERIAL") {
			t.Fatalf("SERIAL width=%d want %d", got, len("SERIAL"))
		}
	})

	t.Run("mixed paths", func(t *testing.T) {
		var buf bytes.Buffer
		paths := []string{"a.pem", "b.pem"}
		p := tablePrinter{verbose: true, paths: paths, now: now}
		if err := p.write(&buf, certs); err != nil {
			t.Fatal(err)
		}
		out := buf.String()
		if strings.HasPrefix(out, "PATH:") {
			t.Fatalf("mixed paths were hoisted:\n%s", out)
		}
		lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
		if !strings.Contains(lines[0], "PATH") {
			t.Fatalf("mixed paths dropped PATH:\n%s", out)
		}
		if !strings.Contains(out, "a.pem") || !strings.Contains(out, "b.pem") {
			t.Fatalf("missing path cells:\n%s", out)
		}
		headers := []string{"SUBJECT", "ISSUER", "KEY", "DAYS", "SHA256-FINGERPRINT", "SERIAL", "PATH", "NOT-BEFORE", "NOT-AFTER"}
		rows := expectedTableRows(certs, now, true, paths)
		assertContentColumnWidths(t, out, headers, rows)
		if got := contentWidth(headers, rows, 5); got != len("SERIAL") {
			t.Fatalf("SERIAL width=%d want %d", got, len("SERIAL"))
		}
		if got := contentWidth(headers, rows, 6); got != len("a.pem") {
			t.Fatalf("PATH width=%d want %d", got, len("a.pem"))
		}
	})
}

func expectedTableRows(certs []*x509.Certificate, now time.Time, verbose bool, paths []string) [][]string {
	ordered := append([]*x509.Certificate(nil), certs...)
	var orderedPaths []string
	if paths != nil {
		orderedPaths = append([]string(nil), paths...)
	}
	orderCertsAndPaths(ordered, orderedPaths)

	rows := make([][]string, len(ordered))
	for i, cert := range ordered {
		fp := certutil.GetHexSHA256Fingerprint(*cert)
		subject := truncateColumn(certutil.StringifyPKIXName(cert.Subject), tableColumnWidth)
		issuer := "="
		if !bytes.Equal(cert.RawIssuer, cert.RawSubject) {
			issuer = truncateColumn(certutil.StringifyPKIXName(cert.Issuer), tableColumnWidth)
		}
		key := certutil.FormatKeyLabel(cert)
		daysLeft := certutil.DaysUntilExpiry(cert, now)
		days := formatTableDays(daysLeft)
		preview := fp[:fingerprintPreviewLength]
		if verbose {
			days = fmt.Sprintf("%d", daysLeft)
			preview = fp
		}
		rows[i] = []string{subject, issuer, key, days, preview}
		if verbose {
			path := "-"
			if i < len(orderedPaths) && orderedPaths[i] != "" {
				path = orderedPaths[i]
			}
			rows[i] = append(rows[i],
				cert.SerialNumber.String(),
				path,
				cert.NotBefore.Format("2006-01-02"),
				cert.NotAfter.Format("2006-01-02"),
			)
		}
	}
	return rows
}

func dropPathCells(rows [][]string) [][]string {
	out := make([][]string, len(rows))
	for i, row := range rows {
		// SUBJECT ISSUER KEY DAYS FP SERIAL PATH NOT-BEFORE NOT-AFTER
		next := append([]string{}, row[:6]...)
		next = append(next, row[7:]...)
		out[i] = next
	}
	return out
}

func contentWidth(headers []string, rows [][]string, col int) int {
	w := utf8.RuneCountInString(headers[col])
	for _, row := range rows {
		if n := utf8.RuneCountInString(row[col]); n > w {
			w = n
		}
	}
	return w
}

func assertContentColumnWidths(t *testing.T, out string, headers []string, rows [][]string) {
	t.Helper()
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if len(lines) != len(rows)+1 {
		t.Fatalf("got %d lines, want %d\n%s", len(lines), len(rows)+1, out)
	}
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = utf8.RuneCountInString(h)
	}
	for _, row := range rows {
		if len(row) != len(headers) {
			t.Fatalf("row has %d cells, headers %d: %q", len(row), len(headers), row)
		}
		for i, cell := range row {
			if n := utf8.RuneCountInString(cell); n > widths[i] {
				widths[i] = n
			}
		}
	}
	check := func(line string, cells []string) {
		t.Helper()
		rest := line
		for i, cell := range cells {
			if !strings.HasPrefix(rest, cell) {
				t.Fatalf("col %d %q: line %q rest %q", i, cell, line, rest)
			}
			rest = rest[len(cell):]
			if i == len(cells)-1 {
				if rest != "" {
					t.Fatalf("trailing %q on %q", rest, line)
				}
				return
			}
			gap := strings.Repeat(" ", widths[i]-utf8.RuneCountInString(cell)) + "  "
			if !strings.HasPrefix(rest, gap) {
				t.Fatalf("col %d gap %q want %q (width %d) line %q", i, rest, gap, widths[i], line)
			}
			rest = rest[len(gap):]
		}
	}
	check(lines[0], headers)
	for i, row := range rows {
		check(lines[i+1], row)
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

type listedCert struct {
	subject string
	fp      string
}

// TestListFormatsShareSubjectFingerprintOrder checks that table, json, and
// long print the same order: case-insensitive subject, then SHA-256 fingerprint.
// The shared-subject pair is chosen so DAYS order disagrees with the fingerprint,
// which is the order the old joined-cell table sort would have used.
func TestListFormatsShareSubjectFingerprintOrder(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	alpha := mustTestCertWithExpiry(t, "alpha", now.Add(300*24*time.Hour))
	beta := mustTestCertWithExpiry(t, "Beta", now.Add(300*24*time.Hour))
	zeta := mustTestCertWithExpiry(t, "zeta", now.Add(300*24*time.Hour))

	var sooner, later *x509.Certificate
	for attempt := 0; attempt < 30; attempt++ {
		a := mustTestCertWithExpiry(t, "Shared", now.Add(10*24*time.Hour))
		b := mustTestCertWithExpiry(t, "Shared", now.Add(200*24*time.Hour))
		fa := certutil.GetHexSHA256Fingerprint(*a)
		fb := certutil.GetHexSHA256Fingerprint(*b)
		// "10!" sorts before "200" in the old joined-cell comparison.
		// Keep the pair where the later certificate has the smaller fingerprint.
		if fb < fa {
			sooner, later = a, b
			break
		}
	}
	if sooner == nil || later == nil {
		t.Fatal("could not build a fingerprint tie that disagrees with DAYS order")
	}

	// Reverse of case-insensitive subject order. A byte-wise comparison
	// would place "Beta" before "alpha".
	certs := []*x509.Certificate{zeta, beta, later, alpha, sooner}
	want := []listedCert{
		{subject: "alpha", fp: certutil.GetHexSHA256Fingerprint(*alpha)},
		{subject: "Beta", fp: certutil.GetHexSHA256Fingerprint(*beta)},
		{subject: "Shared", fp: certutil.GetHexSHA256Fingerprint(*later)},
		{subject: "Shared", fp: certutil.GetHexSHA256Fingerprint(*sooner)},
		{subject: "zeta", fp: certutil.GetHexSHA256Fingerprint(*zeta)},
	}
	for i := 1; i < len(want); i++ {
		prev, cur := strings.ToLower(want[i-1].subject), strings.ToLower(want[i].subject)
		if prev > cur || (prev == cur && want[i-1].fp > want[i].fp) {
			t.Fatalf("fixture order: %+v", want)
		}
	}
	if want[2].fp[:fingerprintPreviewLength] == want[3].fp[:fingerprintPreviewLength] {
		t.Fatal("shared fingerprint previews collide")
	}

	for _, format := range []string{"table", "json", "long"} {
		t.Run(format, func(t *testing.T) {
			got := listFormatIDs(t, certs, format)
			if len(got) != len(want) {
				t.Fatalf("got %d certificates, want %d: %+v", len(got), len(want), got)
			}
			for i := range want {
				if got[i].subject != want[i].subject {
					t.Errorf("idx %d subject=%q want %q", i, got[i].subject, want[i].subject)
				}
				if format == "table" {
					if len(got[i].fp) != fingerprintPreviewLength || !strings.HasPrefix(want[i].fp, got[i].fp) {
						t.Errorf("idx %d fingerprint=%q want prefix of %s", i, got[i].fp, want[i].fp)
					}
					continue
				}
				if got[i].fp != want[i].fp {
					t.Errorf("idx %d fingerprint=%q want %s", i, got[i].fp, want[i].fp)
				}
			}
		})
	}
}

func TestTablePrinterSortKeepsPathsAligned(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	t.Run("case", func(t *testing.T) {
		zulu := mustTestCertWithExpiry(t, "Zulu", now.Add(100*24*time.Hour))
		alpha := mustTestCertWithExpiry(t, "alpha", now.Add(120*24*time.Hour))
		certs := []*x509.Certificate{zulu, alpha}
		paths := []string{"z.pem", "a.pem"}
		out := verboseTable(t, certs, paths, now)
		if strings.Index(out, "alpha") > strings.Index(out, "Zulu") {
			t.Fatalf("case-insensitive order:\n%s", out)
		}
		assertLineHas(t, out, "alpha", "a.pem")
		assertLineHas(t, out, "Zulu", "z.pem")
		if paths[0] != "a.pem" || paths[1] != "z.pem" {
			t.Fatalf("paths=%v", paths)
		}
	})

	t.Run("fingerprint", func(t *testing.T) {
		a := mustTestCertWithExpiry(t, "Shared", now.Add(100*24*time.Hour))
		b := mustTestCertWithExpiry(t, "Shared", now.Add(140*24*time.Hour))
		fa := certutil.GetHexSHA256Fingerprint(*a)
		fb := certutil.GetHexSHA256Fingerprint(*b)
		low, high := a, b
		lowPath, highPath := "low.pem", "high.pem"
		lowFP, highFP := fa, fb
		if fb < fa {
			low, high = b, a
			lowFP, highFP = fb, fa
		}
		certs := []*x509.Certificate{high, low}
		paths := []string{highPath, lowPath}
		out := verboseTable(t, certs, paths, now)
		if strings.Index(out, lowFP) > strings.Index(out, highFP) {
			t.Fatalf("fingerprint order:\n%s", out)
		}
		assertLineHas(t, out, lowFP, lowPath)
		assertLineHas(t, out, highFP, highPath)
		if paths[0] != lowPath || paths[1] != highPath {
			t.Fatalf("paths=%v", paths)
		}
	})
}

func TestListCountDoesNotReorder(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	zeta := mustTestCertWithExpiry(t, "zeta", now.Add(10*24*time.Hour))
	alpha := mustTestCertWithExpiry(t, "alpha", now.Add(10*24*time.Hour))
	certs := []*x509.Certificate{zeta, alpha}
	out, err := captureStdout(t, func() error {
		return ListCertificatesWithMeta(Meta{}, certs, &Config{Count: true, Format: "table", UI: DefaultUI()})
	})
	if err != nil {
		t.Fatal(err)
	}
	if out != "2\n" {
		t.Fatalf("count=%q", out)
	}
	if certs[0] != zeta || certs[1] != alpha {
		t.Fatal("count reordered certificates")
	}
}

func listFormatIDs(t *testing.T, certs []*x509.Certificate, format string) []listedCert {
	t.Helper()
	cp := append([]*x509.Certificate(nil), certs...)
	out, err := captureStdout(t, func() error {
		return ListCertificatesWithMeta(Meta{Name: "file"}, cp, &Config{
			Format:     format,
			UI:         DefaultUI(),
			SourcePath: "mem",
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	switch format {
	case "table":
		return tableIDs(t, out)
	case "json":
		return jsonIDs(t, out)
	case "long":
		return longIDs(t, out)
	default:
		t.Fatalf("unknown format %s", format)
		return nil
	}
}

func tableIDs(t *testing.T, out string) []listedCert {
	t.Helper()
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) < 2 || !strings.Contains(lines[0], "SUBJECT") {
		t.Fatalf("table:\n%s", out)
	}
	got := make([]listedCert, 0, len(lines)-1)
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			t.Fatalf("short row %q", line)
		}
		got = append(got, listedCert{subject: fields[0], fp: fields[len(fields)-1]})
	}
	return got
}

func jsonIDs(t *testing.T, out string) []listedCert {
	t.Helper()
	var rows []jsonCert
	if err := json.Unmarshal([]byte(out), &rows); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	got := make([]listedCert, len(rows))
	for i, row := range rows {
		got[i] = listedCert{subject: row.Subject, fp: row.SHA256}
	}
	return got
}

func longIDs(t *testing.T, out string) []listedCert {
	t.Helper()
	blocks := strings.Split(out, "Certificate\n")
	got := make([]listedCert, 0, len(blocks))
	for _, block := range blocks {
		if strings.TrimSpace(block) == "" {
			continue
		}
		var id listedCert
		for _, line := range strings.Split(block, "\n") {
			if rest, ok := strings.CutPrefix(line, "  SHA256 Fingerprint: "); ok {
				id.fp = rest
			}
			if rest, ok := strings.CutPrefix(line, "  Subject: "); ok {
				id.subject = rest
			}
		}
		if id.subject == "" || id.fp == "" {
			t.Fatalf("long block:\n%s", block)
		}
		got = append(got, id)
	}
	return got
}

func verboseTable(t *testing.T, certs []*x509.Certificate, paths []string, now time.Time) string {
	t.Helper()
	var buf bytes.Buffer
	p := tablePrinter{verbose: true, paths: paths, now: now}
	if err := p.write(&buf, certs); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func assertLineHas(t *testing.T, out, marker, path string) {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, marker) {
			if !strings.Contains(line, path) {
				t.Fatalf("line with %s missing %s:\n%s", marker, path, line)
			}
			return
		}
	}
	t.Fatalf("missing %s:\n%s", marker, out)
}
