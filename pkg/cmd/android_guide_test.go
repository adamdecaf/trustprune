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
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/adamdecaf/trustprune/pkg/allowlist"
	"github.com/adamdecaf/trustprune/pkg/certutil"
	"github.com/adamdecaf/trustprune/pkg/ui"
)

func TestRankAndroidDisableOrder(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	later := now.Add(365 * 24 * time.Hour)
	sooner := now.Add(30 * 24 * time.Hour)
	expired := now.Add(-24 * time.Hour)

	denylistCert := mintAndroidGuideCA(t, "Zzz Denylist", 1, later)
	chromiumCert := mintAndroidGuideCA(t, "Yyy Chromium", 2, later)
	mozillaCert := mintAndroidGuideCA(t, "Xxx Mozilla", 3, later)
	appleCert := mintAndroidGuideCA(t, "Www Apple", 4, later)
	ccadbCert := mintAndroidGuideCA(t, "Vvv CCADB", 5, later)
	userCert := mintAndroidGuideCA(t, "Uuu User", 6, later)
	expiredSys := mintAndroidGuideCA(t, "Aaa Expired System", 7, expired)
	soonSys := mintAndroidGuideCA(t, "Mmm Soon System", 8, sooner)
	laterSys := mintAndroidGuideCA(t, "Bbb Later System", 9, later)
	tieA := mintAndroidGuideCA(t, "Tie Root", 10, later)
	tieB := mintAndroidGuideCA(t, "Tie Root", 11, later)

	t.Cleanup(allowlist.AddDeniedForTest("fixture root", certutil.GetHexSHA256Fingerprint(*denylistCert), ""))
	t.Cleanup(allowlist.AddBlocklistedForTest("chromium", certutil.GetHexSHA256Fingerprint(*chromiumCert)))
	t.Cleanup(allowlist.AddBlocklistedForTest("mozilla", certutil.GetHexSHA256Fingerprint(*mozillaCert)))
	t.Cleanup(allowlist.AddBlocklistedForTest("apple", certutil.GetHexSHA256Fingerprint(*appleCert)))
	t.Cleanup(allowlist.AddBlocklistedForTest("ccadb", certutil.GetHexSHA256Fingerprint(*ccadbCert)))

	rows := []androidDisable{
		rankAndroidDisable(certutil.AndroidFile{Cert: laterSys, Path: "/tmp/cacerts/bbbbbbbb.0"}, now),
		rankAndroidDisable(certutil.AndroidFile{Cert: userCert, Path: "/tmp/user.crt"}, now),
		rankAndroidDisable(certutil.AndroidFile{Cert: ccadbCert, Path: "/tmp/cacerts/cccccc01.0"}, now),
		rankAndroidDisable(certutil.AndroidFile{Cert: expiredSys, Path: "/tmp/cacerts/aaaaaaaa.0"}, now),
		rankAndroidDisable(certutil.AndroidFile{Cert: appleCert, Path: "/tmp/cacerts/cccccc02.0"}, now),
		rankAndroidDisable(certutil.AndroidFile{Cert: soonSys, Path: "/tmp/cacerts/dddddddd.0"}, now),
		rankAndroidDisable(certutil.AndroidFile{Cert: mozillaCert, Path: "/tmp/cacerts/cccccc03.0"}, now),
		rankAndroidDisable(certutil.AndroidFile{Cert: chromiumCert, Path: "/tmp/cacerts/cccccc04.0"}, now),
		rankAndroidDisable(certutil.AndroidFile{Cert: denylistCert, Path: "/tmp/cacerts/cccccc05.0"}, now),
		rankAndroidDisable(certutil.AndroidFile{Cert: tieB, Path: "/tmp/cacerts/eeeeee02.0"}, now),
		rankAndroidDisable(certutil.AndroidFile{Cert: tieA, Path: "/tmp/cacerts/eeeeee01.0"}, now),
	}
	sortAndroidDisable(rows)

	want := []string{
		"Zzz Denylist",
		"Yyy Chromium",
		"Xxx Mozilla",
		"Www Apple",
		"Vvv CCADB",
		"Uuu User",
		"Aaa Expired System",
		"Mmm Soon System",
		"Bbb Later System",
	}
	// The two Tie Root certs come last among allowlist misses with the same
	// expiry, ordered by fingerprint.
	var got []string
	for _, row := range rows {
		got = append(got, row.file.Cert.Subject.CommonName)
	}
	if len(got) != 11 {
		t.Fatalf("got %d rows: %v", len(got), got)
	}
	for i, cn := range want {
		if got[i] != cn {
			t.Fatalf("rank %d: got %v, want prefix %v", i, got, want)
		}
	}
	if got[9] != "Tie Root" || got[10] != "Tie Root" {
		t.Fatalf("tie rows: %v", got[9:])
	}
	if !certutil.Less(rows[9].file.Cert, rows[10].file.Cert) {
		t.Fatalf("tie break is not subject-then-fingerprint: %s then %s",
			certutil.GetHexSHA256Fingerprint(*rows[9].file.Cert),
			certutil.GetHexSHA256Fingerprint(*rows[10].file.Cert))
	}

	wantReasons := map[string]string{
		"Zzz Denylist":       "built-in denylist (fixture root)",
		"Yyy Chromium":       allowlist.BlocklistChromium,
		"Xxx Mozilla":        allowlist.BlocklistMozilla,
		"Www Apple":          allowlist.BlocklistApple,
		"Vvv CCADB":          allowlist.BlocklistCCADB,
		"Uuu User":           "not in the allowlist (user CA)",
		"Aaa Expired System": "not in the allowlist (expired)",
		"Mmm Soon System":    "not in the allowlist",
		"Bbb Later System":   "not in the allowlist",
	}
	for _, row := range rows {
		cn := row.file.Cert.Subject.CommonName
		if want, ok := wantReasons[cn]; ok && row.reason != want {
			t.Errorf("%s reason=%q, want %q", cn, row.reason, want)
		}
	}
}

func TestRankAndroidDisableUserBeforeSystem(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	later := now.Add(365 * 24 * time.Hour)
	user := mintAndroidGuideCA(t, "Zzz User", 1, later)
	sys := mintAndroidGuideCA(t, "Aaa System", 2, later)
	rows := []androidDisable{
		rankAndroidDisable(certutil.AndroidFile{Cert: sys, Path: "/tmp/cacerts/aaaaaaaa.0"}, now),
		rankAndroidDisable(certutil.AndroidFile{Cert: user, Path: "/tmp/cacerts-added/aaaaaaaa.0"}, now),
	}
	sortAndroidDisable(rows)
	if rows[0].file.Cert.Subject.CommonName != "Zzz User" || rows[0].reason != "not in the allowlist (user CA)" {
		t.Fatalf("got %s %q", rows[0].file.Cert.Subject.CommonName, rows[0].reason)
	}
}

func TestWriteAndroidGuideIncludesReasons(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	cert := mintAndroidGuideCA(t, "Disable Root", 1, now.Add(24*time.Hour))
	row := rankAndroidDisable(certutil.AndroidFile{Cert: cert, Path: "/tmp/cacerts/aaaaaaaa.0"}, now)
	var buf bytes.Buffer
	if err := writeAndroidGuide(&buf, []androidDisable{row}, 1, now, false); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "SUBJECT") || !strings.Contains(out, "REASON") || !strings.Contains(out, "DAYS") || !strings.Contains(out, "SHA256-FINGERPRINT") || !strings.Contains(out, "LABELS") {
		t.Fatalf("missing table headers:\n%s", out)
	}
	fp := certutil.GetHexSHA256Fingerprint(*cert)
	if !strings.Contains(out, fp[:16]) {
		t.Fatalf("missing fingerprint preview:\n%s", out)
	}
	if strings.Contains(out, fp) {
		t.Fatalf("full fingerprint in non-verbose table:\n%s", out)
	}
	if !strings.Contains(out, "not in the allowlist") {
		t.Fatalf("missing reason:\n%s", out)
	}
	if !strings.Contains(out, "1 to disable of 1") {
		t.Fatalf("missing footer:\n%s", out)
	}
	if strings.Contains(out, "Settings > Security") || strings.Contains(out, "adb pull") {
		t.Fatalf("guide text printed without -v:\n%s", out)
	}

	buf.Reset()
	if err := writeAndroidGuide(&buf, []androidDisable{row}, 1, now, true); err != nil {
		t.Fatal(err)
	}
	verbose := buf.String()
	if !strings.Contains(verbose, fp) {
		t.Fatalf("verbose missing full fingerprint:\n%s", verbose)
	}
	if !strings.Contains(verbose, "Settings > Security > Encryption & credentials > Trusted credentials") {
		t.Fatalf("verbose missing steps:\n%s", verbose)
	}
	if !strings.Contains(verbose, "PATH") {
		t.Fatalf("verbose missing PATH:\n%s", verbose)
	}
}

func TestWriteAndroidGuideEmptyFooter(t *testing.T) {
	var buf bytes.Buffer
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	if err := writeAndroidGuide(&buf, nil, 5, now, false); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "SUBJECT") || !strings.Contains(out, "REASON") {
		t.Fatalf("missing headers:\n%s", out)
	}
	if !strings.Contains(out, "0 to disable of 5") {
		t.Fatalf("missing empty footer:\n%s", out)
	}
	if strings.Contains(out, "adb pull") {
		t.Fatalf("guide text without -v:\n%s", out)
	}
}

func TestAndroidGuideReasonIncludesMozillaDistrustAfter(t *testing.T) {
	now := time.Date(2026, 11, 27, 18, 0, 0, 0, time.UTC)
	certs := loadLotsCerts(t)
	var entrust *x509.Certificate
	for _, c := range certs {
		fp := certutil.GetHexSHA256Fingerprint(*c)
		if strings.HasPrefix(fp, "02ed0eb28c14da45") {
			entrust = c
			break
		}
	}
	if entrust == nil {
		t.Fatal("lots.crt missing Entrust Root CA EC1")
	}
	row := rankAndroidDisable(certutil.AndroidFile{Cert: entrust, Path: "/tmp/cacerts/02ed0eb2.0"}, now)
	if !strings.Contains(row.reason, allowlist.BlocklistMozilla) {
		t.Fatalf("reason=%q, want Mozilla blocklist", row.reason)
	}
	if !strings.Contains(row.reason, "distrust after 2024-11-30T23:59:59Z") {
		t.Fatalf("reason=%q, want recorded distrust-after", row.reason)
	}
	var buf bytes.Buffer
	if err := writeAndroidGuide(&buf, []androidDisable{row}, 1, now, false); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "distrusted,blocklist:mozilla") {
		t.Fatalf("missing LABELS:\n%s", out)
	}
	if !strings.Contains(out, "distrust after 2024-11-30T23:59:59Z") {
		t.Fatalf("missing distrust after in REASON:\n%s", out)
	}

	outFile := filepath.Join(t.TempDir(), "android.json")
	if err := writeAndroidGuideJSON(&ui.Config{Format: "json", Outfile: outFile}, []androidDisable{row}, 1, now); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatal(err)
	}
	var doc androidGuideJSON
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("json: %v\n%s", err, body)
	}
	if doc.ToDisable != 1 || doc.Total != 1 || len(doc.Certificates) != 1 {
		t.Fatalf("json counts: %+v", doc)
	}
	got := doc.Certificates[0]
	if got.DistrustAfter != "2024-11-30T23:59:59Z" {
		t.Errorf("distrust_after=%q", got.DistrustAfter)
	}
	if len(got.Blocklists) != 1 || got.Blocklists[0] != "mozilla" {
		t.Errorf("blocklists=%v", got.Blocklists)
	}
	wantLabels := []string{allowlist.ListLabelDistrusted, allowlist.ListBlocklistPrefix + "mozilla"}
	if !slices.Equal(got.Labels, wantLabels) {
		t.Errorf("labels=%v want %v", got.Labels, wantLabels)
	}
}

func loadLotsCerts(t *testing.T) []*x509.Certificate {
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

func mintAndroidGuideCA(t *testing.T, cn string, serial int64, notAfter time.Time) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"trustprune test"}},
		NotBefore:             notAfter.Add(-365 * 24 * time.Hour),
		NotAfter:              notAfter,
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
