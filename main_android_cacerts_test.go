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

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/adamdecaf/trustprune/pkg/allowlist"
	"github.com/adamdecaf/trustprune/pkg/certutil"
)

func TestListFileAndroidCacertsDir(t *testing.T) {
	bin := cliBinary(t)
	home := t.TempDir()
	dir := t.TempDir()

	a := mintListAndroidCA(t, "Android List Root A", 1)
	b := mintListAndroidCA(t, "Android List Root B", 2)
	writeListAndroidPEM(t, dir, "aaaaaaaa.0", a)
	writeListAndroidPEM(t, dir, "bbbbbbbb.0", b)
	if err := os.WriteFile(filepath.Join(dir, "README"), []byte("ignore\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	fpA := certutil.GetHexSHA256Fingerprint(*a)
	fpB := certutil.GetHexSHA256Fingerprint(*b)

	count := runCLI(t, bin, home, "list", "--file", dir, "--count")
	if count.code != 0 {
		t.Fatalf("count: code=%d\nstdout=%s\nstderr=%s", count.code, count.stdout, count.stderr)
	}
	if strings.TrimSpace(count.stdout) != "2" {
		t.Fatalf("count = %q, want 2", count.stdout)
	}

	for _, format := range []string{"table", "json", "long"} {
		res := runCLI(t, bin, home, "list", "--file", dir, "--format", format)
		if res.code != 0 {
			t.Fatalf("%s: code=%d\nstdout=%s\nstderr=%s", format, res.code, res.stdout, res.stderr)
		}
		wantA, wantB := fpA, fpB
		if format == "table" {
			wantA, wantB = fpA[:16], fpB[:16]
		}
		if !strings.Contains(res.stdout, wantA) {
			t.Fatalf("%s output missing fingerprint %s\n%s", format, wantA, res.stdout)
		}
		if !strings.Contains(res.stdout, wantB) {
			t.Fatalf("%s output missing fingerprint %s\n%s", format, wantB, res.stdout)
		}
	}

	empty := runCLI(t, bin, home, "list", "--file", t.TempDir())
	if empty.code == 0 {
		t.Fatalf("empty dir: code=0 stdout=%s", empty.stdout)
	}
}

func TestListAppAndroidGuide(t *testing.T) {
	bin := cliBinary(t)
	home := t.TempDir()
	dir := t.TempDir()
	keep := mintListAndroidCA(t, "Android Keep Root", 1)
	drop := mintListAndroidCA(t, "Android Disable Root", 2)
	writeListAndroidPEM(t, dir, "aaaaaaaa.0", keep)
	writeListAndroidPEM(t, dir, "bbbbbbbb.0", drop)
	// #nosec G304 -- temp cacerts file under t.TempDir
	keepBytes, err := os.ReadFile(filepath.Join(dir, "aaaaaaaa.0"))
	if err != nil {
		t.Fatal(err)
	}
	// #nosec G304 -- temp cacerts file under t.TempDir
	dropBytes, err := os.ReadFile(filepath.Join(dir, "bbbbbbbb.0"))
	if err != nil {
		t.Fatal(err)
	}

	keepFP := certutil.GetHexSHA256Fingerprint(*keep)
	dropFP := certutil.GetHexSHA256Fingerprint(*drop)
	alPath := filepath.Join(t.TempDir(), "allowlist.yaml")
	if err := (allowlist.Allowlist{Fingerprints: []string{keepFP}}).ToFile(alPath); err != nil {
		t.Fatal(err)
	}

	res := runCLI(t, bin, home, "list", "--app", "android", "--file", dir, "--allowlist", alPath)
	if res.code != 0 {
		t.Fatalf("code=%d\nstdout=%s\nstderr=%s", res.code, res.stdout, res.stderr)
	}
	out := res.stdout
	if strings.Contains(out, keepFP) || strings.Contains(out, keepFP[:16]) {
		t.Fatalf("kept fingerprint was listed as disabled:\n%s", out)
	}
	if !strings.Contains(out, dropFP[:16]) {
		t.Fatalf("disabled fingerprint preview missing:\n%s", out)
	}
	if strings.Contains(out, dropFP) {
		t.Fatalf("full fingerprint in default table:\n%s", out)
	}
	if !strings.Contains(out, "Android Disable Root") {
		t.Fatalf("disabled subject missing:\n%s", out)
	}
	if !strings.Contains(out, "SUBJECT") || !strings.Contains(out, "REASON") || !strings.Contains(out, "LABELS") {
		t.Fatalf("missing table headers:\n%s", out)
	}
	if !strings.Contains(out, "1 to disable of 2") {
		t.Fatalf("missing footer:\n%s", out)
	}
	if strings.Contains(out, "Settings > Security") || strings.Contains(out, "adb pull") || strings.Contains(out, "cannot change an Android device") {
		t.Fatalf("guide text printed without -v:\n%s", out)
	}

	verbose := runCLI(t, bin, home, "list", "--app", "android", "--file", dir, "--allowlist", alPath, "-v")
	if verbose.code != 0 {
		t.Fatalf("verbose code=%d\nstdout=%s\nstderr=%s", verbose.code, verbose.stdout, verbose.stderr)
	}
	vout := verbose.stdout
	if !strings.Contains(vout, dropFP) {
		t.Fatalf("verbose missing full fingerprint:\n%s", vout)
	}
	if !strings.Contains(vout, "Settings > Security > Encryption & credentials > Trusted credentials") {
		t.Fatalf("Settings steps missing:\n%s", vout)
	}
	if !strings.Contains(vout, "adb pull") || !strings.Contains(vout, "rooted") {
		t.Fatalf("adb steps missing:\n%s", vout)
	}
	if !strings.Contains(vout, "cannot change an Android device") {
		t.Fatalf("guide-only notice missing:\n%s", vout)
	}

	// #nosec G304 -- temp cacerts file under t.TempDir
	gotKeep, err := os.ReadFile(filepath.Join(dir, "aaaaaaaa.0"))
	if err != nil {
		t.Fatal(err)
	}
	// #nosec G304 -- temp cacerts file under t.TempDir
	gotDrop, err := os.ReadFile(filepath.Join(dir, "bbbbbbbb.0"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotKeep, keepBytes) || !bytes.Equal(gotDrop, dropBytes) {
		t.Fatal("list --app android wrote to the cacerts directory")
	}
}

func TestListAppAndroidOutputFlags(t *testing.T) {
	bin := cliBinary(t)
	home := t.TempDir()
	dir := t.TempDir()
	keep := mintListAndroidCA(t, "Android Keep Root", 1)
	drop := mintListAndroidCA(t, "Android Disable Root", 2)
	writeListAndroidPEM(t, dir, "aaaaaaaa.0", keep)
	writeListAndroidPEM(t, dir, "bbbbbbbb.0", drop)
	keepFP := certutil.GetHexSHA256Fingerprint(*keep)
	dropFP := certutil.GetHexSHA256Fingerprint(*drop)
	alPath := filepath.Join(t.TempDir(), "allowlist.yaml")
	if err := (allowlist.Allowlist{Fingerprints: []string{keepFP}}).ToFile(alPath); err != nil {
		t.Fatal(err)
	}
	base := []string{"list", "--app", "android", "--file", dir, "--allowlist", alPath}

	tests := []struct {
		name          string
		extra         []string
		wantUsage     string
		outFile       bool
		wantCount     string
		wantCountJSON int
		wantJSON      bool
	}{
		{name: "out", extra: []string{"--out", filepath.Join(t.TempDir(), "report.txt")}, outFile: true},
		{name: "count", extra: []string{"--count"}, wantCount: "1\n"},
		{name: "json-count", extra: []string{"--count", "--format", "json"}, wantCountJSON: 1},
		{name: "json", extra: []string{"--format", "json"}, wantJSON: true},
		{name: "format-long", extra: []string{"--format", "long"}, wantUsage: "list --app android --format supports table and json"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			args := append(append([]string{}, base...), tc.extra...)
			res := runCLI(t, bin, home, args...)
			if tc.wantUsage != "" {
				assertUsageError(t, res, tc.wantUsage)
				return
			}
			if res.code != 0 {
				t.Fatalf("code=%d\nstdout=%s\nstderr=%s", res.code, res.stdout, res.stderr)
			}
			if tc.wantCount != "" {
				if res.stdout != tc.wantCount {
					t.Fatalf("count stdout=%q want %q", res.stdout, tc.wantCount)
				}
				return
			}
			if tc.wantCountJSON != 0 || (tc.name == "json-count") {
				var doc struct {
					Count int `json:"count"`
				}
				if err := json.Unmarshal([]byte(res.stdout), &doc); err != nil {
					t.Fatalf("count json: %v\n%s", err, res.stdout)
				}
				if doc.Count != 1 {
					t.Fatalf("count json=%d", doc.Count)
				}
				return
			}
			if tc.wantJSON {
				if !strings.Contains(res.stdout, `"to_disable"`) || !strings.Contains(res.stdout, `"total"`) {
					t.Fatalf("json missing counts:\n%s", res.stdout)
				}
				if !strings.Contains(res.stdout, dropFP) {
					t.Fatalf("json missing disabled fingerprint:\n%s", res.stdout)
				}
				if strings.Contains(res.stdout, keepFP) {
					t.Fatalf("json listed kept fingerprint:\n%s", res.stdout)
				}
				if strings.Contains(res.stdout, "Settings > Security") {
					t.Fatalf("json included guide text:\n%s", res.stdout)
				}
				return
			}
			if !tc.outFile {
				return
			}
			if res.stdout != "" {
				t.Fatalf("stdout=%q, want empty when --out is set", res.stdout)
			}
			outPath := tc.extra[1]
			// #nosec G304 -- temp report path under t.TempDir
			body, err := os.ReadFile(outPath)
			if err != nil {
				t.Fatal(err)
			}
			got := string(body)
			if strings.Contains(got, keepFP) || strings.Contains(got, keepFP[:16]) {
				t.Fatalf("kept fingerprint was listed as disabled:\n%s", got)
			}
			if !strings.Contains(got, dropFP[:16]) {
				t.Fatalf("disabled fingerprint missing:\n%s", got)
			}
			if !strings.Contains(got, "1 to disable of 2") {
				t.Fatalf("footer missing:\n%s", got)
			}
			if strings.Contains(got, "Settings > Security") {
				t.Fatalf("guide text written to --out without -v:\n%s", got)
			}
		})
	}
}

func TestListAppAndroidRequiresAllowlist(t *testing.T) {
	bin := cliBinary(t)
	home := t.TempDir()
	dir := t.TempDir()
	writeListAndroidPEM(t, dir, "aaaaaaaa.0", mintListAndroidCA(t, "Android Keep Root", 1))
	res := runCLI(t, bin, home, "list", "--app", "android", "--file", dir)
	assertUsageError(t, res, "list --app android requires --allowlist")
}

func TestAppsShowsAndroidGuideOnly(t *testing.T) {
	bin := cliBinary(t)
	home := t.TempDir()
	res := runCLI(t, bin, home, "apps")
	if res.code != 0 {
		t.Fatalf("code=%d stdout=%s stderr=%s", res.code, res.stdout, res.stderr)
	}
	found := false
	for _, line := range strings.Split(res.stdout, "\n") {
		if strings.Contains(line, "android") && strings.Contains(line, "guide only") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("apps missing android guide-only row:\n%s", res.stdout)
	}

	res = runCLI(t, bin, home, "apps", "--format", "json")
	if res.code != 0 {
		t.Fatalf("json code=%d stdout=%s stderr=%s", res.code, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stdout, `"name": "android"`) || !strings.Contains(res.stdout, `"guideOnly": true`) {
		t.Fatalf("apps json missing android guideOnly:\n%s", res.stdout)
	}
}

func TestMutatingCommandsAppAndroidGuideOnly(t *testing.T) {
	bin := cliBinary(t)
	keep := mintListAndroidCA(t, "Android Keep Root", 1)
	alPath := filepath.Join(t.TempDir(), "allowlist.yaml")
	if err := (allowlist.Allowlist{Fingerprints: []string{certutil.GetHexSHA256Fingerprint(*keep)}}).ToFile(alPath); err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(t.TempDir(), "keep.pem")
	writeListAndroidPEM(t, filepath.Dir(certPath), filepath.Base(certPath), keep)

	type mutCase struct {
		name string
		args func(home, out string) []string
	}
	cases := []mutCase{
		{"allowlist", func(home, out string) []string {
			return []string{"allowlist", "--app", "android", "--file", alPath, "--dry-run"}
		}},
		{"add", func(home, out string) []string {
			return []string{"add", "--app", "android", "--file", certPath, "--dry-run"}
		}},
		{"backup", func(home, out string) []string {
			return []string{"backup", "--app", "android", "--dry-run"}
		}},
		{"restore", func(home, out string) []string {
			return []string{"restore", "--app", "android", "--dry-run"}
		}},
		{"create", func(home, out string) []string {
			return []string{"create", "--app", "android", "--file", alPath, "--out", out}
		}},
	}
	phrases := []string{
		"guide only",
		"cannot change an Android device",
		"Settings > Security > Encryption & credentials > Trusted credentials",
		"adb pull",
		"/system/etc/security/cacerts",
		"/apex/com.android.conscrypt/cacerts",
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			out := filepath.Join(home, "created.pem")
			res := runCLI(t, bin, home, tc.args(home, out)...)
			if res.code != 1 {
				t.Fatalf("code=%d stdout=%s stderr=%s", res.code, res.stdout, res.stderr)
			}
			if !strings.HasPrefix(strings.TrimSpace(res.stdout), "ERROR:") {
				t.Fatalf("want ERROR: on stdout, got stdout=%s stderr=%s", res.stdout, res.stderr)
			}
			if strings.Contains(res.stdout, "unknown app") || strings.Contains(res.stderr, "unknown app") {
				t.Fatalf("treated android as unknown: stdout=%s stderr=%s", res.stdout, res.stderr)
			}
			for _, phrase := range phrases {
				if !strings.Contains(res.stdout, phrase) {
					t.Errorf("stdout missing %q\nstdout=%s", phrase, res.stdout)
				}
			}
			if _, err := os.Stat(out); err == nil {
				t.Fatalf("create wrote %s", out)
			}
			entries, err := os.ReadDir(home)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatalf("command wrote into HOME: %v", entries)
			}
		})
		t.Run(tc.name+"-store", func(t *testing.T) {
			home := t.TempDir()
			out := filepath.Join(home, "created.pem")
			args := append(tc.args(home, out), "--store", filepath.Join(home, "override"))
			res := runCLI(t, bin, home, args...)
			assertUsageError(t, res, "--store with --app android")
			if _, err := os.Stat(out); err == nil {
				t.Fatalf("create wrote %s under --store", out)
			}
			entries, err := os.ReadDir(home)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatalf("--store rejection wrote into HOME: %v", entries)
			}
		})
	}
}

func TestListAppAndroidGuideRanking(t *testing.T) {
	bin := cliBinary(t)
	home := t.TempDir()
	dir := t.TempDir()
	now := time.Now()
	keep := mintListAndroidCAAt(t, "Keep Root", 1, now.Add(24*time.Hour))
	user := mintListAndroidCAAt(t, "Zzz User", 2, now.Add(365*24*time.Hour))
	expired := mintListAndroidCAAt(t, "Aaa Expired", 3, now.Add(-24*time.Hour))
	later := mintListAndroidCAAt(t, "Mmm Later", 4, now.Add(200*24*time.Hour))
	writeListAndroidPEM(t, dir, "cccccccc.0", keep)
	writeListAndroidPEM(t, dir, "aaaaaaaa.0", expired)
	writeListAndroidPEM(t, dir, "bbbbbbbb.0", later)
	writeListAndroidPEM(t, dir, "user.crt", user)

	keepFP := certutil.GetHexSHA256Fingerprint(*keep)
	userFP := certutil.GetHexSHA256Fingerprint(*user)
	expiredFP := certutil.GetHexSHA256Fingerprint(*expired)
	laterFP := certutil.GetHexSHA256Fingerprint(*later)
	alPath := filepath.Join(t.TempDir(), "allowlist.yaml")
	if err := (allowlist.Allowlist{Fingerprints: []string{keepFP}}).ToFile(alPath); err != nil {
		t.Fatal(err)
	}

	res := runCLI(t, bin, home, "list", "--app", "android", "--file", dir, "--allowlist", alPath)
	if res.code != 0 {
		t.Fatalf("code=%d\nstdout=%s\nstderr=%s", res.code, res.stdout, res.stderr)
	}
	out := res.stdout
	if strings.Contains(out, keepFP) {
		t.Fatalf("kept fingerprint was listed as disabled:\n%s", out)
	}
	userAt := strings.Index(out, userFP[:16])
	expiredAt := strings.Index(out, expiredFP[:16])
	laterAt := strings.Index(out, laterFP[:16])
	if userAt < 0 || expiredAt < 0 || laterAt < 0 {
		t.Fatalf("missing fingerprints:\n%s", out)
	}
	if userAt >= expiredAt || expiredAt >= laterAt {
		t.Fatalf("order user=%d expired=%d later=%d\n%s", userAt, expiredAt, laterAt, out)
	}
	if !strings.Contains(out, "not in the allowlist (user CA)") {
		t.Fatalf("missing user CA reason:\n%s", out)
	}
	if !strings.Contains(out, "not in the allowlist (expired)") {
		t.Fatalf("missing expired reason:\n%s", out)
	}
	if !strings.Contains(out, "3 to disable of 4") {
		t.Fatalf("missing footer:\n%s", out)
	}
	if strings.Contains(out, "Settings > Security") {
		t.Fatalf("guide text printed without -v:\n%s", out)
	}
}

func mintListAndroidCA(t *testing.T, cn string, serial int64) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"trustprune test"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
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

func mintListAndroidCAAt(t *testing.T, cn string, serial int64, notAfter time.Time) *x509.Certificate {
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

func writeListAndroidPEM(t *testing.T, dir, name string, cert *x509.Certificate) {

	t.Helper()
	var buf bytes.Buffer
	if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(&buf, "Certificate:\n    Subject: CN=%s\n", cert.Subject.CommonName)
	if err := os.WriteFile(filepath.Join(dir, name), buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}
