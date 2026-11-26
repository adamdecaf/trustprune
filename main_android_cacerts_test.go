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
	if strings.Contains(out, keepFP) {
		t.Fatalf("kept fingerprint was listed as disabled:\n%s", out)
	}
	if !strings.Contains(out, dropFP) {
		t.Fatalf("disabled fingerprint missing:\n%s", out)
	}
	if !strings.Contains(out, "Android Disable Root") {
		t.Fatalf("disabled subject missing:\n%s", out)
	}
	if !strings.Contains(out, "Settings > Security > Encryption & credentials > Trusted credentials") {
		t.Fatalf("Settings steps missing:\n%s", out)
	}
	if !strings.Contains(out, "adb pull") || !strings.Contains(out, "rooted") {
		t.Fatalf("adb steps missing:\n%s", out)
	}
	if !strings.Contains(out, "cannot change an Android device") {
		t.Fatalf("guide-only notice missing:\n%s", out)
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
		name      string
		extra     []string
		wantUsage string
		outFile   bool
	}{
		{name: "out", extra: []string{"--out", filepath.Join(t.TempDir(), "report.txt")}, outFile: true},
		{name: "count", extra: []string{"--count"}, wantUsage: "list --app android does not support --count"},
		{name: "format", extra: []string{"--format", "json"}, wantUsage: "list --app android does not support --format"},
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
			if strings.Contains(got, keepFP) {
				t.Fatalf("kept fingerprint was listed as disabled:\n%s", got)
			}
			if !strings.Contains(got, dropFP) {
				t.Fatalf("disabled fingerprint missing:\n%s", got)
			}
			if !strings.Contains(got, "Settings > Security > Encryption & credentials > Trusted credentials") {
				t.Fatalf("Settings steps missing:\n%s", got)
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

func TestMutatingCommandsRejectAppAndroid(t *testing.T) {
	bin := cliBinary(t)
	home := t.TempDir()
	keep := mintListAndroidCA(t, "Android Keep Root", 1)
	alPath := filepath.Join(t.TempDir(), "allowlist.yaml")
	if err := (allowlist.Allowlist{Fingerprints: []string{certutil.GetHexSHA256Fingerprint(*keep)}}).ToFile(alPath); err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(t.TempDir(), "keep.pem")
	writeListAndroidPEM(t, filepath.Dir(certPath), filepath.Base(certPath), keep)

	cases := [][]string{
		{"allowlist", "--app", "android", "--file", alPath, "--dry-run"},
		{"add", "--app", "android", "--file", certPath, "--dry-run"},
		{"backup", "--app", "android", "--dry-run"},
		{"restore", "--app", "android", "--dry-run"},
	}
	for _, args := range cases {
		t.Run(args[0], func(t *testing.T) {
			res := runCLI(t, bin, home, args...)
			if res.code == 0 {
				t.Fatalf("code=0 stdout=%s stderr=%s", res.stdout, res.stderr)
			}
			out := res.stdout + res.stderr
			if !strings.Contains(out, "unknown app android") {
				t.Fatalf("want unknown app android, got code=%d\nstdout=%s\nstderr=%s", res.code, res.stdout, res.stderr)
			}
		})
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
