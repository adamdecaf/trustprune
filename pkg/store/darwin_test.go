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

//go:build darwin
// +build darwin

package store

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/adamdecaf/trustprune/pkg/certutil"
)

func TestStoreDarwin__SystemCertPool(t *testing.T) {
	if !debug {
		t.Skip("skipping SystemCertPool() test")
	}

	pool, err := x509.SystemCertPool()
	if err != nil {
		t.Error(err)
	}
	fmt.Printf("%d from Go's SystemCertPool()\n", len(pool.Subjects()))
}

func TestStoreDarwin__Backup(t *testing.T) {
	t.Skip("darwin support is wip")

	dir, err := getCertManageDir(darwinBackupDir)
	if err != nil {
		t.Fatal(err)
	}
	namesBefore, err := os.ReadDir(dir)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}

	s := platform()
	err = s.Backup()
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}

	// check we added one backup file
	namesAfter, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(namesAfter)-len(namesBefore) != 1 {
		t.Errorf("before=%d, after=%d", len(namesBefore), len(namesAfter))
	}

	// make sure backup file is non-empty
	latest, err := getLatestBackup(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(latest)

	fi, err := os.Stat(latest)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() == 0 {
		t.Errorf("backup file %s is empty", latest)
	}
}

// There are various locations for certificates across OSX
// Mostly the Keychain groups the certificates (and trust policies)
// into a few groups
func TestStoreDarwin__locations(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("not on darwin based host")
	}

	paths := darwinKeychainPaths()

	count := 0

	for _, p := range paths {
		certs, err := readInstalledCerts(p)
		if err != nil {
			t.Errorf("%s - err=%v", p, err)
		}
		count += len(certs)

		if !debug {
			continue
		}

		// Debug info
		fmt.Printf("%d certs from %s\n", len(certs), p)
		out := make([]string, 0)
		for i := range certs {
			if certs[i].Subject.CommonName != "" {
				out = append(out, fmt.Sprintf("  Subject CN=%v", certs[i].Subject.CommonName))
				continue
			}
			if certs[i].Issuer.CommonName != "" {
				out = append(out, fmt.Sprintf("  Issuer CN=%v", certs[i].Issuer.CommonName))
				continue
			}
		}
		sort.Strings(out)
		fmt.Printf("%s\n", strings.Join(out, "\n"))
	}

	if count == 0 {
		t.Errorf("Didn't find any certs from all %d paths", len(paths))
	}
}

func TestParseDarwinTrustSettings(t *testing.T) {
	in := `Number of trusted certs = 2
Cert 0: Example Root
   Number of trust settings : 0
Cert 1: Denied CA
   Number of trust settings : 1
   Trust Setting 0:
      Policy OID            : SSL
      Result Type           : kSecTrustSettingsResultDeny
`
	ts := darwinTrustSettings{}
	parseDarwinTrustSettings(in, &ts)
	if !ts.isTrusted("Example Root") {
		t.Fatal("Example Root should be trusted")
	}
	if !ts.isDenied("Denied CA") {
		t.Fatal("Denied CA should be denied")
	}
	if ts.isTrusted("Denied CA") {
		t.Fatal("Denied CA must not be trusted")
	}
}

func TestStoreDarwin__List(t *testing.T) {
	certs, err := platform().List(&ListOptions{Trusted: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) <= 10 {
		t.Errorf("expected more than 10 trusted platform certs, got %d", len(certs))
	}
}

func TestStoreDarwin__info(t *testing.T) {
	st := darwinStore{}
	info := st.GetInfo()
	if info == nil {
		t.Fatal("nil Info")
	}
	if info.Name == "" {
		t.Error("blank Name")
	}
	if info.Version == "" {
		t.Error("blank Version")
	}
}

// writeDarwinBackupCert writes a tiny self-signed ECDSA cert into dir as
// $fingerprint.crt (the Backup layout) and returns the fingerprint.
func writeDarwinBackupCert(t *testing.T, dir string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "darwin-backup-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	fp := certutil.GetHexSHA256Fingerprint(*cert)
	path := filepath.Join(dir, fp+".crt")
	if err := certutil.ToFile(path, []*x509.Certificate{cert}); err != nil {
		t.Fatal(err)
	}
	return fp
}

func TestResolveDarwinLoginBackupDir(t *testing.T) {
	// Temp dirs only — never touch the live login/system keychain.
	root := t.TempDir()
	ts := filepath.Join(root, "darwin", "1700000000")
	login := filepath.Join(ts, "login.keychain")
	if err := os.MkdirAll(login, 0o700); err != nil {
		t.Fatal(err)
	}
	writeDarwinBackupCert(t, login)

	got, err := resolveDarwinLoginBackupDir(ts)
	if err != nil {
		t.Fatalf("timestamp dir: %v", err)
	}
	if got != login {
		t.Fatalf("timestamp dir: got %s want %s", got, login)
	}

	got, err = resolveDarwinLoginBackupDir(login)
	if err != nil {
		t.Fatalf("login.keychain dir: %v", err)
	}
	if got != login {
		t.Fatalf("login.keychain dir: got %s want %s", got, login)
	}

	flat := t.TempDir()
	writeDarwinBackupCert(t, flat)
	got, err = resolveDarwinLoginBackupDir(flat)
	if err != nil {
		t.Fatalf("flat crt dir: %v", err)
	}
	if got != flat {
		t.Fatalf("flat crt dir: got %s want %s", got, flat)
	}

	empty := t.TempDir()
	if _, err := resolveDarwinLoginBackupDir(empty); err == nil {
		t.Fatal("empty dir should error")
	}

	filePath := filepath.Join(t.TempDir(), "not-a-dir.pem")
	if err := os.WriteFile(filePath, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveDarwinLoginBackupDir(filePath); err == nil {
		t.Fatal("file path should error")
	}

	// login.keychain as a file (not a dir) must fall back to the parent when
	// the parent itself has .crt exports.
	mixed := t.TempDir()
	if err := os.WriteFile(filepath.Join(mixed, "login.keychain"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	writeDarwinBackupCert(t, mixed)
	got, err = resolveDarwinLoginBackupDir(mixed)
	if err != nil {
		t.Fatalf("login.keychain file fallback: %v", err)
	}
	if got != mixed {
		t.Fatalf("login.keychain file fallback: got %s want %s", got, mixed)
	}

	junk := t.TempDir()
	if err := os.WriteFile(filepath.Join(junk, "deadbeef.crt"), []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveDarwinLoginBackupDir(junk); err == nil {
		t.Fatal("dir with only invalid deadbeef.crt should error")
	}

	// One valid export plus an empty sibling .crt must fail clearly, not
	// accept the directory on the first match.
	mixedValidAndJunk := t.TempDir()
	writeDarwinBackupCert(t, mixedValidAndJunk)
	fake := strings.Repeat("0", 64) + ".crt"
	if err := os.WriteFile(filepath.Join(mixedValidAndJunk, fake), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveDarwinLoginBackupDir(mixedValidAndJunk); err == nil {
		t.Fatal("dir with valid export and empty sibling .crt should error")
	}

	// A damaged login.keychain child must not be hidden by a valid export
	// sitting on the timestamp directory.
	tsDamaged := filepath.Join(t.TempDir(), "darwin", "1700000001")
	loginDamaged := filepath.Join(tsDamaged, "login.keychain")
	if err := os.MkdirAll(loginDamaged, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(loginDamaged, "deadbeef.crt"), []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	writeDarwinBackupCert(t, tsDamaged)
	if _, err := resolveDarwinLoginBackupDir(tsDamaged); err == nil {
		t.Fatal("damaged login.keychain should not fall through to parent")
	}
}

func TestDarwinRestore_DryRunHonorsWhere(t *testing.T) {
	login := filepath.Join(t.TempDir(), "login.keychain")
	if err := os.MkdirAll(login, 0o700); err != nil {
		t.Fatal(err)
	}
	writeDarwinBackupCert(t, login)

	var buf bytes.Buffer
	SetDryRunOutput(&buf)
	SetDryRun(true)
	t.Cleanup(func() {
		SetDryRun(false)
		SetDryRunOutput(nil)
	})

	s := darwinStore{}
	if err := s.Restore(login); err != nil {
		t.Fatalf("Restore dry-run: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, login) {
		t.Fatalf("dry-run should name where=%s, got %q", login, out)
	}
}

func TestDarwinBackupCertFingerprint(t *testing.T) {
	tests := []struct {
		name string
		in   string
		fp   string
		ok   bool
	}{
		{name: "strips .crt", in: "aabbccddeeff.crt", fp: "aabbccddeeff", ok: true},
		{name: "basename of path", in: filepath.Join("login.keychain", "deadbeef.crt"), fp: "deadbeef", ok: true},
		{name: "pem skipped", in: "aabbccddeeff.pem", ok: false},
		{name: "no suffix skipped", in: "aabbccddeeff", ok: false},
		{name: "directory name skipped", in: "login.keychain", ok: false},
		{name: "empty fingerprint skipped", in: ".crt", ok: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := darwinBackupCertFingerprint(tt.in)
			if ok != tt.ok || got != tt.fp {
				t.Fatalf("darwinBackupCertFingerprint(%q)=(%q,%v) want (%q,%v)", tt.in, got, ok, tt.fp, tt.ok)
			}
		})
	}
}
