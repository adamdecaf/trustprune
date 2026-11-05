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

package store

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/adamdecaf/trustprune/pkg/allowlist"
	"github.com/adamdecaf/trustprune/pkg/certutil"
)

func opensslTestHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	return home
}

func isolateOpenSSLLookup(t *testing.T) {
	t.Helper()
	t.Setenv("SSL_CERT_FILE", "")
	t.Setenv("CURL_CA_BUNDLE", "")
	orig := gitHTTPSSLCAInfo
	gitHTTPSSLCAInfo = func() string { return "" }
	t.Cleanup(func() { gitHTTPSSLCAInfo = orig })
}

func refuseIfSystemOpenSSL(t *testing.T, path string) {
	t.Helper()
	clean := filepath.Clean(path)
	if clean == filepath.Clean(defaultDarwinSSLCertPEM) {
		t.Fatalf("refusing to use real system path %s in tests", path)
	}
	if strings.HasPrefix(clean, "/etc/") || strings.HasPrefix(clean, "/System/") {
		t.Fatalf("refusing system path in tests: %s", path)
	}
}

func opensslFileEnv(t *testing.T) (opensslStore, string, []*x509.Certificate) {
	t.Helper()
	opensslTestHome(t)
	certs, err := certutil.FromFile(filepath.Join("..", "..", "testdata", "lots.crt"))
	if err != nil || len(certs) < 2 {
		t.Fatalf("load lots.crt: len=%d err=%v", len(certs), err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "ca-bundle.pem")
	if err := certutil.ToFile(path, certs); err != nil {
		t.Fatal(err)
	}
	refuseIfSystemOpenSSL(t, path)
	return opensslStoreAt(path), path, certs
}

func opensslDirEnv(t *testing.T) (opensslStore, string, []*x509.Certificate) {
	t.Helper()
	opensslTestHome(t)
	certs, err := certutil.FromFile(filepath.Join("..", "..", "testdata", "lots.crt"))
	if err != nil || len(certs) < 3 {
		t.Fatalf("load lots.crt: len=%d err=%v", len(certs), err)
	}
	keep := certs[:3]
	dir := t.TempDir()
	refuseIfSystemOpenSSL(t, dir)
	for i, c := range keep {
		p := filepath.Join(dir, fmt.Sprintf("ca-%d.crt", i))
		if err := certutil.ToFile(p, []*x509.Certificate{c}); err != nil {
			t.Fatal(err)
		}
		refuseIfSystemOpenSSL(t, p)
	}
	return opensslStoreAt(dir), dir, keep
}

func extraExampleCert(t *testing.T) []*x509.Certificate {
	t.Helper()
	extra, err := certutil.FromFile(filepath.Join("..", "..", "testdata", "example.crt"))
	if err != nil || len(extra) == 0 {
		t.Fatalf("example.crt: %v", err)
	}
	return extra
}

func skipIfNoCRehash(t *testing.T) {
	t.Helper()
	if findCRehash() == "" {
		t.Skip("c_rehash not available")
	}
}

func TestStoreOpenSSL__paths(t *testing.T) {
	err := exec.Command("openssl", "version").Run()
	if err != nil {
		t.Skipf("can't find openssl, err=%v", err)
	}
	if runtime.GOOS == "windows" {
		t.Skip("openssl store has no default Windows paths")
	}

	st := opensslStore{}
	dir, err := st.findCertPath()
	if err != nil {
		t.Skip(err.Error())
	}
	if dir == "" {
		t.Error("empty dir")
	}
	if filepath.Clean(dir) == filepath.Clean(defaultDarwinSSLCertPEM) {
		t.Fatalf("openssl defaulted to Darwin /etc/ssl/cert.pem; that path is -app ssl")
	}
}

func TestOpenSSLStore_ListFile(t *testing.T) {
	s, _, want := opensslFileEnv(t)
	got, err := s.List(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("List len=%d want %d", len(got), len(want))
	}
}

func TestOpenSSLStore_ListDir(t *testing.T) {
	s, _, want := opensslDirEnv(t)
	got, err := s.List(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("List len=%d want %d", len(got), len(want))
	}
}

func TestOpenSSLStore_FileBackupRestoreRoundTrip(t *testing.T) {
	s, path, want := opensslFileEnv(t)

	SetDryRun(false)
	if err := s.Backup(); err != nil {
		t.Fatalf("Backup: %v", err)
	}
	latest, err := s.GetLatestBackup()
	if err != nil || latest == "" {
		t.Fatalf("GetLatestBackup: %q err=%v", latest, err)
	}
	backupFile := filepath.Join(latest, opensslBackupFilename)
	refuseIfSystemOpenSSL(t, backupFile)
	backed, err := os.ReadFile(backupFile)
	if err != nil {
		t.Fatal(err)
	}
	live, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(backed, live) {
		t.Fatal("backup contents differ from live PEM")
	}

	if err := certutil.ToFile(path, want[:1]); err != nil {
		t.Fatal(err)
	}
	if err := s.Restore(""); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	after, err := certutil.FromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(want) {
		t.Fatalf("after restore len=%d want %d", len(after), len(want))
	}
}

func TestOpenSSLStore_DirBackupRestoreRoundTrip(t *testing.T) {
	s, dir, want := opensslDirEnv(t)
	SetDryRun(false)
	if err := s.Backup(); err != nil {
		t.Fatalf("Backup: %v", err)
	}
	latest, err := s.GetLatestBackup()
	if err != nil || latest == "" {
		t.Fatalf("GetLatestBackup: %q err=%v", latest, err)
	}
	refuseIfSystemOpenSSL(t, latest)

	removed := filepath.Join(dir, "ca-2.crt")
	if err := os.Remove(removed); err != nil {
		t.Fatal(err)
	}
	if err := s.Restore(""); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	after, err := s.List(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(want) {
		t.Fatalf("after restore len=%d want %d", len(after), len(want))
	}
	if _, err := os.Stat(removed); err != nil {
		t.Fatalf("restored file missing: %v", err)
	}
}

func TestOpenSSLStore_RestoreHonorsWhere(t *testing.T) {
	s, path, want := opensslFileEnv(t)
	SetDryRun(false)
	if err := s.Backup(); err != nil {
		t.Fatal(err)
	}
	altDir := t.TempDir()
	alt := filepath.Join(altDir, "alt.pem")
	if err := certutil.ToFile(alt, want[:1]); err != nil {
		t.Fatal(err)
	}
	refuseIfSystemOpenSSL(t, alt)
	if err := s.Restore(alt); err != nil {
		t.Fatalf("Restore(where): %v", err)
	}
	got, err := certutil.FromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("Restore(where) len=%d want 1", len(got))
	}
}

func TestOpenSSLStore_RestoreNoBackupRefusesBeforeWrite(t *testing.T) {
	for _, mode := range []string{"file", "dir"} {
		for _, dry := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/%v", mode, dry), func(t *testing.T) {
				var s opensslStore
				var live string
				if mode == "file" {
					s, live, _ = opensslFileEnv(t)
				} else {
					s, live, _ = opensslDirEnv(t)
				}
				home := os.Getenv("HOME")
				if dry {
					SetDryRun(true)
					defer SetDryRun(false)
				} else {
					SetDryRun(false)
				}

				var before []byte
				var err error
				isDir := mode == "dir"
				if !isDir {
					before, err = os.ReadFile(live)
					if err != nil {
						t.Fatal(err)
					}
				}
				entsBefore, err := os.ReadDir(filepath.Dir(live))
				if err != nil {
					t.Fatal(err)
				}

				err = s.Restore("")
				if err == nil {
					t.Fatal("expected error with no backup")
				}
				want := errNoBackupCmd("openssl", opensslBackupDir, "trustprune backup -app openssl").Error()
				if err.Error() != want {
					t.Fatalf("got %q, want %q", err.Error(), want)
				}

				if !isDir {
					after, err := os.ReadFile(live)
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(before, after) {
						t.Fatal("restore with no backup mutated live PEM")
					}
				}
				entsAfter, err := os.ReadDir(filepath.Dir(live))
				if err != nil {
					t.Fatal(err)
				}
				if len(entsAfter) != len(entsBefore) {
					t.Fatalf("live parent changed: before=%d after=%d", len(entsBefore), len(entsAfter))
				}
				for _, leftover := range []string{live + ".restore-tmp", live + ".restore-old"} {
					if _, err := os.Stat(leftover); !os.IsNotExist(err) {
						t.Fatalf("created %s: %v", leftover, err)
					}
				}
				parent := primaryBackupParent(home)
				if _, err := os.Stat(filepath.Join(parent, opensslBackupDir)); err == nil {
					t.Fatal("created openssl backup directory with no backup")
				}
			})
		}
	}
}

func TestOpenSSLStore_RemoveAllowlistFile(t *testing.T) {
	s, path, certs := opensslFileEnv(t)
	keep := allowlist.FromCertificates([]*x509.Certificate{certs[0]})
	SetDryRun(false)
	if err := s.Backup(); err != nil {
		t.Fatal(err)
	}
	if err := s.Remove(keep); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	got, err := certutil.FromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("after allowlist len=%d want 1", len(got))
	}
	if certutil.GetHexSHA256Fingerprint(*got[0]) != certutil.GetHexSHA256Fingerprint(*certs[0]) {
		t.Fatal("kept unexpected certificate")
	}
}

func TestOpenSSLStore_RemoveAllowlistDir(t *testing.T) {
	s, dir, certs := opensslDirEnv(t)
	keep := allowlist.FromCertificates([]*x509.Certificate{certs[0]})
	SetDryRun(false)
	if err := s.Backup(); err != nil {
		t.Fatal(err)
	}
	if err := s.Remove(keep); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	got, err := s.List(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("after allowlist len=%d want 1", len(got))
	}
	if certutil.GetHexSHA256Fingerprint(*got[0]) != certutil.GetHexSHA256Fingerprint(*certs[0]) {
		t.Fatal("kept unexpected certificate")
	}
	if _, err := os.Stat(filepath.Join(dir, "ca-1.crt")); !os.IsNotExist(err) {
		t.Fatalf("non-matching cert file should be gone: %v", err)
	}
}

func TestOpenSSLStore_RemoveRefusesEmptyBundle(t *testing.T) {
	s, path, _ := opensslFileEnv(t)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	SetDryRun(false)
	if err := s.Backup(); err != nil {
		t.Fatal(err)
	}
	empty := allowlist.FromCertificates(nil)
	err = s.Remove(empty)
	if err == nil {
		t.Fatal("expected error refusing empty bundle")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Fatalf("error should mention empty, got %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("empty remove mutated PEM")
	}
}

func TestOpenSSLStore_RemoveDryRunRejectsEmpty(t *testing.T) {
	s, path, _ := opensslFileEnv(t)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	SetDryRun(true)
	defer SetDryRun(false)
	empty := allowlist.FromCertificates(nil)
	err = s.Remove(empty)
	if err == nil {
		t.Fatal("dry-run should reject empty allowlist result")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("dry-run empty remove mutated PEM")
	}
}

func TestOpenSSLStore_AddToPEMFile(t *testing.T) {
	s, path, certs := opensslFileEnv(t)
	extra := extraExampleCert(t)
	SetDryRun(false)
	if err := s.Backup(); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(extra); err != nil {
		t.Fatalf("Add: %v", err)
	}
	got, err := certutil.FromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(certs)+len(extra) {
		t.Fatalf("after add len=%d want %d", len(got), len(certs)+len(extra))
	}
}

func TestOpenSSLStore_AddToDirectory(t *testing.T) {
	skipIfNoCRehash(t)
	s, dir, certs := opensslDirEnv(t)
	extra := extraExampleCert(t)
	SetDryRun(false)
	if err := s.Backup(); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(extra); err != nil {
		t.Fatalf("Add: %v", err)
	}
	got, err := s.List(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(certs)+len(extra) {
		t.Fatalf("after add len=%d want %d", len(got), len(certs)+len(extra))
	}
	fp := certutil.GetHexSHA256Fingerprint(*extra[0])
	written := filepath.Join(dir, fp+".crt")
	refuseIfSystemOpenSSL(t, written)
	if _, err := os.Stat(written); err != nil {
		t.Fatalf("added cert file missing: %v", err)
	}
}

func TestOpenSSLStore_DryRunDoesNotWrite(t *testing.T) {
	s, path, certs := opensslFileEnv(t)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	home := os.Getenv("HOME")

	var buf bytes.Buffer
	SetDryRunOutput(&buf)
	SetDryRun(true)
	defer func() {
		SetDryRun(false)
		SetDryRunOutput(nil)
	}()

	keep := allowlist.FromCertificates([]*x509.Certificate{certs[0]})
	if err := s.Backup(); err != nil {
		t.Fatalf("Backup dry-run: %v", err)
	}
	if err := s.Add(extraExampleCert(t)); err != nil {
		t.Fatalf("Add dry-run: %v", err)
	}
	if err := s.Remove(keep); err != nil {
		t.Fatalf("Remove dry-run: %v", err)
	}
	// No backup exists; Restore must still refuse rather than preview a write.
	if err := s.Restore(""); err == nil {
		t.Fatal("dry-run Restore with no backup should error")
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("dry-run mutated live PEM")
	}
	parent := primaryBackupParent(home)
	if _, err := os.Stat(filepath.Join(parent, opensslBackupDir)); err == nil {
		t.Fatal("dry-run created openssl backup directory")
	}
	out := buf.String()
	if !strings.Contains(out, "dry-run") {
		t.Fatalf("missing dry-run plan: %q", out)
	}
}

func TestOpenSSLStore_DirDryRunDoesNotWrite(t *testing.T) {
	s, dir, certs := opensslDirEnv(t)
	before, err := s.List(nil)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	SetDryRunOutput(&buf)
	SetDryRun(true)
	defer func() {
		SetDryRun(false)
		SetDryRunOutput(nil)
	}()

	if err := s.Backup(); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(extraExampleCert(t)); err != nil {
		t.Fatal(err)
	}
	keep := allowlist.FromCertificates([]*x509.Certificate{certs[0]})
	if err := s.Remove(keep); err != nil {
		t.Fatal(err)
	}
	after, err := s.List(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("dry-run mutated dir store: before=%d after=%d", len(before), len(after))
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 3 {
		t.Fatalf("dry-run changed dir entries: %d", len(ents))
	}
}

func TestOpenSSLStore_FileVsDirectoryPathModes(t *testing.T) {
	fileStore, filePath, fileCerts := opensslFileEnv(t)
	dirStore, dirPath, dirCerts := opensslDirEnv(t)

	st, err := os.Stat(filePath)
	if err != nil || st.IsDir() {
		t.Fatalf("file path should be a file: %v", err)
	}
	st, err = os.Stat(dirPath)
	if err != nil || !st.IsDir() {
		t.Fatalf("dir path should be a directory: %v", err)
	}

	gotFile, err := fileStore.List(nil)
	if err != nil {
		t.Fatal(err)
	}
	gotDir, err := dirStore.List(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(gotFile) != len(fileCerts) {
		t.Fatalf("file List len=%d want %d", len(gotFile), len(fileCerts))
	}
	if len(gotDir) != len(dirCerts) {
		t.Fatalf("dir List len=%d want %d", len(gotDir), len(dirCerts))
	}

	info := fileStore.GetInfo()
	if info.Path != filePath {
		t.Fatalf("file GetInfo.Path=%q want %s", info.Path, filePath)
	}
	info = dirStore.GetInfo()
	if info.Path != dirPath {
		t.Fatalf("dir GetInfo.Path=%q want %s", info.Path, dirPath)
	}
}

func TestOpenSSLStore_PathResolutionOrder(t *testing.T) {
	isolateOpenSSLLookup(t)
	opensslTestHome(t)

	sslCert := filepath.Join(t.TempDir(), "ssl-cert-file.pem")
	curlBundle := filepath.Join(t.TempDir(), "curl-ca-bundle.pem")
	defaultPath := filepath.Join(t.TempDir(), "default.pem")
	gitPath := filepath.Join(t.TempDir(), "git-ca.pem")
	for _, p := range []string{sslCert, curlBundle, defaultPath, gitPath} {
		if err := os.WriteFile(p, []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
		refuseIfSystemOpenSSL(t, p)
	}

	origPaths := openSSLCertPaths
	t.Cleanup(func() { openSSLCertPaths = origPaths })
	openSSLCertPaths = []string{defaultPath}

	origGit := gitHTTPSSLCAInfo
	gitHTTPSSLCAInfo = func() string { return gitPath }
	t.Cleanup(func() { gitHTTPSSLCAInfo = origGit })

	t.Setenv("SSL_CERT_FILE", sslCert)
	t.Setenv("CURL_CA_BUNDLE", curlBundle)
	got, err := opensslStore{}.findCertPath()
	if err != nil {
		t.Fatal(err)
	}
	if got != sslCert {
		t.Fatalf("SSL_CERT_FILE should win, got %s", got)
	}

	t.Setenv("SSL_CERT_FILE", filepath.Join(t.TempDir(), "missing.pem"))
	got, err = opensslStore{}.findCertPath()
	if err != nil {
		t.Fatal(err)
	}
	if got != curlBundle {
		t.Fatalf("CURL_CA_BUNDLE should win when SSL_CERT_FILE is missing, got %s", got)
	}

	t.Setenv("CURL_CA_BUNDLE", "")
	got, err = opensslStore{}.findCertPath()
	if err != nil {
		t.Fatal(err)
	}
	if got != defaultPath {
		t.Fatalf("openSSLCertPaths should win next, got %s", got)
	}

	openSSLCertPaths = []string{filepath.Join(t.TempDir(), "nope")}
	got, err = opensslStore{}.findCertPath()
	if err != nil {
		t.Fatal(err)
	}
	if got != gitPath {
		t.Fatalf("git http.sslCAInfo should win last, got %s", got)
	}
}

func TestOpenSSLStore_SkipsDarwinCertPEMDefault(t *testing.T) {
	isolateOpenSSLLookup(t)
	opensslTestHome(t)

	temp := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(temp, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	refuseIfSystemOpenSSL(t, temp)

	orig := openSSLCertPaths
	t.Cleanup(func() { openSSLCertPaths = orig })
	openSSLCertPaths = []string{defaultDarwinSSLCertPEM, temp}

	got, err := opensslStore{}.findCertPath()
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Clean(got) == filepath.Clean(defaultDarwinSSLCertPEM) {
		t.Fatal("openssl must not default to Darwin /etc/ssl/cert.pem")
	}
	if got != temp {
		t.Fatalf("got %s want %s", got, temp)
	}
}

func TestOpenSSLStore_StoreAtIgnoresEnv(t *testing.T) {
	s, path, _ := opensslFileEnv(t)
	other := filepath.Join(t.TempDir(), "other.pem")
	if err := os.WriteFile(other, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", other)
	t.Setenv("CURL_CA_BUNDLE", other)
	got, err := s.findCertPath()
	if err != nil {
		t.Fatal(err)
	}
	if got != path {
		t.Fatalf("opensslStoreAt should ignore env, got %s want %s", got, path)
	}
}

func TestOpenSSLStore_GetInfo(t *testing.T) {
	s, path, _ := opensslFileEnv(t)
	info := s.GetInfo()
	if info.Path != path {
		t.Fatalf("Path=%q want %s", info.Path, path)
	}
	if info.Name == "" {
		t.Fatal("Name should be set")
	}
}

func TestOpenSSLStore_BackupUniqueDirsSameSecond(t *testing.T) {
	s, _, _ := opensslFileEnv(t)
	SetDryRun(false)
	if err := s.Backup(); err != nil {
		t.Fatalf("Backup 1: %v", err)
	}
	first, err := s.GetLatestBackup()
	if err != nil || first == "" {
		t.Fatalf("GetLatestBackup after 1: %q err=%v", first, err)
	}
	if err := s.Backup(); err != nil {
		t.Fatalf("Backup 2: %v", err)
	}
	second, err := s.GetLatestBackup()
	if err != nil || second == "" {
		t.Fatalf("GetLatestBackup after 2: %q err=%v", second, err)
	}
	if first == second {
		t.Fatalf("two backups reused directory %s", first)
	}
}

func TestOpenSSLStore_RestoreRejectsGarbageWhere(t *testing.T) {
	s, path, _ := opensslFileEnv(t)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	garbage := filepath.Join(t.TempDir(), "not-a-pem")
	if err := os.WriteFile(garbage, []byte("not-pem-at-all\n"), 0644); err != nil {
		t.Fatal(err)
	}
	SetDryRun(false)
	err = s.Restore(garbage)
	if err == nil {
		t.Fatal("expected restore to reject garbage source")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("failed restore overwrote live PEM")
	}
}

func TestOpenSSLStore_RestoreDryRunDoesNotWrite(t *testing.T) {
	s, path, want := opensslFileEnv(t)
	SetDryRun(false)
	if err := s.Backup(); err != nil {
		t.Fatal(err)
	}
	if err := certutil.ToFile(path, want[:1]); err != nil {
		t.Fatal(err)
	}
	mutated, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	SetDryRunOutput(&buf)
	SetDryRun(true)
	defer func() {
		SetDryRun(false)
		SetDryRunOutput(nil)
	}()
	if err := s.Restore(""); err != nil {
		t.Fatalf("Restore dry-run: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mutated, after) {
		t.Fatal("dry-run Restore mutated live PEM")
	}
	if !strings.Contains(buf.String(), "dry-run") {
		t.Fatalf("missing dry-run plan: %q", buf.String())
	}
}

func TestOpenSSLStore_CertPathResolvesSymlink(t *testing.T) {
	isolateOpenSSLLookup(t)
	s, path, certs := opensslFileEnv(t)
	link := filepath.Join(filepath.Dir(path), "ca-bundle-link.crt")
	if err := os.Symlink(path, link); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}
	linked := opensslStoreAt(link)
	got, err := linked.certPath()
	if err != nil {
		t.Fatal(err)
	}
	want, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Clean(got) != filepath.Clean(want) {
		t.Fatalf("certPath=%q, want resolved %q", got, want)
	}
	keep := allowlist.FromCertificates([]*x509.Certificate{certs[0]})
	SetDryRun(false)
	if err := linked.Backup(); err != nil {
		t.Fatal(err)
	}
	if err := linked.Remove(keep); err != nil {
		t.Fatal(err)
	}
	after, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if after.Mode()&os.ModeSymlink == 0 {
		t.Fatal("symlink was replaced by a regular file")
	}
	resolved, err := filepath.EvalSymlinks(link)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Clean(resolved) != filepath.Clean(want) {
		t.Fatalf("link no longer points at target: %q vs %q", resolved, want)
	}
	_ = s
}

func TestOpenSSLStore_DirRestoreRefusesLeftoverAside(t *testing.T) {
	isolateOpenSSLLookup(t)
	s, dir, _ := opensslDirEnv(t)
	SetDryRun(false)
	if err := s.Backup(); err != nil {
		t.Fatal(err)
	}
	aside := dir + ".restore-old"
	if err := os.Mkdir(aside, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(aside, "keep.crt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := s.Restore("")
	if err == nil {
		t.Fatal("expected error for leftover .restore-old")
	}
	if !strings.Contains(err.Error(), ".restore-old") {
		t.Fatalf("error should name leftover aside, got %v", err)
	}
	if _, err := os.Lstat(aside); err != nil {
		t.Fatalf("leftover aside was deleted: %v", err)
	}
}

func TestOpenSSLStore_DirRestoreRejectsFileWhere(t *testing.T) {
	s, dir, certs := opensslDirEnv(t)
	pem := filepath.Join(t.TempDir(), "bundle.pem")
	if err := certutil.ToFile(pem, certs[:1]); err != nil {
		t.Fatal(err)
	}
	SetDryRun(false)
	err := s.Restore(pem)
	if err == nil {
		t.Fatal("expected directory store to reject a file restore source")
	}
	got, err := s.List(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(certs) {
		t.Fatalf("failed restore mutated dir: len=%d want %d", len(got), len(certs))
	}
	_ = dir
}
