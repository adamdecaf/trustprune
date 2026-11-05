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

package store

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adamdecaf/trustprune/pkg/allowlist"
	"github.com/adamdecaf/trustprune/pkg/certutil"
)

func certifiTestHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	return home
}

func refuseIfSystemCertifi(t *testing.T, path string) {
	t.Helper()
	clean := filepath.Clean(path)
	if strings.HasPrefix(clean, "/etc/") || strings.HasPrefix(clean, "/System/") ||
		strings.HasPrefix(clean, "/usr/") || strings.HasPrefix(clean, "/Library/") {
		t.Fatalf("refusing system path in tests: %s", path)
	}
}

func certifiFileEnv(t *testing.T) (certifiStore, string, []*x509.Certificate) {
	t.Helper()
	certifiTestHome(t)
	certs, err := certutil.FromFile(filepath.Join("..", "..", "testdata", "lots.crt"))
	if err != nil || len(certs) < 2 {
		t.Fatalf("load lots.crt: len=%d err=%v", len(certs), err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "cacert.pem")
	if err := certutil.ToFile(path, certs); err != nil {
		t.Fatal(err)
	}
	refuseIfSystemCertifi(t, path)
	return certifiStore{path: path}, path, certs
}

func TestCertifiStore_ListBackupRestoreRoundTrip(t *testing.T) {
	s, path, certs := certifiFileEnv(t)
	SetDryRun(false)

	got, err := s.List(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(certs) {
		t.Fatalf("list len=%d want %d", len(got), len(certs))
	}

	if err := s.Backup(); err != nil {
		t.Fatal(err)
	}
	backup, err := s.GetLatestBackup()
	if err != nil || backup == "" {
		t.Fatalf("latest backup: %q err=%v", backup, err)
	}
	backupFile := filepath.Join(backup, certifiBackupFilename)
	if _, err := os.Stat(backupFile); err != nil {
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
	if len(after) != 1 {
		t.Fatalf("after remove len=%d want 1", len(after))
	}

	if err := s.Restore(""); err != nil {
		t.Fatal(err)
	}
	restored, err := s.List(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(restored) != len(certs) {
		t.Fatalf("restored len=%d want %d", len(restored), len(certs))
	}
	live, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	backed, err := os.ReadFile(backupFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(live, backed) {
		t.Fatal("restored live PEM does not match backup")
	}
}

func TestCertifiStore_RestoreNoBackupRefusesBeforeWrite(t *testing.T) {
	for _, dry := range []bool{false, true} {
		t.Run(fmt.Sprintf("dry=%v", dry), func(t *testing.T) {
			s, live, _ := certifiFileEnv(t)
			home := os.Getenv("HOME")
			if dry {
				SetDryRun(true)
				defer SetDryRun(false)
			} else {
				SetDryRun(false)
			}

			before, err := os.ReadFile(live)
			if err != nil {
				t.Fatal(err)
			}
			entsBefore, err := os.ReadDir(filepath.Dir(live))
			if err != nil {
				t.Fatal(err)
			}

			err = s.Restore("")
			if err == nil {
				t.Fatal("expected error with no backup")
			}
			want := errNoBackupCmd("certifi", certifiBackupDir, "trustprune backup -app certifi").Error()
			if err.Error() != want {
				t.Fatalf("got %q, want %q", err.Error(), want)
			}

			after, err := os.ReadFile(live)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("restore with no backup mutated live PEM")
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
			if _, err := os.Stat(filepath.Join(parent, certifiBackupDir)); err == nil {
				t.Fatal("created certifi backup directory with no backup")
			}
		})
	}
}

func TestCertifiStore_RemoveAllowlistAndDryRun(t *testing.T) {
	s, path, certs := certifiFileEnv(t)
	keep := allowlist.FromCertificates([]*x509.Certificate{certs[0]})
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	SetDryRun(true)
	if err := s.Remove(keep); err != nil {
		t.Fatal(err)
	}
	afterDry, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, afterDry) {
		t.Fatal("dry-run Remove mutated live PEM")
	}

	SetDryRun(false)
	if err := s.Backup(); err != nil {
		t.Fatal(err)
	}
	if err := s.Remove(keep); err != nil {
		t.Fatal(err)
	}
	got, err := s.List(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("len=%d want 1", len(got))
	}
	for _, c := range got {
		if !bytes.Equal(c.Raw, certs[0].Raw) {
			t.Fatal("kept unexpected certificate")
		}
	}
}

func TestCertifiStore_RemoveRefusesEmptyBundle(t *testing.T) {
	s, _, _ := certifiFileEnv(t)
	SetDryRun(false)
	empty := allowlist.FromCertificates(nil)
	err := s.Remove(empty)
	if err == nil {
		t.Fatal("expected empty-bundle refusal")
	}
	if !strings.Contains(err.Error(), "refusing to write an empty bundle") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCertifiStore_AddToPEMFile(t *testing.T) {
	s, _, certs := certifiFileEnv(t)
	extra := extraExampleCert(t)
	SetDryRun(false)
	if err := s.Add(extra); err != nil {
		t.Fatal(err)
	}
	got, err := s.List(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(certs)+len(extra) {
		t.Fatalf("len=%d want %d", len(got), len(certs)+len(extra))
	}
}

func TestCertifiStore_DryRunDoesNotWrite(t *testing.T) {
	s, path, certs := certifiFileEnv(t)
	home := os.Getenv("HOME")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	SetDryRun(true)
	defer SetDryRun(false)

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
	if _, err := os.Stat(filepath.Join(parent, certifiBackupDir)); err == nil {
		t.Fatal("dry-run created certifi backup directory")
	}
}

func TestCertifiStore_RestoreHonorsWhere(t *testing.T) {
	s, path, certs := certifiFileEnv(t)
	SetDryRun(false)
	if err := s.Backup(); err != nil {
		t.Fatal(err)
	}
	keep := allowlist.FromCertificates([]*x509.Certificate{certs[0]})
	if err := s.Remove(keep); err != nil {
		t.Fatal(err)
	}

	altDir := t.TempDir()
	alt := filepath.Join(altDir, certifiBackupFilename)
	if err := certutil.ToFile(alt, certs); err != nil {
		t.Fatal(err)
	}
	if err := s.Restore(altDir); err != nil {
		t.Fatal(err)
	}
	got, err := s.List(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(certs) {
		t.Fatalf("len=%d want %d", len(got), len(certs))
	}
	_ = path
}

func TestCertifiStore_RestoreRejectsGarbageWhere(t *testing.T) {
	s, _, _ := certifiFileEnv(t)
	SetDryRun(false)
	garbage := filepath.Join(t.TempDir(), "not-a-pem")
	if err := os.WriteFile(garbage, []byte("not pem\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := s.Restore(garbage); err == nil {
		t.Fatal("expected garbage restore to fail")
	}
}

func TestCertifiStore_RestoreRefusesLeftoverAside(t *testing.T) {
	s, path, certs := certifiFileEnv(t)
	SetDryRun(false)
	if err := s.Backup(); err != nil {
		t.Fatal(err)
	}
	aside := path + ".restore-old"
	if err := os.WriteFile(aside, []byte("leftover\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(t.TempDir(), certifiBackupFilename)
	if err := certutil.ToFile(src, certs); err != nil {
		t.Fatal(err)
	}
	err := s.Restore(src)
	if err == nil {
		t.Fatal("expected leftover aside refusal")
	}
	if !strings.Contains(err.Error(), ".restore-old") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCertifiStore_CertPathResolvesSymlink(t *testing.T) {
	_, path, _ := certifiFileEnv(t)
	link := filepath.Join(t.TempDir(), "cacert-link.pem")
	if err := os.Symlink(path, link); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}
	linked := certifiStore{path: link}
	got, err := linked.certPath()
	if err != nil {
		t.Fatal(err)
	}
	want := mustEvalSymlinks(t, path)
	if got != want {
		t.Fatalf("got %s want %s", got, want)
	}
}

func TestCertifiStore_GetInfo(t *testing.T) {
	s, path, _ := certifiFileEnv(t)
	info := s.GetInfo()
	if info.Name != "certifi" {
		t.Fatalf("name=%q", info.Name)
	}
	want := mustEvalSymlinks(t, path)
	if info.Path != want {
		t.Fatalf("path=%q want %q", info.Path, want)
	}
	if info.Version == "" {
		t.Fatal("expected version/size")
	}
}

func TestCertifiStore_FindCertPathUsesPythonWhere(t *testing.T) {
	certifiTestHome(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "cacert.pem")
	if err := os.WriteFile(path, []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	refuseIfSystemCertifi(t, path)

	origWhere := certifiPythonWhere
	origFallback := certifiFallbackPaths
	certifiPythonWhere = func() string { return path }
	certifiFallbackPaths = nil
	t.Cleanup(func() {
		certifiPythonWhere = origWhere
		certifiFallbackPaths = origFallback
	})

	got, err := certifiStore{}.findCertPath()
	if err != nil {
		t.Fatal(err)
	}
	if got != path {
		t.Fatalf("got %s want %s", got, path)
	}
}

func TestCertifiStore_FindCertPathFallsBack(t *testing.T) {
	certifiTestHome(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "site-packages", "certifi", "cacert.pem")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	refuseIfSystemCertifi(t, path)

	origWhere := certifiPythonWhere
	origFallback := certifiFallbackPaths
	certifiPythonWhere = func() string { return "" }
	certifiFallbackPaths = []string{filepath.Join(dir, "site-packages", "certifi", "cacert.pem")}
	t.Cleanup(func() {
		certifiPythonWhere = origWhere
		certifiFallbackPaths = origFallback
	})

	got, err := certifiStore{}.findCertPath()
	if err != nil {
		t.Fatal(err)
	}
	if got != path {
		t.Fatalf("got %s want %s", got, path)
	}
}

func TestCertifiStore_StoreAtIgnoresDiscovery(t *testing.T) {
	s, path, _ := certifiFileEnv(t)
	origWhere := certifiPythonWhere
	certifiPythonWhere = func() string { return filepath.Join(t.TempDir(), "other.pem") }
	t.Cleanup(func() { certifiPythonWhere = origWhere })

	got, err := s.certPath()
	if err != nil {
		t.Fatal(err)
	}
	want := mustEvalSymlinks(t, path)
	if got != want {
		t.Fatalf("storeAt should ignore discovery, got %s want %s", got, want)
	}
}

func TestCertifiStore_BackupUniqueDirsSameSecond(t *testing.T) {
	s, _, _ := certifiFileEnv(t)
	SetDryRun(false)
	if err := s.Backup(); err != nil {
		t.Fatal(err)
	}
	if err := s.Backup(); err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(primaryBackupParent(os.Getenv("HOME")), certifiBackupDir)
	ents, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) < 2 {
		t.Fatalf("want >=2 backup dirs, got %d", len(ents))
	}
}

func TestForAppWithFile_Certifi(t *testing.T) {
	_, path, _ := certifiFileEnv(t)
	st, err := ForAppWithFile("certifi", path)
	if err != nil {
		t.Fatal(err)
	}
	info := st.GetInfo()
	want := mustEvalSymlinks(t, path)
	if info.Path != want {
		t.Fatalf("path=%q want %q", info.Path, want)
	}
}
