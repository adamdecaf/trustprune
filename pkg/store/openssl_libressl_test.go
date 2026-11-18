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
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/adamdecaf/trustprune/pkg/allowlist"
	"github.com/adamdecaf/trustprune/pkg/certutil"
	"github.com/adamdecaf/trustprune/pkg/file"
)

func TestLibreSSL_DefaultPaths(t *testing.T) {
	wantBins := []string{
		"/usr/local/opt/libressl/bin/openssl",
		"/opt/homebrew/opt/libressl/bin/openssl",
	}
	wantCerts := []string{
		"/usr/local/etc/libressl/cert.pem",
		"/opt/homebrew/etc/libressl/cert.pem",
		"/usr/local/etc/libressl/certs",
		"/opt/homebrew/etc/libressl/certs",
		"/etc/ssl/cert.pem",
	}
	if strings.Join(libreSSLBinPaths, "\n") != strings.Join(wantBins, "\n") {
		t.Fatalf("bins = %q", libreSSLBinPaths)
	}
	if strings.Join(libreSSLCertPaths, "\n") != strings.Join(wantCerts, "\n") {
		t.Fatalf("certs = %q", libreSSLCertPaths)
	}
}

func TestLibreSSL_SkipSystemBundleOnlyOnDarwin(t *testing.T) {
	isolateOpenSSLLookup(t)
	if !skipLibreSSLCertPath("") {
		t.Fatal("empty path should be skipped")
	}
	for _, goos := range []string{"linux", "openbsd", "freebsd", "windows"} {
		opensslGOOS = goos
		if skipLibreSSLCertPath(defaultDarwinSSLCertPEM) {
			t.Fatalf("%s should allow /etc/ssl/cert.pem as a LibreSSL bundle", goos)
		}
	}
	opensslGOOS = "darwin"
	if !skipLibreSSLCertPath(defaultDarwinSSLCertPEM) {
		t.Fatal("darwin /etc/ssl/cert.pem must stay --app ssl")
	}
	if skipLibreSSLCertPath("/usr/local/etc/libressl/cert.pem") {
		t.Fatal("Homebrew LibreSSL CA file must stay eligible on darwin")
	}
}

func TestLibreSSL_DetectsBrewPathOrVersion(t *testing.T) {
	isolateOpenSSLLookup(t)

	brew := filepath.Join(t.TempDir(), "openssl")
	if err := os.WriteFile(brew, []byte("not executable"), 0o644); err != nil {
		t.Fatal(err)
	}
	opensslVersionOutput = func(string) (string, error) {
		t.Fatal("brew path detection must not require version output")
		return "", nil
	}
	libreSSLBinPaths = []string{"", brew}
	if got := findLibreSSLBin(); got != brew {
		t.Fatalf("brew bin = %q want %s", got, brew)
	}

	libreSSLBinPaths = nil
	opensslVersionOutput = func(string) (string, error) {
		return "LibreSSL 3.3.6\n", nil
	}
	opensslLookPath = func(string) (string, error) {
		return darwinSystemOpenSSL, nil
	}
	opensslGOOS = "darwin"
	if got := findLibreSSLBin(); got != "" {
		t.Fatalf("darwin system openssl = %q, want ignored", got)
	}
	opensslGOOS = "openbsd"
	if got := findLibreSSLBin(); got != darwinSystemOpenSSL {
		t.Fatalf("openbsd system openssl = %q", got)
	}
	opensslGOOS = "linux"
	if got := findLibreSSLBin(); got != darwinSystemOpenSSL {
		t.Fatalf("linux LibreSSL openssl = %q", got)
	}

	opensslGOOS = "darwin"
	opensslLookPath = func(string) (string, error) {
		return "/opt/local/bin/openssl", nil
	}
	if got := findLibreSSLBin(); got != "/opt/local/bin/openssl" {
		t.Fatalf("non-system darwin LibreSSL = %q", got)
	}

	// Brew path wins over a PATH openssl, including Apple's.
	libreSSLBinPaths = []string{brew}
	opensslLookPath = func(string) (string, error) {
		return darwinSystemOpenSSL, nil
	}
	if got := findLibreSSLBin(); got != brew {
		t.Fatalf("brew should beat PATH, got %q", got)
	}
}

func TestLibreSSL_VersionPrefix(t *testing.T) {
	cases := []struct {
		out  string
		want bool
	}{
		{"LibreSSL 2.6.4\n", true},
		{"LibreSSL\n", true},
		{"  LibreSSL 1.0\n", true},
		{"OpenSSL 3.5.7 9 Jun 2026\n", false},
		{"OpenSSL 3.0.0 (LibreSSL compatible)\n", false},
		{"libressl 3.0.0\n", false},
		{"not LibreSSL\n", false},
		{"", false},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%q", tc.out), func(t *testing.T) {
			isolateOpenSSLLookup(t)
			libreSSLBinPaths = nil
			opensslGOOS = "linux"
			opensslLookPath = func(string) (string, error) {
				return "/usr/bin/openssl", nil
			}
			opensslVersionOutput = func(string) (string, error) {
				return tc.out, nil
			}
			got := findLibreSSLBin()
			if tc.want && got == "" {
				t.Fatalf("output %q should detect LibreSSL", tc.out)
			}
			if !tc.want && got != "" {
				t.Fatalf("output %q detected %q", tc.out, got)
			}
		})
	}

	t.Run("version error", func(t *testing.T) {
		isolateOpenSSLLookup(t)
		opensslGOOS = "linux"
		opensslLookPath = func(string) (string, error) {
			return "/usr/bin/openssl", nil
		}
		opensslVersionOutput = func(string) (string, error) {
			return "LibreSSL 3.0.0\n", errors.New("exit status 1")
		}
		if got := findLibreSSLBin(); got != "" {
			t.Fatalf("failed version command detected %q", got)
		}
	})
}

func TestLibreSSL_PathPrecedence(t *testing.T) {
	isolateOpenSSLLookup(t)
	opensslTestHome(t)

	root := t.TempDir()
	intelPEM := filepath.Join(root, "intel-cert.pem")
	siliconPEM := filepath.Join(root, "silicon-cert.pem")
	intelDir := filepath.Join(root, "intel-certs")
	siliconDir := filepath.Join(root, "silicon-certs")
	opensslDir := filepath.Join(root, "openssl-certs")
	gitPEM := filepath.Join(root, "git-ca.pem")
	for _, dir := range []string{intelDir, siliconDir, opensslDir} {
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range []string{intelPEM, siliconPEM, gitPEM} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		refuseIfSystemOpenSSL(t, p)
	}

	bin, _ := writeFakeSSL(t, "LibreSSL 3.9.2", 0, 0)
	libreSSLBinPaths = []string{bin}
	libreSSLCertPaths = []string{intelPEM, siliconPEM, intelDir, siliconDir}
	origOpenSSL := openSSLCertPaths
	openSSLCertPaths = []string{opensslDir}
	t.Cleanup(func() { openSSLCertPaths = origOpenSSL })
	origGit := gitHTTPSSLCAInfo
	gitHTTPSSLCAInfo = func() string { return gitPEM }
	t.Cleanup(func() { gitHTTPSSLCAInfo = origGit })

	sslCert := filepath.Join(root, "ssl-cert-file.pem")
	curlBundle := filepath.Join(root, "curl-ca-bundle.pem")
	for _, p := range []string{sslCert, curlBundle} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("SSL_CERT_FILE", sslCert)
	t.Setenv("CURL_CA_BUNDLE", curlBundle)
	got, err := opensslStore{}.findCertPath()
	if err != nil || got != sslCert {
		t.Fatalf("SSL_CERT_FILE got %s err %v", got, err)
	}

	t.Setenv("SSL_CERT_FILE", filepath.Join(root, "missing.pem"))
	got, err = opensslStore{}.findCertPath()
	if err != nil || got != curlBundle {
		t.Fatalf("CURL_CA_BUNDLE got %s err %v", got, err)
	}

	t.Setenv("CURL_CA_BUNDLE", "")
	got, err = opensslStore{}.findCertPath()
	if err != nil || got != intelPEM {
		t.Fatalf("Intel CA file got %s err %v", got, err)
	}
	if err := os.Remove(intelPEM); err != nil {
		t.Fatal(err)
	}
	got, err = opensslStore{}.findCertPath()
	if err != nil || got != siliconPEM {
		t.Fatalf("Apple Silicon CA file got %s err %v", got, err)
	}
	if err := os.Remove(siliconPEM); err != nil {
		t.Fatal(err)
	}
	got, err = opensslStore{}.findCertPath()
	if err != nil || got != intelDir {
		t.Fatalf("Intel certs dir got %s err %v", got, err)
	}
	if err := os.RemoveAll(intelDir); err != nil {
		t.Fatal(err)
	}
	got, err = opensslStore{}.findCertPath()
	if err != nil || got != siliconDir {
		t.Fatalf("Apple Silicon certs dir got %s err %v", got, err)
	}
	if err := os.RemoveAll(siliconDir); err != nil {
		t.Fatal(err)
	}
	got, err = opensslStore{}.findCertPath()
	if err != nil || got != opensslDir {
		t.Fatalf("OpenSSL dir should follow LibreSSL misses, got %s err %v", got, err)
	}

	openSSLCertPaths = []string{filepath.Join(root, "missing-openssl")}
	got, err = opensslStore{}.findCertPath()
	if err != nil || got != gitPEM {
		t.Fatalf("git http.sslCAInfo got %s err %v", got, err)
	}
}

func TestLibreSSL_AbsentKeepsOpenSSLPaths(t *testing.T) {
	isolateOpenSSLLookup(t)
	libre := filepath.Join(t.TempDir(), "cert.pem")
	opensslPEM := filepath.Join(t.TempDir(), "ca-bundle.crt")
	for _, p := range []string{libre, opensslPEM} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	libreSSLCertPaths = []string{libre}
	orig := openSSLCertPaths
	openSSLCertPaths = []string{opensslPEM}
	t.Cleanup(func() { openSSLCertPaths = orig })

	got, err := opensslStore{}.findCertPath()
	if err != nil {
		t.Fatal(err)
	}
	if got != opensslPEM {
		t.Fatalf("got %s want OpenSSL path %s", got, opensslPEM)
	}
}

func TestLibreSSL_SystemCertPEM(t *testing.T) {
	isolateOpenSSLLookup(t)
	bin, _ := writeFakeSSL(t, "LibreSSL 3.8.0", 0, 0)
	libreSSLBinPaths = []string{bin}

	fallback := filepath.Join(t.TempDir(), "ca-certificates.crt")
	if err := os.WriteFile(fallback, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	refuseIfSystemOpenSSL(t, fallback)
	orig := openSSLCertPaths
	openSSLCertPaths = []string{fallback}
	t.Cleanup(func() { openSSLCertPaths = orig })

	libreSSLCertPaths = []string{defaultDarwinSSLCertPEM}
	libreSSLPathExists = func(p string) bool {
		return filepath.Clean(p) == filepath.Clean(defaultDarwinSSLCertPEM) || file.Exists(p)
	}

	for _, goos := range []string{"linux", "openbsd"} {
		opensslGOOS = goos
		got, err := opensslStore{}.findCertPath()
		if err != nil {
			t.Fatal(err)
		}
		if filepath.Clean(got) != filepath.Clean(defaultDarwinSSLCertPEM) {
			t.Fatalf("%s got %s want /etc/ssl/cert.pem", goos, got)
		}
	}

	opensslGOOS = "darwin"
	got, err := opensslStore{}.findCertPath()
	if err != nil {
		t.Fatal(err)
	}
	if got != fallback {
		t.Fatalf("darwin got %s want OpenSSL fallback %s", got, fallback)
	}
}

func TestLibreSSL_PEMBackupRestoreListRemove(t *testing.T) {
	isolateOpenSSLLookup(t)
	opensslTestHome(t)
	certs := loadLotsCerts(t, 2)
	pem := filepath.Join(t.TempDir(), "cert.pem")
	if err := certutil.ToFile(pem, certs); err != nil {
		t.Fatal(err)
	}
	refuseIfSystemOpenSSL(t, pem)
	decoy := filepath.Join(t.TempDir(), "ca-certificates.crt")
	if err := certutil.ToFile(decoy, certs[:1]); err != nil {
		t.Fatal(err)
	}

	bin, logPath := writeFakeSSL(t, "LibreSSL 2.6.4", 0, 0)
	libreSSLBinPaths = []string{bin}
	libreSSLCertPaths = []string{pem}
	orig := openSSLCertPaths
	openSSLCertPaths = []string{decoy}
	t.Cleanup(func() { openSSLCertPaths = orig })

	s := opensslStore{}
	gotPath, err := s.findCertPath()
	if err != nil || gotPath != pem {
		t.Fatalf("discover %s err %v", gotPath, err)
	}
	got, err := s.List(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(certs) {
		t.Fatalf("List len=%d want %d", len(got), len(certs))
	}
	info := s.GetInfo()
	if info.Name != "LibreSSL" || info.Version != "2.6.4" {
		t.Fatalf("GetInfo name=%q version=%q", info.Name, info.Version)
	}
	if info.Path != mustEvalSymlinks(t, pem) {
		t.Fatalf("GetInfo.Path=%q want %s", info.Path, mustEvalSymlinks(t, pem))
	}

	SetDryRun(false)
	if err := s.Backup(); err != nil {
		t.Fatal(err)
	}
	if err := certutil.ToFile(pem, certs[:1]); err != nil {
		t.Fatal(err)
	}
	if err := s.Restore(""); err != nil {
		t.Fatal(err)
	}
	restored, err := certutil.FromFile(pem)
	if err != nil {
		t.Fatal(err)
	}
	if len(restored) != len(certs) {
		t.Fatalf("after restore len=%d want %d", len(restored), len(certs))
	}
	keep := allowlist.FromCertificates([]*x509.Certificate{certs[0]})
	if err := s.Remove(keep); err != nil {
		t.Fatal(err)
	}
	left, err := certutil.FromFile(pem)
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 1 {
		t.Fatalf("after remove len=%d want 1", len(left))
	}
	if strings.Contains(readCallLog(t, logPath), "certhash") {
		t.Fatal("PEM backup/restore/remove must not run certhash")
	}
	decoyAfter, err := certutil.FromFile(decoy)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoyAfter) != 1 {
		t.Fatal("OpenSSL decoy bundle was modified")
	}
}

func TestLibreSSL_DirBackupRestoreRemoveUsesCerthash(t *testing.T) {
	isolateOpenSSLLookup(t)
	hideCRehash(t)
	opensslTestHome(t)
	bin, logPath := writeFakeSSL(t, "LibreSSL 3.9.2", 0, 0)
	libreSSLBinPaths = []string{bin}

	_, dir, certs := opensslDirEnv(t)
	libreSSLCertPaths = []string{dir}
	s := opensslStore{}
	gotPath, err := s.findCertPath()
	if err != nil || gotPath != dir {
		t.Fatalf("discover %s err %v", gotPath, err)
	}
	refuseIfSystemOpenSSL(t, gotPath)

	SetDryRun(false)
	listed, err := s.List(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != len(certs) {
		t.Fatalf("List len=%d want %d", len(listed), len(certs))
	}
	if err := s.Backup(); err != nil {
		t.Fatal(err)
	}
	removed := filepath.Join(dir, "ca-2.crt")
	if err := os.Remove(removed); err != nil {
		t.Fatal(err)
	}
	if err := s.Restore(""); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	promoted := strings.TrimSuffix(removed, ".crt") + ".pem"
	if _, err := os.Stat(promoted); err != nil {
		t.Fatalf("restored file missing (expected certhash promotion to %s): %v", promoted, err)
	}
	resolved := mustEvalSymlinks(t, dir)
	log := readCallLog(t, logPath)
	if !strings.Contains(log, "certhash "+resolved) {
		t.Fatalf("restore log %q, want certhash %s", log, resolved)
	}

	keep := allowlist.FromCertificates([]*x509.Certificate{certs[0]})
	if err := s.Remove(keep); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	left, err := s.List(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 1 {
		t.Fatalf("after remove len=%d want 1", len(left))
	}
	log = readCallLog(t, logPath)
	if strings.Count(log, "certhash "+resolved) < 2 {
		t.Fatalf("remove should certhash again, log %q", log)
	}
}

func TestLibreSSL_AddDirCerthashWithoutCRehash(t *testing.T) {
	isolateOpenSSLLookup(t)
	hideCRehash(t)
	bin, logPath := writeFakeSSL(t, "LibreSSL 3.9.2", 0, 0)
	libreSSLBinPaths = []string{bin}
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
	log := readCallLog(t, logPath)
	if !strings.Contains(log, "certhash "+mustEvalSymlinks(t, dir)) {
		t.Fatalf("log %q want certhash %s", log, mustEvalSymlinks(t, dir))
	}
	if strings.Contains(log, "unexpected") {
		t.Fatalf("unexpected command: %s", log)
	}
}

func TestLibreSSL_CerthashFailureOnAdd(t *testing.T) {
	isolateOpenSSLLookup(t)
	hideCRehash(t)
	bin, logPath := writeFakeSSL(t, "LibreSSL 3.9.2", 0, 1)
	libreSSLBinPaths = []string{bin}
	s, dir, _ := opensslDirEnv(t)
	SetDryRun(false)
	err := s.Add(extraExampleCert(t))
	if err == nil {
		t.Fatal("expected certhash failure")
	}
	log := readCallLog(t, logPath)
	if !strings.Contains(log, "certhash "+mustEvalSymlinks(t, dir)) {
		t.Fatalf("log %q", log)
	}
}

func TestLibreSSL_CerthashFailureRollsBackRestore(t *testing.T) {
	isolateOpenSSLLookup(t)
	hideCRehash(t)
	bin, logPath := writeFakeSSL(t, "LibreSSL 3.9.2", 0, 1)
	libreSSLBinPaths = []string{bin}
	s, dir, _ := opensslDirEnv(t)
	SetDryRun(false)
	if err := s.Backup(); err != nil {
		t.Fatal(err)
	}
	removed := filepath.Join(dir, "ca-2.crt")
	if err := os.Remove(removed); err != nil {
		t.Fatal(err)
	}
	err := s.Restore("")
	if err == nil {
		t.Fatal("expected restore to fail when certhash fails")
	}
	if _, statErr := os.Stat(removed); !os.IsNotExist(statErr) {
		t.Fatalf("failed restore should leave live dir unchanged, stat %v", statErr)
	}
	for _, leftover := range []string{dir + ".restore-old", dir + ".restore-failed", dir + ".restore-tmp"} {
		if _, statErr := os.Stat(leftover); !os.IsNotExist(statErr) {
			t.Fatalf("leftover %s: %v", leftover, statErr)
		}
	}
	if !strings.Contains(readCallLog(t, logPath), "certhash "+mustEvalSymlinks(t, dir)) {
		t.Fatalf("log %q", readCallLog(t, logPath))
	}
}

func TestLibreSSL_DryRunPrintsCerthash(t *testing.T) {
	isolateOpenSSLLookup(t)
	hideCRehash(t)
	bin, logPath := writeFakeSSL(t, "LibreSSL 3.9.2", 0, 0)
	libreSSLBinPaths = []string{bin}
	s, dir, certs := opensslDirEnv(t)

	var buf bytes.Buffer
	SetDryRunOutput(&buf)
	SetDryRun(true)
	defer func() {
		SetDryRun(false)
		SetDryRunOutput(nil)
	}()
	if err := s.Add(extraExampleCert(t)); err != nil {
		t.Fatal(err)
	}
	keep := allowlist.FromCertificates([]*x509.Certificate{certs[0]})
	if err := s.Remove(keep); err != nil {
		t.Fatal(err)
	}
	if err := s.Backup(); err != nil {
		t.Fatal(err)
	}
	if err := s.Restore(""); err == nil {
		t.Fatal("dry-run restore with no backup should still error")
	}
	// A backup dry-run does not create a backup, so restore cannot preview
	// the directory swap. Add and remove must name certhash.
	out := buf.String()
	want := "then run " + bin + " certhash " + mustEvalSymlinks(t, dir)
	if strings.Count(out, want) < 2 {
		t.Fatalf("dry-run plan %q, want %q twice", out, want)
	}
	if strings.Contains(out, "c_rehash") {
		t.Fatalf("dry-run used c_rehash: %s", out)
	}
	if strings.Contains(readCallLog(t, logPath), "certhash") {
		t.Fatal("dry-run executed certhash")
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 3 {
		t.Fatalf("dry-run changed dir entries: %d", len(ents))
	}
}

func TestOpenSSLStore_DryRunRehashUnchangedWithoutLibreSSL(t *testing.T) {
	isolateOpenSSLLookup(t)
	rehash := findCRehash()
	if rehash == "" {
		t.Skip("c_rehash not available")
	}
	s, dir, _ := opensslDirEnv(t)
	var buf bytes.Buffer
	SetDryRunOutput(&buf)
	SetDryRun(true)
	defer func() {
		SetDryRun(false)
		SetDryRunOutput(nil)
	}()
	if err := s.Add(extraExampleCert(t)); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	want := "then run " + rehash + " " + mustEvalSymlinks(t, dir)
	if !strings.Contains(out, want) {
		t.Fatalf("plan %q, want %q", out, want)
	}
	if strings.Contains(out, "certhash") {
		t.Fatalf("plain OpenSSL dry-run used certhash: %s", out)
	}
}

func TestOpenSSLStore_AddDirRequiresCRehash(t *testing.T) {
	isolateOpenSSLLookup(t)
	hideCRehash(t)
	s, dir, _ := opensslDirEnv(t)
	before, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	SetDryRun(false)
	err = s.Add(extraExampleCert(t))
	if err == nil || err.Error() != "unable to find openssl c_rehash binary" {
		t.Fatalf("got %v", err)
	}
	after, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("add wrote without c_rehash: before=%d after=%d", len(before), len(after))
	}
}

func TestLibreSSL_AddWritesPEMAndPromotesCRTs(t *testing.T) {
	isolateOpenSSLLookup(t)
	hideCRehash(t)
	opensslTestHome(t)
	bin, _ := writeFakeSSL(t, "LibreSSL 3.9.2", 0, 0)
	libreSSLBinPaths = []string{bin}
	s, dir, certs := opensslDirEnv(t)
	extra := extraExampleCert(t)
	SetDryRun(false)
	if err := s.Add(extra); err != nil {
		t.Fatal(err)
	}
	fp := certutil.GetHexSHA256Fingerprint(*extra[0])
	if _, err := os.Stat(filepath.Join(dir, fp+".pem")); err != nil {
		t.Fatalf("added cert should be written as .pem: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, fp+".crt")); !os.IsNotExist(err) {
		t.Fatal("added cert should not be left as .crt")
	}
	for i := range certs {
		crt := filepath.Join(dir, fmt.Sprintf("ca-%d.crt", i))
		pem := filepath.Join(dir, fmt.Sprintf("ca-%d.pem", i))
		if _, err := os.Stat(pem); err != nil {
			t.Fatalf("existing %s was not promoted for certhash: %v", crt, err)
		}
		if _, err := os.Stat(crt); !os.IsNotExist(err) {
			t.Fatalf("leftover %s after certhash promotion", crt)
		}
	}
	got, err := s.List(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(certs)+len(extra) {
		t.Fatalf("List len=%d want %d (duplicate .crt/.pem?)", len(got), len(certs)+len(extra))
	}
}

func TestLibreSSL_PromoteCRTSymlinkAndNameCollision(t *testing.T) {
	dir := t.TempDir()
	certs := loadLotsCerts(t, 3)
	target := filepath.Join(dir, "target-cert")
	if err := certutil.ToFile(target, certs[0:1]); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "linked.crt")
	if err := os.Symlink(filepath.Base(target), link); err != nil {
		t.Skipf("symlink: %v", err)
	}
	if err := certutil.ToFile(filepath.Join(dir, "both.crt"), certs[1:2]); err != nil {
		t.Fatal(err)
	}
	if err := certutil.ToFile(filepath.Join(dir, "both.pem"), certs[2:3]); err != nil {
		t.Fatal(err)
	}
	if err := promoteCRTsForCerthash(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "linked.pem")); err != nil {
		t.Fatalf("symlink .crt was not aliased as .pem: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "both.crt.pem")); err != nil {
		t.Fatalf("colliding .crt was not aliased: %v", err)
	}

	// A .pem symlink to a .crt outside the store, and a regular foo.crt.pem
	// that holds a different certificate than foo.crt, must stay in List.
	outside := filepath.Join(t.TempDir(), "outside.crt")
	if err := certutil.ToFile(outside, extraExampleCert(t)); err != nil {
		t.Fatal(err)
	}
	outsidePEM := filepath.Join(dir, "outside-link.pem")
	if err := os.Symlink(outside, outsidePEM); err != nil {
		t.Skipf("symlink: %v", err)
	}
	if isCerthashAliasPEM(outsidePEM) {
		t.Fatal("pem symlink to a .crt outside the store must not be treated as an alias")
	}

	got, err := opensslStoreAt(dir).List(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("List len=%d want 4 (alias skipped, outside pem counted)", len(got))
	}
}

func TestLibreSSL_RemoveDropsAliasesAndKeepsIndependentPEMs(t *testing.T) {
	isolateOpenSSLLookup(t)
	hideCRehash(t)
	opensslTestHome(t)
	bin, _ := writeFakeSSL(t, "LibreSSL 3.9.2", 0, 0)
	libreSSLBinPaths = []string{bin}

	dir := t.TempDir()
	certs := loadLotsCerts(t, 3)
	if err := certutil.ToFile(filepath.Join(dir, "keep.pem"), certs[0:1]); err != nil {
		t.Fatal(err)
	}
	if err := certutil.ToFile(filepath.Join(dir, "drop.crt"), certs[1:2]); err != nil {
		t.Fatal(err)
	}
	if err := certutil.ToFile(filepath.Join(dir, "drop.pem"), certs[2:3]); err != nil {
		t.Fatal(err)
	}
	if err := promoteCRTsForCerthash(dir); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(dir, "drop.crt.pem")
	if _, err := os.Lstat(alias); err != nil {
		t.Fatalf("expected alias %s: %v", alias, err)
	}

	s := opensslStoreAt(dir)
	refuseIfSystemOpenSSL(t, dir)
	SetDryRun(false)
	keep := allowlist.FromCertificates([]*x509.Certificate{certs[0], certs[2]})
	if err := s.Remove(keep); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "drop.crt")); !os.IsNotExist(err) {
		t.Fatal("removed .crt is still present")
	}
	if _, err := os.Lstat(alias); !os.IsNotExist(err) {
		t.Fatal("dangling alias left behind after removing .crt")
	}
	if _, err := os.Stat(filepath.Join(dir, "drop.pem")); err != nil {
		t.Fatalf("independent drop.pem should be kept: %v", err)
	}
	got, err := s.List(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("List len=%d want 2", len(got))
	}
}

func TestLibreSSL_RealCerthashHashLinks(t *testing.T) {
	bin := findLibreSSLCerthash(t)
	if bin == "" {
		t.Skip("no LibreSSL openssl with working certhash")
	}
	isolateOpenSSLLookup(t)
	hideCRehash(t)
	opensslTestHome(t)
	libreSSLBinPaths = []string{bin}
	s, dir, certs := opensslDirEnv(t)
	extra := extraExampleCert(t)
	target := filepath.Join(dir, "target-cert")
	if err := certutil.ToFile(target, extra); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Base(target), filepath.Join(dir, "linked.crt")); err != nil {
		t.Skipf("symlink: %v", err)
	}
	// Collision: same basename, different certificate than ca-0.crt.
	if err := certutil.ToFile(filepath.Join(dir, "ca-0.pem"), extra); err != nil {
		t.Fatal(err)
	}
	SetDryRun(false)
	if err := s.Backup(); err != nil {
		t.Fatal(err)
	}
	if err := s.Restore(""); err != nil {
		t.Fatalf("Restore/certhash: %v", err)
	}
	assertCerthashLinks(t, dir)
	got, err := s.List(nil)
	if err != nil {
		t.Fatal(err)
	}
	// opensslDirEnv has 3 certs; plus linked extra and ca-0.pem extra. linked.crt aliases extra,
	// ca-0.pem is a second copy of extra, ca-0.crt is certs[0]. Unique: certs[0], certs[1], certs[2], extra = 4
	if len(got) != 4 {
		t.Fatalf("List len=%d want 4", len(got))
	}
	keep := allowlist.FromCertificates([]*x509.Certificate{certs[0], certs[1], certs[2]})
	if err := s.Remove(keep); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	got, err = s.List(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("after remove List len=%d want 3", len(got))
	}
	if _, err := os.Lstat(filepath.Join(dir, "linked.crt")); !os.IsNotExist(err) {
		t.Fatal("removed linked.crt still present")
	}
	if _, err := os.Lstat(filepath.Join(dir, "linked.pem")); !os.IsNotExist(err) {
		t.Fatal("alias for removed linked.crt still present")
	}
	assertCerthashLinks(t, dir)
}

func assertCerthashLinks(t *testing.T, dir string) {
	t.Helper()
	pems, err := filepath.Glob(filepath.Join(dir, "*.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if len(pems) == 0 {
		t.Fatal("no .pem files for certhash to scan")
	}
	linked := pemsWithHashLinks(t, dir)
	if len(linked) == 0 {
		t.Fatal("certhash created no hash links")
	}
	for _, p := range pems {
		if isCerthashAliasPEM(p) {
			// alias must still be reachable via a hash link
		}
		if !linked[filepath.Base(p)] && !linked[p] {
			t.Errorf("no hash link points at %s", p)
		}
	}
}

func findLibreSSLCerthash(t *testing.T) string {
	t.Helper()
	candidates := []string{
		"/usr/local/opt/libressl/bin/openssl",
		"/opt/homebrew/opt/libressl/bin/openssl",
		darwinSystemOpenSSL,
	}
	if p, err := exec.LookPath("openssl"); err == nil {
		candidates = append(candidates, p)
	}
	for _, bin := range candidates {
		st, err := os.Stat(bin)
		if err != nil || st.IsDir() {
			continue
		}
		out, err := exec.Command(bin, "version").CombinedOutput()
		if err != nil || !strings.HasPrefix(strings.TrimSpace(string(out)), "LibreSSL") {
			continue
		}
		cmd := exec.Command(bin, "certhash", t.TempDir())
		if err := cmd.Run(); err != nil {
			continue
		}
		return bin
	}
	return ""
}

func pemsWithHashLinks(t *testing.T, dir string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, ent := range ents {
		name := ent.Name()
		if !isOpenSSLHashLinkName(name) {
			continue
		}
		path := filepath.Join(dir, name)
		st, err := os.Lstat(path)
		if err != nil || st.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("hash name %s is not a symlink", name)
		}
		target, err := os.Readlink(path)
		if err != nil {
			t.Fatal(err)
		}
		out[target] = true
		out[filepath.Base(target)] = true
	}
	return out
}

func isOpenSSLHashLinkName(name string) bool {
	if len(name) < 10 || name[8] != '.' {
		return false
	}
	for i := 0; i < 8; i++ {
		c := name[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	rest := strings.TrimPrefix(name[9:], "r")
	if rest == "" {
		return false
	}
	for i := 0; i < len(rest); i++ {
		if rest[i] < '0' || rest[i] > '9' {
			return false
		}
	}
	return true
}

func writeFakeSSL(t *testing.T, version string, versionExit, certhashExit int) (bin, logPath string) {
	t.Helper()
	dir := t.TempDir()
	logPath = filepath.Join(dir, "calls.log")
	if runtime.GOOS == "windows" {
		bin = filepath.Join(dir, "openssl.cmd")
		script := fmt.Sprintf("@echo off\r\n"+
			"set \"LOG=%s\"\r\n"+
			"if /I \"%%~1\"==\"version\" (\r\n"+
			"  >>\"%%LOG%%\" echo version\r\n"+
			"  echo %s\r\n"+
			"  exit /b %d\r\n"+
			")\r\n"+
			"if /I \"%%~1\"==\"certhash\" (\r\n"+
			"  >>\"%%LOG%%\" echo certhash %%~2\r\n"+
			"  exit /b %d\r\n"+
			")\r\n"+
			">>\"%%LOG%%\" echo unexpected %%*\r\n"+
			"exit /b 1\r\n",
			logPath, version, versionExit, certhashExit)
		if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
		return bin, logPath
	}
	bin = filepath.Join(dir, "openssl")
	script := fmt.Sprintf(`#!/bin/sh
log=%s
if [ "$1" = "version" ]; then
  printf 'version\n' >> "$log"
  printf '%%s\n' %s
  exit %d
fi
if [ "$1" = "certhash" ]; then
  printf 'certhash %%s\n' "$2" >> "$log"
  exit %d
fi
printf 'unexpected %%s\n' "$*" >> "$log"
exit 1
`, quoteShell(logPath), quoteShell(version), versionExit, certhashExit)
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin, logPath
}

func quoteShell(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

func readCallLog(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ""
		}
		t.Fatal(err)
	}
	return string(b)
}

func hideCRehash(t *testing.T) {
	t.Helper()
	origPaths := openSSLRehashPaths
	openSSLRehashPaths = nil
	origLook := cRehashLookPath
	cRehashLookPath = func(string) (string, error) {
		return "", errors.New("c_rehash not on PATH")
	}
	t.Cleanup(func() {
		openSSLRehashPaths = origPaths
		cRehashLookPath = origLook
	})
}

func loadLotsCerts(t *testing.T, min int) []*x509.Certificate {
	t.Helper()
	certs, err := certutil.FromFile(filepath.Join("..", "..", "testdata", "lots.crt"))
	if err != nil || len(certs) < min {
		t.Fatalf("load lots.crt: len=%d err=%v", len(certs), err)
	}
	return certs
}
