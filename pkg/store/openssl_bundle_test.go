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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adamdecaf/trustprune/pkg/certutil"
)

func TestOpenSSLBundleAt_RejectsDirAndMissing(t *testing.T) {
	dir := t.TempDir()
	_, err := OpenSSLBundleAt(dir)
	if err == nil || !strings.Contains(err.Error(), "is a directory") {
		t.Fatalf("directory: %v", err)
	}
	missing := filepath.Join(dir, "missing.pem")
	_, err = OpenSSLBundleAt(missing)
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("missing: %v", err)
	}
	if _, err := OpenSSLBundleAt("  "); err == nil {
		t.Fatal("expected empty -bundle path to fail")
	}
}

func TestOpenSSLBundle_ExplicitPEMIgnoresDiscovery(t *testing.T) {
	opensslTestHome(t)
	certs, err := certutil.FromFile(filepath.Join("..", "..", "testdata", "lots.crt"))
	if err != nil || len(certs) < 2 {
		t.Fatalf("lots.crt: len=%d err=%v", len(certs), err)
	}
	one, err := certutil.FromFile(filepath.Join("..", "..", "testdata", "example.crt"))
	if err != nil || len(one) == 0 {
		t.Fatalf("example.crt: %v", err)
	}
	if len(one) == len(certs) {
		t.Fatal("fixture bundles have the same count; cannot tell them apart")
	}

	dir := t.TempDir()
	bundle := filepath.Join(dir, "ca-bundle.pem")
	decoy := filepath.Join(dir, "decoy.pem")
	if err := certutil.ToFile(bundle, certs); err != nil {
		t.Fatal(err)
	}
	if err := certutil.ToFile(decoy, one); err != nil {
		t.Fatal(err)
	}
	refuseIfSystemOpenSSL(t, bundle)
	refuseIfSystemOpenSSL(t, decoy)
	decoyBefore, err := os.ReadFile(decoy)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", decoy)
	t.Setenv("CURL_CA_BUNDLE", decoy)

	st, err := OpenSSLBundleAt(bundle)
	if err != nil {
		t.Fatal(err)
	}
	got, err := st.List(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(certs) {
		t.Fatalf("List len=%d want %d (decoy has %d); -bundle followed discovery", len(got), len(certs), len(one))
	}
	decoyAfter, err := os.ReadFile(decoy)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoyBefore, decoyAfter) {
		t.Fatal("listing -bundle mutated SSL_CERT_FILE")
	}
}

func TestOpenSSLBundle_BackupRestoreIsPerPEM(t *testing.T) {
	opensslTestHome(t)
	SetDryRun(false)
	SetForceRestore(false)
	t.Cleanup(func() {
		SetDryRun(false)
		SetForceRestore(false)
	})

	certs, err := certutil.FromFile(filepath.Join("..", "..", "testdata", "lots.crt"))
	if err != nil || len(certs) < 2 {
		t.Fatalf("lots.crt: len=%d err=%v", len(certs), err)
	}
	dir := t.TempDir()
	pathA := filepath.Join(dir, "a.pem")
	pathB := filepath.Join(dir, "b.pem")
	if err := certutil.ToFile(pathA, certs); err != nil {
		t.Fatal(err)
	}
	if err := certutil.ToFile(pathB, certs[:1]); err != nil {
		t.Fatal(err)
	}
	refuseIfSystemOpenSSL(t, pathA)
	refuseIfSystemOpenSSL(t, pathB)
	origA, err := os.ReadFile(pathA)
	if err != nil {
		t.Fatal(err)
	}
	origB, err := os.ReadFile(pathB)
	if err != nil {
		t.Fatal(err)
	}

	sA := opensslStoreAt(pathA)
	sB := opensslStoreAt(pathB)
	if err := sA.Backup(); err != nil {
		t.Fatal(err)
	}
	if err := sB.Backup(); err != nil {
		t.Fatal(err)
	}
	latestA, err := sA.GetLatestBackup()
	if err != nil || latestA == "" {
		t.Fatalf("backup A: %q err=%v", latestA, err)
	}
	latestB, err := sB.GetLatestBackup()
	if err != nil || latestB == "" {
		t.Fatalf("backup B: %q err=%v", latestB, err)
	}
	if latestA == latestB {
		t.Fatalf("distinct PEMs shared backup %s", latestA)
	}
	recorded, err := os.ReadFile(filepath.Join(latestA, opensslBackupSourceName))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(recorded)) != opensslCanonicalPath(pathA) {
		t.Fatalf("source=%q want %q", strings.TrimSpace(string(recorded)), opensslCanonicalPath(pathA))
	}

	t.Setenv("SSL_CERT_FILE", pathA)
	t.Setenv("CURL_CA_BUNDLE", "")
	discLatest, err := (opensslStore{}).GetLatestBackup()
	if err != nil {
		t.Fatal(err)
	}
	if discLatest != latestA {
		t.Fatalf("discovery latest=%s want backup of SSL_CERT_FILE %s (not newer %s)", discLatest, latestA, latestB)
	}

	if err := os.WriteFile(pathA, []byte("MUTATED\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := sA.Restore(""); err != nil {
		t.Fatalf("restore A: %v", err)
	}
	gotA, err := os.ReadFile(pathA)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotA, origA) {
		t.Fatal("explicit restore did not put A's backup back")
	}
	gotB, err := os.ReadFile(pathB)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotB, origB) {
		t.Fatal("restore of A mutated B")
	}

	err = sB.Restore(latestA)
	if err == nil || !strings.Contains(err.Error(), "refusing restore") {
		t.Fatalf("cross-path restore: %v", err)
	}
	gotB, err = os.ReadFile(pathB)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotB, origB) {
		t.Fatal("refused cross-path restore mutated B")
	}

	SetDryRun(true)
	err = sB.Restore(latestA)
	SetDryRun(false)
	if err == nil || !strings.Contains(err.Error(), "refusing restore") {
		t.Fatalf("dry-run cross-path: %v", err)
	}
	gotB, err = os.ReadFile(pathB)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotB, origB) {
		t.Fatal("dry-run cross-path restore mutated B")
	}

	SetForceRestore(true)
	if err := sB.Restore(latestA); err != nil {
		t.Fatalf("forced restore: %v", err)
	}
	gotB, err = os.ReadFile(pathB)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotB, origA) {
		t.Fatal("forced restore did not write A's backup into B")
	}
}

func opensslPEMPair(t *testing.T) (home, pathA, pathB string, origA, origB []byte) {
	t.Helper()
	home = opensslTestHome(t)
	certsA, err := certutil.FromFile(filepath.Join("..", "..", "testdata", "lots.crt"))
	if err != nil || len(certsA) < 2 {
		t.Fatalf("lots.crt: len=%d err=%v", len(certsA), err)
	}
	certsB := extraExampleCert(t)
	dir := t.TempDir()
	pathA = filepath.Join(dir, "a.pem")
	pathB = filepath.Join(dir, "b.pem")
	if err := certutil.ToFile(pathA, certsA); err != nil {
		t.Fatal(err)
	}
	if err := certutil.ToFile(pathB, certsB); err != nil {
		t.Fatal(err)
	}
	refuseIfSystemOpenSSL(t, pathA)
	refuseIfSystemOpenSSL(t, pathB)
	origA, err = os.ReadFile(pathA)
	if err != nil {
		t.Fatal(err)
	}
	origB, err = os.ReadFile(pathB)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(origA, origB) {
		t.Fatal("fixture PEMs are identical")
	}
	return home, pathA, pathB, origA, origB
}

// writeOpenSSLSourceLessBackup creates an openssl backup directory that has
// ca-bundle.pem and no source sidecar. The timestamp is old so a later Backup
// of another bundle is newer.
func writeOpenSSLSourceLessBackup(t *testing.T, home string, pem []byte) string {
	t.Helper()
	dir := filepath.Join(primaryBackupParent(home), opensslBackupDir, "100")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, opensslBackupFilename), pem, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, opensslBackupSourceName)); !os.IsNotExist(err) {
		t.Fatalf("source-less fixture has a source file: %v", err)
	}
	return dir
}

func TestOpenSSLBundle_DiscoveryRestoreRefusesMismatchedBackup(t *testing.T) {
	_, pathA, pathB, origA, origB := opensslPEMPair(t)
	SetDryRun(false)
	SetForceRestore(false)
	t.Cleanup(func() {
		SetDryRun(false)
		SetForceRestore(false)
	})
	t.Setenv("SSL_CERT_FILE", pathA)
	t.Setenv("CURL_CA_BUNDLE", "")

	sB := opensslStoreAt(pathB)
	if err := sB.Backup(); err != nil {
		t.Fatal(err)
	}
	latestB, err := sB.GetLatestBackup()
	if err != nil || latestB == "" {
		t.Fatalf("backup B: %q err=%v", latestB, err)
	}

	disc := opensslStore{}
	err = disc.Restore(latestB)
	if err == nil || !strings.Contains(err.Error(), "refusing restore") {
		t.Fatalf("discovery cross-path restore: %v", err)
	}
	gotA, err := os.ReadFile(pathA)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotA, origA) {
		t.Fatal("refused discovery restore mutated A")
	}

	SetDryRun(true)
	err = disc.Restore(latestB)
	SetDryRun(false)
	if err == nil || !strings.Contains(err.Error(), "refusing restore") {
		t.Fatalf("dry-run discovery cross-path: %v", err)
	}
	gotA, err = os.ReadFile(pathA)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotA, origA) {
		t.Fatal("dry-run discovery restore mutated A")
	}

	SetForceRestore(true)
	if err := disc.Restore(latestB); err != nil {
		t.Fatalf("forced discovery restore: %v", err)
	}
	gotA, err = os.ReadFile(pathA)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotA, origB) {
		t.Fatal("forced discovery restore did not write B's backup into A")
	}
	gotB, err := os.ReadFile(pathB)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotB, origB) {
		t.Fatal("forced discovery restore mutated B")
	}
}

func TestOpenSSLBundle_DiscoveryGetLatestBackupRequiresMatchingSource(t *testing.T) {
	_, pathA, pathB, _, _ := opensslPEMPair(t)
	t.Setenv("SSL_CERT_FILE", pathA)
	t.Setenv("CURL_CA_BUNDLE", "")

	sB := opensslStoreAt(pathB)
	if err := sB.Backup(); err != nil {
		t.Fatal(err)
	}
	latestB, err := sB.GetLatestBackup()
	if err != nil || latestB == "" {
		t.Fatalf("backup B: %q err=%v", latestB, err)
	}

	got, err := (opensslStore{}).GetLatestBackup()
	if err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Fatalf("discovery GetLatestBackup=%q want empty when only B is backed up (%s)", got, latestB)
	}

	sA := opensslStoreAt(pathA)
	if err := sA.Backup(); err != nil {
		t.Fatal(err)
	}
	latestA, err := sA.GetLatestBackup()
	if err != nil || latestA == "" {
		t.Fatalf("backup A: %q err=%v", latestA, err)
	}
	if latestA == latestB {
		t.Fatal("A and B shared a backup directory")
	}
	got, err = (opensslStore{}).GetLatestBackup()
	if err != nil {
		t.Fatal(err)
	}
	if got != latestA {
		t.Fatalf("discovery GetLatestBackup=%q want A's backup %q", got, latestA)
	}
}

func TestOpenSSLBundle_DiscoveryAcceptsLegacySourceLessBackup(t *testing.T) {
	home, pathA, pathB, origA, origB := opensslPEMPair(t)
	SetDryRun(false)
	SetForceRestore(false)
	t.Cleanup(func() {
		SetDryRun(false)
		SetForceRestore(false)
	})
	t.Setenv("SSL_CERT_FILE", pathA)
	t.Setenv("CURL_CA_BUNDLE", "")

	legacy := writeOpenSSLSourceLessBackup(t, home, origA)
	sB := opensslStoreAt(pathB)
	if err := sB.Backup(); err != nil {
		t.Fatal(err)
	}
	latestB, err := sB.GetLatestBackup()
	if err != nil || latestB == "" {
		t.Fatalf("backup B: %q err=%v", latestB, err)
	}
	if latestB == legacy {
		t.Fatal("B's backup reused the source-less directory")
	}

	got, err := (opensslStore{}).GetLatestBackup()
	if err != nil {
		t.Fatal(err)
	}
	if got != legacy {
		t.Fatalf("discovery GetLatestBackup=%q want source-less %q (not newer %q)", got, legacy, latestB)
	}
	explicit, err := opensslStoreAt(pathA).GetLatestBackup()
	if err != nil {
		t.Fatal(err)
	}
	if explicit != "" {
		t.Fatalf("explicit PEM GetLatestBackup=%q want empty (source-less and other bundles skipped)", explicit)
	}

	if err := os.WriteFile(pathA, []byte("MUTATED\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := (opensslStore{}).Restore(""); err != nil {
		t.Fatalf("discovery restore of source-less backup: %v", err)
	}
	gotA, err := os.ReadFile(pathA)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotA, origA) {
		t.Fatal("discovery restore did not apply the source-less backup")
	}
	gotB, err := os.ReadFile(pathB)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotB, origB) {
		t.Fatal("discovery restore mutated B")
	}
}

func TestOpenSSLBundle_UnresolvedDiscoveryMatchesOnlySourceLess(t *testing.T) {
	home, pathA, _, origA, _ := opensslPEMPair(t)
	isolateOpenSSLLookup(t)
	origPaths := openSSLCertPaths
	t.Cleanup(func() { openSSLCertPaths = origPaths })
	openSSLCertPaths = []string{filepath.Join(t.TempDir(), "missing-ca.pem")}

	legacy := writeOpenSSLSourceLessBackup(t, home, origA)
	sA := opensslStoreAt(pathA)
	if err := sA.Backup(); err != nil {
		t.Fatal(err)
	}
	latestA, err := sA.GetLatestBackup()
	if err != nil || latestA == "" {
		t.Fatalf("backup A: %q err=%v", latestA, err)
	}
	if latestA == legacy {
		t.Fatal("A's backup reused the source-less directory")
	}

	got, err := (opensslStore{}).GetLatestBackup()
	if err != nil {
		t.Fatal(err)
	}
	if got != legacy {
		t.Fatalf("unresolved discovery GetLatestBackup=%q want source-less %q (not recorded %q)", got, legacy, latestA)
	}

	if err := os.RemoveAll(legacy); err != nil {
		t.Fatal(err)
	}
	got, err = (opensslStore{}).GetLatestBackup()
	if err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Fatalf("unresolved discovery GetLatestBackup=%q want empty when only a recorded backup remains", got)
	}
}
