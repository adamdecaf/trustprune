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
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestStoreNSS_certdbDiscovery(t *testing.T) {
	// create a dir, add a 'cert.db' file and verify we can discover it
	tmp, err := os.MkdirTemp("", "nss-discovery")
	if err != nil {
		t.Error(err)
	}
	defer os.Remove(tmp)

	// Verify we don't find anything in an empty dir
	if containsCertdb(tmp) {
		t.Errorf("%s shouldn't contain a cert.db", tmp)
	}

	// Create a blank cert.db file
	where := filepath.Join(tmp, "cert9.db")
	err = os.WriteFile(where, []byte("data"), 0644)
	if err != nil {
		t.Error(err)
	}

	// Now we should find the cert.db path
	if !containsCertdb(tmp) {
		t.Errorf("should have found cert.db in %s", tmp)
	}
}

func TestNSSAppendScheme_Cert9Directory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cert9.db"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	got := cutil.appendScheme(dir)
	want := "sql:" + dir
	if got != want {
		t.Fatalf("appendScheme(cert9 dir)=%q want %q", got, want)
	}
}

func TestNSSAppendScheme_Cert8Directory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cert8.db"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	got := cutil.appendScheme(dir)
	want := "dbm:" + dir
	if got != want {
		t.Fatalf("appendScheme(cert8 dir)=%q want %q", got, want)
	}
}

func TestNSSAppendScheme_PrefersCert9WhenBothPresent(t *testing.T) {
	// Firefox leaves cert8.db after migrating to the shared DB.
	dir := t.TempDir()
	for _, name := range []string{"cert9.db", "cert8.db"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	got := cutil.appendScheme(dir)
	want := "sql:" + dir
	if got != want {
		t.Fatalf("appendScheme(both)=%q want %q", got, want)
	}
}

func TestNSSAppendScheme_FilePathUsesParent(t *testing.T) {
	dir := t.TempDir()
	cert9 := filepath.Join(dir, "cert9.db")
	if err := os.WriteFile(cert9, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	got := cutil.appendScheme(cert9)
	want := "sql:" + dir
	if got != want {
		t.Fatalf("appendScheme(cert9 file)=%q want %q", got, want)
	}

	cert8 := filepath.Join(dir, "cert8.db")
	if err := os.WriteFile(cert8, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	// Explicit cert8.db path still selects dbm: even if cert9 exists alongside.
	got = cutil.appendScheme(cert8)
	want = "dbm:" + dir
	if got != want {
		t.Fatalf("appendScheme(cert8 file)=%q want %q", got, want)
	}
}

func TestNSSNotifyToRestart_OnlyCert8(t *testing.T) {
	capture := func(fn func()) []byte {
		t.Helper()
		old := os.Stdout
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		os.Stdout = w
		defer func() { os.Stdout = old }()
		fn()
		_ = w.Close()
		out, err := io.ReadAll(r)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}

	cert8Dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(cert8Dir, "cert8.db"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	s := nssStore{nssType: "firefox-test", foundCertdbLocation: cert8Dir, notify: &sync.Once{}}
	out := capture(func() {
		s.notifyToRestart()
		s.notifyToRestart() // Once: second call must not print again
	})
	if !bytes.Contains(out, []byte("Restart Firefox-test")) {
		t.Fatalf("expected restart hint on stdout, got %q", out)
	}
	if bytes.Count(out, []byte("Restart Firefox-test")) != 1 {
		t.Fatalf("expected single restart hint, got %q", out)
	}

	cert9Dir := t.TempDir()
	for _, name := range []string{"cert9.db", "cert8.db"} {
		if err := os.WriteFile(filepath.Join(cert9Dir, name), []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	s = nssStore{nssType: "firefox-test", foundCertdbLocation: cert9Dir, notify: &sync.Once{}}
	out = capture(func() { s.notifyToRestart() })
	if len(out) != 0 {
		t.Fatalf("cert9 profile should not print restart hint, got %q", out)
	}
}

func TestStoreNSS_trustedForSSL(t *testing.T) {
	trusted := map[string]bool{
		// trusted attrs
		"c,c,c": true,
		",,":    true,
		"CT,,":  true,
		"u,,":   true,
		"wC,,":  true,
		// not trusted
		"p,p,p": false,
		"p,,":   false,
	}
	for attrs, answer := range trusted {
		item := certdbItem{trustAttrs: attrs}
		if res := item.trustedForSSL(); res != answer {
			t.Errorf("attrs (%s), trustedForSSL()=%v should be %v", attrs, res, answer)
		}
	}
}

func TestStoreNSS_BackupCert9ProfileSet(t *testing.T) {
	// cert9 layout: cert9.db + key4.db + pkcs11.txt (copy whichever exist).
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	nssdbDir := filepath.Join(t.TempDir(), "nssdb")
	if err := os.MkdirAll(nssdbDir, 0755); err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{
		"cert9.db":      []byte("cert9-payload\n"),
		"key4.db":       []byte("key4-payload\n"),
		"pkcs11.txt":    []byte("pkcs11-payload\n"),
		"unrelated.txt": []byte("should-not-be-backed-up\n"),
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(nssdbDir, name), body, 0644); err != nil {
			t.Fatal(err)
		}
	}

	s := NssStore("firefox-test", "0", nssdbDir)
	if err := s.Backup(); err != nil {
		t.Fatalf("Backup: %v", err)
	}
	latest, err := s.GetLatestBackup()
	if err != nil || latest == "" {
		t.Fatalf("GetLatestBackup: path=%q err=%v", latest, err)
	}
	st, err := os.Stat(latest)
	if err != nil || !st.IsDir() {
		t.Fatalf("latest backup should be a directory, got %s err=%v", latest, err)
	}
	for _, name := range []string{"cert9.db", "key4.db", "pkcs11.txt"} {
		got, err := os.ReadFile(filepath.Join(latest, name))
		if err != nil {
			t.Fatalf("missing %s in backup: %v", name, err)
		}
		if !bytes.Equal(got, files[name]) {
			t.Fatalf("%s content mismatch", name)
		}
	}
	if _, err := os.Stat(filepath.Join(latest, "unrelated.txt")); !os.IsNotExist(err) {
		t.Fatal("unrelated.txt should not be in the backup set")
	}
}

func TestStoreNSS_BackupCert8ProfileSet(t *testing.T) {
	// Legacy cert8 layout: cert8.db + key3.db + secmod.db.
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	nssdbDir := filepath.Join(t.TempDir(), "nssdb")
	if err := os.MkdirAll(nssdbDir, 0755); err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{
		"cert8.db":  []byte("cert8-payload\n"),
		"key3.db":   []byte("key3-payload\n"),
		"secmod.db": []byte("secmod-payload\n"),
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(nssdbDir, name), body, 0644); err != nil {
			t.Fatal(err)
		}
	}

	s := NssStore("firefox-test", "0", nssdbDir)
	if err := s.Backup(); err != nil {
		t.Fatalf("Backup: %v", err)
	}
	latest, err := s.GetLatestBackup()
	if err != nil || latest == "" {
		t.Fatalf("GetLatestBackup: path=%q err=%v", latest, err)
	}
	for _, name := range []string{"cert8.db", "key3.db", "secmod.db"} {
		got, err := os.ReadFile(filepath.Join(latest, name))
		if err != nil {
			t.Fatalf("missing %s in backup: %v", name, err)
		}
		if !bytes.Equal(got, files[name]) {
			t.Fatalf("%s content mismatch", name)
		}
	}
}

func TestStoreNSS_BackupCert9PartialSet(t *testing.T) {
	// Copy whichever members of the set exist (cert9.db required to select the set).
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	nssdbDir := filepath.Join(t.TempDir(), "nssdb")
	if err := os.MkdirAll(nssdbDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nssdbDir, "cert9.db"), []byte("cert9-only\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nssdbDir, "key4.db"), []byte("key4-only\n"), 0644); err != nil {
		t.Fatal(err)
	}
	// pkcs11.txt intentionally absent

	s := NssStore("firefox-test", "0", nssdbDir)
	if err := s.Backup(); err != nil {
		t.Fatalf("Backup: %v", err)
	}
	latest, err := s.GetLatestBackup()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(latest, "cert9.db")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(latest, "key4.db")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(latest, "pkcs11.txt")); !os.IsNotExist(err) {
		t.Fatal("pkcs11.txt should be absent from backup when missing in profile")
	}
}

func TestStoreNSS_BackupRestoreCert9ProfileRoundTrip(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	nssdbDir := filepath.Join(t.TempDir(), "nssdb")
	if err := os.MkdirAll(nssdbDir, 0755); err != nil {
		t.Fatal(err)
	}
	original := map[string][]byte{
		"cert9.db":   []byte("cert9-rt\n"),
		"key4.db":    []byte("key4-rt\n"),
		"pkcs11.txt": []byte("pkcs11-rt\n"),
	}
	for name, body := range original {
		if err := os.WriteFile(filepath.Join(nssdbDir, name), body, 0644); err != nil {
			t.Fatal(err)
		}
	}

	s := NssStore("firefox-test", "0", nssdbDir)
	if err := s.Backup(); err != nil {
		t.Fatalf("Backup: %v", err)
	}
	for name := range original {
		if err := os.WriteFile(filepath.Join(nssdbDir, name), []byte("mutated-"+name+"\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Restore(""); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	for name, want := range original {
		got, err := os.ReadFile(filepath.Join(nssdbDir, name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s after restore: got %q want %q", name, got, want)
		}
	}
}

func TestStoreNSS_BackupRestoreCert8ProfileRoundTrip(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	nssdbDir := filepath.Join(t.TempDir(), "nssdb")
	if err := os.MkdirAll(nssdbDir, 0755); err != nil {
		t.Fatal(err)
	}
	original := map[string][]byte{
		"cert8.db":  []byte("cert8-rt\n"),
		"key3.db":   []byte("key3-rt\n"),
		"secmod.db": []byte("secmod-rt\n"),
	}
	for name, body := range original {
		if err := os.WriteFile(filepath.Join(nssdbDir, name), body, 0644); err != nil {
			t.Fatal(err)
		}
	}

	s := NssStore("firefox-test", "0", nssdbDir)
	if err := s.Backup(); err != nil {
		t.Fatalf("Backup: %v", err)
	}
	for name := range original {
		if err := os.WriteFile(filepath.Join(nssdbDir, name), []byte("mutated-"+name+"\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Restore(""); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	for name, want := range original {
		got, err := os.ReadFile(filepath.Join(nssdbDir, name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s after restore: got %q want %q", name, got, want)
		}
	}
}

func TestStoreNSS_RestoreHonorsWhereFolder(t *testing.T) {
	// Restore(where) with a directory must copy the full profile set from that folder.
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	nssdbDir := filepath.Join(t.TempDir(), "nssdb")
	if err := os.MkdirAll(nssdbDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nssdbDir, "cert9.db"), []byte("live-cert9\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nssdbDir, "key4.db"), []byte("live-key4\n"), 0644); err != nil {
		t.Fatal(err)
	}

	alternate := t.TempDir()
	want := map[string][]byte{
		"cert9.db":   []byte("alt-cert9\n"),
		"key4.db":    []byte("alt-key4\n"),
		"pkcs11.txt": []byte("alt-pkcs11\n"),
	}
	for name, body := range want {
		if err := os.WriteFile(filepath.Join(alternate, name), body, 0644); err != nil {
			t.Fatal(err)
		}
	}

	s := NssStore("firefox-test", "0", nssdbDir)
	if err := s.Restore(alternate); err != nil {
		t.Fatalf("Restore(where folder): %v", err)
	}
	for name, body := range want {
		got, err := os.ReadFile(filepath.Join(nssdbDir, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !bytes.Equal(got, body) {
			t.Fatalf("%s: got %q want %q", name, got, body)
		}
	}
}

func TestStoreNSS_RestoreHonorsWhereSingleFile(t *testing.T) {
	// Legacy single-file -file path still restores to cert9.db.
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	nssdbDir := filepath.Join(t.TempDir(), "nssdb")
	if err := os.MkdirAll(nssdbDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nssdbDir, "cert9.db"), []byte("live-cert9\n"), 0644); err != nil {
		t.Fatal(err)
	}

	alternate := filepath.Join(t.TempDir(), "alternate-cert.db")
	alt := []byte("ALTERNATE-NSS-BACKUP\n")
	if err := os.WriteFile(alternate, alt, 0644); err != nil {
		t.Fatal(err)
	}

	s := NssStore("firefox-test", "0", nssdbDir)
	if err := s.Restore(alternate); err != nil {
		t.Fatalf("Restore(where file): %v", err)
	}
	got, err := os.ReadFile(filepath.Join(nssdbDir, "cert9.db"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, alt) {
		t.Fatalf("Restore did not honor where file; got %q want %q", got, alt)
	}
}

func TestStoreNSS_FailedStageLeavesLiveIntact(t *testing.T) {
	// A mid-stage copy failure must not mutate live profile files.
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	nssdbDir := filepath.Join(t.TempDir(), "nssdb")
	if err := os.MkdirAll(nssdbDir, 0755); err != nil {
		t.Fatal(err)
	}
	live := map[string][]byte{
		"cert9.db":   []byte("live-cert9\n"),
		"key4.db":    []byte("live-key4\n"),
		"pkcs11.txt": []byte("live-pkcs11\n"),
	}
	for name, body := range live {
		if err := os.WriteFile(filepath.Join(nssdbDir, name), body, 0644); err != nil {
			t.Fatal(err)
		}
	}

	backup := t.TempDir()
	if err := os.WriteFile(filepath.Join(backup, "cert9.db"), []byte("backup-cert9\n"), 0644); err != nil {
		t.Fatal(err)
	}
	// Directory where a file is expected makes CopyFile fail (EISDIR on read).
	if err := os.Mkdir(filepath.Join(backup, "key4.db"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(backup, "pkcs11.txt"), []byte("backup-pkcs11\n"), 0644); err != nil {
		t.Fatal(err)
	}

	s := NssStore("firefox-test", "0", nssdbDir)
	if err := s.Restore(backup); err == nil {
		t.Fatal("expected Restore to fail when staging key4.db")
	}
	for name, want := range live {
		got, err := os.ReadFile(filepath.Join(nssdbDir, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s mutated after failed stage: got %q want %q", name, got, want)
		}
	}
	if nssPathExists(t, nssdbDir+".restore-tmp") {
		t.Errorf("restore-tmp left behind: %s", nssdbDir+".restore-tmp")
	}
	if nssPathExists(t, nssdbDir+".restore-old") {
		t.Errorf("restore-old left behind: %s", nssdbDir+".restore-old")
	}
}

func TestStoreNSS_RestoreTmpCleanedOnStageFailure(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	nssdbDir := filepath.Join(t.TempDir(), "nssdb")
	if err := os.MkdirAll(nssdbDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nssdbDir, "cert9.db"), []byte("live\n"), 0644); err != nil {
		t.Fatal(err)
	}

	backup := t.TempDir()
	if err := os.WriteFile(filepath.Join(backup, "cert9.db"), []byte("backup\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(backup, "key4.db"), 0755); err != nil {
		t.Fatal(err)
	}

	tmp := nssdbDir + ".restore-tmp"
	if err := os.MkdirAll(tmp, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "stale"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}

	s := NssStore("firefox-test", "0", nssdbDir)
	if err := s.Restore(backup); err == nil {
		t.Fatal("expected Restore to fail")
	}
	if nssPathExists(t, tmp) {
		t.Fatalf("expected %s cleaned up after stage failure", tmp)
	}
}

func TestStoreNSS_SwapRollbackRestoresLive(t *testing.T) {
	// Mid-swap failure after the first file is installed must put live back.
	dst := t.TempDir()
	tmp := dst + ".restore-tmp"
	aside := dst + ".restore-old"
	if err := os.MkdirAll(tmp, 0755); err != nil {
		t.Fatal(err)
	}
	live := map[string][]byte{
		"cert9.db": []byte("live-cert9\n"),
		"key4.db":  []byte("live-key4\n"),
	}
	for name, body := range live {
		if err := os.WriteFile(filepath.Join(dst, name), body, 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(tmp, "cert9.db"), []byte("staged-cert9\n"), 0644); err != nil {
		t.Fatal(err)
	}
	// Missing staged key4.db makes the second rename fail after cert9 swapped.

	err := nssSwapStagedFiles(dst, tmp, aside, []string{"cert9.db", "key4.db"})
	if err == nil {
		t.Fatal("expected swap to fail on missing staged key4.db")
	}
	for name, want := range live {
		got, err := os.ReadFile(filepath.Join(dst, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s after rollback: got %q want %q", name, got, want)
		}
	}
	if nssPathExists(t, tmp) {
		t.Errorf("tmp left behind: %s", tmp)
	}
	if nssPathExists(t, aside) {
		t.Errorf("aside left behind: %s", aside)
	}
}

func TestStoreNSS_SwapRollbackRemovesNewFile(t *testing.T) {
	// A file with no live copy must be removed when a later swap step fails.
	dst := t.TempDir()
	tmp := dst + ".restore-tmp"
	aside := dst + ".restore-old"
	if err := os.MkdirAll(tmp, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dst, "cert9.db"), []byte("live-cert9\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "key4.db"), []byte("staged-key4\n"), 0644); err != nil {
		t.Fatal(err)
	}
	// No live key4.db and no staged cert9.db: key4 installs, then cert9 fails.

	err := nssSwapStagedFiles(dst, tmp, aside, []string{"key4.db", "cert9.db"})
	if err == nil {
		t.Fatal("expected swap to fail on missing staged cert9.db")
	}
	if nssPathExists(t, filepath.Join(dst, "key4.db")) {
		t.Errorf("newly installed key4.db left after rollback")
	}
	got, err := os.ReadFile(filepath.Join(dst, "cert9.db"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("live-cert9\n")) {
		t.Fatalf("cert9.db after rollback: got %q", got)
	}
	if nssPathExists(t, tmp) {
		t.Errorf("tmp left behind: %s", tmp)
	}
	if nssPathExists(t, aside) {
		t.Errorf("aside left behind: %s", aside)
	}
}

func TestStoreNSS_RejectsNonEmptyAside(t *testing.T) {
	dst := t.TempDir()
	tmp := dst + ".restore-tmp"
	aside := dst + ".restore-old"
	if err := os.MkdirAll(tmp, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(aside, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(aside, "cert9.db"), []byte("crash-survivor\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "cert9.db"), []byte("staged\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dst, "cert9.db"), []byte("live\n"), 0644); err != nil {
		t.Fatal(err)
	}

	err := nssSwapStagedFiles(dst, tmp, aside, []string{"cert9.db"})
	if err == nil {
		t.Fatal("expected swap to reject non-empty aside")
	}
	got, err := os.ReadFile(filepath.Join(aside, "cert9.db"))
	if err != nil {
		t.Fatalf("aside should be preserved: %v", err)
	}
	if string(got) != "crash-survivor\n" {
		t.Fatalf("aside cert9.db=%q", got)
	}
	live, err := os.ReadFile(filepath.Join(dst, "cert9.db"))
	if err != nil {
		t.Fatal(err)
	}
	if string(live) != "live\n" {
		t.Fatalf("live should be untouched: %q", live)
	}
}

func TestStoreNSS_RestoreCleansTmpAndAside(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	nssdbDir := filepath.Join(t.TempDir(), "nssdb")
	if err := os.MkdirAll(nssdbDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nssdbDir, "cert9.db"), []byte("live\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nssdbDir, "key4.db"), []byte("live-key\n"), 0644); err != nil {
		t.Fatal(err)
	}

	backup := t.TempDir()
	if err := os.WriteFile(filepath.Join(backup, "cert9.db"), []byte("bak\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(backup, "key4.db"), []byte("bak-key\n"), 0644); err != nil {
		t.Fatal(err)
	}

	s := NssStore("firefox-test", "0", nssdbDir)
	if err := s.Restore(backup); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if nssPathExists(t, nssdbDir+".restore-tmp") {
		t.Errorf("restore-tmp left after success")
	}
	if nssPathExists(t, nssdbDir+".restore-old") {
		t.Errorf("restore-old left after success")
	}
	got, err := os.ReadFile(filepath.Join(nssdbDir, "cert9.db"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "bak\n" {
		t.Fatalf("cert9.db=%q", got)
	}
}

func TestStoreNSS_LogsAsidePath(t *testing.T) {
	// Successful restore deletes *.restore-old, so do not print the path.
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	nssdbDir := filepath.Join(t.TempDir(), "nssdb")
	if err := os.MkdirAll(nssdbDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nssdbDir, "cert9.db"), []byte("live\n"), 0644); err != nil {
		t.Fatal(err)
	}

	backup := t.TempDir()
	if err := os.WriteFile(filepath.Join(backup, "cert9.db"), []byte("bak\n"), 0644); err != nil {
		t.Fatal(err)
	}

	aside := nssdbDir + ".restore-old"
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	s := NssStore("firefox-test", "0", nssdbDir)
	err = s.Restore(backup)
	_ = w.Close()
	os.Stdout = old
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	out, err := io.ReadAll(r)
	_ = r.Close()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out, []byte("moved aside")) {
		t.Fatalf("successful restore must not log moved-aside path, got %q", out)
	}
	if nssPathExists(t, aside) {
		t.Errorf("aside left behind: %s", aside)
	}
}

func nssPathExists(t *testing.T, path string) bool {
	t.Helper()
	_, err := os.Stat(path)
	if err == nil {
		return true
	}
	if os.IsNotExist(err) {
		return false
	}
	t.Fatalf("stat %s: %v", path, err)
	return false
}

func TestStoreNSS_AsideCleanupFailureWarns(t *testing.T) {
	// After a successful restore, a leftover *.restore-old is a warning, not an error.
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	nssdbDir := filepath.Join(t.TempDir(), "nssdb")
	if err := os.MkdirAll(nssdbDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nssdbDir, "cert9.db"), []byte("live\n"), 0644); err != nil {
		t.Fatal(err)
	}

	backup := t.TempDir()
	if err := os.WriteFile(filepath.Join(backup, "cert9.db"), []byte("bak\n"), 0644); err != nil {
		t.Fatal(err)
	}

	aside := nssdbDir + ".restore-old"
	orig := nssRemoveAll
	nssRemoveAll = func(path string) error {
		if path == aside {
			return errors.New("aside locked")
		}
		return orig(path)
	}
	t.Cleanup(func() { nssRemoveAll = orig })

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldOut := os.Stdout
	os.Stdout = w
	s := NssStore("firefox-test", "0", nssdbDir)
	err = s.Restore(backup)
	_ = w.Close()
	os.Stdout = oldOut
	if err != nil {
		t.Fatalf("Restore should succeed despite aside cleanup failure: %v", err)
	}
	out, readErr := io.ReadAll(r)
	_ = r.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !bytes.Contains(out, []byte("warning")) || !bytes.Contains(out, []byte(aside)) {
		t.Fatalf("expected warning naming kept aside %s, got %q", aside, out)
	}
	if !nssPathExists(t, aside) {
		t.Errorf("aside should remain when cleanup fails: %s", aside)
	}
}
