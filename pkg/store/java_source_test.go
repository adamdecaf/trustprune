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
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func javaSourceTestHome(t *testing.T) (a, b string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	dir := t.TempDir()
	a = filepath.Join(dir, "a", "cacerts")
	b = filepath.Join(dir, "b", "cacerts")
	for _, p := range []string{a, b} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("ORIG-"+p), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return a, b
}

func TestJavaBackup_RecordsSourceKeystore(t *testing.T) {
	a, _ := javaSourceTestHome(t)
	s := JavaStoreAt(a)
	if err := s.Backup(); err != nil {
		t.Fatal(err)
	}
	latest, err := s.GetLatestBackup()
	if err != nil {
		t.Fatal(err)
	}
	got, err := readJavaBackupSource(latest)
	if err != nil || got != javaCanonicalPath(a) {
		t.Fatalf("recorded source %q err=%v, want %q", got, err, javaCanonicalPath(a))
	}
}

func TestJavaRestore_RefusesOtherKeystoreBackup(t *testing.T) {
	a, b := javaSourceTestHome(t)
	if err := JavaStoreAt(a).Backup(); err != nil {
		t.Fatal(err)
	}
	backupA, err := JavaStoreAt(a).GetLatestBackup()
	if err != nil {
		t.Fatal(err)
	}
	// Implicit restore of b must not pick a's backup.
	if err := JavaStoreAt(b).Restore(""); err == nil {
		t.Fatal("expected no backup for b")
	}
	// Explicit restore of a's backup onto b must be refused.
	err = JavaStoreAt(b).Restore(backupA)
	if err == nil || !strings.Contains(err.Error(), "refusing restore") {
		t.Fatalf("expected refusal, got %v", err)
	}
	got, _ := os.ReadFile(b)
	if !bytes.Equal(got, []byte("ORIG-"+b)) {
		t.Fatalf("keystore b was modified: %q", got)
	}
}

func TestJavaRestore_MatchingSourceRestores(t *testing.T) {
	a, _ := javaSourceTestHome(t)
	s := JavaStoreAt(a)
	if err := s.Backup(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(a, []byte("MUTATED"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := s.Restore(""); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(a)
	if !bytes.Equal(got, []byte("ORIG-"+a)) {
		t.Fatalf("restore mismatch: %q", got)
	}
}

func TestJavaLatestBackup_SkipsUnknownSourceForOverride(t *testing.T) {
	a, _ := javaSourceTestHome(t)
	dir, err := getCertManageDir(javaCertManageDir)
	if err != nil {
		t.Fatal(err)
	}
	legacy := filepath.Join(dir, "cacerts-100.bck")
	if err := os.WriteFile(legacy, []byte("LEGACY"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := latestJavaBackupFor(a, false); err == nil {
		t.Fatal("override restore must not pick a backup without a recorded source")
	}
	got, err := latestJavaBackupFor(a, true)
	if err != nil || got != legacy {
		t.Fatalf("discovered keystore should accept legacy backup: got %q err=%v", got, err)
	}
}

func TestJavaRestore_SymlinkReplacedByFileStillMatches(t *testing.T) {
	a, _ := javaSourceTestHome(t)
	link := filepath.Join(t.TempDir(), "cacerts")
	if err := os.Symlink(a, link); err != nil {
		t.Skipf("symlink: %v", err)
	}
	s := JavaStoreAt(link)
	if err := s.Backup(); err != nil {
		t.Fatal(err)
	}
	// Replace the symlink with a regular file, as some keystore writers do.
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(link, []byte("MUTATED"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := s.Restore(""); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	got, _ := os.ReadFile(link)
	if !bytes.Equal(got, []byte("ORIG-"+a)) {
		t.Fatalf("restore mismatch: %q", got)
	}
}
