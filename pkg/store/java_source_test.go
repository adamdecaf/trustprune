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
	"os"
	"path/filepath"
	"strconv"
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

func TestJavaRestore_CrossPathRefuseForceAndSamePath(t *testing.T) {
	a, b := javaSourceTestHome(t)
	sA := JavaStoreAt(a)
	sB := JavaStoreAt(b)
	SetDryRun(false)
	SetForceRestore(false)
	t.Cleanup(func() {
		SetDryRun(false)
		SetForceRestore(false)
	})

	if err := sA.Backup(); err != nil {
		t.Fatal(err)
	}
	backupA, err := sA.GetLatestBackup()
	if err != nil || backupA == "" {
		t.Fatalf("latest A: %q err=%v", backupA, err)
	}

	beforeB, err := os.ReadFile(b)
	if err != nil {
		t.Fatal(err)
	}

	for _, dry := range []bool{false, true} {
		t.Run("refuse dry="+strconv.FormatBool(dry), func(t *testing.T) {
			SetDryRun(dry)
			SetForceRestore(false)
			err := sB.Restore(backupA)
			if err == nil || !strings.Contains(err.Error(), "refusing restore") {
				t.Fatalf("expected refusal, got %v", err)
			}
			if !strings.Contains(err.Error(), "-force") {
				t.Fatalf("error should mention -force: %v", err)
			}
			got, err := os.ReadFile(b)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, beforeB) {
				t.Fatalf("cross-path restore mutated target: %q", got)
			}
		})
	}

	SetDryRun(false)
	SetForceRestore(false)
	if err := os.WriteFile(a, []byte("MUTATED"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := sA.Restore(""); err != nil {
		t.Fatalf("same-path restore: %v", err)
	}
	gotA, err := os.ReadFile(a)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotA, []byte("ORIG-"+a)) {
		t.Fatalf("same-path restore mismatch: %q", gotA)
	}

	SetForceRestore(true)
	if err := sB.Restore(backupA); err != nil {
		t.Fatalf("forced restore: %v", err)
	}
	gotB, err := os.ReadFile(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotB, []byte("ORIG-"+a)) {
		t.Fatalf("forced restore mismatch: %q", gotB)
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

func TestJavaBackup_SameSecondDoesNotOverwrite(t *testing.T) {
	a, _ := javaSourceTestHome(t)
	dir := t.TempDir()
	first, err := createJavaBackupFile(dir, "cacerts", 1700000000, a)
	if err != nil {
		t.Fatal(err)
	}
	second, err := createJavaBackupFile(dir, "cacerts", 1700000000, a)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatalf("same-second backups share a name: %s", first)
	}
	if ts, ok := backupBasenameUnix(filepath.Base(second)); !ok || ts != 1700000000 {
		t.Fatalf("counter name %s does not parse to timestamp: %d %v", second, ts, ok)
	}
	// Writing a sidecar a second time must not overwrite the first record.
	if err := writeJavaBackupSource(first, "/other/cacerts"); err == nil {
		t.Fatal("expected O_EXCL failure on existing .source")
	}
	if got, _ := readJavaBackupSource(first); got != javaCanonicalPath(a) {
		t.Fatalf(".source overwritten: %q", got)
	}
}

func TestJavaBackup_TwoBackupsSameSecondBothKept(t *testing.T) {
	a, b := javaSourceTestHome(t)
	if err := JavaStoreAt(a).Backup(); err != nil {
		t.Fatal(err)
	}
	if err := JavaStoreAt(b).Backup(); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{a, b} {
		p, err := JavaStoreAt(k).GetLatestBackup()
		if err != nil {
			t.Fatalf("%s: %v", k, err)
		}
		got, _ := os.ReadFile(p)
		if !bytes.Equal(got, []byte("ORIG-"+k)) {
			t.Fatalf("backup for %s has wrong content %q", k, got)
		}
	}
}

func TestJavaLatestBackup_IgnoresSourceSidecars(t *testing.T) {
	a, _ := javaSourceTestHome(t)
	dir, err := getCertManageDir(javaCertManageDir)
	if err != nil {
		t.Fatal(err)
	}
	bck := filepath.Join(dir, "cacerts-100.bck")
	if err := os.WriteFile(bck, []byte("B"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeJavaBackupSource(bck, a); err != nil {
		t.Fatal(err)
	}
	// A stray, newer-looking sidecar must never be selected as a backup.
	if err := os.WriteFile(filepath.Join(dir, "cacerts-999.bck.source"), []byte(javaCanonicalPath(a)), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := latestJavaBackupFor(a, false)
	if err != nil || got != bck {
		t.Fatalf("got %q err=%v, want %q", got, err, bck)
	}
}

func TestJavaLatestBackup_PrefersHigherCounterSameSecond(t *testing.T) {
	a, _ := javaSourceTestHome(t)
	dir, err := getCertManageDir(javaCertManageDir)
	if err != nil {
		t.Fatal(err)
	}
	var last string
	for i := 0; i < 3; i++ {
		p, err := createJavaBackupFile(dir, "cacerts", 1700000000, a)
		if err != nil {
			t.Fatal(err)
		}
		last = p
	}
	got, err := latestJavaBackupFor(a, false)
	if err != nil || got != last {
		t.Fatalf("got %q err=%v, want newest %q", got, err, last)
	}
}

func javaBackupDirEntries(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	return names
}

func TestJavaBackup_InterruptedBeforePublishLeavesNothing(t *testing.T) {
	a, _ := javaSourceTestHome(t)
	dir := t.TempDir()
	orig := javaBackupBeforePublish
	t.Cleanup(func() { javaBackupBeforePublish = orig })
	javaBackupBeforePublish = func() error { return errors.New("simulated interruption") }

	if _, err := createJavaBackupFile(dir, "cacerts", 1700000000, a); err == nil {
		t.Fatal("expected simulated interruption error")
	}
	if names := javaBackupDirEntries(t, dir); len(names) != 0 {
		t.Fatalf("interrupted backup left files behind: %v", names)
	}
}

func TestJavaLatestBackup_IgnoresCrashLeftovers(t *testing.T) {
	a, _ := javaSourceTestHome(t)
	dir, err := getCertManageDir(javaCertManageDir)
	if err != nil {
		t.Fatal(err)
	}
	good, err := createJavaBackupFile(dir, "cacerts", 1700000000, a)
	if err != nil {
		t.Fatal(err)
	}
	// A crash mid-copy can leave a temp partial; old code could leave a
	// newer .bck with no record. Neither may be chosen for a -file override.
	if err := os.WriteFile(filepath.Join(dir, ".cacerts-123.partial"), []byte("PART"), 0o644); err != nil {
		t.Fatal(err)
	}
	orphan := filepath.Join(dir, "cacerts-1800000000.bck")
	if err := os.WriteFile(orphan, []byte("PART"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := latestJavaBackupFor(a, false)
	if err != nil || got != good {
		t.Fatalf("got %q err=%v, want %q", got, err, good)
	}
	// Restore with the override must use the recorded backup, not the orphan.
	if err := os.WriteFile(a, []byte("MUTATED"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := JavaStoreAt(a).Restore(""); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(a); !bytes.Equal(b, []byte("ORIG-"+a)) {
		t.Fatalf("restored wrong content %q", b)
	}
}

func TestJavaBackup_PublishedBackupHasRecordAndNoTemp(t *testing.T) {
	a, _ := javaSourceTestHome(t)
	dir := t.TempDir()
	p, err := createJavaBackupFile(dir, "cacerts", 1700000000, a)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := readJavaBackupSource(p); got != javaCanonicalPath(a) {
		t.Fatalf("missing/incorrect record: %q", got)
	}
	for _, n := range javaBackupDirEntries(t, dir) {
		if strings.HasSuffix(n, ".partial") {
			t.Fatalf("temp file left behind: %s", n)
		}
	}
	if b, _ := os.ReadFile(p); !bytes.Equal(b, []byte("ORIG-"+a)) {
		t.Fatalf("backup content %q", b)
	}
}
