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
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestStore__getCertManageDir(t *testing.T) {
	name := "test-getCertManageDir"
	d1, err := getCertManageDir(name)
	if err != nil {
		t.Error(err)
	}

	// make the dir again just to make sure everything is ok
	d2, err := getCertManageDir(name)
	if err != nil {
		t.Error(err)
	}

	if d1 != d2 {
		t.Errorf("%s != %s", d1, d2)
	}
	defer os.Remove(d1)

	// If we're asking for an abs reference just return that.
	// AKA. Don't append getCertManageParentDir()
	dir, err := filepath.Abs(filepath.Join("..", "..", "testdata", "backups", "files"))
	if err != nil {
		t.Error(err)
	}
	_, err = os.Stat(dir) // make sure `dir` exists
	if err != nil {
		t.Error(err)
	}
	d3, err := getCertManageDir(dir)
	if err != nil {
		t.Error(err)
	}
	if dir != d3 {
		t.Errorf("dir=%s != d3=%s", dir, d3)
	}
	_, err = os.Stat(dir) // make sure `dir` exists
	if err != nil {
		t.Error(err)
	}
}

func TestStore__getCertManageDirNeg(t *testing.T) {
	// Grab a file and ensure it can't be modified
	f, err := filepath.Abs("../../main.go")
	if err != nil {
		t.Error(err)
	}
	s, err := os.Stat(f)
	if err != nil {
		t.Error(err)
	}

	// "get dir"
	dir, err := getCertManageDir(f)
	if err == nil {
		t.Errorf("expected error, dir=%s", dir)
	}
	s2, err := os.Stat(f)
	if err != nil {
		t.Error(err)
	}
	if s.Mode().String() != s2.Mode().String() {
		t.Errorf("s.Mode()=%s != s2.Mode()=%s", s.Mode().String(), s2.Mode().String())
	}
}

func TestStore__getLatestBackup(t *testing.T) {
	// return an error if the dir doesn't exist
	dir, err := getLatestBackup("missing")
	if err == nil {
		t.Errorf("expected error, got dir=%s, err=%v", dir, err)
	}
	if !os.IsNotExist(err) {
		t.Errorf("expected IsNotExist, got err=%v", err)
	}
	if dir != "" {
		t.Errorf("expected empty dir, dir=%s", dir)
	}

	// Get latest backup from dir of files
	dir, err = getLatestBackup(filepath.Join("..", "..", "testdata", "backups", "files"))
	if err != nil {
		t.Error(err)
	}
	if dir != filepath.Join("..", "..", "testdata", "backups", "files", "lasjdaslja") {
		t.Errorf("got other backup file, dir=%s", dir)
	}

	// Latest backup from dir list
	dir, err = getLatestBackup(filepath.Join("..", "..", "testdata", "backups", "alpha"))
	if err != nil {
		t.Error(err)
	}
	if dir != filepath.Join("..", "..", "testdata", "backups", "alpha", "zzzjalaj") {
		t.Errorf("got other backup dir, dir=%s", dir)
	}

	// Numeric dir list
	dir, err = getLatestBackup(filepath.Join("..", "..", "testdata", "backups", "numbers"))
	if err != nil {
		t.Error(err)
	}
	if dir != filepath.Join("..", "..", "testdata", "backups", "numbers", "1513034181") {
		t.Errorf("got other backup dir, dir=%s", dir)
	}
}

func TestStore__getLatestBackupAmong(t *testing.T) {
	root := t.TempDir()
	a := filepath.Join(root, "a")
	b := filepath.Join(root, "b")
	if err := os.MkdirAll(filepath.Join(a, "100"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(b, "200"), 0755); err != nil {
		t.Fatal(err)
	}
	// Same basename in both: primary (a) wins for that name, but 200 is newer overall.
	if err := os.MkdirAll(filepath.Join(a, "150"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(b, "150"), 0755); err != nil {
		t.Fatal(err)
	}

	got, err := getLatestBackupAmong(a, b)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(b, "200")
	if got != want {
		t.Fatalf("got %s want %s", got, want)
	}

	// Prefer primary when the newest basename exists only there.
	if err := os.MkdirAll(filepath.Join(a, "300"), 0755); err != nil {
		t.Fatal(err)
	}
	got, err = getLatestBackupAmong(a, b)
	if err != nil {
		t.Fatal(err)
	}
	if got != filepath.Join(a, "300") {
		t.Fatalf("got %s want primary 300", got)
	}

	// Missing dirs are fine.
	got, err = getLatestBackupAmong(filepath.Join(root, "missing"), b)
	if err != nil {
		t.Fatal(err)
	}
	if got != filepath.Join(b, "200") {
		t.Fatalf("got %s want %s", got, filepath.Join(b, "200"))
	}

	// A non-missing primary read error must be returned, not masked by legacy.
	// Skip on Windows: ReadDir of a file can look like IsNotExist there.
	if runtime.GOOS != "windows" {
		notDir := filepath.Join(root, "file")
		if err := os.WriteFile(notDir, []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
		got, err = getLatestBackupAmong(notDir, b)
		if err == nil || got != "" {
			t.Fatalf("expected primary read error, got %q, err=%v", got, err)
		}
	}
}

func TestBackupBasenameUnix(t *testing.T) {
	cases := []struct {
		name string
		ts   int64
		ok   bool
	}{
		{"1761780000", 1761780000, true},
		{"cert8.db-1700000000", 1700000000, true},
		{"cert.db-1700000000", 1700000000, true},
		{"cacerts-1761780000.bck", 1761780000, true},
		{"something-99.bck", 99, true},
		{"zzzjalaj", 0, false},
		{"cert8.db-", 0, false},
		{"cert8.db-nope", 0, false},
		{"cacerts.bck", 0, false},
		{"", 0, false},
	}
	for _, tc := range cases {
		ts, ok := backupBasenameUnix(tc.name)
		if ok != tc.ok || ts != tc.ts {
			t.Fatalf("%q: got ts=%d ok=%v want ts=%d ok=%v", tc.name, ts, ok, tc.ts, tc.ok)
		}
	}
}

func TestGetLatestBackupAmong_MixedNSSLayouts(t *testing.T) {
	root := t.TempDir()
	primary := filepath.Join(root, "primary")
	legacy := filepath.Join(root, "legacy")
	newerDir := filepath.Join(primary, "1761780000")
	if err := os.MkdirAll(newerDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(newerDir, "cert9.db"), []byte("new\n"), 0644); err != nil {
		t.Fatal(err)
	}
	// Older legacy single-file backup whose basename sorts after the newer dir.
	legacyFile := filepath.Join(primary, "cert8.db-1700000000")
	if err := os.WriteFile(legacyFile, []byte("old\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(primary, "cert.db-1600000000"), []byte("older\n"), 0644); err != nil {
		t.Fatal(err)
	}
	// Unparseable noise must be ignored when timestamps are present.
	if err := os.WriteFile(filepath.Join(primary, "readme.txt"), []byte("nope\n"), 0644); err != nil {
		t.Fatal(err)
	}

	got, err := getLatestBackupAmong(primary, legacy)
	if err != nil {
		t.Fatal(err)
	}
	if got != newerDir {
		t.Fatalf("got %s want %s (legacy cert8.db-* must not beat newer <unix>/)", got, newerDir)
	}
}

func TestGetLatestBackupAmong_JavaBckAcrossTrees(t *testing.T) {
	root := t.TempDir()
	primary := filepath.Join(root, "primary")
	legacy := filepath.Join(root, "legacy")
	if err := os.MkdirAll(primary, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(legacy, 0755); err != nil {
		t.Fatal(err)
	}
	// Lexicographic order would prefer cacerts-999.bck over cacerts-1000.bck.
	older := filepath.Join(primary, "cacerts-1000.bck")
	newer := filepath.Join(legacy, "cacerts-2000.bck")
	lexBiggerOlder := filepath.Join(primary, "cacerts-999.bck")
	for _, p := range []string{older, newer, lexBiggerOlder} {
		if err := os.WriteFile(p, []byte(p+"\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	got, err := getLatestBackupAmong(primary, legacy)
	if err != nil {
		t.Fatal(err)
	}
	if got != newer {
		t.Fatalf("got %s want %s", got, newer)
	}

	// Equal timestamps: primary wins.
	tieLegacy := filepath.Join(legacy, "other-2000.bck")
	if err := os.WriteFile(tieLegacy, []byte("tie\n"), 0644); err != nil {
		t.Fatal(err)
	}
	tiePrimary := filepath.Join(primary, "cacerts-2000.bck")
	if err := os.WriteFile(tiePrimary, []byte("tie-primary\n"), 0644); err != nil {
		t.Fatal(err)
	}
	got, err = getLatestBackupAmong(primary, legacy)
	if err != nil {
		t.Fatal(err)
	}
	if got != tiePrimary {
		t.Fatalf("equal ts: got %s want primary %s", got, tiePrimary)
	}
}

func TestGetLatestBackup_NSSMixedUnderTempHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	primaryRoot := primaryBackupParent(home)
	legacyRoot := legacyBackupParent(home)
	if primaryRoot == "" || legacyRoot == "" {
		t.Skipf("unsupported GOOS %s for backup parents", runtime.GOOS)
	}

	newer := filepath.Join(primaryRoot, "firefox", "1761780000")
	if err := os.MkdirAll(newer, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(newer, "cert9.db"), []byte("new-cert9\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(newer, "key4.db"), []byte("new-key4\n"), 0644); err != nil {
		t.Fatal(err)
	}
	legacyFile := filepath.Join(primaryRoot, "firefox", "cert8.db-1700000000")
	if err := os.WriteFile(legacyFile, []byte("old\n"), 0644); err != nil {
		t.Fatal(err)
	}
	// Also seed a still-older legacy tree entry that would win lexicographically.
	if err := os.MkdirAll(filepath.Join(legacyRoot, "firefox"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacyRoot, "firefox", "cert.db-1650000000"), []byte("legacy-tree\n"), 0644); err != nil {
		t.Fatal(err)
	}

	s := NssStore("firefox", "0", "")
	got, err := s.GetLatestBackup()
	if err != nil {
		t.Fatal(err)
	}
	if got != newer {
		t.Fatalf("got %s want %s", got, newer)
	}
}

func TestForAppUnknown(t *testing.T) {
	_, err := ForApp("nope")
	if err == nil {
		t.Fatal("expected error")
	}
	wantPrefix := "unknown app nope (apps: "
	if !strings.HasPrefix(err.Error(), wantPrefix) {
		t.Fatalf("got %q, want prefix %q", err.Error(), wantPrefix)
	}
	if !strings.Contains(err.Error(), "java") {
		t.Fatalf("expected apps list in %q", err.Error())
	}
}

func TestForAppWithFileUnknown(t *testing.T) {
	_, err := ForAppWithFile("NoPe", "/tmp/x")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.HasPrefix(err.Error(), "unknown app NoPe (apps: ") {
		t.Fatalf("got %q", err.Error())
	}
}

func TestForAppPlatformOSName(t *testing.T) {
	for _, name := range []string{runtime.GOOS, strings.ToUpper(runtime.GOOS)} {
		got, err := ForApp(name)
		if err != nil {
			t.Fatalf("ForApp(%q): %v", name, err)
		}
		want := Platform()
		if fmt.Sprintf("%T", got) != fmt.Sprintf("%T", want) {
			t.Fatalf("ForApp(%q) type %T, platform type %T", name, got, want)
		}
		gi, wi := got.GetInfo(), want.GetInfo()
		if gi == nil || wi == nil || gi.Name != wi.Name || gi.Path != wi.Path || gi.Version != wi.Version {
			t.Fatalf("ForApp(%q) info %#v, platform %#v", name, gi, wi)
		}

		got, err = ForAppWithStore(name, "")
		if err != nil {
			t.Fatalf("ForAppWithStore(%q, empty): %v", name, err)
		}
		if fmt.Sprintf("%T", got) != fmt.Sprintf("%T", want) {
			t.Fatalf("empty -store type %T, platform type %T", got, want)
		}
		got, err = ForAppWithStore(name, "  ")
		if err != nil {
			t.Fatalf("ForAppWithStore(%q, blank): %v", name, err)
		}
		if fmt.Sprintf("%T", got) != fmt.Sprintf("%T", want) {
			t.Fatalf("blank -store type %T, platform type %T", got, want)
		}
	}

	_, err := ForAppWithStore(runtime.GOOS, "/tmp/not-a-store")
	if err == nil || !strings.Contains(err.Error(), "-store with -app "+runtime.GOOS) {
		t.Fatalf("expected -store rejection, got %v", err)
	}

	other := "darwin"
	if other == runtime.GOOS {
		other = "linux"
	}
	_, err = ForApp(other)
	if err == nil || !strings.Contains(err.Error(), "unknown app "+other) {
		t.Fatalf("ForApp(%q) = %v, want unknown app", other, err)
	}

	for _, name := range GetApps() {
		if name == runtime.GOOS {
			t.Fatalf("GetApps includes platform OS name %s", runtime.GOOS)
		}
	}
}
