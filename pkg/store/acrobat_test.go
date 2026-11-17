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
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/adamdecaf/trustprune/pkg/allowlist"
)

func writeAcrobatFile(t *testing.T, path string, body []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
}

func acrobatBook(root, ver string) string {
	return filepath.Join(root, "Adobe", "Acrobat", ver, "Security", acrobatAddressBookFilename)
}

func setAcrobatFixture(t *testing.T, search acrobatSearch, running func() (bool, error)) {
	t.Helper()
	prevRoots := acrobatRoots
	prevRun := acrobatProcessRunning
	acrobatRoots = func() acrobatSearch { return search }
	if running != nil {
		acrobatProcessRunning = running
	}
	t.Cleanup(func() {
		acrobatRoots = prevRoots
		acrobatProcessRunning = prevRun
	})
}

func TestLocateAcrobatWindows(t *testing.T) {
	t.Parallel()

	appData := t.TempDir()
	search := acrobatSearch{goos: "windows", appData: appData}
	if st := locateAcrobat(search); st.Found || st.GuideOnly || st.Path != "" || st.Name != "acrobat" {
		t.Fatalf("empty profile: %#v", st)
	}

	if st := locateAcrobat(acrobatSearch{goos: "windows", appData: "  "}); st.Found || st.Path != "" {
		t.Fatalf("blank APPDATA: %#v", st)
	}

	// A version directory with no address book is not a store.
	onlyDir := filepath.Join(appData, "Adobe", "Acrobat", "11.0", "Security")
	if err := os.MkdirAll(onlyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if st := locateAcrobat(search); st.Found {
		t.Fatalf("security dir without the file: %#v", st)
	}

	// The address book path has to be a file.
	dirBook := acrobatBook(appData, "10.0")
	if err := os.MkdirAll(dirBook, 0o755); err != nil {
		t.Fatal(err)
	}
	if st := locateAcrobat(search); st.Found {
		t.Fatalf("address book path is a directory: %#v", st)
	}

	v10 := acrobatBook(appData, "10.0")
	_ = os.RemoveAll(v10)
	v11 := acrobatBook(appData, "11.0")
	v9 := acrobatBook(appData, "9.0")
	writeAcrobatFile(t, v10, []byte("10"))
	writeAcrobatFile(t, v11, []byte("11"))
	writeAcrobatFile(t, v9, []byte("9"))
	st := locateAcrobat(search)
	if !st.Found || st.GuideOnly || st.Path != v11 || st.StatusLabel() != "found" {
		t.Fatalf("11.0 should beat 10.0 and 9.0: %#v", st)
	}

	v2024 := acrobatBook(appData, "2024")
	writeAcrobatFile(t, v2024, []byte("2024"))
	st = locateAcrobat(search)
	if st.Path != v2024 {
		t.Fatalf("2024 should beat 11.0, got %s", st.Path)
	}

	// DC is the current Document Cloud folder and beats a newer-stamped year folder.
	dc := acrobatBook(appData, "DC")
	writeAcrobatFile(t, dc, []byte("dc"))
	old := time.Now().Add(-3 * time.Hour)
	newer := time.Now()
	if err := os.Chtimes(dc, old, old); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(v2024, newer, newer); err != nil {
		t.Fatal(err)
	}
	st = locateAcrobat(search)
	if st.Path != dc || st.GuideOnly {
		t.Fatalf("DC should beat a newer 2024 file: %#v", st)
	}

	// A non-numeric folder loses to any numbered folder.
	custom := acrobatBook(appData, "custom")
	writeAcrobatFile(t, custom, []byte("custom"))
	if err := os.Chtimes(custom, newer, newer); err != nil {
		t.Fatal(err)
	}
	st = locateAcrobat(search)
	if st.Path != dc {
		t.Fatalf("custom should not beat DC, got %s", st.Path)
	}
}

func TestLocateAcrobatDarwin(t *testing.T) {
	t.Parallel()

	home := t.TempDir()
	search := acrobatSearch{goos: "darwin", home: home}
	if st := locateAcrobat(search); st.Found {
		t.Fatalf("empty home: %#v", st)
	}
	if st := locateAcrobat(acrobatSearch{goos: "darwin", home: " "}); st.Found || st.Path != "" {
		t.Fatalf("blank home: %#v", st)
	}

	root := filepath.Join(home, "Library", "Application Support")
	v11 := filepath.Join(root, "Adobe", "Acrobat", "11.0", "Security", acrobatAddressBookFilename)
	dc := filepath.Join(root, "Adobe", "Acrobat", "dc", "Security", acrobatAddressBookFilename)
	writeAcrobatFile(t, v11, []byte("11"))
	writeAcrobatFile(t, dc, []byte("dc"))
	st := locateAcrobat(search)
	if st.Path != dc || !st.Found || st.GuideOnly || st.StatusLabel() != "found" {
		t.Fatalf("dc should win over 11.0: %#v", st)
	}
}

func TestLocateAcrobatVersionTie(t *testing.T) {
	t.Parallel()

	appData := t.TempDir()
	search := acrobatSearch{goos: "windows", appData: appData}
	plain := acrobatBook(appData, "11")
	dotted := acrobatBook(appData, "11.0")
	writeAcrobatFile(t, plain, []byte("plain"))
	writeAcrobatFile(t, dotted, []byte("dotted"))
	old := time.Now().Add(-2 * time.Hour)
	newer := time.Now()
	if err := os.Chtimes(dotted, old, old); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(plain, newer, newer); err != nil {
		t.Fatal(err)
	}
	st := locateAcrobat(search)
	if st.Path != plain {
		t.Fatalf("equal versions should use the newer file, got %s", st.Path)
	}

	// With no numbered folder and no DC, the later file wins.
	other := t.TempDir()
	beta := acrobatBook(other, "beta")
	custom := acrobatBook(other, "custom")
	writeAcrobatFile(t, beta, []byte("beta"))
	writeAcrobatFile(t, custom, []byte("custom"))
	if err := os.Chtimes(custom, old, old); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(beta, newer, newer); err != nil {
		t.Fatal(err)
	}
	st = locateAcrobat(acrobatSearch{goos: "windows", appData: other})
	if st.Path != beta {
		t.Fatalf("newer non-numeric file should win, got %s", st.Path)
	}
}

func TestLocateAcrobatOtherOS(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeAcrobatFile(t, acrobatBook(root, "DC"), []byte("dc"))
	for _, goos := range []string{"linux", "freebsd", ""} {
		st := locateAcrobat(acrobatSearch{goos: goos, appData: root, home: root})
		if st.Found || st.GuideOnly || st.Path != "" || st.Name != "acrobat" {
			t.Fatalf("goos %q should not probe, got %#v", goos, st)
		}
		if st.StatusLabel() != "not-found" {
			t.Fatalf("goos %q label %q", goos, st.StatusLabel())
		}
	}
}

func TestDetectAcrobatCurrentOS(t *testing.T) {
	st := detectAcrobat()
	if st.Name != "acrobat" {
		t.Fatalf("name %#v", st)
	}
	if runtime.GOOS != "windows" && runtime.GOOS != "darwin" {
		if st.Found || st.GuideOnly || st.Path != "" {
			t.Fatalf("non-desktop probe: %#v", st)
		}
	}
	if st.Found && st.GuideOnly {
		t.Fatalf("a found address book is a store path, not guide-only: %#v", st)
	}
	if !st.Found && (st.GuideOnly || st.Path != "") {
		t.Fatalf("a miss must be not-found: %#v", st)
	}
}

func TestAcrobatProcessNames(t *testing.T) {
	t.Parallel()

	for _, name := range []string{
		"Acrobat",
		"acrobat",
		"Acrobat.exe",
		"ACROBAT.EXE",
		"AcroRd32",
		"AcroRd32.exe",
		"AdobeReader",
		"AdobeReader.exe",
		"/Applications/Acrobat.app/Contents/MacOS/Acrobat",
	} {
		if !acrobatBaseMatch(name) {
			t.Errorf("want match %q", name)
		}
	}
	for _, name := range []string{
		"",
		"   ",
		"AcrobatUpdater.exe",
		"Adobe Acrobat",
		"AdobeAcrobat",
		"not-acrobat",
	} {
		if acrobatBaseMatch(name) {
			t.Errorf("want no match %q", name)
		}
	}

	tasklist := []byte("\"System Idle Process\",\"0\",\"Services\",\"0\",\"8 K\"\r\n\"AcroRd32.exe\",\"1234\",\"Console\",\"1\",\"100,000 K\"\r\n")
	got, err := tasklistHasAcrobat(tasklist)
	if err != nil || !got {
		t.Fatalf("tasklist AcroRd32: got %v err %v", got, err)
	}
	got, err = tasklistHasAcrobat([]byte("\"explorer.exe\",\"4\",\"Console\",\"1\",\"1 K\"\r\n"))
	if err != nil || got {
		t.Fatalf("tasklist explorer: got %v err %v", got, err)
	}
	got, err = tasklistHasAcrobat([]byte("INFO: No tasks are running which match the specified criteria.\r\n"))
	if err != nil || got {
		t.Fatalf("tasklist empty: got %v err %v", got, err)
	}

	if !psCommHasAcrobat([]byte("/usr/sbin/coreauthd\n/Applications/Acrobat.app/Contents/MacOS/Acrobat\n")) {
		t.Fatal("ps should see Acrobat")
	}
	if psCommHasAcrobat([]byte("loginwindow\nWindowServer\n")) {
		t.Fatal("ps should not match unrelated processes")
	}

	if runtime.GOOS != "windows" && runtime.GOOS != "darwin" {
		running, err := detectAcrobatRunning()
		if err != nil || running {
			t.Fatalf("non-desktop process check: running=%v err=%v", running, err)
		}
	}
}

func TestAcrobatBackupRestoreRoundTrip(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	appData := t.TempDir()
	dc := acrobatBook(appData, "DC")
	v11 := acrobatBook(appData, "11.0")
	original := []byte{0x00, 0x01, 0xff, 'A', 'c', 'r', 'o', ' ', 'o', 'p', 'a', 'q', 'u', 'e'}
	other := []byte("eleven")
	writeAcrobatFile(t, dc, original)
	writeAcrobatFile(t, v11, other)
	// 11.0 is newer on disk. DC still wins.
	if err := os.Chtimes(dc, time.Now().Add(-time.Hour), time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}

	setAcrobatFixture(t, acrobatSearch{goos: "windows", appData: appData}, func() (bool, error) {
		return false, nil
	})

	s, err := ForApp("Acrobat")
	if err != nil {
		t.Fatal(err)
	}
	info := s.GetInfo()
	if info == nil || info.Name != "Acrobat" || info.Path != dc {
		t.Fatalf("info %#v", info)
	}

	if err := s.Backup(); err != nil {
		t.Fatal(err)
	}
	latest, err := s.GetLatestBackup()
	if err != nil || latest == "" {
		t.Fatalf("latest %q err %v", latest, err)
	}
	backed, err := os.ReadFile(filepath.Join(latest, acrobatAddressBookFilename))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(backed, original) {
		t.Fatalf("backup bytes %q", backed)
	}
	recorded, err := os.ReadFile(filepath.Join(latest, nssBackupSourceName))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(recorded)) != acrobatCanonicalPath(dc) {
		t.Fatalf("source %q", recorded)
	}
	live, err := os.ReadFile(v11)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(live, other) {
		t.Fatalf("11.0 changed during backup: %q", live)
	}

	mutated := []byte("mutated-live-file")
	if err := os.WriteFile(dc, mutated, 0o644); err != nil {
		t.Fatal(err)
	}

	SetDryRun(true)
	t.Cleanup(func() { SetDryRun(false) })
	if err := s.Restore(""); err != nil {
		t.Fatal(err)
	}
	dry, err := os.ReadFile(dc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dry, mutated) {
		t.Fatalf("dry-run restore wrote the live file: %q", dry)
	}
	SetDryRun(false)

	if err := s.Restore(""); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("restored %q", got)
	}
	if _, err := os.Stat(dc + ".restore-old"); !os.IsNotExist(err) {
		t.Fatalf("restore left aside file: %v", err)
	}
	live, err = os.ReadFile(v11)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(live, other) {
		t.Fatalf("11.0 changed during restore: %q", live)
	}
}

func TestAcrobatRunningRefusesBackupAndRestore(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	appData := t.TempDir()
	book := acrobatBook(appData, "DC")
	body := []byte("live")
	writeAcrobatFile(t, book, body)
	setAcrobatFixture(t, acrobatSearch{goos: "windows", appData: appData}, func() (bool, error) {
		return true, nil
	})

	s := AcrobatStore()
	SetDryRun(true)
	t.Cleanup(func() { SetDryRun(false) })
	for _, call := range []struct {
		name string
		fn   func() error
	}{
		{"backup", s.Backup},
		{"restore", func() error { return s.Restore("") }},
	} {
		err := call.fn()
		if !errors.Is(err, ErrAcrobatRunning) {
			t.Fatalf("%s: %v", call.name, err)
		}
		for _, phrase := range []string{"Acrobat", "AcroRd32", "AdobeReader"} {
			if !strings.Contains(err.Error(), phrase) {
				t.Errorf("%s message %q missing %s", call.name, err.Error(), phrase)
			}
		}
	}
	SetDryRun(false)
	if err := s.Backup(); !errors.Is(err, ErrAcrobatRunning) {
		t.Fatalf("live backup: %v", err)
	}
	if err := s.Restore(""); !errors.Is(err, ErrAcrobatRunning) {
		t.Fatalf("live restore: %v", err)
	}

	got, err := os.ReadFile(book)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("live file changed: %q", got)
	}
	entries, err := os.ReadDir(home)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("running refusal wrote into HOME: %v", entries)
	}

	checkErr := errors.New("tasklist failed")
	acrobatProcessRunning = func() (bool, error) { return false, checkErr }
	err = s.Backup()
	if err == nil || !errors.Is(err, checkErr) {
		t.Fatalf("process check error: %v", err)
	}
	if entries, err = os.ReadDir(home); err != nil || len(entries) != 0 {
		t.Fatalf("failed process check wrote into HOME: %v %v", entries, err)
	}
}

func TestAcrobatAddressBookNotFound(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	appData := t.TempDir()
	if err := os.MkdirAll(filepath.Join(appData, "Adobe", "Acrobat", "DC", "Security"), 0o755); err != nil {
		t.Fatal(err)
	}
	setAcrobatFixture(t, acrobatSearch{goos: "windows", appData: appData}, func() (bool, error) {
		return false, nil
	})

	s := AcrobatStore()
	SetDryRun(true)
	t.Cleanup(func() { SetDryRun(false) })
	root := filepath.Join(appData, "Adobe", "Acrobat")
	for _, call := range []struct {
		name string
		fn   func() error
	}{
		{"backup", s.Backup},
		{"restore", func() error { return s.Restore("") }},
	} {
		err := call.fn()
		if err == nil || !errors.Is(err, errAcrobatAddressBookNotFound) {
			t.Fatalf("%s: %v", call.name, err)
		}
		if !strings.Contains(err.Error(), "addressbook.acrodata not found") || !strings.Contains(err.Error(), root) {
			t.Fatalf("%s message %q", call.name, err.Error())
		}
	}

	blank := t.TempDir()
	t.Setenv("HOME", blank)
	setAcrobatFixture(t, acrobatSearch{goos: "linux"}, func() (bool, error) {
		return false, nil
	})
	err := AcrobatStore().Backup()
	if err == nil || err.Error() != "addressbook.acrodata not found" {
		t.Fatalf("no root message: %v", err)
	}
	entries, err := os.ReadDir(blank)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("not-found wrote into HOME: %v", entries)
	}
}

func TestAcrobatGuideOnly(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	appData := t.TempDir()
	writeAcrobatFile(t, acrobatBook(appData, "DC"), []byte("book"))
	setAcrobatFixture(t, acrobatSearch{goos: "windows", appData: appData}, func() (bool, error) {
		return false, nil
	})

	s, err := ForApp("acrobat")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ForAppWithStore("acrobat", filepath.Join(home, "store")); err == nil || !strings.Contains(err.Error(), "--store with --app acrobat") {
		t.Fatalf("store override: %v", err)
	}

	certs, err := s.List(nil)
	if !errors.Is(err, ErrAcrobatGuideOnly) || certs != nil {
		t.Fatalf("list certs=%v err=%v", certs, err)
	}
	for _, phrase := range []string{
		"guide only",
		"addressbook.acrodata",
		"opaque",
		"unverified",
		"AATL",
		"EUTL",
		"Trust Manager",
		"Identities & Trusted Certificates",
		"Windows Integration",
		"AcroRd32",
	} {
		if !strings.Contains(err.Error(), phrase) {
			t.Errorf("guide missing %q", phrase)
		}
	}
	if err := s.Add(nil); !errors.Is(err, ErrAcrobatGuideOnly) {
		t.Fatalf("add: %v", err)
	}
	if err := s.Remove(allowlist.Allowlist{}); !errors.Is(err, ErrAcrobatGuideOnly) {
		t.Fatalf("remove: %v", err)
	}

	entries, err := os.ReadDir(home)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("guide operations wrote into HOME: %v", entries)
	}
}

func TestAcrobatRestoreRefusesDifferentPath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	appData := t.TempDir()
	dc := acrobatBook(appData, "DC")
	v2024 := acrobatBook(appData, "2024")
	writeAcrobatFile(t, dc, []byte("from-dc"))
	writeAcrobatFile(t, v2024, []byte("from-2024"))
	setAcrobatFixture(t, acrobatSearch{goos: "windows", appData: appData}, func() (bool, error) {
		return false, nil
	})

	s := AcrobatStore()
	if err := s.Backup(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(dc); err != nil {
		t.Fatal(err)
	}
	err := s.Restore("")
	if err == nil || !strings.Contains(err.Error(), "pass --force") {
		t.Fatalf("cross-path restore: %v", err)
	}
	got, err := os.ReadFile(v2024)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("from-2024")) {
		t.Fatalf("2024 was overwritten: %q", got)
	}
}
