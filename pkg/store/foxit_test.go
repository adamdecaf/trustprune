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
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/adamdecaf/trustprune/pkg/allowlist"
)

func writeFoxitFile(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLocateFoxitWindows(t *testing.T) {
	t.Parallel()

	pf := t.TempDir()
	pf86 := t.TempDir()
	search := foxitSearch{goos: "windows", programFiles: pf, programFilesX86: pf86}

	if st := locateFoxit(search); st.Found || st.GuideOnly || st.Path != "" || st.Name != "foxit" {
		t.Fatalf("empty roots: %#v", st)
	}

	reader := filepath.Join(pf, "Foxit Software", "Foxit PDF Reader", "FoxitPDFReader.exe")
	editor86 := filepath.Join(pf86, "Foxit Software", "Foxit PDF Editor", "FoxitPDFEditor.exe")
	writeFoxitFile(t, reader)
	writeFoxitFile(t, editor86)

	// The first root wins, so a Reader in Program Files is reported ahead
	// of an Editor under Program Files (x86).
	st := locateFoxit(search)
	if !st.Found || !st.GuideOnly || st.Path != reader || st.StatusLabel() != "guide only" {
		t.Fatalf("reader in Program Files: %#v label %q", st, st.StatusLabel())
	}

	editor := filepath.Join(pf, "Foxit Software", "Foxit PDF Editor", "FoxitPDFEditor.exe")
	writeFoxitFile(t, editor)
	st = locateFoxit(search)
	if st.Path != editor {
		t.Fatalf("editor should win inside Program Files, got %s", st.Path)
	}

	// A product directory with no executable is not an install.
	onlyDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(onlyDir, "Foxit Software", "Foxit PDF Editor"), 0o755); err != nil {
		t.Fatal(err)
	}
	if st := locateFoxit(foxitSearch{goos: "windows", programFiles: onlyDir}); st.Found {
		t.Fatalf("directory without exe: %#v", st)
	}

	// The executable path has to be a file.
	dirExe := t.TempDir()
	exePath := filepath.Join(dirExe, "Foxit Software", "Foxit PDF Editor", "FoxitPDFEditor.exe")
	if err := os.MkdirAll(exePath, 0o755); err != nil {
		t.Fatal(err)
	}
	if st := locateFoxit(foxitSearch{goos: "windows", programFiles: dirExe}); st.Found {
		t.Fatalf("exe path is a directory: %#v", st)
	}

	legacyRoot := t.TempDir()
	phantom := filepath.Join(legacyRoot, "Foxit Software", "Foxit PhantomPDF", "FoxitPhantomPDF.exe")
	writeFoxitFile(t, phantom)
	st = locateFoxit(foxitSearch{goos: "windows", programFiles: "  ", programFilesX86: legacyRoot})
	if st.Path != phantom || !st.GuideOnly {
		t.Fatalf("legacy phantom: %#v", st)
	}

	// The same directory in both roots is searched once.
	shared := t.TempDir()
	sharedExe := filepath.Join(shared, "Foxit Software", "Foxit Reader", "FoxitReader.exe")
	writeFoxitFile(t, sharedExe)
	st = locateFoxit(foxitSearch{goos: "windows", programFiles: shared, programFilesX86: shared + string(filepath.Separator)})
	if st.Path != sharedExe {
		t.Fatalf("duplicate roots: %#v", st)
	}

	x86Only := t.TempDir()
	x86Exe := filepath.Join(x86Only, "Foxit Software", "Foxit PDF Reader", "FoxitPDFReader.exe")
	writeFoxitFile(t, x86Exe)
	st = locateFoxit(foxitSearch{goos: "windows", programFiles: t.TempDir(), programFilesX86: x86Only})
	if st.Path != x86Exe {
		t.Fatalf("x86 fallback: %#v", st)
	}
}

func TestLocateFoxitDarwin(t *testing.T) {
	t.Parallel()

	apps := t.TempDir()
	user := t.TempDir()
	search := foxitSearch{goos: "darwin", applications: apps, userApplications: user}

	if st := locateFoxit(search); st.Found {
		t.Fatalf("empty applications: %#v", st)
	}

	// A bundle directory without Info.plist is not an install.
	if err := os.MkdirAll(filepath.Join(apps, "Foxit PDF Editor.app", "Contents"), 0o755); err != nil {
		t.Fatal(err)
	}
	if st := locateFoxit(search); st.Found {
		t.Fatalf("bundle without plist: %#v", st)
	}

	userEditor := filepath.Join(user, "Foxit PDF Editor.app")
	writeFoxitFile(t, filepath.Join(userEditor, "Contents", "Info.plist"))
	systemReader := filepath.Join(apps, "Foxit PDF Reader.app")
	writeFoxitFile(t, filepath.Join(systemReader, "Contents", "Info.plist"))

	st := locateFoxit(search)
	if st.Path != systemReader || !st.Found || !st.GuideOnly {
		t.Fatalf("system Reader should win over a user Editor, got %#v", st)
	}

	systemEditor := filepath.Join(apps, "Foxit PDF Editor.app")
	writeFoxitFile(t, filepath.Join(systemEditor, "Contents", "Info.plist"))
	st = locateFoxit(search)
	if st.Path != systemEditor {
		t.Fatalf("system Editor should win, got %s", st.Path)
	}

	legacy := t.TempDir()
	reader := filepath.Join(legacy, "Foxit Reader.app")
	writeFoxitFile(t, filepath.Join(reader, "Contents", "Info.plist"))
	st = locateFoxit(foxitSearch{goos: "darwin", userApplications: legacy})
	if st.Path != reader || st.StatusLabel() != "guide only" {
		t.Fatalf("legacy reader bundle: %#v", st)
	}
}

func TestLocateFoxitOtherOS(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFoxitFile(t, filepath.Join(root, "Foxit Software", "Foxit PDF Editor", "FoxitPDFEditor.exe"))
	writeFoxitFile(t, filepath.Join(root, "Foxit PDF Editor.app", "Contents", "Info.plist"))
	for _, goos := range []string{"linux", "freebsd", ""} {
		st := locateFoxit(foxitSearch{
			goos:             goos,
			programFiles:     root,
			applications:     root,
			userApplications: root,
		})
		if st.Found || st.GuideOnly || st.Path != "" || st.Name != "foxit" {
			t.Fatalf("goos %q should not probe, got %#v", goos, st)
		}
		if st.StatusLabel() != "not-found" {
			t.Fatalf("goos %q label %q", goos, st.StatusLabel())
		}
	}
}

func TestDetectFoxitCurrentOS(t *testing.T) {
	st := detectFoxit()
	if st.Name != "foxit" {
		t.Fatalf("name %#v", st)
	}
	if runtime.GOOS != "windows" && runtime.GOOS != "darwin" {
		if st.Found || st.GuideOnly || st.Path != "" {
			t.Fatalf("non-desktop probe: %#v", st)
		}
	}
	if st.Found && !st.GuideOnly {
		t.Fatalf("an install must be guide only: %#v", st)
	}
	if !st.Found && (st.GuideOnly || st.Path != "") {
		t.Fatalf("a miss must be not-found: %#v", st)
	}
}

func TestFoxitStoreRefusesWithoutWriting(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	s, err := ForApp("Foxit")
	if err != nil {
		t.Fatal(err)
	}
	info := s.GetInfo()
	if info == nil || info.Name != "Foxit" {
		t.Fatalf("info %#v", info)
	}

	if _, err := ForAppWithStore("foxit", filepath.Join(home, "store")); err == nil || !strings.Contains(err.Error(), "--store with --app foxit") {
		t.Fatalf("store override: %v", err)
	}

	certs, err := s.List(nil)
	if !errors.Is(err, ErrFoxitGuideOnly) || certs != nil {
		t.Fatalf("list certs=%v err=%v", certs, err)
	}
	for _, phrase := range []string{
		"guide only",
		"unverified",
		"Trusted Certificates",
		"FATL",
		"EUTL",
		"Windows Integration",
		"Protect > Sign & Certify > Trusted Certificates",
		"Trust Manager",
		"Load trusted certificates from Foxit server",
		"every 28 days",
		"HKCU\\Software\\Policies\\Foxit\\PDFEditor",
		"value names are unverified",
	} {
		if !strings.Contains(err.Error(), phrase) {
			t.Errorf("guide missing %q", phrase)
		}
	}

	if err := s.Add(nil); !errors.Is(err, ErrFoxitGuideOnly) {
		t.Fatalf("add: %v", err)
	}
	if err := s.Remove(allowlist.Allowlist{}); !errors.Is(err, ErrFoxitGuideOnly) {
		t.Fatalf("remove: %v", err)
	}
	if err := s.Backup(); !errors.Is(err, ErrFoxitGuideOnly) {
		t.Fatalf("backup: %v", err)
	}
	if path, err := s.GetLatestBackup(); path != "" || !errors.Is(err, ErrFoxitGuideOnly) || errors.Is(err, ErrNoBackupFound) {
		t.Fatalf("latest backup path=%q err=%v", path, err)
	}
	if err := s.Restore(""); !errors.Is(err, ErrFoxitGuideOnly) {
		t.Fatalf("restore: %v", err)
	}

	entries, err := os.ReadDir(home)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("foxit operations wrote into HOME: %v", entries)
	}
}

func TestFoxitStatusLabel(t *testing.T) {
	t.Parallel()

	if (Status{Name: "foxit"}).StatusLabel() != "not-found" {
		t.Fatal("missing")
	}
	if (Status{Name: "java", Found: true}).StatusLabel() != "found" {
		t.Fatal("found")
	}
	// GuideOnly without Found stays not-found. locateFoxit does not emit that pair.
	if (Status{Name: "foxit", GuideOnly: true}).StatusLabel() != "not-found" {
		t.Fatal("guide without found")
	}
}
