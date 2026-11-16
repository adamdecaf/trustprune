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

package gen

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/adamdecaf/trustprune/pkg/file"
	"github.com/adamdecaf/trustprune/pkg/store"
	"github.com/go-sqlite/sqlite3"
)

func TestFindFirefoxPlacesPath(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T) (dirs []string, want string)
	}{
		{
			name: "first-has-places",
			setup: func(t *testing.T) (dirs []string, want string) {
				first := t.TempDir()
				second := t.TempDir()
				writePlaces(t, first)
				return []string{first, second}, filepath.Join(first, "places.sqlite")
			},
		},
		{
			name: "skip-until-places",
			setup: func(t *testing.T) (dirs []string, want string) {
				first := t.TempDir()
				second := t.TempDir()
				writePlaces(t, second)
				return []string{first, second}, filepath.Join(second, "places.sqlite")
			},
		},
		{
			name: "none",
			setup: func(t *testing.T) (dirs []string, want string) {
				return []string{t.TempDir(), t.TempDir()}, ""
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dirs, want := tt.setup(t)
			got := findFirefoxPlacesPath(dirs)
			if got != want {
				t.Fatalf("findFirefoxPlacesPath()=%q want %q", got, want)
			}
		})
	}
}

func TestFindFirefoxPlacesPath_UsesProfileDirs(t *testing.T) {
	home := t.TempDir()
	older := time.Now().Add(-time.Hour)
	newer := time.Now()

	first := filepath.Join(home, ".mozilla", "firefox", "bbbb.default-release")
	second := filepath.Join(home, ".mozilla", "firefox", "aaaa.default")
	writeFirefoxCertDB(t, first, newer)
	writeFirefoxCertDB(t, second, older)
	writePlaces(t, second)

	dirs := store.FirefoxProfileDirs(home, "", func(string) string { return "" })
	if len(dirs) != 2 || dirs[0] != first {
		t.Fatalf("FirefoxProfileDirs()=%q want first %s", dirs, first)
	}
	got := findFirefoxPlacesPath(dirs)
	want := filepath.Join(second, "places.sqlite")
	if got != want {
		t.Fatalf("findFirefoxPlacesPath()=%q want %q", got, want)
	}
}

func writePlaces(t *testing.T, dir string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "places.sqlite"), []byte("sqlite"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeFirefoxCertDB(t *testing.T, dir string, mtime time.Time) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "cert9.db")
	if err := os.WriteFile(path, []byte("certdb"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatal(err)
	}
}

func TestAllowlistGen__findFirefoxPlacesDB(t *testing.T) {
	if !file.Exists("/Applications/Firefox.app") {
		return
	}
	db, err := findFirefoxPlacesDB()
	if err != nil {
		t.Skip(err.Error())
	}
	if db == nil {
		t.Skip("firefox installed, but no places.sqlite")
	}
}

func TestAllowlistGen__getFirefoxUrls(t *testing.T) {
	cases := []struct {
		count int
		path  string
	}{
		{
			count: 3,
			path:  "../../../testdata/firefox-history.sqlite",
		},
		{
			count: 3,
			path:  "../../../testdata/firefox-history-win.sqlite",
		},
	}
	for i := range cases {
		db, err := sqlite3.Open(cases[i].path)
		if err != nil {
			t.Fatalf("%s - err=%v", cases[i].path, err)
		}
		urls, err := getFirefoxUrls(db)
		if err != nil {
			t.Fatalf("store %s, err=%v", cases[i].path, err)
		}
		if len(urls) != cases[i].count {
			t.Fatalf("store: %s, got %d urls", cases[i].path, len(urls))
		}
	}
}
