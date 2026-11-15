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
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFirefoxProfileDirs(t *testing.T) {
	now := time.Now()
	older := now.Add(-time.Hour)
	newer := now

	tests := []struct {
		name  string
		setup func(t *testing.T) (home, appdata string, want []string)
	}{
		{
			name: "no-profile",
			setup: func(t *testing.T) (string, string, []string) {
				return t.TempDir(), t.TempDir(), nil
			},
		},
		{
			name: ".default",
			setup: func(t *testing.T) (string, string, []string) {
				home := t.TempDir()
				empty := filepath.Join(home, ".mozilla", "firefox", "aaaa.default")
				if err := os.MkdirAll(empty, 0o755); err != nil {
					t.Fatal(err)
				}
				good := filepath.Join(home, ".mozilla", "firefox", "bbbb.default")
				writeFirefoxCertDB(t, good, "cert9.db", newer)
				return home, "", []string{good}
			},
		},
		{
			name: ".default-release",
			setup: func(t *testing.T) (string, string, []string) {
				home := t.TempDir()
				other := filepath.Join(home, ".mozilla", "firefox", "xxxx.nightly")
				writeFirefoxCertDB(t, other, "cert9.db", newer)
				rel := filepath.Join(home, ".mozilla", "firefox", "abcd.default-release")
				writeFirefoxCertDB(t, rel, "cert9.db", newer)
				return home, "", []string{rel}
			},
		},
		{
			name: "XDG root preferred by mtime",
			setup: func(t *testing.T) (string, string, []string) {
				home := t.TempDir()
				legacy := filepath.Join(home, ".mozilla", "firefox", "aaaa.default")
				writeFirefoxCertDB(t, legacy, "cert9.db", older)
				xdg := filepath.Join(home, ".config", "mozilla", "firefox", "bbbb.default-release")
				writeFirefoxCertDB(t, xdg, "cert9.db", newer)
				return home, "", []string{xdg, legacy}
			},
		},
		{
			name: "Windows layout",
			setup: func(t *testing.T) (string, string, []string) {
				appdata := t.TempDir()
				prof := filepath.Join(appdata, "Mozilla", "Firefox", "Profiles", "abcd.default-release")
				writeFirefoxCertDB(t, prof, "cert8.db", newer)
				return "", appdata, []string{prof}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home, appdata, want := tt.setup(t)
			got := FirefoxProfileDirs(home, appdata)
			if len(got) != len(want) {
				t.Fatalf("FirefoxProfileDirs()=%q want %q", got, want)
			}
			for i := range want {
				if got[i] != want[i] {
					t.Fatalf("FirefoxProfileDirs()=%q want %q", got, want)
				}
			}
		})
	}
}

func writeFirefoxCertDB(t *testing.T, dir, name string, mtime time.Time) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("certdb"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !mtime.IsZero() {
		if err := os.Chtimes(path, mtime, mtime); err != nil {
			t.Fatal(err)
		}
	}
}

func TestStoreFirefix__info(t *testing.T) {
	st := FirefoxStore()
	if _, ok := st.(emptyStore); ok {
		t.Skip("no firefox profile")
	}

	info := st.GetInfo()
	if info == nil {
		t.Fatal("nil Info")
	}
	if info.Name == "" {
		t.Error("blank Name")
	}
	if info.Version == "" {
		t.Error("blank Version")
	}
}
