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
		setup func(t *testing.T) (home, appdata string, getenv func(string) string, want []string)
	}{
		{
			name: "no-profile",
			setup: func(t *testing.T) (string, string, func(string) string, []string) {
				return t.TempDir(), t.TempDir(), getenvMap(nil), nil
			},
		},
		{
			name: ".default",
			setup: func(t *testing.T) (string, string, func(string) string, []string) {
				home := t.TempDir()
				empty := filepath.Join(home, ".mozilla", "firefox", "aaaa.default")
				if err := os.MkdirAll(empty, 0o755); err != nil {
					t.Fatal(err)
				}
				good := filepath.Join(home, ".mozilla", "firefox", "bbbb.default")
				writeFirefoxCertDB(t, good, "cert9.db", newer)
				return home, "", getenvMap(nil), []string{good}
			},
		},
		{
			name: ".default-release",
			setup: func(t *testing.T) (string, string, func(string) string, []string) {
				home := t.TempDir()
				other := filepath.Join(home, ".mozilla", "firefox", "xxxx.nightly")
				writeFirefoxCertDB(t, other, "cert9.db", newer)
				rel := filepath.Join(home, ".mozilla", "firefox", "abcd.default-release")
				writeFirefoxCertDB(t, rel, "cert9.db", newer)
				return home, "", getenvMap(nil), []string{rel}
			},
		},
		{
			name: "XDG root preferred by mtime",
			setup: func(t *testing.T) (string, string, func(string) string, []string) {
				home := t.TempDir()
				legacy := filepath.Join(home, ".mozilla", "firefox", "aaaa.default")
				writeFirefoxCertDB(t, legacy, "cert9.db", older)
				xdg := filepath.Join(home, ".config", "mozilla", "firefox", "bbbb.default-release")
				writeFirefoxCertDB(t, xdg, "cert9.db", newer)
				return home, "", getenvMap(nil), []string{xdg, legacy}
			},
		},
		{
			name: "Windows layout",
			setup: func(t *testing.T) (string, string, func(string) string, []string) {
				appdata := t.TempDir()
				prof := filepath.Join(appdata, "Mozilla", "Firefox", "Profiles", "abcd.default-release")
				writeFirefoxCertDB(t, prof, "cert8.db", newer)
				return "", appdata, getenvMap(nil), []string{prof}
			},
		},
		{
			name: "XDG_CONFIG_HOME absolute",
			setup: func(t *testing.T) (string, string, func(string) string, []string) {
				home := t.TempDir()
				xdgHome := t.TempDir()
				ignored := filepath.Join(home, ".config", "mozilla", "firefox", "aaaa.default")
				writeFirefoxCertDB(t, ignored, "cert9.db", newer)
				prof := filepath.Join(xdgHome, "mozilla", "firefox", "bbbb.default-release")
				writeFirefoxCertDB(t, prof, "cert9.db", older)
				return home, "", getenvMap(map[string]string{"XDG_CONFIG_HOME": xdgHome}), []string{prof}
			},
		},
		{
			name: "XDG_CONFIG_HOME relative falls back to ~/.config",
			setup: func(t *testing.T) (string, string, func(string) string, []string) {
				home := t.TempDir()
				rel := filepath.Join(home, "not-abs", "mozilla", "firefox", "aaaa.default")
				writeFirefoxCertDB(t, rel, "cert9.db", newer)
				fallback := filepath.Join(home, ".config", "mozilla", "firefox", "bbbb.default")
				writeFirefoxCertDB(t, fallback, "cert9.db", older)
				env := getenvMap(map[string]string{"XDG_CONFIG_HOME": "not-abs"})
				return home, "", env, []string{fallback}
			},
		},
		{
			name: "reject cert9.db directory",
			setup: func(t *testing.T) (string, string, func(string) string, []string) {
				home := t.TempDir()
				bad := filepath.Join(home, ".mozilla", "firefox", "aaaa.default-release")
				if err := os.MkdirAll(filepath.Join(bad, "cert9.db"), 0o755); err != nil {
					t.Fatal(err)
				}
				// Give the directory a nonzero size and a newer mtime than the valid DB.
				if err := os.WriteFile(filepath.Join(bad, "cert9.db", "x"), []byte("x"), 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.Chtimes(filepath.Join(bad, "cert9.db"), newer, newer); err != nil {
					t.Fatal(err)
				}
				good := filepath.Join(home, ".mozilla", "firefox", "bbbb.default")
				writeFirefoxCertDB(t, good, "cert9.db", older)
				return home, "", getenvMap(nil), []string{good}
			},
		},
		{
			name: "MOZ_LEGACY_HOME=1 still prefers newer XDG profile",
			setup: func(t *testing.T) (string, string, func(string) string, []string) {
				home := t.TempDir()
				legacy := filepath.Join(home, ".mozilla", "firefox", "aaaa.default")
				writeFirefoxCertDB(t, legacy, "cert9.db", older)
				xdg := filepath.Join(home, ".config", "mozilla", "firefox", "bbbb.default-release")
				writeFirefoxCertDB(t, xdg, "cert9.db", newer)
				env := getenvMap(map[string]string{"MOZ_LEGACY_HOME": "1"})
				return home, "", env, []string{xdg, legacy}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home, appdata, getenv, want := tt.setup(t)
			got := FirefoxProfileDirs(home, appdata, getenv)
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

func TestFirefoxProfileRoots(t *testing.T) {
	home := t.TempDir()
	xdgHome := t.TempDir()
	appdata := t.TempDir()
	legacy := filepath.Join(home, ".mozilla", "firefox")
	fallback := filepath.Join(home, ".config", "mozilla", "firefox")
	custom := filepath.Join(xdgHome, "mozilla", "firefox")
	macos := filepath.Join(home, "Library", "Application Support", "Firefox", "Profiles")
	win := filepath.Join(appdata, "Mozilla", "Firefox", "Profiles")

	tests := []struct {
		name    string
		home    string
		appdata string
		env     map[string]string
		want    []string
	}{
		{
			name: "default XDG then legacy",
			home: home,
			want: []string{fallback, legacy, macos},
		},
		{
			name: "MOZ_LEGACY_HOME=1 checks legacy first",
			home: home,
			env:  map[string]string{"MOZ_LEGACY_HOME": "1"},
			want: []string{legacy, fallback, macos},
		},
		{
			name: "XDG_CONFIG_HOME absolute",
			home: home,
			env:  map[string]string{"XDG_CONFIG_HOME": xdgHome},
			want: []string{custom, legacy, macos},
		},
		{
			name: "XDG_CONFIG_HOME relative falls back",
			home: home,
			env:  map[string]string{"XDG_CONFIG_HOME": "relative"},
			want: []string{fallback, legacy, macos},
		},
		{
			name:    "Windows appdata only",
			appdata: appdata,
			want:    []string{win},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := firefoxProfileRoots(tt.home, tt.appdata, getenvMap(tt.env))
			if len(got) != len(tt.want) {
				t.Fatalf("firefoxProfileRoots()=%q want %q", got, tt.want)
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Fatalf("firefoxProfileRoots()=%q want %q", got, tt.want)
				}
			}
		})
	}
}

func getenvMap(env map[string]string) func(string) string {
	return func(key string) string {
		return env[key]
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
