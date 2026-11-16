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
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestForAppPopplerIsNSS(t *testing.T) {
	s, err := ForApp("poppler")
	if err != nil {
		t.Fatal(err)
	}
	ns, ok := s.(nssStore)
	if !ok {
		t.Fatalf("ForApp(\"poppler\") type %T, want nssStore", s)
	}
	if ns.nssType != "poppler" {
		t.Fatalf("nssType=%q", ns.nssType)
	}
	info := s.GetInfo()
	if info == nil || info.Name != "Poppler" || info.Path == "" {
		t.Fatalf("GetInfo()=%#v, want name Poppler and a path", info)
	}
	detected := detectPoppler()
	if detected.Name != "poppler" || !detected.Found || detected.Path == "" {
		t.Fatalf("detectPoppler()=%#v, want the chosen path", detected)
	}

	const override = "/tmp/poppler-nssdb"
	over, err := ForAppWithStore("poppler", override)
	if err != nil {
		t.Fatal(err)
	}
	ons, ok := over.(nssStore)
	if !ok || ons.nssType != "poppler" {
		t.Fatalf("override type %T", over)
	}
	oinfo := over.GetInfo()
	if oinfo == nil || oinfo.Path != override || oinfo.Name != "Poppler" {
		t.Fatalf("override GetInfo()=%#v, want path %s", oinfo, override)
	}
}

func TestPopplerNSSDir(t *testing.T) {
	alwaysOpen := func(string) bool { return true }
	neverOpen := func(string) bool { return false }
	pki := func(home string) string { return filepath.Join(home, ".pki", "nssdb") }

	tests := []struct {
		name  string
		setup func(t *testing.T) (home, appdata string, getenv func(string) string, systemDir string, opens func(string) bool, want string)
	}{
		{
			name: "profile found",
			setup: func(t *testing.T) (string, string, func(string) string, string, func(string) bool, string) {
				home := t.TempDir()
				prof := filepath.Join(home, ".mozilla", "firefox", "abcd.default")
				writeFirefoxCertDB(t, prof, "cert9.db", time.Now())
				sys := t.TempDir()
				writeFirefoxCertDB(t, sys, "cert9.db", time.Now())
				return home, "", getenvMap(nil), sys, alwaysOpen, prof
			},
		},
		{
			name: "profile fails open -> ~/.pki/nssdb",
			setup: func(t *testing.T) (string, string, func(string) string, string, func(string) bool, string) {
				home := t.TempDir()
				prof := filepath.Join(home, ".mozilla", "firefox", "abcd.default")
				writeFirefoxCertDB(t, prof, "cert9.db", time.Now())
				sys := t.TempDir()
				writeFirefoxCertDB(t, sys, "cert9.db", time.Now())
				return home, "", getenvMap(nil), sys, neverOpen, pki(home)
			},
		},
		{
			name: "no profile -> systemDir",
			setup: func(t *testing.T) (string, string, func(string) string, string, func(string) bool, string) {
				home := t.TempDir()
				sys := t.TempDir()
				if err := os.WriteFile(filepath.Join(sys, "cert9.db"), []byte("certdb"), 0o644); err != nil {
					t.Fatal(err)
				}
				return home, "", getenvMap(nil), sys, alwaysOpen, sys
			},
		},
		{
			name: "nothing -> ~/.pki/nssdb",
			setup: func(t *testing.T) (string, string, func(string) string, string, func(string) bool, string) {
				home := t.TempDir()
				sys := t.TempDir()
				return home, "", getenvMap(nil), sys, alwaysOpen, pki(home)
			},
		},
		{
			name: "systemDir fails open -> ~/.pki/nssdb",
			setup: func(t *testing.T) (string, string, func(string) string, string, func(string) bool, string) {
				home := t.TempDir()
				sys := t.TempDir()
				if err := os.WriteFile(filepath.Join(sys, "cert9.db"), []byte("certdb"), 0o644); err != nil {
					t.Fatal(err)
				}
				return home, "", getenvMap(nil), sys, neverOpen, pki(home)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home, appdata, getenv, systemDir, opens, want := tt.setup(t)
			got := PopplerNSSDir(home, appdata, getenv, systemDir, opens)
			if got != want {
				t.Fatalf("PopplerNSSDir()=%q want %q", got, want)
			}
		})
	}
}
