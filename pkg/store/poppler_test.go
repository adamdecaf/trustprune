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
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/adamdecaf/trustprune/pkg/allowlist"
)

func TestForAppPopplerIsNSS(t *testing.T) {
	s, err := ForApp("poppler")
	if err != nil {
		t.Fatal(err)
	}
	ns, ok := s.(popplerStore)
	if !ok {
		t.Fatalf("ForApp(\"poppler\") type %T, want popplerStore", s)
	}
	if ns.nssType != "poppler" {
		t.Fatalf("nssType=%q", ns.nssType)
	}
	info := s.GetInfo()
	if info == nil || info.Name != "Poppler" || info.Path == "" {
		t.Fatalf("GetInfo()=%#v, want name Poppler and a path", info)
	}
	detected := detectPoppler()
	if detected.Name != "poppler" {
		t.Fatalf("detectPoppler()=%#v, want name poppler", detected)
	}
	if detected.Found && detected.Path == "" {
		t.Fatalf("detectPoppler()=%#v, found with empty path", detected)
	}
	if detected.Found && info.Path != detected.Path {
		t.Fatalf("detectPoppler path %q != GetInfo path %q", detected.Path, info.Path)
	}
	if detected.Found && !systemHasCert9(detected.Path) {
		t.Fatalf("detectPoppler Found=true but %q has no cert9.db", detected.Path)
	}
	if !detected.Found && systemHasCert9(info.Path) {
		t.Fatalf("detectPoppler Found=false but %q has cert9.db", info.Path)
	}

	const override = "/tmp/poppler-nssdb"
	over, err := ForAppWithStore("poppler", override)
	if err != nil {
		t.Fatal(err)
	}
	ons, ok := over.(popplerStore)
	if !ok || ons.nssType != "poppler" {
		t.Fatalf("override type %T", over)
	}
	oinfo := over.GetInfo()
	if oinfo == nil || oinfo.Path != override || oinfo.Name != "Poppler" {
		t.Fatalf("override GetInfo()=%#v, want path %s", oinfo, override)
	}
}

func TestPopplerNSSDir(t *testing.T) {
	alwaysOpen := func(string) (bool, error) { return true, nil }
	neverOpen := func(string) (bool, error) { return false, nil }
	unavailable := func(string) (bool, error) { return false, errors.New("certutil not found") }
	pki := func(home string) string { return filepath.Join(home, ".pki", "nssdb") }

	tests := []struct {
		name  string
		setup func(t *testing.T) (home, appdata string, getenv func(string) string, systemDir string, opens func(string) (bool, error), want string)
	}{
		{
			name: "profile found",
			setup: func(t *testing.T) (string, string, func(string) string, string, func(string) (bool, error), string) {
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
			setup: func(t *testing.T) (string, string, func(string) string, string, func(string) (bool, error), string) {
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
			setup: func(t *testing.T) (string, string, func(string) string, string, func(string) (bool, error), string) {
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
			setup: func(t *testing.T) (string, string, func(string) string, string, func(string) (bool, error), string) {
				home := t.TempDir()
				sys := t.TempDir()
				return home, "", getenvMap(nil), sys, alwaysOpen, pki(home)
			},
		},
		{
			name: "systemDir fails open -> ~/.pki/nssdb",
			setup: func(t *testing.T) (string, string, func(string) string, string, func(string) (bool, error), string) {
				home := t.TempDir()
				sys := t.TempDir()
				if err := os.WriteFile(filepath.Join(sys, "cert9.db"), []byte("certdb"), 0o644); err != nil {
					t.Fatal(err)
				}
				return home, "", getenvMap(nil), sys, neverOpen, pki(home)
			},
		},
		{
			name: "cert8-only profile skipped -> systemDir",
			setup: func(t *testing.T) (string, string, func(string) string, string, func(string) (bool, error), string) {
				home := t.TempDir()
				prof := filepath.Join(home, ".mozilla", "firefox", "abcd.default")
				writeFirefoxCertDB(t, prof, "cert8.db", time.Now())
				sys := t.TempDir()
				if err := os.WriteFile(filepath.Join(sys, "cert9.db"), []byte("certdb"), 0o644); err != nil {
					t.Fatal(err)
				}
				return home, "", getenvMap(nil), sys, alwaysOpen, sys
			},
		},
		{
			name: "cert8-only profile and no system cert9 -> ~/.pki/nssdb",
			setup: func(t *testing.T) (string, string, func(string) string, string, func(string) (bool, error), string) {
				home := t.TempDir()
				prof := filepath.Join(home, ".mozilla", "firefox", "abcd.default")
				writeFirefoxCertDB(t, prof, "cert8.db", time.Now())
				sys := t.TempDir()
				return home, "", getenvMap(nil), sys, alwaysOpen, pki(home)
			},
		},
		{
			name: "newer cert9 in later root wins",
			setup: func(t *testing.T) (string, string, func(string) string, string, func(string) (bool, error), string) {
				home := t.TempDir()
				xdg := filepath.Join(home, ".config", "mozilla", "firefox", "old.default")
				legacy := filepath.Join(home, ".mozilla", "firefox", "new.default")
				writeFirefoxCertDB(t, xdg, "cert9.db", time.Now().Add(-time.Hour))
				writeFirefoxCertDB(t, legacy, "cert9.db", time.Now())
				sys := t.TempDir()
				return home, "", getenvMap(nil), sys, alwaysOpen, legacy
			},
		},
		{
			name: "probe unavailable keeps profile",
			setup: func(t *testing.T) (string, string, func(string) string, string, func(string) (bool, error), string) {
				home := t.TempDir()
				prof := filepath.Join(home, ".mozilla", "firefox", "abcd.default")
				writeFirefoxCertDB(t, prof, "cert9.db", time.Now())
				sys := t.TempDir()
				if err := os.WriteFile(filepath.Join(sys, "cert9.db"), []byte("certdb"), 0o644); err != nil {
					t.Fatal(err)
				}
				return home, "", getenvMap(nil), sys, unavailable, prof
			},
		},
		{
			name: "probe unavailable keeps systemDir",
			setup: func(t *testing.T) (string, string, func(string) string, string, func(string) (bool, error), string) {
				home := t.TempDir()
				sys := t.TempDir()
				if err := os.WriteFile(filepath.Join(sys, "cert9.db"), []byte("certdb"), 0o644); err != nil {
					t.Fatal(err)
				}
				return home, "", getenvMap(nil), sys, unavailable, sys
			},
		},
		{
			name: "empty cert9 profile skipped -> systemDir",
			setup: func(t *testing.T) (string, string, func(string) string, string, func(string) (bool, error), string) {
				home := t.TempDir()
				prof := filepath.Join(home, ".mozilla", "firefox", "abcd.default")
				if err := os.MkdirAll(prof, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(prof, "cert9.db"), nil, 0o644); err != nil {
					t.Fatal(err)
				}
				sys := t.TempDir()
				if err := os.WriteFile(filepath.Join(sys, "cert9.db"), []byte("certdb"), 0o644); err != nil {
					t.Fatal(err)
				}
				return home, "", getenvMap(nil), sys, alwaysOpen, sys
			},
		},
		{
			name: "empty system cert9 -> ~/.pki/nssdb",
			setup: func(t *testing.T) (string, string, func(string) string, string, func(string) (bool, error), string) {
				home := t.TempDir()
				sys := t.TempDir()
				if err := os.WriteFile(filepath.Join(sys, "cert9.db"), nil, 0o644); err != nil {
					t.Fatal(err)
				}
				return home, "", getenvMap(nil), sys, alwaysOpen, pki(home)
			},
		},
		{
			name: "system cert9 directory -> ~/.pki/nssdb",
			setup: func(t *testing.T) (string, string, func(string) string, string, func(string) (bool, error), string) {
				home := t.TempDir()
				sys := t.TempDir()
				if err := os.Mkdir(filepath.Join(sys, "cert9.db"), 0o755); err != nil {
					t.Fatal(err)
				}
				return home, "", getenvMap(nil), sys, alwaysOpen, pki(home)
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

func TestPopplerNSSOpens_UnavailableIsNotOpenFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("certutil stand-in is a unix shell script")
	}
	orig := cutil
	t.Cleanup(func() { cutil = orig })

	dir := t.TempDir()
	cutil = crtutil{execPaths: []string{filepath.Join(dir, "missing-certutil")}}
	ok, err := popplerNSSOpens(dir)
	if ok || err == nil {
		t.Fatalf("missing certutil: ok=%v err=%v, want probe error", ok, err)
	}

	bin := filepath.Join(dir, "certutil")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	cutil = crtutil{execPaths: []string{bin}}
	ok, err = popplerNSSOpens(dir)
	if ok || err != nil {
		t.Fatalf("certutil exit 1: ok=%v err=%v, want open failure without probe error", ok, err)
	}

	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	ok, err = popplerNSSOpens(dir)
	if !ok || err != nil {
		t.Fatalf("certutil exit 0: ok=%v err=%v, want opened", ok, err)
	}
}

// TestPopplerNoCert9FailsBeforeCertutil covers list, backup, add, and
// allowlist when the resolved directory has no usable cert9.db. certutil
// must not run: its failure on a missing database is only "exit status 255".
func TestPopplerNoCert9FailsBeforeCertutil(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("certutil stand-in is a unix shell script")
	}
	marker := filepath.Join(t.TempDir(), "certutil-called")
	installCertutilTrap(t, marker)

	missing := filepath.Join(t.TempDir(), "nssdb")
	assertPopplerMissingDB(t, PopplerStoreAt(missing), missing, marker)

	emptyDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(emptyDir, "cert9.db"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	assertPopplerMissingDB(t, PopplerStoreAt(emptyDir), emptyDir, marker)

	// Same failure `trustprune list --app poppler` hits with no Firefox
	// profile and no ~/.pki/nssdb. A host /etc/pki/nssdb/cert9.db is a real
	// database pdfsig would use, so that case is not this error.
	if !systemHasCert9("/etc/pki/nssdb") {
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("USERPROFILE", home)
		t.Setenv("APPDATA", "")
		t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "xdg"))
		t.Setenv("MOZ_LEGACY_HOME", "")
		fallback := filepath.Join(home, ".pki", "nssdb")
		s := PopplerStore()
		if got := s.GetInfo().Path; got != fallback {
			t.Fatalf("PopplerStore path %q, want %q", got, fallback)
		}
		assertPopplerMissingDB(t, s, fallback, marker)
	}

	withDB := t.TempDir()
	if err := os.WriteFile(filepath.Join(withDB, "cert9.db"), []byte("certdb"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(marker); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	_, err := PopplerStoreAt(withDB).List(nil)
	if err == nil || strings.Contains(err.Error(), "no NSS database found") {
		t.Fatalf("cert9.db present: got %v, want certutil's own error", err)
	}
	if _, statErr := os.Stat(marker); statErr != nil {
		t.Fatal("certutil was not run for an existing cert9.db")
	}
}

func assertPopplerMissingDB(t *testing.T, s Store, dir, marker string) {
	t.Helper()
	want := fmt.Sprintf("poppler: no NSS database found (looked in %s); run Firefox once or create one with certutil -N -d sql:%s", dir, dir)
	ops := []struct {
		name string
		run  func() error
	}{
		{name: "list", run: func() error { _, err := s.List(nil); return err }},
		{name: "backup", run: func() error { return s.Backup() }},
		{name: "add", run: func() error { return s.Add(nil) }},
		{name: "allowlist", run: func() error { return s.Remove(allowlist.Allowlist{}) }},
	}
	for _, op := range ops {
		if err := os.Remove(marker); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		err := op.run()
		if err == nil || err.Error() != want {
			t.Fatalf("%s: got %v, want %q", op.name, err, want)
		}
		if _, statErr := os.Stat(marker); statErr == nil {
			t.Fatalf("%s ran certutil", op.name)
		}
	}
}

func installCertutilTrap(t *testing.T, marker string) {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "certutil")
	script := "#!/bin/sh\nprintf 'x' >> '" + marker + "'\nexit 255\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	orig := cutil
	t.Cleanup(func() { cutil = orig })
	cutil = crtutil{execPaths: []string{bin}}
}

func TestPopplerRequireCert9_PermissionError(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cert9.db"), []byte("certdb"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	if _, err := os.Stat(filepath.Join(dir, "cert9.db")); err == nil {
		t.Skip("process can stat a mode-000 directory")
	}
	err := popplerStore{nssStore: nssStore{foundCertdbLocation: dir}}.requireCert9()
	if err == nil || strings.Contains(err.Error(), "no NSS database found") || !strings.Contains(err.Error(), "checking NSS database") {
		t.Fatalf("got %v, want a wrapped filesystem error", err)
	}
}
