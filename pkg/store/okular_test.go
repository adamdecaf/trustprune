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
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/adamdecaf/trustprune/pkg/allowlist"
)

func isolateOkularHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("XDG_CONFIG_DIRS", t.TempDir())
	t.Setenv("POPPLER_SIGNATURE_BACKEND", "")
	t.Setenv("APPDATA", "")
	t.Setenv("MOZ_LEGACY_HOME", "")
	orig := OkularCompiledSignatureBackend
	t.Cleanup(func() { OkularCompiledSignatureBackend = orig })
	OkularCompiledSignatureBackend = okularBackendNSS
	return home
}

func okularFileURL(path string) string {
	slash := filepath.ToSlash(path)
	if runtime.GOOS == "windows" && len(slash) >= 2 && slash[1] == ':' && !strings.HasPrefix(slash, "/") {
		slash = "/" + slash
	}
	return (&url.URL{Scheme: "file", Path: slash}).String()
}

func writeOkularRC(t *testing.T, home, body string) {
	t.Helper()
	dir := filepath.Join(home, ".config")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, okularConfigFileName), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func mustOkularStore(t *testing.T) okularStore {
	t.Helper()
	s := OkularStore()
	oks, ok := s.(okularStore)
	if !ok {
		t.Fatalf("OkularStore() type %T, want okularStore", s)
	}
	return oks
}

func TestForAppOkular(t *testing.T) {
	isolateOkularHome(t)
	s, err := ForApp("okular")
	if err != nil {
		t.Fatal(err)
	}
	oks, ok := s.(okularStore)
	if !ok {
		t.Fatalf("ForApp(\"okular\") type %T, want okularStore", s)
	}
	if oks.nssType != okularAppName {
		t.Fatalf("nssType=%q", oks.nssType)
	}
	info := s.GetInfo()
	if info == nil || info.Name != "Okular" || info.Path == "" {
		t.Fatalf("GetInfo()=%#v, want name Okular and a path", info)
	}
	detected := detectOkular()
	if detected.Name != okularAppName {
		t.Fatalf("detectOkular()=%#v, want name okular", detected)
	}
}

func TestOkularDefault(t *testing.T) {
	isolateOkularHome(t)

	s := mustOkularStore(t)
	if s.backend != okularBackendNSS {
		t.Fatalf("backend=%q, want NSS", s.backend)
	}
	poppler := PopplerStore()
	want := poppler.GetInfo().Path
	info := s.GetInfo()
	if info == nil || info.Name != "Okular" || info.Path != want {
		t.Fatalf("GetInfo()=%#v, want path %q (poppler default)", info, want)
	}
	if detected := detectOkular(); detected.GuideOnly {
		t.Fatalf("default NSS detect=%#v, want not guide-only", detected)
	}
	if detected := detectOkular(); detected.Found != systemHasCert9(want) {
		t.Fatalf("detect Found=%v, cert9 at %q is %v", detected.Found, want, systemHasCert9(want))
	}
	if detected := detectOkular(); detected.Found && detected.Path != want {
		t.Fatalf("detect path %q, want %q", detected.Path, want)
	}
}

func TestOkularCustomPath(t *testing.T) {
	home := isolateOkularHome(t)
	custom := filepath.Join(t.TempDir(), "okular-nssdb")
	if err := os.MkdirAll(custom, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(custom, "cert9.db"), []byte("certdb"), 0o644); err != nil {
		t.Fatal(err)
	}
	writeOkularRC(t, home, fmt.Sprintf("[Signatures]\nSignatureBackend=NSS\nUseDefaultCertDB=false\nDBCertificatePath=%s\n", custom))

	s := mustOkularStore(t)
	if s.backend != okularBackendNSS {
		t.Fatalf("backend=%q, want NSS", s.backend)
	}
	info := s.GetInfo()
	if info == nil || info.Name != "Okular" || info.Path != custom {
		t.Fatalf("GetInfo()=%#v, want custom path %q", info, custom)
	}
	detected := detectOkular()
	if !detected.Found || detected.GuideOnly || detected.Path != custom {
		t.Fatalf("detectOkular()=%#v, want found %q", detected, custom)
	}
}

func TestOkularExplicitGPG(t *testing.T) {
	home := isolateOkularHome(t)
	t.Setenv("POPPLER_SIGNATURE_BACKEND", "NSS")
	writeOkularRC(t, home, "[Signatures]\nSignatureBackend=GPG\nUseDefaultCertDB=false\nDBCertificatePath=/tmp/unused-nss\n")

	s := mustOkularStore(t)
	assertOkularGPG(t, s)
}

func TestOkularGPGViaPopplerSignatureBackend(t *testing.T) {
	home := isolateOkularHome(t)
	writeOkularRC(t, home, "[General]\nfoo=bar\n\n[Signatures]\nUseDefaultCertDB=true\n")
	t.Setenv("POPPLER_SIGNATURE_BACKEND", "GPG")

	s := mustOkularStore(t)
	assertOkularGPG(t, s)
}

func TestOkularCompiledDefaultGPG(t *testing.T) {
	isolateOkularHome(t)
	OkularCompiledSignatureBackend = okularBackendGPG

	s := mustOkularStore(t)
	assertOkularGPG(t, s)
}

func assertOkularGPG(t *testing.T, s okularStore) {
	t.Helper()
	if s.backend != okularBackendGPG {
		t.Fatalf("backend=%q, want GPG", s.backend)
	}
	info := s.GetInfo()
	if info == nil || info.Name != "Okular" || info.Path != okularBackendGPG {
		t.Fatalf("GetInfo()=%#v, want path GPG", info)
	}
	detected := detectOkular()
	if !detected.Found || !detected.GuideOnly || detected.Path != okularBackendGPG {
		t.Fatalf("detectOkular()=%#v, want guide only GPG", detected)
	}

	_, err := s.List(nil)
	if !errors.Is(err, ErrOkularGPG) {
		t.Fatalf("List: %v", err)
	}
	if !strings.Contains(err.Error(), "GPG") {
		t.Fatalf("List error should name GPG: %v", err)
	}
	ops := []struct {
		name string
		run  func() error
	}{
		{name: "add", run: func() error { return s.Add(nil) }},
		{name: "backup", run: func() error { return s.Backup() }},
		{name: "allowlist", run: func() error { return s.Remove(allowlist.Allowlist{}) }},
		{name: "restore", run: func() error { return s.Restore("") }},
		{name: "latest", run: func() error { _, e := s.GetLatestBackup(); return e }},
	}
	for _, op := range ops {
		if err := op.run(); !errors.Is(err, ErrOkularGPG) {
			t.Fatalf("%s: %v", op.name, err)
		}
	}
}

func TestOkularNoCert9FailsBeforeCertutil(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("certutil stand-in is a unix shell script")
	}
	home := isolateOkularHome(t)
	marker := filepath.Join(t.TempDir(), "certutil-called")
	installCertutilTrap(t, marker)

	missing := filepath.Join(t.TempDir(), "nssdb")
	writeOkularRC(t, home, fmt.Sprintf("[Signatures]\nUseDefaultCertDB=false\nDBCertificatePath=%s\n", missing))
	s := OkularStore()
	want := fmt.Sprintf("okular: no NSS database found (looked in %s); run Firefox once or create one with certutil -N -d sql:%s", missing, missing)
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

func TestParseKConfigSection(t *testing.T) {
	const body = "\ufeff# comment\n[General]\nfoo=bar\n[Signatures][$i]\nSignatureBackend[$e]=NSS\nUseDefaultCertDB=false\nDBCertificatePath=\"/tmp/db\"\n; ignored\n"
	got, unresolved := parseKConfigSection(body, "Signatures", nil)
	if got["SignatureBackend"] != "NSS" || got["UseDefaultCertDB"] != "false" || got["DBCertificatePath"] != "/tmp/db" {
		t.Fatalf("got %#v", got)
	}
	if len(unresolved) != 0 {
		t.Fatalf("unresolved %#v, want none", unresolved)
	}
	if _, ok := got["foo"]; ok {
		t.Fatalf("leaked General key: %#v", got)
	}
}

func TestOkularSignatureBackendWinsOverEnv(t *testing.T) {
	home := isolateOkularHome(t)
	t.Setenv("POPPLER_SIGNATURE_BACKEND", "GPG")
	writeOkularRC(t, home, "[Signatures]\nSignatureBackend=NSS\n")

	s := mustOkularStore(t)
	if s.backend != okularBackendNSS {
		t.Fatalf("backend=%q, want NSS (setting beats env)", s.backend)
	}
}

func TestOkularFileURLCertificatePath(t *testing.T) {
	home := isolateOkularHome(t)
	custom := filepath.Join(t.TempDir(), "okular nssdb")
	if err := os.MkdirAll(custom, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(custom, "cert9.db"), []byte("certdb"), 0o644); err != nil {
		t.Fatal(err)
	}
	writeOkularRC(t, home, fmt.Sprintf("[Signatures]\nSignatureBackend=NSS\nUseDefaultCertDB=false\nDBCertificatePath=%s\n", okularFileURL(custom)))

	s := mustOkularStore(t)
	info := s.GetInfo()
	if info == nil || info.Path != custom {
		t.Fatalf("GetInfo()=%#v, want decoded path %q", info, custom)
	}
}

func TestOkularSystemConfigDirsGPG(t *testing.T) {
	isolateOkularHome(t)
	sys := t.TempDir()
	if err := os.WriteFile(filepath.Join(sys, okularConfigFileName), []byte("[Signatures]\nSignatureBackend=GPG\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CONFIG_DIRS", sys)

	s := mustOkularStore(t)
	assertOkularGPG(t, s)
}

func TestOkularUserConfigOverridesSystem(t *testing.T) {
	home := isolateOkularHome(t)
	custom := filepath.Join(t.TempDir(), "system-nssdb")
	if err := os.MkdirAll(custom, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(custom, "cert9.db"), []byte("certdb"), 0o644); err != nil {
		t.Fatal(err)
	}
	sys := t.TempDir()
	if err := os.WriteFile(filepath.Join(sys, okularConfigFileName), []byte("[Signatures]\nSignatureBackend=GPG\nUseDefaultCertDB=false\nDBCertificatePath="+custom+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CONFIG_DIRS", sys)
	writeOkularRC(t, home, "[Signatures]\nSignatureBackend=NSS\n")

	s := mustOkularStore(t)
	if s.backend != okularBackendNSS {
		t.Fatalf("backend=%q, want NSS (user overrides system)", s.backend)
	}
	info := s.GetInfo()
	if info == nil || info.Path != custom {
		t.Fatalf("GetInfo()=%#v, want system DB path %q kept when the user file omits it", info, custom)
	}
}

func TestOkularExpandableBackendFromEnv(t *testing.T) {
	home := isolateOkularHome(t)
	t.Setenv("BACKEND", "GPG")
	writeOkularRC(t, home, "[Signatures]\nSignatureBackend[$e]=$BACKEND\n")

	s := mustOkularStore(t)
	assertOkularGPG(t, s)
}

func TestOkularUnexpandedBackendRefusesNSS(t *testing.T) {
	home := isolateOkularHome(t)
	t.Setenv("BACKEND", "")
	writeOkularRC(t, home, "[Signatures]\nSignatureBackend[$e]=$BACKEND\n")

	s := mustOkularStore(t)
	if s.backend != okularBackendUnresolved {
		t.Fatalf("backend=%q, want unresolved", s.backend)
	}
	if _, err := s.List(nil); !errors.Is(err, ErrOkularUnresolvedBackend) {
		t.Fatalf("List: %v", err)
	}
	if err := s.Backup(); !errors.Is(err, ErrOkularUnresolvedBackend) {
		t.Fatalf("Backup: %v", err)
	}
	detected := detectOkular()
	if !detected.Found || !detected.GuideOnly {
		t.Fatalf("detectOkular()=%#v, want guide only", detected)
	}
}

func TestOkularLocalFilePath(t *testing.T) {
	dir := t.TempDir()
	got := okularLocalFilePath(okularFileURL(dir))
	if got != dir {
		t.Fatalf("file URL %q, want %q", got, dir)
	}
	if okularLocalFilePath(dir) != dir {
		t.Fatalf("plain path changed: %q", okularLocalFilePath(dir))
	}
}

func TestOkularLiteralUnresolvedBackendIsNSS(t *testing.T) {
	home := isolateOkularHome(t)
	writeOkularRC(t, home, "[Signatures]\nSignatureBackend=unresolved\n")

	s := mustOkularStore(t)
	if s.backend != okularBackendNSS {
		t.Fatalf("backend=%q, want NSS for a literal SignatureBackend=unresolved", s.backend)
	}
	if s.refuseNonNSS() != nil {
		t.Fatalf("literal unresolved should not refuse NSS: %v", s.refuseNonNSS())
	}
}
