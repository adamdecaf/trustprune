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
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adamdecaf/trustprune/pkg/certutil"
)

func TestReportAllowlistDryRun_Format(t *testing.T) {
	var buf bytes.Buffer
	SetDryRunOutput(&buf)
	SetDryRunVerbose(false)
	t.Cleanup(func() {
		SetDryRunOutput(nil)
		SetDryRunVerbose(false)
	})

	reportAllowlistDryRun("empty", "", nil, nil, nil, nil, []string{"remove hidden"})
	want := "dry-run: would remove certificates from empty\ndry-run: no changes made\ndry-run: 0 kept, 0 removed\n"
	if buf.String() != want {
		t.Fatalf("stub plan:\n%q", buf.String())
	}

	buf.Reset()
	reportAllowlistDryRun("linux", "/ca", nil, nil,
		[]string{"unparsable PEM block (4 bytes) in /ca/mixed.crt"},
		[]string{"then run /bin/true"},
		[]string{"remove CN=Nope (SHA256 aa) from /ca/mixed.crt", "keep unparsable PEM block (4 bytes) in /ca/mixed.crt"},
	)
	want = "dry-run: would remove certificates from linux at /ca\n  then run /bin/true\nKept:\n  unparsable PEM block (4 bytes) in /ca/mixed.crt\ndry-run: no changes made\ndry-run: 0 kept, 0 removed\n"
	if buf.String() != want {
		t.Fatalf("default plan:\n%q", buf.String())
	}

	buf.Reset()
	SetDryRunVerbose(true)
	reportAllowlistDryRun("linux", "/ca", nil, nil,
		[]string{"unparsable PEM block (4 bytes) in /ca/mixed.crt"},
		[]string{"then run /bin/true"},
		[]string{"remove CN=Nope (SHA256 aa) from /ca/mixed.crt", "keep unparsable PEM block (4 bytes) in /ca/mixed.crt"},
	)
	want = "dry-run: would remove certificates from linux at /ca\n  then run /bin/true\nKept:\n  unparsable PEM block (4 bytes) in /ca/mixed.crt\n  remove CN=Nope (SHA256 aa) from /ca/mixed.crt\n  keep unparsable PEM block (4 bytes) in /ca/mixed.crt\ndry-run: no changes made\ndry-run: 0 kept, 0 removed\n"
	if buf.String() != want {
		t.Fatalf("verbose plan:\n%q", buf.String())
	}
}

func enableDryRunCaptureAny(t *testing.T) *bytes.Buffer {
	t.Helper()
	buf := &bytes.Buffer{}
	SetDryRun(true)
	SetDryRunOutput(buf)
	t.Cleanup(func() {
		SetDryRun(false)
		SetDryRunOutput(nil)
	})
	return buf
}

func fileSHA256(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func dirSHA256(t *testing.T, dir string) string {
	t.Helper()
	h := sha256.New()
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		h.Write([]byte(rel))
		h.Write(b)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func TestJavaDryRun_RestoreLeavesStoreUnchanged(t *testing.T) {
	layouts := activeJavaLayouts()
	if len(layouts) == 0 {
		t.Skip("no java home layouts configured")
	}
	cacertsBytes := sharedTempCacertsBytes(t)
	layout := layouts[0]
	s, kpath := javaBackupTestEnvFor(t, layout, cacertsBytes)

	alternate := filepath.Join(t.TempDir(), "alternate-java.bck")
	if err := os.WriteFile(alternate, []byte("ALTERNATE-JAVA-DRY-RUN\n"), 0644); err != nil {
		t.Fatal(err)
	}
	before := fileSHA256(t, kpath)

	buf := enableDryRunCaptureAny(t)
	if err := s.Restore(alternate); err != nil {
		t.Fatalf("Restore dry-run: %v", err)
	}
	if fileSHA256(t, kpath) != before {
		t.Fatal("dry-run Restore mutated java keystore")
	}
	out := buf.String()
	if !strings.Contains(out, "dry-run: would restore java") {
		t.Fatalf("missing restore plan: %q", out)
	}
	if !strings.Contains(out, alternate) {
		t.Fatalf("plan missing source path: %q", out)
	}
}

func TestJavaDryRun_AddLeavesStoreUnchanged(t *testing.T) {
	layouts := activeJavaLayouts()
	if len(layouts) == 0 {
		t.Skip("no java home layouts configured")
	}
	cacertsBytes := sharedTempCacertsBytes(t)
	layout := layouts[0]
	s, kpath := javaBackupTestEnvFor(t, layout, cacertsBytes)
	before := fileSHA256(t, kpath)

	certs, err := certutil.FromFile(filepath.Join("..", "..", "testdata", "example.crt"))
	if err != nil || len(certs) == 0 {
		t.Fatalf("load example.crt: %v", err)
	}
	fp := certutil.GetHexSHA256Fingerprint(*certs[0])

	buf := enableDryRunCaptureAny(t)
	if err := s.Add(certs); err != nil {
		t.Fatalf("Add dry-run: %v", err)
	}
	if fileSHA256(t, kpath) != before {
		t.Fatal("dry-run Add mutated java keystore")
	}
	out := buf.String()
	if !strings.Contains(out, "dry-run: would add certificates to java") {
		t.Fatalf("missing add plan: %q", out)
	}
	if !strings.Contains(out, fp) {
		t.Fatalf("plan missing fingerprint %s: %q", fp, out)
	}
}

func TestJavaDryRun_RestoreWithoutFlagDoesMutate(t *testing.T) {
	layouts := activeJavaLayouts()
	if len(layouts) == 0 {
		t.Skip("no java home layouts configured")
	}
	cacertsBytes := sharedTempCacertsBytes(t)
	layout := layouts[0]
	s, kpath := javaBackupTestEnvFor(t, layout, cacertsBytes)

	alternate := filepath.Join(t.TempDir(), "alternate-java.bck")
	alt := []byte("ALTERNATE-JAVA-CONTROL\n")
	if err := os.WriteFile(alternate, alt, 0644); err != nil {
		t.Fatal(err)
	}
	before := fileSHA256(t, kpath)
	SetDryRun(false)
	if err := s.Restore(alternate); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	after := fileSHA256(t, kpath)
	if before == after {
		t.Fatal("Restore without dry-run did not change java keystore")
	}
	got, err := os.ReadFile(kpath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, alt) {
		t.Fatalf("got %q want %q", got, alt)
	}
}

func TestNSSDryRun_RestoreLeavesStoreUnchanged(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	nssdbDir := filepath.Join(t.TempDir(), "nssdb")
	if err := os.MkdirAll(nssdbDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nssdbDir, "cert9.db"), []byte("live-cert9\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nssdbDir, "key4.db"), []byte("live-key4\n"), 0644); err != nil {
		t.Fatal(err)
	}

	alternate := t.TempDir()
	for name, body := range map[string][]byte{
		"cert9.db":   []byte("alt-cert9\n"),
		"key4.db":    []byte("alt-key4\n"),
		"pkcs11.txt": []byte("alt-pkcs11\n"),
	} {
		if err := os.WriteFile(filepath.Join(alternate, name), body, 0644); err != nil {
			t.Fatal(err)
		}
	}

	before := dirSHA256(t, nssdbDir)
	s := NssStore("firefox-test", "0", nssdbDir)
	buf := enableDryRunCaptureAny(t)
	if err := s.Restore(alternate); err != nil {
		t.Fatalf("Restore dry-run: %v", err)
	}
	if dirSHA256(t, nssdbDir) != before {
		t.Fatal("dry-run Restore mutated NSS profile")
	}
	out := buf.String()
	if !strings.Contains(out, "dry-run: would restore firefox-test") {
		t.Fatalf("missing restore plan: %q", out)
	}
	if !strings.Contains(out, "cert9.db") || !strings.Contains(out, "key4.db") {
		t.Fatalf("plan missing profile files: %q", out)
	}
}

func TestNSSDryRun_BackupMakesNoWrites(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	nssdbDir := filepath.Join(t.TempDir(), "nssdb")
	if err := os.MkdirAll(nssdbDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nssdbDir, "cert9.db"), []byte("live-cert9\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nssdbDir, "key4.db"), []byte("live-key4\n"), 0644); err != nil {
		t.Fatal(err)
	}
	before := dirSHA256(t, nssdbDir)

	s := NssStore("firefox-test", "0", nssdbDir)
	buf := enableDryRunCaptureAny(t)
	if err := s.Backup(); err != nil {
		t.Fatalf("Backup dry-run: %v", err)
	}
	if dirSHA256(t, nssdbDir) != before {
		t.Fatal("dry-run Backup mutated NSS profile")
	}
	for _, name := range []string{".cert-manage", ".trustprune"} {
		cm := filepath.Join(home, name)
		if _, err := os.Stat(cm); !os.IsNotExist(err) {
			t.Fatalf("dry-run Backup must not create %s (err=%v)", cm, err)
		}
	}
	out := buf.String()
	if !strings.Contains(out, "dry-run: would backup firefox-test") {
		t.Fatalf("missing backup plan: %q", out)
	}
}

func TestNSSDryRun_RestoreWithoutFlagDoesMutate(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	nssdbDir := filepath.Join(t.TempDir(), "nssdb")
	if err := os.MkdirAll(nssdbDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nssdbDir, "cert9.db"), []byte("live-cert9\n"), 0644); err != nil {
		t.Fatal(err)
	}

	alternate := t.TempDir()
	want := []byte("alt-cert9-control\n")
	if err := os.WriteFile(filepath.Join(alternate, "cert9.db"), want, 0644); err != nil {
		t.Fatal(err)
	}

	before := fileSHA256(t, filepath.Join(nssdbDir, "cert9.db"))
	s := NssStore("firefox-test", "0", nssdbDir)
	SetDryRun(false)
	if err := s.Restore(alternate); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	after := fileSHA256(t, filepath.Join(nssdbDir, "cert9.db"))
	if before == after {
		t.Fatal("Restore without dry-run did not change NSS profile")
	}
	got, err := os.ReadFile(filepath.Join(nssdbDir, "cert9.db"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestFormatCertLine(t *testing.T) {
	certs, err := certutil.FromFile(filepath.Join("..", "..", "testdata", "example.crt"))
	if err != nil || len(certs) == 0 {
		t.Fatalf("load example.crt: %v", err)
	}
	line := formatCertLine(certs[0])
	fp := certutil.GetHexSHA256Fingerprint(*certs[0])
	if !strings.Contains(line, fp) {
		t.Fatalf("line missing fingerprint: %q", line)
	}
	if !strings.Contains(line, "SHA256") {
		t.Fatalf("line missing SHA256 label: %q", line)
	}
}
