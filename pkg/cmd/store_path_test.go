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

package cmd

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/adamdecaf/trustprune/pkg/certutil"
	"github.com/adamdecaf/trustprune/pkg/store"
	"github.com/adamdecaf/trustprune/pkg/ui"
)

// defaultJavaStorePassword matches pkg/store defaultKeystorePassword.
// The Java store reads this password; the test cannot see that unexported name.
const defaultJavaStorePassword = "changeit"

func TestAddCertsToAppFromStoreCertifiDryRun(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	bundle := writeLotsBundle(t, filepath.Join(t.TempDir(), "venv", "lib", "python3.12", "site-packages", "certifi", "cacert.pem"))
	before, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	cert := filepath.Join("..", "..", "testdata", "example.crt")

	var plan bytes.Buffer
	store.SetDryRun(true)
	store.SetDryRunOutput(&plan)
	t.Cleanup(func() {
		store.SetDryRun(false)
		store.SetDryRunOutput(nil)
	})

	if err := AddCertsToAppFromStore("certifi", bundle, cert); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plan.String(), bundle) {
		t.Fatalf("dry-run plan %q does not name the -store bundle", plan.String())
	}
	if !strings.Contains(plan.String(), "certifi") {
		t.Fatalf("dry-run plan %q does not name certifi", plan.String())
	}
	after, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("dry-run add modified the certifi bundle")
	}
}

func TestAddCertsToAppFromStoreJavaDryRun(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	ks := filepath.Join(t.TempDir(), "cacerts")
	if err := os.WriteFile(ks, []byte("not-a-real-keystore"), 0o644); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(ks)
	if err != nil {
		t.Fatal(err)
	}

	var plan bytes.Buffer
	store.SetDryRun(true)
	store.SetDryRunOutput(&plan)
	t.Cleanup(func() {
		store.SetDryRun(false)
		store.SetDryRunOutput(nil)
	})

	cert := filepath.Join("..", "..", "testdata", "example.crt")
	if err := AddCertsToAppFromStore("java", ks, cert); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plan.String(), ks) || !strings.Contains(plan.String(), "java") {
		t.Fatalf("dry-run plan %q does not name the java keystore", plan.String())
	}
	after, err := os.ReadFile(ks)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("dry-run add modified the keystore")
	}
}

func TestAddCertsToAppFromStoreRejectsOtherApps(t *testing.T) {
	err := AddCertsToAppFromStore("firefox", "/tmp/cert9.db", filepath.Join("..", "..", "testdata", "example.crt"))
	if err == nil || !strings.Contains(err.Error(), "-store with -app firefox") {
		t.Fatalf("got %v", err)
	}
}

func TestListCertsForAppWithFileCertifiCount(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	bundle := writeLotsBundle(t, filepath.Join(t.TempDir(), "venv", "lib", "python3.12", "site-packages", "certifi", "cacert.pem"))
	certs, err := certutil.FromFile(bundle)
	if err != nil || len(certs) == 0 {
		t.Fatalf("bundle certs: %d %v", len(certs), err)
	}

	out := captureStdout(t, func() error {
		return ListCertsForAppWithFile("certifi", bundle, &ui.Config{Count: true})
	})
	if strings.TrimSpace(out) != strconv.Itoa(len(certs)) {
		t.Fatalf("count %q want %d", out, len(certs))
	}
}

func TestJavaStorePathListUsesOverride(t *testing.T) {
	ks := filepath.Join(t.TempDir(), "cacerts")
	if err := os.WriteFile(ks, []byte("not-a-real-keystore"), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := store.ForAppWithStore("java", ks)
	if err != nil {
		t.Fatal(err)
	}
	info := st.GetInfo()
	if info == nil || info.Path != ks {
		t.Fatalf("GetInfo path=%v want %s", info, ks)
	}
	_, err = st.List(nil)
	if err == nil {
		return
	}
	if strings.Contains(err.Error(), "never found java") || strings.Contains(err.Error(), "has no cacerts") {
		t.Fatalf("discovery ran instead of the -store path: %v", err)
	}
}

func TestAllowlistForAppWithStoreJavaDryRun(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	ks := filepath.Join(t.TempDir(), "cacerts")
	writeJavaKeystore(t, ks)
	before, err := os.ReadFile(ks)
	if err != nil {
		t.Fatal(err)
	}
	if err := BackupForAppWithFile("java", ks); err != nil {
		t.Fatal(err)
	}
	al := filepath.Join(t.TempDir(), "allowlist.yaml")
	if err := os.WriteFile(al, []byte("fingerprints: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var plan bytes.Buffer
	store.SetDryRun(true)
	store.SetDryRunOutput(&plan)
	t.Cleanup(func() {
		store.SetDryRun(false)
		store.SetDryRunOutput(nil)
	})

	if err := AllowlistForAppWithStore("java", ks, al); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plan.String(), ks) || !strings.Contains(plan.String(), "java") {
		t.Fatalf("dry-run plan %q does not name the java keystore", plan.String())
	}
	after, err := os.ReadFile(ks)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("dry-run allowlist modified the keystore")
	}
}

func TestAllowlistForAppWithStoreCertifiDryRun(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	bundle := writeLotsBundle(t, filepath.Join(t.TempDir(), "venv", "lib", "python3.12", "site-packages", "certifi", "cacert.pem"))
	before, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if err := BackupForAppWithFile("certifi", bundle); err != nil {
		t.Fatal(err)
	}

	al := filepath.Join(t.TempDir(), "allowlist.yaml")
	if err := os.WriteFile(al, []byte(allFingerprintAllowlist(t, bundle)), 0o644); err != nil {
		t.Fatal(err)
	}

	var plan bytes.Buffer
	store.SetDryRun(true)
	store.SetDryRunOutput(&plan)
	t.Cleanup(func() {
		store.SetDryRun(false)
		store.SetDryRunOutput(nil)
	})

	if err := AllowlistForAppWithStore("certifi", bundle, al); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plan.String(), bundle) {
		t.Fatalf("dry-run plan %q does not name the -store bundle", plan.String())
	}
	after, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("dry-run allowlist modified the certifi bundle")
	}
}

func captureStdout(t *testing.T, fn func() error) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = w
	var buf bytes.Buffer
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(&buf, r)
		close(done)
	}()
	fnErr := fn()
	_ = w.Close()
	os.Stdout = stdout
	<-done
	_ = r.Close()
	if fnErr != nil {
		t.Fatal(fnErr)
	}
	return buf.String()
}

// writeJavaKeystore imports testdata/example.crt into a new keystore at dest
// using keytool and the default store password. The Java store calls
// $JAVA_HOME/bin/keytool when that file exists, so the keystore is created
// with that binary; otherwise keytool on PATH is used. Skips when neither
// is available.
func writeJavaKeystore(t *testing.T, dest string) {
	t.Helper()
	bin, err := javaKeytoolBin()
	if err != nil {
		t.Skipf("keytool not on PATH and JAVA_HOME has no keytool; cannot create a Java keystore: %v", err)
	}
	crt := filepath.Join("..", "..", "testdata", "example.crt")
	cmd := exec.Command(bin,
		"-importcert", "-noprompt", "-alias", "example",
		"-file", crt,
		"-keystore", dest,
		"-storepass", defaultJavaStorePassword,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("keytool -importcert: %v: %s", err, bytes.TrimSpace(out))
	}
}

// javaKeytoolBin returns the keytool binary the Java store will run.
func javaKeytoolBin() (string, error) {
	if home := strings.TrimSpace(os.Getenv("JAVA_HOME")); home != "" {
		names := []string{"keytool"}
		if runtime.GOOS == "windows" {
			names = []string{"keytool.exe", "keytool.bat", "keytool.cmd", "keytool"}
		}
		for _, name := range names {
			p := filepath.Join(home, "bin", name)
			st, err := os.Stat(p)
			if err == nil && !st.IsDir() {
				return p, nil
			}
		}
	}
	return exec.LookPath("keytool")
}

func writeLotsBundle(t *testing.T, path string) string {
	t.Helper()
	src, err := os.ReadFile(filepath.Join("..", "..", "testdata", "lots.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, src, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func allFingerprintAllowlist(t *testing.T, bundle string) string {
	t.Helper()
	certs, err := certutil.FromFile(bundle)
	if err != nil || len(certs) == 0 {
		t.Fatalf("bundle certs: %d %v", len(certs), err)
	}
	var b strings.Builder
	b.WriteString("fingerprints:\n")
	for _, c := range certs {
		b.WriteString("  - \"")
		b.WriteString(certutil.GetHexSHA256Fingerprint(*c))
		b.WriteString("\"\n")
	}
	return b.String()
}
