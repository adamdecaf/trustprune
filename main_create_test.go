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

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/adamdecaf/trustprune/pkg/certutil"
)

func TestCreateCLI(t *testing.T) {
	bin := cliBinary(t)
	src := readTestFile(t, filepath.Join("testdata", "lots.crt"))
	certs, err := certutil.Decode(src)
	if err != nil || len(certs) < 2 {
		t.Fatalf("lots.crt: len=%d err=%v", len(certs), err)
	}
	keepFP := certutil.GetHexSHA256Fingerprint(*firstAllowlistedCert(t, certs))

	t.Run("help", func(t *testing.T) {
		home := t.TempDir()
		res := runCLI(t, bin, home, "create", "--help")
		if res.code != 0 {
			t.Fatalf("code=%d stdout=%s stderr=%s", res.code, res.stdout, res.stderr)
		}
		for _, needle := range []string{
			"trustprune create --file allowlist.yaml",
			"trustprune create --file allowlist.yaml --out ca-bundle.pem",
			"--format jks --out trusted.jks",
			"--format pkcs12 --out trusted.p12",
			"--app certifi --store /path/to/cacert.pem",
			"--app openssl --file allowlist.yaml --bundle",
			"default: pem",
			"options: pem",
			"mode 0644",
			"without changing the store",
			"TRUSTPRUNE_JAVA_STOREPASS",
			"--out is required",
			"sha256-",
		} {
			if !strings.Contains(res.stdout, needle) {
				t.Fatalf("create help missing %q:\n%s", needle, res.stdout)
			}
		}
		top := runCLI(t, bin, home, "--help")
		if top.code != 0 {
			t.Fatalf("root help code=%d stdout=%s stderr=%s", top.code, top.stdout, top.stderr)
		}
		if !strings.Contains(top.stdout, "create") || !strings.Contains(top.stdout, "without changing the store") {
			t.Fatalf("root help missing create:\n%s", top.stdout)
		}
	})

	t.Run("file and stdout", func(t *testing.T) {
		home, bundle, before := certifiBundle(t, src)
		al := writeKeepFirstAllowlist(t, src)
		out := filepath.Join(t.TempDir(), "kept.pem")
		res := runCLI(t, bin, home, "create", "--app", "certifi", "--store", bundle, "--file", al, "--out", out)
		if res.code != 0 {
			t.Fatalf("code=%d stdout=%s stderr=%s", res.code, res.stdout, res.stderr)
		}
		if res.stdout != "" || res.stderr != "" {
			t.Fatalf("stdout=%q stderr=%q", res.stdout, res.stderr)
		}
		assertSameBytes(t, bundle, before)
		assertNoBackupRoot(t, home)
		info, err := os.Stat(out)
		if err != nil {
			t.Fatal(err)
		}
		// Windows reports Perm() as 0666 and does not honor Unix mode bits.
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0o644 {
			t.Fatalf("mode=%o want 0644", info.Mode().Perm())
		}
		got, err := certutil.FromFile(out)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || certutil.GetHexSHA256Fingerprint(*got[0]) != keepFP {
			t.Fatalf("kept %d certs", len(got))
		}

		stdoutRes := runCLI(t, bin, home, "create", "--app", "certifi", "--store", bundle, "--file", al, "--format", "PEM")
		if stdoutRes.code != 0 {
			t.Fatalf("stdout code=%d stdout=%s stderr=%s", stdoutRes.code, stdoutRes.stdout, stdoutRes.stderr)
		}
		if stdoutRes.stderr != "" {
			t.Fatalf("stderr=%q", stdoutRes.stderr)
		}
		parsed, err := certutil.Decode([]byte(stdoutRes.stdout))
		if err != nil {
			t.Fatal(err)
		}
		if len(parsed) != 1 || certutil.GetHexSHA256Fingerprint(*parsed[0]) != keepFP {
			t.Fatalf("stdout kept %d certs", len(parsed))
		}
		assertSameBytes(t, bundle, before)
		assertNoBackupRoot(t, home)
	})

	t.Run("openssl bundle", func(t *testing.T) {
		home := t.TempDir()
		bundle := writeTestFile(t, "ca-bundle.pem", src)
		before := readTestFile(t, bundle)
		al := writeKeepFirstAllowlist(t, src)
		out := filepath.Join(t.TempDir(), "kept.pem")
		res := runCLI(t, bin, home, "create", "--app", "openssl", "--bundle", bundle, "--file", al, "--out", out)
		if res.code != 0 {
			t.Fatalf("code=%d stdout=%s stderr=%s", res.code, res.stdout, res.stderr)
		}
		assertSameBytes(t, bundle, before)
		assertNoBackupRoot(t, home)
		got, err := certutil.FromFile(out)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || certutil.GetHexSHA256Fingerprint(*got[0]) != keepFP {
			t.Fatalf("kept %d certs", len(got))
		}
	})

	t.Run("no match", func(t *testing.T) {
		home, bundle, before := certifiBundle(t, src)
		al := writeTestFile(t, "allowlist.yaml", []byte("fingerprints:\n  - \"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"\n"))
		out := filepath.Join(t.TempDir(), "kept.pem")
		if err := os.WriteFile(out, []byte("stale\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		res := runCLI(t, bin, home, "create", "--app", "certifi", "--store", bundle, "--file", al, "--out", out)
		if res.code != 1 {
			t.Fatalf("code=%d stdout=%s stderr=%s", res.code, res.stdout, res.stderr)
		}
		if !strings.Contains(res.stdout, "no certificates matched the allowlist") {
			t.Fatalf("stdout=%q stderr=%q", res.stdout, res.stderr)
		}
		if res.stderr != "" {
			t.Fatalf("stderr=%q", res.stderr)
		}
		assertSameBytes(t, bundle, before)
		assertSameBytes(t, out, []byte("stale\n"))
		assertNoBackupRoot(t, home)
	})

	t.Run("refuses store path", func(t *testing.T) {
		home, bundle, before := certifiBundle(t, src)
		al := writeKeepFirstAllowlist(t, src)
		res := runCLI(t, bin, home, "create", "--app", "certifi", "--store", bundle, "--file", al, "--out", bundle)
		if res.code != 1 || !strings.Contains(res.stdout, "refusing to write") {
			t.Fatalf("code=%d stdout=%s stderr=%s", res.code, res.stdout, res.stderr)
		}
		assertSameBytes(t, bundle, before)
		assertNoBackupRoot(t, home)
	})

	t.Run("unknown format", func(t *testing.T) {
		home, bundle, before := certifiBundle(t, src)
		al := writeKeepFirstAllowlist(t, src)
		res := runCLI(t, bin, home, "create", "--app", "certifi", "--store", bundle, "--file", al, "--format", "java")
		assertUsageError(t, res, `unknown format "java"`)
		if !strings.Contains(res.stderr, "pem") || !strings.Contains(res.stderr, "jks") || !strings.Contains(res.stderr, "pkcs12") {
			t.Fatalf("stderr=%q", res.stderr)
		}
		assertSameBytes(t, bundle, before)
		assertNoBackupRoot(t, home)
	})

	t.Run("bundle requires openssl", func(t *testing.T) {
		home := t.TempDir()
		res := runCLI(t, bin, home, "create", "--app", "java", "--bundle", filepath.Join(home, "ca.pem"), "--file", filepath.Join(home, "al.yaml"))
		assertUsageError(t, res, "--bundle requires --app openssl")
	})

	t.Run("java truststore requires out", func(t *testing.T) {
		home, bundle, before := certifiBundle(t, src)
		al := writeKeepFirstAllowlist(t, src)
		for _, format := range []string{"jks", "PKCS12"} {
			res := runCLI(t, bin, home, "create", "--app", "certifi", "--store", bundle, "--file", al, "--format", format)
			want := "--out is required for format " + strings.ToLower(format)
			assertUsageError(t, res, want)
			assertSameBytes(t, bundle, before)
			assertNoBackupRoot(t, home)
		}
	})

	t.Run("java truststore", func(t *testing.T) {
		keytoolBin := testKeytool(t)
		home, bundle, before := certifiBundle(t, src)
		al := writeKeepFirstAllowlist(t, src)
		for _, format := range []string{"jks", "pkcs12"} {
			out := filepath.Join(t.TempDir(), "trusted."+format)
			env := prependPath(envWithout(envWithHome(home), "TRUSTPRUNE_JAVA_STOREPASS="), filepath.Dir(keytoolBin))
			res := runCLIWithEnv(t, bin, env, "create", "--app", "certifi", "--store", bundle, "--file", al, "--format", format, "--out", out)
			if res.code != 0 {
				t.Fatalf("%s code=%d stdout=%s stderr=%s", format, res.code, res.stdout, res.stderr)
			}
			if res.stdout != "" || res.stderr != "" {
				t.Fatalf("%s stdout=%q stderr=%q", format, res.stdout, res.stderr)
			}
			assertSameBytes(t, bundle, before)
			assertNoBackupRoot(t, home)
			info, err := os.Stat(out)
			if err != nil {
				t.Fatal(err)
			}
			if runtime.GOOS != "windows" && info.Mode().Perm() != 0o644 {
				t.Fatalf("%s mode=%o want 0644", format, info.Mode().Perm())
			}
			listed := cliListTruststore(t, keytoolBin, out, format, "changeit")
			if len(listed) != 1 || listed[0] != keepFP {
				t.Fatalf("%s certs=%v", format, listed)
			}
		}

		const secret = "not-changeit-create-9f3a"
		out := filepath.Join(t.TempDir(), "custom.jks")
		env := prependPath(envWithout(envWithHome(home), "TRUSTPRUNE_JAVA_STOREPASS="), filepath.Dir(keytoolBin))
		env = append(env, "TRUSTPRUNE_JAVA_STOREPASS="+secret)
		res := runCLIWithEnv(t, bin, env, "create", "--app", "certifi", "--store", bundle, "--file", al, "--format", "jks", "--out", out)
		if res.code != 0 {
			t.Fatalf("custom code=%d stdout=%s stderr=%s", res.code, res.stdout, res.stderr)
		}
		if strings.Contains(res.stdout, secret) || strings.Contains(res.stderr, secret) {
			t.Fatalf("secret leaked stdout=%q stderr=%q", res.stdout, res.stderr)
		}
		assertSameBytes(t, bundle, before)
		listed := cliListTruststore(t, keytoolBin, out, "jks", secret)
		if len(listed) != 1 || listed[0] != keepFP {
			t.Fatalf("custom certs=%v", listed)
		}
		if err := cliListTruststoreErr(keytoolBin, out, "jks", "changeit"); err == nil {
			t.Fatal("default password opened the custom truststore")
		}
	})

	t.Run("stray args", func(t *testing.T) {
		home, bundle, before := certifiBundle(t, src)
		al := writeKeepFirstAllowlist(t, src)
		res := runCLI(t, bin, home, "create", "--app", "certifi", "--store", bundle, "--file", al, "extra")
		assertStrayRejected(t, res, "extra")
		assertSameBytes(t, bundle, before)
		assertNoBackupRoot(t, home)
	})
}

func testKeytool(t *testing.T) string {
	t.Helper()
	if home := strings.TrimSpace(os.Getenv("JAVA_HOME")); home != "" {
		names := []string{"keytool"}
		if runtime.GOOS == "windows" {
			names = []string{"keytool.exe", "keytool.bat", "keytool.cmd", "keytool"}
		}
		for _, name := range names {
			p := filepath.Join(home, "bin", name)
			st, err := os.Stat(p)
			if err == nil && !st.IsDir() {
				return p
			}
		}
	}
	if p, err := exec.LookPath("keytool"); err == nil {
		return p
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		names := []string{"keytool"}
		if runtime.GOOS == "windows" {
			names = []string{"keytool.exe", "keytool.bat", "keytool.cmd", "keytool"}
		}
		for _, name := range names {
			p := filepath.Join(home, ".local", "bin", name)
			st, err := os.Stat(p)
			if err == nil && !st.IsDir() {
				return p
			}
		}
	}
	t.Skip("keytool not on PATH, in JAVA_HOME, or in ~/.local/bin")
	return ""
}

func envWithout(env []string, prefix string) []string {
	out := make([]string, 0, len(env))
	for _, e := range env {
		if strings.HasPrefix(e, prefix) {
			continue
		}
		out = append(out, e)
	}
	return out
}

func prependPath(env []string, dir string) []string {
	for i, e := range env {
		if strings.HasPrefix(e, "PATH=") {
			env[i] = "PATH=" + dir + string(os.PathListSeparator) + strings.TrimPrefix(e, "PATH=")
			return env
		}
	}
	return append(env, "PATH="+dir)
}

func cliListTruststore(t *testing.T, bin, path, format, password string) []string {
	t.Helper()
	out, err := runCLIKeytoolList(bin, path, format, password)
	if err != nil {
		t.Fatalf("keytool -list: %v", err)
	}
	certs, err := certutil.ParsePEM(out)
	if err != nil {
		t.Fatal(err)
	}
	fps := make([]string, 0, len(certs))
	text := string(out)
	for i := range certs {
		fp := certutil.GetHexSHA256Fingerprint(*certs[i])
		alias := "sha256-" + fp
		if !strings.Contains(text, alias) {
			t.Fatalf("alias %s missing from keytool output:\n%s", alias, text)
		}
		fps = append(fps, fp)
	}
	return fps
}

func cliListTruststoreErr(bin, path, format, password string) error {
	_, err := runCLIKeytoolList(bin, path, format, password)
	return err
}

func runCLIKeytoolList(bin, path, format, password string) ([]byte, error) {
	storeType := "JKS"
	if strings.EqualFold(format, "pkcs12") {
		storeType = "PKCS12"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	args := []string{"-list", "-rfc", "-noprompt", "-keystore", path, "-storetype", storeType, "-storepass:env", "TRUSTPRUNE_JAVA_STOREPASS"}
	cmd := exec.CommandContext(ctx, bin, args...)
	env := make([]string, 0, len(os.Environ())+1)
	for _, e := range os.Environ() {
		if strings.HasPrefix(e, "TRUSTPRUNE_JAVA_STOREPASS=") {
			continue
		}
		env = append(env, e)
	}
	cmd.Env = append(env, "TRUSTPRUNE_JAVA_STOREPASS="+password)
	cmd.Stdin = nil
	cmd.WaitDelay = 2 * time.Second
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail == "" {
			detail = strings.TrimSpace(stdout.String())
		}
		if detail == "" {
			return nil, err
		}
		return nil, errors.New(err.Error() + ": " + detail)
	}
	return stdout.Bytes(), nil
}
