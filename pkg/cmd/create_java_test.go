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
	"context"
	"crypto/x509"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/adamdecaf/trustprune/pkg/allowlist"
	"github.com/adamdecaf/trustprune/pkg/certutil"
	"github.com/adamdecaf/trustprune/pkg/store"
)

func TestCreateJavaOutRequiredBeforeRead(t *testing.T) {
	dir := t.TempDir()
	st := &fakeCreateStore{listErr: os.ErrNotExist}
	for _, format := range []string{"jks", "JKS", "pkcs12", " Pkcs12 "} {
		err := CreateFromStore(st, CreateOptions{
			AllowlistPath: filepath.Join(dir, "missing.yaml"),
			Format:        format,
		})
		want := CreateOutRequiredError(normalizeOrFail(t, format)).Error()
		if err == nil || err.Error() != want {
			t.Fatalf("format %q: err=%v want %s", format, err, want)
		}
	}
	if st.listCalls != 0 || st.mutated {
		t.Fatalf("listCalls=%d mutated=%v", st.listCalls, st.mutated)
	}
	out := filepath.Join(dir, "out.jks")
	if err := os.WriteFile(out, []byte("stale\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := CreateFromStore(st, CreateOptions{AllowlistPath: filepath.Join(dir, "missing.yaml"), Format: "jks"})
	if err == nil {
		t.Fatal("expected missing --out")
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "stale\n" {
		t.Fatalf("output changed: %q", got)
	}
}

func TestCreateJavaNoMatchAndStoreOverlapWriteNothing(t *testing.T) {
	cert := mustCreateCert(t, "Keep", "US", 1)
	dir := t.TempDir()
	storeFile := filepath.Join(dir, "store.pem")
	if err := os.WriteFile(storeFile, []byte("original\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	alPath := writeCreateAllowlist(t, allowlist.Allowlist{
		Fingerprints: []string{"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
	})
	st := &fakeCreateStore{
		info:  &store.Info{Name: "fake", Path: storeFile},
		certs: []*x509.Certificate{cert},
	}
	out := filepath.Join(dir, "out.jks")
	if err := os.WriteFile(out, []byte("stale\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := CreateFromStore(st, CreateOptions{AllowlistPath: alPath, Format: "jks", Out: out})
	if !errors.Is(err, ErrNoMatchingCerts) {
		t.Fatalf("err=%v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "stale\n" || st.mutated {
		t.Fatalf("out=%q mutated=%v", got, st.mutated)
	}
	assertNoCreateTemps(t, dir)

	alPath = writeCreateAllowlist(t, allowlist.FromCertificates([]*x509.Certificate{cert}))
	err = CreateFromStore(st, CreateOptions{AllowlistPath: alPath, Format: "pkcs12", Out: storeFile})
	if err == nil || !strings.Contains(err.Error(), "refusing to write") {
		t.Fatalf("err=%v", err)
	}
	got, err = os.ReadFile(storeFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "original\n" || st.mutated {
		t.Fatalf("store=%q mutated=%v", got, st.mutated)
	}
	assertNoCreateTemps(t, dir)
}

func TestCreatePEMDoesNotNeedKeytool(t *testing.T) {
	hideCreateKeytool(t)
	cert := mustCreateCert(t, "Keep", "US", 1)
	st := &fakeCreateStore{
		info:  &store.Info{Name: "fake"},
		certs: []*x509.Certificate{cert},
	}
	alPath := writeCreateAllowlist(t, allowlist.FromCertificates([]*x509.Certificate{cert}))
	var buf bytes.Buffer
	if err := CreateFromStore(st, CreateOptions{AllowlistPath: alPath, Stdout: &buf}); err != nil {
		t.Fatal(err)
	}
	got, err := certutil.Decode(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || certutil.GetHexSHA256Fingerprint(*got[0]) != certutil.GetHexSHA256Fingerprint(*cert) {
		t.Fatalf("kept %d", len(got))
	}

	dir := t.TempDir()
	out := filepath.Join(dir, "out.jks")
	err = CreateFromStore(st, CreateOptions{AllowlistPath: alPath, Format: "jks", Out: out})
	if err == nil || !strings.Contains(err.Error(), "keytool not found") {
		t.Fatalf("err=%v", err)
	}
	if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
		t.Fatalf("jks created without keytool: %v", statErr)
	}
	assertNoCreateTemps(t, dir)
	if st.mutated {
		t.Fatal("create called a store mutation")
	}
}

func TestCreateJavaFakeKeytool(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake keytool shell script is unix-only")
	}
	keep := mustCreateCert(t, "Keep", "US", 1)
	other := mustCreateCert(t, "Other", "JP", 2)
	drop := mustCreateCert(t, "Drop", "DE", 3)
	keepAlias := javaTruststoreAlias(keep)
	otherAlias := javaTruststoreAlias(other)

	t.Run("writes stable aliases and leaves the store alone", func(t *testing.T) {
		seen := filepath.Join(t.TempDir(), "seen")
		passFile := filepath.Join(t.TempDir(), "pass")
		javaHome := t.TempDir()
		writeCreateFakeKeytool(t, javaHome, recordingKeytoolScript(seen, passFile, ""))
		t.Setenv("JAVA_HOME", javaHome)
		t.Setenv(javaStorePassEnv, "")

		dir := t.TempDir()
		storeFile := filepath.Join(dir, "store.pem")
		if err := os.WriteFile(storeFile, []byte("store-bytes\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		out := filepath.Join(dir, "trusted.jks")
		if err := os.WriteFile(out, []byte("stale\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		st := &fakeCreateStore{
			info:  &store.Info{Name: "fake", Path: storeFile},
			certs: []*x509.Certificate{keep, nil, drop, other, keep},
		}
		alPath := writeCreateAllowlist(t, allowlist.Allowlist{
			Fingerprints: []string{certutil.GetHexSHA256Fingerprint(*keep)},
			Countries:    []string{"JP"},
		})
		var stdout bytes.Buffer
		if err := CreateFromStore(st, CreateOptions{
			AllowlistPath: alPath,
			Format:        "JKS",
			Out:           out,
			Stdout:        &stdout,
		}); err != nil {
			t.Fatal(err)
		}
		if stdout.Len() != 0 {
			t.Fatalf("stdout=%q", stdout.String())
		}
		if st.mutated || st.listCalls != 1 || st.listOpts == nil || !st.listOpts.Trusted {
			t.Fatalf("listCalls=%d opts=%+v mutated=%v", st.listCalls, st.listOpts, st.mutated)
		}
		gotStore, err := os.ReadFile(storeFile)
		if err != nil {
			t.Fatal(err)
		}
		if string(gotStore) != "store-bytes\n" {
			t.Fatalf("store changed: %q", gotStore)
		}
		body, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		if string(body) != "ok\nok\n" {
			t.Fatalf("truststore body=%q", body)
		}
		info, err := os.Stat(out)
		if err != nil {
			t.Fatal(err)
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0o644 {
			t.Fatalf("mode=%o want 0644", info.Mode().Perm())
		}
		assertNoCreateTemps(t, dir)
		invocations := parseKeytoolInvocations(t, seen)
		if len(invocations) != 2 {
			t.Fatalf("invocations=%d want 2 (duplicate cert must be one alias)", len(invocations))
		}
		var aliases []string
		var keystore string
		for _, args := range invocations {
			assertKeytoolTokens(t, args, map[string]string{
				"-importcert": "",
				"-noprompt":   "",
				"-storetype":  "JKS",
				"-storepass":  defaultJavaStorePassword,
			})
			if hasToken(args, "-storepass:env") {
				t.Fatalf("default password used -storepass:env: %v", args)
			}
			aliases = append(aliases, tokenValue(t, args, "-alias"))
			ks := tokenValue(t, args, "-keystore")
			if keystore == "" {
				keystore = ks
			} else if ks != keystore {
				t.Fatalf("keystore changed from %s to %s", keystore, ks)
			}
			if ks == out || ks == storeFile {
				t.Fatalf("keytool wrote %s directly", ks)
			}
			if filepath.Dir(ks) != dir || !strings.HasPrefix(filepath.Base(ks), ".trustprune-create-") {
				t.Fatalf("temp keystore %s is not a sibling of %s", ks, out)
			}
			fileArg := tokenValue(t, args, "-file")
			if fileArg == storeFile || filepath.Dir(fileArg) == dir {
				t.Fatalf("cert pem %s is the store or the output dir", fileArg)
			}
		}
		if strings.Join(aliases, ",") != keepAlias+","+otherAlias {
			t.Fatalf("aliases=%v", aliases)
		}
		if _, err := os.Stat(keystore); !os.IsNotExist(err) {
			t.Fatalf("temp keystore still present: %v", err)
		}
		pass, err := os.ReadFile(passFile)
		if err != nil {
			t.Fatal(err)
		}
		if string(pass) != "" {
			t.Fatalf("default password run exported storepass %q", pass)
		}
	})

	t.Run("custom password stays out of argv", func(t *testing.T) {
		const secret = "not-changeit-create-9f3a"
		seen := filepath.Join(t.TempDir(), "seen")
		passFile := filepath.Join(t.TempDir(), "pass")
		javaHome := t.TempDir()
		writeCreateFakeKeytool(t, javaHome, recordingKeytoolScript(seen, passFile, ""))
		t.Setenv("JAVA_HOME", javaHome)
		t.Setenv(javaStorePassEnv, "  "+secret+"  ")

		cert := mustCreateCert(t, "Keep", "US", 4)
		dir := t.TempDir()
		out := filepath.Join(dir, "trusted.p12")
		st := &fakeCreateStore{
			info:  &store.Info{Name: "fake", Path: filepath.Join(dir, "store.pem")},
			certs: []*x509.Certificate{cert},
		}
		alPath := writeCreateAllowlist(t, allowlist.FromCertificates([]*x509.Certificate{cert}))
		if err := CreateFromStore(st, CreateOptions{AllowlistPath: alPath, Format: "pkcs12", Out: out}); err != nil {
			t.Fatal(err)
		}
		invocations := parseKeytoolInvocations(t, seen)
		if len(invocations) != 1 {
			t.Fatalf("invocations=%d", len(invocations))
		}
		args := invocations[0]
		raw := strings.Join(args, "\n")
		if strings.Contains(raw, secret) {
			t.Fatalf("secret appeared in argv:\n%s", raw)
		}
		assertKeytoolTokens(t, args, map[string]string{
			"-storetype":     "PKCS12",
			"-storepass:env": javaStorePassEnv,
			"-alias":         javaTruststoreAlias(cert),
		})
		if hasToken(args, "-storepass") {
			t.Fatalf("custom password used literal -storepass: %v", args)
		}
		pass, err := os.ReadFile(passFile)
		if err != nil {
			t.Fatal(err)
		}
		if string(pass) != secret {
			t.Fatalf("child storepass=%q", pass)
		}
	})

	t.Run("whitespace-only password is changeit", func(t *testing.T) {
		seen := filepath.Join(t.TempDir(), "seen")
		javaHome := t.TempDir()
		writeCreateFakeKeytool(t, javaHome, recordingKeytoolScript(seen, "", ""))
		t.Setenv("JAVA_HOME", javaHome)
		t.Setenv(javaStorePassEnv, "   ")
		cert := mustCreateCert(t, "Keep", "US", 5)
		out := filepath.Join(t.TempDir(), "trusted.jks")
		st := &fakeCreateStore{certs: []*x509.Certificate{cert}}
		alPath := writeCreateAllowlist(t, allowlist.FromCertificates([]*x509.Certificate{cert}))
		if err := CreateFromStore(st, CreateOptions{AllowlistPath: alPath, Format: "jks", Out: out}); err != nil {
			t.Fatal(err)
		}
		args := parseKeytoolInvocations(t, seen)[0]
		assertKeytoolTokens(t, args, map[string]string{"-storepass": defaultJavaStorePassword})
		if hasToken(args, "-storepass:env") {
			t.Fatalf("whitespace password used env: %v", args)
		}
	})

	t.Run("failure leaves the destination and no temp", func(t *testing.T) {
		const secret = "not-changeit-create-9f3a"
		keep := mustCreateCert(t, "Keep", "US", 6)
		other := mustCreateCert(t, "Other", "JP", 7)
		seen := filepath.Join(t.TempDir(), "seen")
		javaHome := t.TempDir()
		writeCreateFakeKeytool(t, javaHome, recordingKeytoolScript(seen, "", javaTruststoreAlias(other)))
		t.Setenv("JAVA_HOME", javaHome)
		t.Setenv(javaStorePassEnv, secret)

		dir := t.TempDir()
		out := filepath.Join(dir, "trusted.jks")
		if err := os.WriteFile(out, []byte("stale\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		st := &fakeCreateStore{certs: []*x509.Certificate{keep, other}}
		alPath := writeCreateAllowlist(t, allowlist.FromCertificates([]*x509.Certificate{keep, other}))
		err := CreateFromStore(st, CreateOptions{AllowlistPath: alPath, Format: "jks", Out: out})
		if err == nil || !strings.Contains(err.Error(), "forced-failure") {
			t.Fatalf("err=%v", err)
		}
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("secret leaked into error: %v", err)
		}
		if !strings.Contains(err.Error(), "boom-***") {
			t.Fatalf("stderr was not redacted: %v", err)
		}
		got, readErr := os.ReadFile(out)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if string(got) != "stale\n" {
			t.Fatalf("destination changed: %q", got)
		}
		info, statErr := os.Stat(out)
		if statErr != nil {
			t.Fatal(statErr)
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
			t.Fatalf("mode=%o want 0600", info.Mode().Perm())
		}
		assertNoCreateTemps(t, dir)
		raw, readErr := os.ReadFile(seen)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if strings.Contains(string(raw), secret) {
			t.Fatalf("secret appeared in argv:\n%s", raw)
		}
	})

	t.Run("timeout", func(t *testing.T) {
		orig := createKeytoolTimeout
		createKeytoolTimeout = 300 * time.Millisecond
		t.Cleanup(func() { createKeytoolTimeout = orig })
		javaHome := t.TempDir()
		writeCreateFakeKeytool(t, javaHome, "sleep 30\n")
		t.Setenv("JAVA_HOME", javaHome)
		t.Setenv(javaStorePassEnv, "")
		cert := mustCreateCert(t, "Keep", "US", 8)
		dir := t.TempDir()
		out := filepath.Join(dir, "trusted.jks")
		st := &fakeCreateStore{certs: []*x509.Certificate{cert}}
		alPath := writeCreateAllowlist(t, allowlist.FromCertificates([]*x509.Certificate{cert}))
		start := time.Now()
		err := CreateFromStore(st, CreateOptions{AllowlistPath: alPath, Format: "jks", Out: out})
		elapsed := time.Since(start)
		if err == nil || !strings.Contains(err.Error(), "timed out") {
			t.Fatalf("err=%v", err)
		}
		if elapsed > 8*time.Second {
			t.Fatalf("timeout took %s", elapsed)
		}
		if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
			t.Fatalf("output created: %v", statErr)
		}
		assertNoCreateTemps(t, dir)
	})
}

func TestCreateKeytoolLookupOrder(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake keytool shell script is unix-only")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	javaHome := filepath.Join(home, "java")
	pathDir := filepath.Join(home, "pathbin")
	localDir := filepath.Join(home, ".local", "bin")
	for _, dir := range []string{filepath.Join(javaHome, "bin"), pathDir, localDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeKeytoolScript(t, filepath.Join(javaHome, "bin", "keytool"), "#!/bin/sh\nprintf javahome > \"$1\"\n")
	writeKeytoolScript(t, filepath.Join(pathDir, "keytool"), "#!/bin/sh\nprintf path > \"$1\"\n")
	writeKeytoolScript(t, filepath.Join(localDir, "keytool"), "#!/bin/sh\nprintf local > \"$1\"\n")

	t.Setenv("JAVA_HOME", javaHome)
	t.Setenv("PATH", pathDir)
	got := runLookupMarker(t)
	if got != "javahome" {
		t.Fatalf("JAVA_HOME lost to %q", got)
	}

	t.Setenv("JAVA_HOME", filepath.Join(home, "missing-java"))
	t.Setenv("PATH", pathDir)
	got = runLookupMarker(t)
	if got != "path" {
		t.Fatalf("PATH lost to %q", got)
	}

	empty := filepath.Join(home, "empty-path")
	if err := os.MkdirAll(empty, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("JAVA_HOME", "")
	t.Setenv("PATH", empty)
	got = runLookupMarker(t)
	if got != "local" {
		t.Fatalf("~/.local/bin lost to %q", got)
	}
}

func TestWriteJavaTruststoreRoundTrip(t *testing.T) {
	bin := locateCreateKeytool(t)
	keep := mustCreateCert(t, "Keep", "US", 11)
	other := mustCreateCert(t, "Other", "JP", 12)
	drop := mustCreateCert(t, "Drop", "DE", 13)

	for _, format := range []string{"jks", "pkcs12"} {
		t.Run(format, func(t *testing.T) {
			t.Setenv(javaStorePassEnv, "")
			dir := t.TempDir()
			storeFile := filepath.Join(dir, "store.pem")
			if err := os.WriteFile(storeFile, []byte("store-bytes\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			out := filepath.Join(dir, "trusted."+format)
			st := &fakeCreateStore{
				info:  &store.Info{Name: "fake", Path: storeFile},
				certs: []*x509.Certificate{keep, drop, keep, other},
			}
			alPath := writeCreateAllowlist(t, allowlist.Allowlist{
				Fingerprints: []string{certutil.GetHexSHA256Fingerprint(*keep)},
				Countries:    []string{"JP"},
			})
			var stdout bytes.Buffer
			if err := CreateFromStore(st, CreateOptions{
				AllowlistPath: alPath,
				Format:        format,
				Out:           out,
				Stdout:        &stdout,
			}); err != nil {
				t.Fatal(err)
			}
			if stdout.Len() != 0 || st.mutated {
				t.Fatalf("stdout=%q mutated=%v", stdout.String(), st.mutated)
			}
			gotStore, err := os.ReadFile(storeFile)
			if err != nil {
				t.Fatal(err)
			}
			if string(gotStore) != "store-bytes\n" {
				t.Fatalf("store changed: %q", gotStore)
			}
			info, err := os.Stat(out)
			if err != nil {
				t.Fatal(err)
			}
			if runtime.GOOS != "windows" && info.Mode().Perm() != 0o644 {
				t.Fatalf("mode=%o want 0644", info.Mode().Perm())
			}
			assertNoCreateTemps(t, dir)
			assertTruststoreMagic(t, out, format)
			listed := listTruststore(t, bin, out, format, defaultJavaStorePassword)
			want := map[string]string{
				javaTruststoreAlias(keep):  certutil.GetHexSHA256Fingerprint(*keep),
				javaTruststoreAlias(other): certutil.GetHexSHA256Fingerprint(*other),
			}
			if len(listed) != len(want) {
				t.Fatalf("certs=%d want %d (%v)", len(listed), len(want), listed)
			}
			for alias, fp := range want {
				got, ok := listed[alias]
				if !ok || got != fp {
					t.Fatalf("alias %s fp=%q ok=%v", alias, got, ok)
				}
			}
			if _, ok := listed[javaTruststoreAlias(drop)]; ok {
				t.Fatal("dropped cert was written")
			}
			if err := listTruststoreErr(bin, out, format, "wrong-password-value"); err == nil {
				t.Fatal("wrong password listed the truststore")
			}
		})
	}

	t.Run("custom password", func(t *testing.T) {
		const secret = "not-changeit-create-9f3a"
		t.Setenv(javaStorePassEnv, "\t"+secret+"\n")
		cert := mustCreateCert(t, "Keep", "US", 14)
		dir := t.TempDir()
		out := filepath.Join(dir, "trusted.jks")
		st := &fakeCreateStore{certs: []*x509.Certificate{cert}}
		alPath := writeCreateAllowlist(t, allowlist.FromCertificates([]*x509.Certificate{cert}))
		if err := CreateFromStore(st, CreateOptions{AllowlistPath: alPath, Format: "jks", Out: out}); err != nil {
			t.Fatal(err)
		}
		listed := listTruststore(t, bin, out, "jks", secret)
		if listed[javaTruststoreAlias(cert)] != certutil.GetHexSHA256Fingerprint(*cert) {
			t.Fatalf("listed=%v", listed)
		}
		if err := listTruststoreErr(bin, out, "jks", defaultJavaStorePassword); err == nil {
			t.Fatal("default password opened a custom-password truststore")
		}
	})
}

func normalizeOrFail(t *testing.T, format string) string {
	t.Helper()
	got, err := NormalizeCreateFormat(format)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func hideCreateKeytool(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("JAVA_HOME", "")
	empty := filepath.Join(home, "empty-path")
	if err := os.MkdirAll(empty, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", empty)
}

func locateCreateKeytool(t *testing.T) string {
	t.Helper()
	bin, err := findCreateKeytool()
	if err != nil {
		t.Skipf("keytool not on PATH, in JAVA_HOME, or in ~/.local/bin: %v", err)
	}
	return bin
}

func assertNoCreateTemps(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".trustprune-create-") {
			t.Fatalf("leftover temp %s", e.Name())
		}
	}
}

func writeCreateFakeKeytool(t *testing.T, javaHome, script string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(javaHome, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeKeytoolScript(t, filepath.Join(javaHome, "bin", "keytool"), "#!/bin/sh\n"+script+"\n")
}

func writeKeytoolScript(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
}

// recordingKeytoolScript appends each invocation's argv to seenPath and the
// child TRUSTPRUNE_JAVA_STOREPASS value to passFile. failAlias, when set,
// makes that alias exit 1 after writing a stderr line that contains the
// password, so the writer must redact it and must not publish the keystore.
func recordingKeytoolScript(seenPath, passFile, failAlias string) string {
	var b strings.Builder
	b.WriteString("seen=")
	b.WriteString(createShellQuote(seenPath))
	b.WriteString("\n{\n  echo ---\n  for a in \"$@\"; do\n    printf '%s\\n' \"$a\"\n  done\n} >> \"$seen\"\n")
	if passFile != "" {
		b.WriteString("printf '%s' \"${TRUSTPRUNE_JAVA_STOREPASS-}\" > ")
		b.WriteString(createShellQuote(passFile))
		b.WriteString("\n")
	}
	if failAlias != "" {
		b.WriteString("prev=\"\"\nfor a in \"$@\"; do\n")
		b.WriteString("  if [ \"$prev\" = \"-alias\" ] && [ \"$a\" = ")
		b.WriteString(createShellQuote(failAlias))
		b.WriteString(" ]; then\n    echo \"boom-${TRUSTPRUNE_JAVA_STOREPASS-}\" >&2\n    echo forced-failure >&2\n    exit 1\n  fi\n  prev=\"$a\"\ndone\n")
	}
	b.WriteString("ks=\"\"\nprev=\"\"\nfor a in \"$@\"; do\n  if [ \"$prev\" = \"-keystore\" ]; then\n    ks=\"$a\"\n  fi\n  prev=\"$a\"\ndone\n")
	b.WriteString("if [ -n \"$ks\" ]; then\n  printf 'ok\\n' >> \"$ks\"\nfi\nexit 0\n")
	return b.String()
}

func createShellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

func parseKeytoolInvocations(t *testing.T, path string) [][]string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out [][]string
	var cur []string
	started := false
	for _, line := range strings.Split(string(raw), "\n") {
		if line == "---" {
			if started {
				out = append(out, cur)
			}
			cur = nil
			started = true
			continue
		}
		if started {
			cur = append(cur, line)
		}
	}
	if started {
		// The trailing newline after the last arg yields an empty line.
		if len(cur) > 0 && cur[len(cur)-1] == "" {
			cur = cur[:len(cur)-1]
		}
		out = append(out, cur)
	}
	if len(out) == 0 {
		t.Fatalf("no keytool invocations in %s:\n%s", path, raw)
	}
	return out
}

func assertKeytoolTokens(t *testing.T, args []string, want map[string]string) {
	t.Helper()
	for flag, value := range want {
		if value == "" {
			if !hasToken(args, flag) {
				t.Fatalf("missing %s in %v", flag, args)
			}
			continue
		}
		got := tokenValue(t, args, flag)
		if got != value {
			t.Fatalf("%s=%q want %q in %v", flag, got, value, args)
		}
	}
}

func hasToken(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
	}
	return false
}

func tokenValue(t *testing.T, args []string, flag string) string {
	t.Helper()
	for i := 0; i < len(args)-1; i++ {
		if args[i] == flag {
			return args[i+1]
		}
	}
	t.Fatalf("missing %s in %v", flag, args)
	return ""
}

func runLookupMarker(t *testing.T) string {
	t.Helper()
	bin, err := findCreateKeytool()
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "marker")
	cmd := exec.Command(bin, out)
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return string(got)
}

func assertTruststoreMagic(t *testing.T, path, format string) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	buf := make([]byte, 4)
	if _, err := f.Read(buf); err != nil {
		t.Fatal(err)
	}
	switch format {
	case createFormatJKS:
		if !bytes.Equal(buf, []byte{0xfe, 0xed, 0xfe, 0xed}) {
			t.Fatalf("jks magic %x", buf)
		}
	case createFormatPKCS12:
		if buf[0] != 0x30 {
			t.Fatalf("pkcs12 magic %x", buf)
		}
	default:
		t.Fatalf("format %s", format)
	}
}

func listTruststore(t *testing.T, bin, path, format, password string) map[string]string {
	t.Helper()
	out, err := runKeytoolList(bin, path, format, password)
	if err != nil {
		t.Fatalf("keytool -list: %v", err)
	}
	certs, err := certutil.ParsePEM(out)
	if err != nil {
		t.Fatal(err)
	}
	aliases := truststoreAliasOrder(out)
	if len(aliases) != len(certs) {
		t.Fatalf("aliases=%d certs=%d\n%s", len(aliases), len(certs), out)
	}
	got := make(map[string]string, len(certs))
	for i := range certs {
		got[aliases[i]] = certutil.GetHexSHA256Fingerprint(*certs[i])
	}
	return got
}

func listTruststoreErr(bin, path, format, password string) error {
	_, err := runKeytoolList(bin, path, format, password)
	return err
}

func runKeytoolList(bin, path, format, password string) ([]byte, error) {
	storeType := "JKS"
	if format == createFormatPKCS12 {
		storeType = "PKCS12"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	args := []string{"-list", "-rfc", "-noprompt", "-keystore", path, "-storetype", storeType}
	if password == defaultJavaStorePassword {
		args = append(args, "-storepass", password)
	} else {
		args = append(args, "-storepass:env", javaStorePassEnv)
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	if password != defaultJavaStorePassword {
		cmd.Env = mergeCreateEnviron(os.Environ(), []string{javaStorePassEnv + "=" + password})
	}
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

func truststoreAliasOrder(listRFC []byte) []string {
	var out []string
	for _, line := range strings.Split(string(listRFC), "\n") {
		line = strings.TrimSpace(line)
		if name, ok := strings.CutPrefix(line, "Alias name:"); ok {
			out = append(out, strings.TrimSpace(name))
		}
	}
	return out
}
