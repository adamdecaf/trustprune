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
	"runtime"
	"strings"
	"testing"
)

func TestKeystorePasswordDefault(t *testing.T) {
	t.Setenv(javaStorePassEnv, "")
	if got := keystorePassword(); got != defaultKeystorePassword {
		t.Fatalf("unset env: got %q want %q", got, defaultKeystorePassword)
	}
	t.Setenv(javaStorePassEnv, "   ")
	if got := keystorePassword(); got != defaultKeystorePassword {
		t.Fatalf("whitespace env: got %q want %q", got, defaultKeystorePassword)
	}
}

func TestKeystorePasswordFromEnv(t *testing.T) {
	const custom = "not-changeit"
	t.Setenv(javaStorePassEnv, custom)
	if got := keystorePassword(); got != custom {
		t.Fatalf("got %q want %q", got, custom)
	}
	t.Setenv(javaStorePassEnv, "  "+custom+"  ")
	if got := keystorePassword(); got != custom {
		t.Fatalf("trimmed: got %q want %q", got, custom)
	}
}

func TestKeystorePasswordAllowsEmbeddedNewline(t *testing.T) {
	custom := "line1\nline2"
	t.Setenv(javaStorePassEnv, custom)
	if got := keystorePassword(); got != custom {
		t.Fatalf("got %q want %q", got, custom)
	}
}

func TestRedactKeytoolArgsHidesStorepass(t *testing.T) {
	args := []string{"-list", "-storepass", "secret-value", "-keystore", "/tmp/k"}
	got := strings.Join(redactKeytoolArgs(args), " ")
	if strings.Contains(got, "secret-value") {
		t.Fatalf("password leaked in redacted args: %q", got)
	}
	if !strings.Contains(got, "-storepass ***") {
		t.Fatalf("expected redacted marker, got %q", got)
	}
	if args[2] != "secret-value" {
		t.Fatalf("redact must not mutate input, got %q", args[2])
	}
	envArgs := []string{"-list", "-storepass:env", javaStorePassEnv, "-keystore", "/tmp/k"}
	got = strings.Join(redactKeytoolArgs(envArgs), " ")
	if !strings.Contains(got, "-storepass:env "+javaStorePassEnv) {
		t.Fatalf("env name should remain visible: %q", got)
	}
}

func TestPrepareStorepassDefault(t *testing.T) {
	t.Setenv(javaStorePassEnv, "")
	flags, env, err := prepareStorepass()
	if err != nil {
		t.Fatal(err)
	}
	if len(flags) != 2 || flags[0] != "-storepass" || flags[1] != defaultKeystorePassword {
		t.Fatalf("flags=%v", flags)
	}
	if len(env) != 0 {
		t.Fatalf("env=%v want empty", env)
	}
}

func TestPrepareStorepassCustomUsesEnv(t *testing.T) {
	const custom = "custom-secret-pass"
	t.Setenv(javaStorePassEnv, custom)
	flags, env, err := prepareStorepass()
	if err != nil {
		t.Fatal(err)
	}
	if len(flags) != 2 || flags[0] != "-storepass:env" || flags[1] != javaStorePassEnv {
		t.Fatalf("flags=%v", flags)
	}
	joined := strings.Join(flags, " ")
	if strings.Contains(joined, custom) {
		t.Fatalf("custom password in flags: %v", flags)
	}
	if len(env) != 1 || env[0] != javaStorePassEnv+"="+custom {
		t.Fatalf("env=%v", env)
	}
}

func TestEnsureKeytoolNonInteractiveCustomNoSecretInArgv(t *testing.T) {
	const custom = "env-store-pass"
	t.Setenv(javaStorePassEnv, custom)
	args, env, err := ensureKeytoolNonInteractive([]string{"-list", "-keystore", "/tmp/k"})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, "\x00")
	if strings.Contains(joined, custom) {
		t.Fatalf("custom secret in argv: %v", redactKeytoolArgs(args))
	}
	foundEnv := false
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "-storepass:env" {
			foundEnv = true
			if args[i+1] != javaStorePassEnv {
				t.Fatalf("env name=%q", args[i+1])
			}
		}
		if args[i] == "-storepass" {
			t.Fatalf("literal -storepass for custom password: %v", redactKeytoolArgs(args))
		}
	}
	if !foundEnv {
		t.Fatalf("missing -storepass:env in %v", redactKeytoolArgs(args))
	}
	if len(env) != 1 || !strings.HasPrefix(env[0], javaStorePassEnv+"=") || !strings.HasSuffix(env[0], "="+custom) {
		t.Fatalf("env override=%v", env)
	}
}

func keytoolArgRecorderScript(seenPath, wantPass string, viaEnv bool) string {
	var b strings.Builder
	b.WriteString("seen=")
	b.WriteString(shellSingleQuote(seenPath))
	b.WriteString("\n: > \"$seen\"\n")
	if wantPass == "" {
		b.WriteString("for a in \"$@\"; do\n  printf '%s\\n' \"$a\" >> \"$seen\"\ndone\nexit 0\n")
		return b.String()
	}
	b.WriteString("pass=\"\"\nprev=\"\"\n")
	b.WriteString("for a in \"$@\"; do\n  printf '%s\\n' \"$a\" >> \"$seen\"\n")
	if viaEnv {
		b.WriteString("  if [ \"$prev\" = \"-storepass:env\" ]; then\n    eval \"pass=\\$$a\"\n  fi\n")
	} else {
		b.WriteString("  if [ \"$prev\" = \"-storepass\" ]; then\n    pass=\"$a\"\n  fi\n")
	}
	b.WriteString("  prev=\"$a\"\ndone\n")
	b.WriteString("if [ \"$pass\" = ")
	b.WriteString(shellSingleQuote(wantPass))
	b.WriteString(" ]; then\n  exit 0\nfi\n")
	b.WriteString("echo 'keytool error: java.io.IOException: Keystore was tampered with, or password was incorrect' >&2\nexit 1\n")
	return b.String()
}

func shellSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

func assertArgvHasNoSecret(t *testing.T, raw []byte, secret string) {
	t.Helper()
	if strings.Contains(string(raw), secret) {
		t.Fatalf("custom secret %q appears in recorded argv:\n%s", secret, raw)
	}
}

func TestRunKeytoolCustomStorepassUsesEnvNotArgv(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake keytool shell script is unix-only")
	}
	const custom = "custom-java-pass"
	javaHome := javaFailFastEnv(t)
	t.Setenv(javaStorePassEnv, custom)
	writeDummyCacerts(t, javaHome)

	seen := filepath.Join(t.TempDir(), "seen-args")
	writeFakeKeytool(t, javaHome, keytoolArgRecorderScript(seen, custom, true))

	kpath := filepath.Join(javaHome, "lib", "security", "cacerts")
	_, err := javaStore{}.tool().runKeytool(kpath, []string{"-list"}, false)
	if err != nil {
		t.Fatalf("runKeytool with matching env storepass failed: %v", err)
	}
	raw, err := os.ReadFile(seen)
	if err != nil {
		t.Fatal(err)
	}
	assertArgvHasNoSecret(t, raw, custom)
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	found := false
	for i := 0; i < len(lines)-1; i++ {
		if lines[i] == "-storepass:env" {
			found = true
			if lines[i+1] != javaStorePassEnv {
				t.Fatalf("env name=%q", lines[i+1])
			}
		}
		if lines[i] == "-storepass" {
			t.Fatalf("literal -storepass in argv for custom password: %q", string(raw))
		}
	}
	if !found {
		t.Fatalf("no -storepass:env in recorded args: %q", string(raw))
	}
}

func TestRunKeytoolDefaultStorepassWhenEnvUnset(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake keytool shell script is unix-only")
	}
	javaHome := javaFailFastEnv(t)
	t.Setenv(javaStorePassEnv, "")
	writeDummyCacerts(t, javaHome)

	seen := filepath.Join(t.TempDir(), "seen-args")
	writeFakeKeytool(t, javaHome, keytoolArgRecorderScript(seen, "", false))

	kpath := filepath.Join(javaHome, "lib", "security", "cacerts")
	_, err := javaStore{}.tool().runKeytool(kpath, []string{"-list"}, false)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(seen)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	for i := 0; i < len(lines)-1; i++ {
		if lines[i] == "-storepass" {
			if lines[i+1] != defaultKeystorePassword {
				t.Fatalf("storepass=%q want default %q", lines[i+1], defaultKeystorePassword)
			}
			return
		}
		if lines[i] == "-storepass:env" {
			t.Fatalf("default password should use -storepass, got env: %q", string(raw))
		}
	}
	t.Fatalf("no -storepass in args: %q", string(raw))
}

func TestEnvironWithOverrides(t *testing.T) {
	got := environWithOverrides([]string{"A=1", "B=2", "C=3"}, []string{"B=9", "D=4"})
	want := []string{"A=1", "C=3", "B=9", "D=4"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v want %v", got, want)
	}
}
