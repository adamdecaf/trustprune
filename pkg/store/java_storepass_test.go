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
}

func TestEnsureKeytoolNonInteractiveUsesEnvStorepass(t *testing.T) {
	const custom = "env-store-pass"
	t.Setenv(javaStorePassEnv, custom)
	args := ensureKeytoolNonInteractive([]string{"-list", "-keystore", "/tmp/k"})
	pass := storepassFromArgs(t, args)
	if pass != custom {
		t.Fatalf("storepass=%q want %q; args=%v", pass, custom, redactKeytoolArgs(args))
	}
}

func keytoolArgRecorderScript(seenPath, wantPass string) string {
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
	b.WriteString("  if [ \"$prev\" = \"-storepass\" ]; then\n    pass=\"$a\"\n  fi\n  prev=\"$a\"\ndone\n")
	b.WriteString("if [ \"$pass\" = ")
	b.WriteString(shellSingleQuote(wantPass))
	b.WriteString(" ]; then\n  exit 0\nfi\n")
	b.WriteString("echo 'keytool error: java.io.IOException: Keystore was tampered with, or password was incorrect' >&2\nexit 1\n")
	return b.String()
}

func shellSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

func TestRunKeytoolPassesEnvStorepass(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake keytool shell script is unix-only")
	}
	const custom = "custom-java-pass"
	javaHome := javaFailFastEnv(t)
	t.Setenv(javaStorePassEnv, custom)
	writeDummyCacerts(t, javaHome)

	seen := filepath.Join(t.TempDir(), "seen-args")
	writeFakeKeytool(t, javaHome, keytoolArgRecorderScript(seen, custom))

	kpath := filepath.Join(javaHome, "lib", "security", "cacerts")
	_, err := javaStore{}.tool().runKeytool(kpath, []string{"-list"}, false)
	if err != nil {
		t.Fatalf("runKeytool with matching env storepass failed: %v", err)
	}
	raw, err := os.ReadFile(seen)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	found := false
	for i := 0; i < len(lines)-1; i++ {
		if lines[i] == "-storepass" {
			found = true
			if lines[i+1] != custom {
				t.Fatalf("recorded storepass=%q want %q", lines[i+1], custom)
			}
		}
	}
	if !found {
		t.Fatalf("no -storepass in recorded args: %q", string(raw))
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
	writeFakeKeytool(t, javaHome, keytoolArgRecorderScript(seen, ""))

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
	}
	t.Fatalf("no -storepass in args: %q", string(raw))
}

func storepassFromArgs(t *testing.T, args []string) string {
	t.Helper()
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "-storepass" {
			return args[i+1]
		}
	}
	t.Fatalf("no -storepass in %v", redactKeytoolArgs(args))
	return ""
}
