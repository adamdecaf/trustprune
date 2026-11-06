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

	fileArgs := []string{"-list", "-storepass:file", "/tmp/secret-pass-file", "-keystore", "/tmp/k"}
	got = strings.Join(redactKeytoolArgs(fileArgs), " ")
	if strings.Contains(got, "/tmp/secret-pass-file") {
		t.Fatalf("storepass file path leaked: %q", got)
	}
	if !strings.Contains(got, "-storepass:file ***") {
		t.Fatalf("expected file path redaction, got %q", got)
	}
}

func TestPrepareStorepassFlagsDefault(t *testing.T) {
	t.Setenv(javaStorePassEnv, "")
	flags, cleanup, err := prepareStorepassFlags()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if len(flags) != 2 || flags[0] != "-storepass" || flags[1] != defaultKeystorePassword {
		t.Fatalf("flags=%v", flags)
	}
}

func TestPrepareStorepassFlagsCustomUsesFile(t *testing.T) {
	const custom = "custom-secret-pass"
	t.Setenv(javaStorePassEnv, custom)
	flags, cleanup, err := prepareStorepassFlags()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if len(flags) != 2 || flags[0] != "-storepass:file" {
		t.Fatalf("flags=%v want -storepass:file <path>", flags)
	}
	joined := strings.Join(flags, " ")
	if strings.Contains(joined, custom) {
		t.Fatalf("custom password in flags: %v", flags)
	}
	raw, err := os.ReadFile(flags[1])
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != custom {
		t.Fatalf("file contents=%q want %q", raw, custom)
	}
	st, err := os.Stat(flags[1])
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && st.Mode().Perm()&0o077 != 0 {
		t.Fatalf("temp storepass file mode=%v want 0600", st.Mode())
	}
	path := flags[1]
	cleanup()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("cleanup left file: err=%v", err)
	}
}

func TestEnsureKeytoolNonInteractiveCustomNoSecretInArgv(t *testing.T) {
	const custom = "env-store-pass"
	t.Setenv(javaStorePassEnv, custom)
	args, cleanup, err := ensureKeytoolNonInteractive([]string{"-list", "-keystore", "/tmp/k"})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	joined := strings.Join(args, "\x00")
	if strings.Contains(joined, custom) {
		t.Fatalf("custom secret in argv: %v", redactKeytoolArgs(args))
	}
	foundFile := false
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "-storepass:file" {
			foundFile = true
			raw, err := os.ReadFile(args[i+1])
			if err != nil {
				t.Fatal(err)
			}
			if string(raw) != custom {
				t.Fatalf("file pass=%q want %q", raw, custom)
			}
		}
		if args[i] == "-storepass" {
			t.Fatalf("literal -storepass for custom password: %v", redactKeytoolArgs(args))
		}
	}
	if !foundFile {
		t.Fatalf("missing -storepass:file in %v", redactKeytoolArgs(args))
	}
}

func keytoolArgRecorderScript(seenPath, wantPass string, viaFile bool) string {
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
	if viaFile {
		b.WriteString("  if [ \"$prev\" = \"-storepass:file\" ]; then\n    pass=$(cat \"$a\")\n  fi\n")
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

func TestRunKeytoolCustomStorepassUsesFileNotArgv(t *testing.T) {
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
		if lines[i] == "-storepass:file" {
			found = true
		}
		if lines[i] == "-storepass" {
			t.Fatalf("literal -storepass in argv for custom password: %q", string(raw))
		}
	}
	if !found {
		t.Fatalf("no -storepass:file in recorded args: %q", string(raw))
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
		if lines[i] == "-storepass:file" {
			t.Fatalf("default password should use -storepass, got file: %q", string(raw))
		}
	}
	t.Fatalf("no -storepass in args: %q", string(raw))
}

func TestRunKeytoolSudoCustomStorepassNotInArgv(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake sudo/keytool shell scripts are unix-only")
	}
	const custom = "sudo-secret-pass"
	javaHome := javaFailFastEnv(t)
	t.Setenv(javaStorePassEnv, custom)
	writeDummyCacerts(t, javaHome)

	seen := filepath.Join(t.TempDir(), "seen-args")
	writeFakeKeytool(t, javaHome, keytoolArgRecorderScript(seen, custom, true))

	sudoPath, sudoArgvFile := writeFakeSudo(t)
	oldSudo := keytoolSudoPath
	keytoolSudoPath = sudoPath
	t.Cleanup(func() { keytoolSudoPath = oldSudo })

	kpath := filepath.Join(javaHome, "lib", "security", "cacerts")
	_, err := javaStore{}.tool().runKeytool(kpath, []string{"-list"}, true)
	if err != nil {
		t.Fatalf("sudo runKeytool: %v", err)
	}
	raw, err := os.ReadFile(seen)
	if err != nil {
		t.Fatal(err)
	}
	assertArgvHasNoSecret(t, raw, custom)

	sudoRaw, err := os.ReadFile(sudoArgvFile)
	if err != nil {
		t.Fatal(err)
	}
	assertArgvHasNoSecret(t, sudoRaw, custom)
	if !strings.Contains(string(sudoRaw), "-storepass:file") {
		t.Fatalf("sudo argv missing -storepass:file: %q", sudoRaw)
	}
	if strings.Contains(string(sudoRaw), "-storepass "+custom) || strings.Contains(string(sudoRaw), "\n"+custom) {
		t.Fatalf("custom secret in sudo argv: %q", sudoRaw)
	}
}
