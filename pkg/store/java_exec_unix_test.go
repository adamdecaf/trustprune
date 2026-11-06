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

//go:build unix

package store

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func writeFakeSudo(t *testing.T) (sudoPath, argvFile string) {
	t.Helper()
	dir := t.TempDir()
	sudoPath = filepath.Join(dir, "sudo")
	argvFile = filepath.Join(dir, "argv")
	script := `#!/bin/sh
for a; do printf '%s\n' "$a"; done > "$SUDO_ARGV_FILE"
while [ $# -gt 0 ]; do
  case "$1" in
    -n|--preserve-env|--preserve-env=*) shift ;;
    *) break ;;
  esac
done
"$@"
`
	if err := os.WriteFile(sudoPath, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SUDO_ARGV_FILE", argvFile)
	return sudoPath, argvFile
}

func writeFakeTimeout(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "timeout")
	script := `#!/bin/sh
if [ "$1" = "-s" ]; then shift 2; fi
shift
exec "$@"
`
	if err := os.WriteFile(p, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	return p
}

func readSudoArgv(t *testing.T, argvFile string) []string {
	t.Helper()
	b, err := os.ReadFile(argvFile)
	if err != nil {
		t.Fatalf("sudo argv: %v", err)
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		t.Fatal("sudo wrote empty argv")
	}
	return strings.Split(s, "\n")
}

func argvHasSeq(argv []string, want ...string) bool {
	if len(want) == 0 {
		return true
	}
	for i := 0; i+len(want) <= len(argv); i++ {
		ok := true
		for j := range want {
			if argv[i+j] != want[j] {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func TestJava_SudoChildHoldsStdoutTimesOut(t *testing.T) {
	javaHome := javaFailFastEnv(t)
	kpath := writeDummyCacerts(t, javaHome)
	// Child keeps stdout open after this process is killed (the sudo hang).
	writeFakeKeytool(t, javaHome, "sleep 60 &\nwait")

	sudoPath, argvFile := writeFakeSudo(t)
	timeoutPath := writeFakeTimeout(t)
	keytoolSudoPath = sudoPath
	findTimeoutBin = func() string { return timeoutPath }
	keytoolTimeout = 400 * time.Millisecond

	started := time.Now()
	_, err := javaStore{}.tool().runKeytool(kpath, []string{"-list"}, true)
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("took %s, want timeout under 5s (child held stdout): %v", elapsed, err)
	}
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if elapsed := time.Since(started); elapsed < 200*time.Millisecond {
		t.Fatalf("timeout returned too quickly (%s); child should block until the context fires", elapsed)
	}
	assertJavaFailsFast(t, err, "timed out", started)
	if strings.Contains(err.Error(), "may still be running as root") {
		t.Fatalf("root timeout wrapper was present; error should not warn about leftover root keytool: %v", err)
	}

	argv := readSudoArgv(t, argvFile)
	secs := strconv.Itoa(keytoolTimeoutSecs())
	if !argvHasSeq(argv, "-n") {
		t.Fatalf("sudo argv missing -n: %q", argv)
	}
	if !argvHasSeq(argv, timeoutPath, "-s", "KILL", secs) {
		t.Fatalf("sudo argv missing timeout wrapper %s -s KILL %s: %q", timeoutPath, secs, argv)
	}
}

func TestJava_SudoTimeoutWithoutTimeoutBin(t *testing.T) {
	javaHome := javaFailFastEnv(t)
	kpath := writeDummyCacerts(t, javaHome)
	writeFakeKeytool(t, javaHome, "sleep 60 &\nwait")

	sudoPath, argvFile := writeFakeSudo(t)
	keytoolSudoPath = sudoPath
	findTimeoutBin = func() string { return "" }
	keytoolTimeout = 400 * time.Millisecond

	started := time.Now()
	_, err := javaStore{}.tool().runKeytool(kpath, []string{"-list"}, true)
	assertJavaFailsFast(t, err, "timed out", started)
	if !strings.Contains(err.Error(), "keytool may still be running as root") {
		t.Fatalf("expected leftover-root warning, got %v", err)
	}

	argv := readSudoArgv(t, argvFile)
	if !argvHasSeq(argv, "-n") {
		t.Fatalf("sudo argv missing -n: %q", argv)
	}
	for _, a := range argv {
		if a == "-s" || strings.HasSuffix(a, string(os.PathSeparator)+"timeout") || a == "timeout" {
			t.Fatalf("sudo argv should not wrap with timeout when none is found: %q", argv)
		}
	}
}
