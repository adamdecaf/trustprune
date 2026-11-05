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
	"time"
)

const javaFailFastLimit = 3 * time.Second

// javaFailFastEnv points package-level ktool at a temp JAVA_HOME, an empty
// temp HOME, and a PATH that prefers JAVA_HOME/bin. Never a real JDK store.
func javaFailFastEnv(t *testing.T) string {
	t.Helper()

	javaHome := t.TempDir()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("JAVA_HOME", javaHome)

	binDir := filepath.Join(javaHome, "bin")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	orig := ktool
	origTimeout := keytoolTimeout
	origSudo := keytoolSudoPath
	origFindTimeout := findTimeoutBin
	t.Cleanup(func() {
		ktool = orig
		keytoolTimeout = origTimeout
		keytoolSudoPath = origSudo
		findTimeoutBin = origFindTimeout
	})
	ktool = keytool{
		javahome:              javaHome,
		javaInstallPaths:      nil,
		relativeKeystorePaths: []string{"/lib/security/cacerts", "/jre/lib/security/cacerts"},
	}
	refuseSystemKeystore(t, javaHome)
	refuseIfOutside(t, javaHome, javaHome, "JAVA_HOME")
	return javaHome
}

func writeFakeKeytool(t *testing.T, javaHome, script string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake keytool shell script is unix-only")
	}
	binDir := filepath.Join(javaHome, "bin")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(binDir, "keytool")
	body := "#!/bin/sh\n" + script + "\n"
	if err := os.WriteFile(path, []byte(body), 0755); err != nil {
		t.Fatal(err)
	}
}

func writeHangingKeytoolIfUnix(t *testing.T, javaHome string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		return
	}
	writeFakeKeytool(t, javaHome, "cat >/dev/null\nexec sleep 86400")
}

func writeDummyCacerts(t *testing.T, javaHome string) string {
	t.Helper()
	kpath := filepath.Join(javaHome, "lib", "security", "cacerts")
	if err := os.MkdirAll(filepath.Dir(kpath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kpath, []byte("not-a-real-keystore"), 0644); err != nil {
		t.Fatal(err)
	}
	refuseSystemKeystore(t, kpath)
	return kpath
}

func assertJavaFailsFast(t *testing.T, err error, wantSubstr string, started time.Time) {
	t.Helper()
	elapsed := time.Since(started)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), wantSubstr) {
		t.Fatalf("error %q does not contain %q", err.Error(), wantSubstr)
	}
	if elapsed > javaFailFastLimit {
		t.Fatalf("took %s, want fail-fast under %s: %v", elapsed, javaFailFastLimit, err)
	}
}

func TestJava_MissingCacertsFailsFast(t *testing.T) {
	javaHome := javaFailFastEnv(t)
	// Hanging keytool proves we never exec it for a missing file.
	writeHangingKeytoolIfUnix(t, javaHome)

	started := time.Now()
	_, err := javaStore{}.List(nil)
	assertJavaFailsFast(t, err, "has no cacerts", started)
	if !strings.Contains(err.Error(), javaHome) {
		t.Fatalf("missing-cacerts error should name JAVA_HOME %s: %v", javaHome, err)
	}
}

func TestJava_CacertsDirectoryFailsFast(t *testing.T) {
	javaHome := javaFailFastEnv(t)
	dir := filepath.Join(javaHome, "lib", "security", "cacerts")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	refuseSystemKeystore(t, dir)
	writeHangingKeytoolIfUnix(t, javaHome)

	started := time.Now()
	_, err := javaStore{}.List(nil)
	assertJavaFailsFast(t, err, "is a directory", started)
	if strings.Contains(err.Error(), "has no cacerts") {
		t.Fatalf("directory error must be distinct from missing cacerts: %v", err)
	}
	if strings.Contains(err.Error(), "wrong keystore password") {
		t.Fatalf("directory error must be distinct from wrong password: %v", err)
	}
}

func TestJava_WrongStorepassFailsFast(t *testing.T) {
	javaHome := javaFailFastEnv(t)
	writeDummyCacerts(t, javaHome)
	writeFakeKeytool(t, javaHome, `echo 'keytool error: java.io.IOException: Keystore was tampered with, or password was incorrect' >&2
exit 1`)

	started := time.Now()
	_, err := javaStore{}.List(nil)
	assertJavaFailsFast(t, err, keystoreTamperedMessage, started)
	if !strings.Contains(err.Error(), "wrong keystore password") {
		t.Fatalf("expected distinct wrong-password error, got %v", err)
	}
	if strings.Contains(err.Error(), "is a directory") || strings.Contains(err.Error(), "has no cacerts") {
		t.Fatalf("wrong-password error must be distinct: %v", err)
	}
}

func TestKeytoolTimeoutSecs(t *testing.T) {
	orig := keytoolTimeout
	t.Cleanup(func() { keytoolTimeout = orig })

	keytoolTimeout = 400 * time.Millisecond
	if g := keytoolTimeoutSecs(); g != 1 {
		t.Errorf("400ms: got %d, want 1", g)
	}
	keytoolTimeout = 30 * time.Second
	if g := keytoolTimeoutSecs(); g != 30 {
		t.Errorf("30s: got %d, want 30", g)
	}
	keytoolTimeout = 30*time.Second + time.Millisecond
	if g := keytoolTimeoutSecs(); g != 31 {
		t.Errorf("30s+1ms: got %d, want 31", g)
	}
}

func TestJava_KeytoolStdinHangTimesOut(t *testing.T) {
	javaHome := javaFailFastEnv(t)
	writeDummyCacerts(t, javaHome)
	writeFakeKeytool(t, javaHome, "cat >/dev/null\nexec sleep 86400")
	keytoolTimeout = 400 * time.Millisecond

	started := time.Now()
	_, err := javaStore{}.List(nil)
	assertJavaFailsFast(t, err, "timed out", started)
	if elapsed := time.Since(started); elapsed < 200*time.Millisecond {
		t.Fatalf("timeout returned too quickly (%s); fake keytool should block until the context fires", elapsed)
	}
}
