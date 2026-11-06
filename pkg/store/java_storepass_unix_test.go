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
	"strings"
	"testing"
)

func TestRunKeytoolSudoCustomStorepassNotInArgv(t *testing.T) {
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
	if !strings.Contains(string(sudoRaw), "-storepass:env") {
		t.Fatalf("sudo argv missing -storepass:env: %q", sudoRaw)
	}
	if !strings.Contains(string(sudoRaw), "--preserve-env="+javaStorePassEnv) {
		t.Fatalf("sudo argv missing --preserve-env: %q", sudoRaw)
	}
	if strings.Contains(string(sudoRaw), custom) {
		t.Fatalf("custom secret in sudo argv: %q", sudoRaw)
	}
}
