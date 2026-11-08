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

package test

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/adamdecaf/trustprune/pkg/certutil"
)

// TestOpenSSLBundleCLI exercises -bundle through the built CLI. Every HOME,
// PEM, allowlist, and decoy path is under t.TempDir. SSL_CERT_FILE points at
// the decoy so a discovery fallback cannot satisfy the list count.
func TestOpenSSLBundleCLI(t *testing.T) {
	bin := CertManage()
	if bin == nil || bin.command == "" {
		t.Fatal("no trustprune binary path for this platform")
	}
	if _, err := os.Stat(bin.command); err != nil {
		t.Skipf("built binary missing at %s", bin.command)
	}

	home := t.TempDir()
	work := t.TempDir()
	live := filepath.Join(work, "ca-bundle.pem")
	other := filepath.Join(work, "other.pem")
	decoy := filepath.Join(work, "decoy.pem")
	bundleDir := filepath.Join(work, "cadir")
	allowlistPath := filepath.Join(work, "allowlist.json")
	refuseSystemPath(t, home, work, live, other, decoy, bundleDir, allowlistPath)

	lots, err := os.ReadFile(filepath.Join("..", "testdata", "lots.crt"))
	if err != nil {
		t.Fatal(err)
	}
	example, err := os.ReadFile(filepath.Join("..", "testdata", "example.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(lots, example) {
		t.Fatal("testdata fixtures must differ so cross-path restore is observable")
	}
	certs, err := certutil.FromFile(filepath.Join("..", "testdata", "lots.crt"))
	if err != nil || len(certs) < 2 {
		t.Fatalf("lots.crt: len=%d err=%v", len(certs), err)
	}
	if err := os.WriteFile(live, lots, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(other, example, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(decoy, []byte("not-a-pem\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(bundleDir, 0o755); err != nil {
		t.Fatal(err)
	}
	fp := certutil.GetHexSHA256Fingerprint(*certs[0])
	if err := os.WriteFile(allowlistPath, []byte(fmt.Sprintf("{\"Fingerprints\":[%q]}\n", fp)), 0o644); err != nil {
		t.Fatal(err)
	}

	env := bundleCLIEnv(home, decoy)
	var stdout, stderr string

	stdout, stderr, err = runBundleCLI(t, bin.command, env, "list", "-app", "openssl", "-bundle", live, "-count")
	if err != nil {
		t.Fatalf("list -count: %v\nstdout=%s\nstderr=%s", err, stdout, stderr)
	}
	if strings.TrimSpace(stdout) != strconv.Itoa(len(certs)) {
		t.Fatalf("list -count=%q want %d\nstderr=%s", stdout, len(certs), stderr)
	}

	stdout, stderr, err = runBundleCLI(t, bin.command, env, "backup", "-app", "openssl", "-bundle", live)
	if err != nil || !strings.Contains(stdout, "Backup completed successfully") {
		t.Fatalf("backup: %v\nstdout=%s\nstderr=%s", err, stdout, stderr)
	}
	backupDir := opensslCLIBackup(t, home)
	backed, err := os.ReadFile(filepath.Join(backupDir, "ca-bundle.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(backed, lots) {
		t.Fatal("backup bytes differ from the -bundle PEM")
	}
	recorded, err := os.ReadFile(filepath.Join(backupDir, "source"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(recorded)) != canonicalBundlePath(t, live) {
		t.Fatalf("source=%q want %q", strings.TrimSpace(string(recorded)), canonicalBundlePath(t, live))
	}

	beforeAllow, err := os.ReadFile(live)
	if err != nil {
		t.Fatal(err)
	}
	stdout, stderr, err = runBundleCLI(t, bin.command, env, "whitelist", "-app", "openssl", "-file", allowlistPath, "-bundle", live, "-dry-run")
	if err != nil || !strings.Contains(stdout, "dry-run: no changes made") {
		t.Fatalf("whitelist -dry-run: %v\nstdout=%s\nstderr=%s", err, stdout, stderr)
	}
	afterAllow, err := os.ReadFile(live)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(beforeAllow, afterAllow) {
		t.Fatal("whitelist -dry-run mutated the PEM")
	}

	if err := os.WriteFile(live, []byte("MUTATED\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, err = runBundleCLI(t, bin.command, env, "restore", "-app", "openssl", "-bundle", live)
	if err != nil || !strings.Contains(stdout, "Restore completed successfully") {
		t.Fatalf("restore latest: %v\nstdout=%s\nstderr=%s", err, stdout, stderr)
	}
	restored, err := os.ReadFile(live)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restored, lots) {
		t.Fatal("restore -bundle did not restore the PEM")
	}

	otherBefore, err := os.ReadFile(other)
	if err != nil {
		t.Fatal(err)
	}
	stdout, stderr, err = runBundleCLI(t, bin.command, env, "restore", "-app", "openssl", "-bundle", other, "-backup", backupDir)
	if err == nil || !strings.Contains(stdout+stderr, "refusing restore") {
		t.Fatalf("cross-path: %v\nstdout=%s\nstderr=%s", err, stdout, stderr)
	}
	assertExitOne(t, err)
	otherAfter, err := os.ReadFile(other)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(otherAfter, otherBefore) {
		t.Fatal("refused restore mutated the other PEM")
	}
	if _, statErr := os.Stat(other + ".restore-old"); !os.IsNotExist(statErr) {
		t.Fatalf("refused restore left aside: %v", statErr)
	}

	stdout, stderr, err = runBundleCLI(t, bin.command, env, "restore", "-app", "openssl", "-bundle", other, "-backup", backupDir, "-force")
	if err != nil || !strings.Contains(stdout, "Restore completed successfully") {
		t.Fatalf("cross-path -force: %v\nstdout=%s\nstderr=%s", err, stdout, stderr)
	}
	forced, err := os.ReadFile(other)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(forced, lots) {
		t.Fatal("-force did not copy the recorded PEM into the other bundle")
	}

	stdout, stderr, err = runBundleCLI(t, bin.command, env, "list", "-app", "java", "-bundle", live, "-count")
	if err == nil || !strings.Contains(stdout+stderr, "-bundle requires -app openssl") {
		t.Fatalf("wrong app: %v\nstdout=%s\nstderr=%s", err, stdout, stderr)
	}
	assertExitOne(t, err)

	stdout, stderr, err = runBundleCLI(t, bin.command, env, "add", "-app", "openssl", "-bundle", live)
	if err == nil || !strings.Contains(stdout+stderr, "-bundle is only supported for list, backup, restore, and allowlist") {
		t.Fatalf("unsupported command: %v\nstdout=%s\nstderr=%s", err, stdout, stderr)
	}
	assertExitOne(t, err)

	stdout, stderr, err = runBundleCLI(t, bin.command, env, "backup", "-app", "openssl", "-bundle", bundleDir)
	if err == nil || !strings.Contains(stdout+stderr, "is a directory") {
		t.Fatalf("directory -bundle: %v\nstdout=%s\nstderr=%s", err, stdout, stderr)
	}
	assertExitOne(t, err)

	decoyAfter, err := os.ReadFile(decoy)
	if err != nil {
		t.Fatal(err)
	}
	if string(decoyAfter) != "not-a-pem\n" {
		t.Fatalf("decoy mutated: %q", decoyAfter)
	}
	liveAfter, err := os.ReadFile(live)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(liveAfter, lots) {
		t.Fatal("rejection cases mutated the live PEM")
	}
}

func bundleCLIEnv(home, decoy string) []string {
	drop := map[string]struct{}{
		"HOME": {}, "USERPROFILE": {},
		"SSL_CERT_FILE": {}, "CURL_CA_BUNDLE": {}, "GIT_SSL_CAINFO": {},
		"XDG_CACHE_HOME": {}, "XDG_CONFIG_HOME": {}, "XDG_DATA_HOME": {}, "XDG_STATE_HOME": {},
	}
	env := make([]string, 0, len(os.Environ())+8)
	for _, e := range os.Environ() {
		key, _, ok := strings.Cut(e, "=")
		if ok {
			if _, skip := drop[key]; skip {
				continue
			}
		}
		env = append(env, e)
	}
	return append(env,
		"HOME="+home,
		"USERPROFILE="+home,
		"SSL_CERT_FILE="+decoy,
		"CURL_CA_BUNDLE="+decoy,
		"XDG_CACHE_HOME="+filepath.Join(home, "xdg", "cache"),
		"XDG_CONFIG_HOME="+filepath.Join(home, "xdg", "config"),
		"XDG_DATA_HOME="+filepath.Join(home, "xdg", "data"),
		"XDG_STATE_HOME="+filepath.Join(home, "xdg", "state"),
	)
}

func runBundleCLI(t *testing.T, bin string, env []string, args ...string) (string, string, error) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = env
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

func assertExitOne(t *testing.T, err error) {
	t.Helper()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
		t.Fatalf("exit %v, want status 1", err)
	}
}

func opensslCLIBackup(t *testing.T, home string) string {
	t.Helper()
	root := filepath.Join(home, ".trustprune", "openssl")
	ents, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("backup dir %s: %v", root, err)
	}
	var dirs []string
	for _, ent := range ents {
		if ent.IsDir() {
			dirs = append(dirs, filepath.Join(root, ent.Name()))
		}
	}
	if len(dirs) != 1 {
		t.Fatalf("openssl backups under %s: %v", root, dirs)
	}
	if !strings.HasPrefix(dirs[0], home) {
		t.Fatalf("backup %s is outside temp HOME %s", dirs[0], home)
	}
	return dirs[0]
}

func canonicalBundlePath(t *testing.T, p string) string {
	t.Helper()
	abs, err := filepath.Abs(p)
	if err != nil {
		t.Fatal(err)
	}
	abs = filepath.Clean(abs)
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil || resolved == "" {
		return abs
	}
	return resolved
}

func refuseSystemPath(t *testing.T, paths ...string) {
	t.Helper()
	for _, p := range paths {
		c := filepath.Clean(p)
		for _, prefix := range []string{"/etc", "/usr", "/System"} {
			if c == prefix || strings.HasPrefix(c, prefix+"/") {
				t.Fatalf("refusing system path in tests: %s", p)
			}
		}
	}
}
