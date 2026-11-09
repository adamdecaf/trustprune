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
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/adamdecaf/trustprune/pkg/certutil"
)

func TestResolveStorePath(t *testing.T) {
	t.Parallel()
	rel := filepath.Join("rel-store", "cacerts")
	absRel, err := filepath.Abs(rel)
	if err != nil {
		t.Fatal(err)
	}
	viaDot := filepath.Join("rel-store", "..", "rel-store", "cacerts")
	tests := []struct {
		name      string
		store     string
		file      string
		alias     bool
		wantPath  string
		wantWarn  bool
		wantError string
	}{
		{name: "alias file only", file: "/ks", alias: true, wantPath: "/ks", wantWarn: true},
		{name: "alias store only", store: "/ks", alias: true, wantPath: "/ks"},
		{name: "same value prefers store and warns", store: "/ks", file: "/ks", alias: true, wantPath: "/ks", wantWarn: true},
		{name: "trim makes same value", store: " /ks ", file: "/ks", alias: true, wantPath: "/ks", wantWarn: true},
		{name: "clean equivalent", store: "/tmp/a", file: "/tmp/./a", alias: true, wantPath: "/tmp/a", wantWarn: true},
		{name: "clean equivalent prefers store text", store: "/tmp/./a", file: "/tmp/a", alias: true, wantPath: "/tmp/./a", wantWarn: true},
		{name: "trim and clean equivalent", store: " /tmp/./a ", file: "/tmp/a", alias: true, wantPath: "/tmp/./a", wantWarn: true},
		{name: "abs equivalent", store: rel, file: absRel, alias: true, wantPath: rel, wantWarn: true},
		{name: "abs equivalent prefers store text", store: absRel, file: rel, alias: true, wantPath: absRel, wantWarn: true},
		{name: "dotdot agrees with absolute", store: viaDot, file: absRel, alias: true, wantPath: viaDot, wantWarn: true},
		{name: "whitespace file is empty", store: "/ks", file: "  ", alias: true, wantPath: "/ks"},
		{name: "disagree", store: "/a", file: "/b", alias: true, wantError: "disagree"},
		{name: "clean still disagrees", store: "/tmp/a", file: "/tmp/b", alias: true, wantError: "disagree"},
		{name: "alias both empty", alias: true},
		{name: "not alias ignores file", store: "", file: "/pem", wantPath: ""},
		{name: "not alias returns store only", store: "/s", file: "/pem", wantPath: "/s"},
		{name: "not alias does not disagree", store: "/a", file: "/b", wantPath: "/a"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path, warn, err := resolveStorePath(tt.store, tt.file, tt.alias)
			if tt.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantError) {
					t.Fatalf("err=%v want %q", err, tt.wantError)
				}
				if warn {
					t.Fatal("warn set on error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if path != tt.wantPath || warn != tt.wantWarn {
				t.Fatalf("path=%q warn=%v want path=%q warn=%v", path, warn, tt.wantPath, tt.wantWarn)
			}
		})
	}
}

func TestFileIsStorePath(t *testing.T) {
	t.Parallel()
	yes := []struct{ cmd, app string }{
		{"list", "java"},
		{"list", "firefox"},
		{"list", " Java "},
		{"backup", "certifi"},
		{"connect", "chrome"},
		{"restore", "java"},
		{"restore", "CERTIFI"},
		{"restore", " Java "},
		{"LIST", "java"},
	}
	no := []struct{ cmd, app string }{
		{"list", ""},
		{"backup", ""},
		{"backup", "  "},
		{"connect", ""},
		{"restore", ""},
		{"restore", "firefox"},
		{"restore", "ssl"},
		{"restore", "openssl"},
		{"restore", "chrome"},
		{"add", "certifi"},
		{"add", "java"},
		{"allowlist", "java"},
		{"whitelist", "certifi"},
		{"gen-allowlist", ""},
	}
	for _, tc := range yes {
		if !fileIsStorePath(tc.cmd, tc.app) {
			t.Errorf("fileIsStorePath(%q, %q) = false, want true", tc.cmd, tc.app)
		}
	}
	for _, tc := range no {
		if fileIsStorePath(tc.cmd, tc.app) {
			t.Errorf("fileIsStorePath(%q, %q) = true, want false", tc.cmd, tc.app)
		}
	}
}

func TestCLIStoreFlag(t *testing.T) {
	bin := cliBinary(t)
	lots := filepath.Join("testdata", "lots.crt")
	certs, err := certutil.FromFile(lots)
	if err != nil || len(certs) == 0 {
		t.Fatalf("lots.crt: %d %v", len(certs), err)
	}
	bundle := filepath.Join(t.TempDir(), "venv", "lib", "python3.12", "site-packages", "certifi", "cacert.pem")
	if err := os.MkdirAll(filepath.Dir(bundle), 0o755); err != nil {
		t.Fatal(err)
	}
	// #nosec G304 -- test fixture path
	src, err := os.ReadFile(lots)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bundle, src, 0o644); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(t.TempDir(), "other.pem")
	if err := os.WriteFile(other, src, 0o644); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()

	t.Run("list store certifi", func(t *testing.T) {
		res := runCLI(t, bin, home, "list", "-app", "certifi", "-store", bundle, "-count")
		if res.code != 0 {
			t.Fatalf("code=%d\nstdout=%s\nstderr=%s", res.code, res.stdout, res.stderr)
		}
		if strings.TrimSpace(res.stdout) != fmt.Sprint(len(certs)) {
			t.Fatalf("count %q want %d", res.stdout, len(certs))
		}
		if strings.Contains(res.stderr, "use -store instead") {
			t.Fatalf("unexpected deprecation warning:\n%s", res.stderr)
		}
	})

	t.Run("list file alias warns", func(t *testing.T) {
		res := runCLI(t, bin, home, "list", "-app", "certifi", "-file", bundle, "-count")
		if res.code != 0 {
			t.Fatalf("code=%d\nstdout=%s\nstderr=%s", res.code, res.stdout, res.stderr)
		}
		if strings.TrimSpace(res.stdout) != fmt.Sprint(len(certs)) {
			t.Fatalf("count %q want %d", res.stdout, len(certs))
		}
		if !strings.Contains(res.stderr, storePathDeprecation) {
			t.Fatalf("stderr missing deprecation warning:\n%s", res.stderr)
		}
	})

	t.Run("list store and file disagree", func(t *testing.T) {
		res := runCLI(t, bin, home, "list", "-app", "certifi", "-store", bundle, "-file", other, "-count")
		if res.code == 0 {
			t.Fatal("expected non-zero exit")
		}
		if !strings.Contains(res.stderr, "ERROR:") || !strings.Contains(res.stderr, "disagree") {
			t.Fatalf("stderr=%q stdout=%q", res.stderr, res.stdout)
		}
		if strings.TrimSpace(res.stdout) == fmt.Sprint(len(certs)) {
			t.Fatal("listed certificates after a flag conflict")
		}
	})

	t.Run("platform list file is pem", func(t *testing.T) {
		res := runCLI(t, bin, home, "list", "-file", lots, "-count")
		if res.code != 0 {
			t.Fatalf("code=%d\nstdout=%s\nstderr=%s", res.code, res.stdout, res.stderr)
		}
		if strings.TrimSpace(res.stdout) != fmt.Sprint(len(certs)) {
			t.Fatalf("count %q want %d", res.stdout, len(certs))
		}
		if strings.Contains(res.stderr, "use -store instead") {
			t.Fatalf("platform list -file warned:\n%s", res.stderr)
		}
	})

	t.Run("add store without file", func(t *testing.T) {
		// #nosec G304 -- test fixture path
		before, err := os.ReadFile(bundle)
		if err != nil {
			t.Fatal(err)
		}
		res := runCLI(t, bin, home, "add", "-app", "certifi", "-store", bundle, "-dry-run")
		if res.code != 0 {
			t.Fatalf("missing -file should print help and exit 0, code=%d stdout=%q stderr=%q", res.code, res.stdout, res.stderr)
		}
		if !strings.Contains(res.stdout, "Usage: trustprune add") {
			t.Fatalf("expected add help, stdout=%q stderr=%q", res.stdout, res.stderr)
		}
		if strings.Contains(res.stdout, "would add") || strings.Contains(res.stderr, "would add") {
			t.Fatalf("treated -store as the certificate:\nstdout=%s\nstderr=%s", res.stdout, res.stderr)
		}
		// #nosec G304 -- test fixture path
		after, err := os.ReadFile(bundle)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(before, after) {
			t.Fatal("add -store modified the bundle")
		}
	})
}

var (
	cliOnce sync.Once
	cliBin  string
	cliErr  error
)

func cliBinary(t *testing.T) string {
	t.Helper()
	cliOnce.Do(func() {
		dir, err := os.MkdirTemp("", "trustprune-cli")
		if err != nil {
			cliErr = err
			return
		}
		cliBin = filepath.Join(dir, "trustprune")
		// go build -o writes trustprune.exe on Windows.
		if runtime.GOOS == "windows" {
			cliBin += ".exe"
		}
		_, file, _, ok := runtime.Caller(0)
		if !ok {
			cliErr = errors.New("runtime.Caller failed")
			return
		}
		cmd := exec.Command("go", "build", "-o", cliBin, ".")
		cmd.Dir = filepath.Dir(file)
		out, err := cmd.CombinedOutput()
		if err != nil {
			cliErr = fmt.Errorf("go build: %w\n%s", err, out)
		}
	})
	if cliErr != nil {
		t.Fatal(cliErr)
	}
	return cliBin
}

type cliResult struct {
	stdout string
	stderr string
	code   int
}

func runCLI(t *testing.T, bin, home string, args ...string) cliResult {
	t.Helper()
	return runCLIWithEnv(t, bin, envWithHome(home), args...)
}

func runCLIWithEnv(t *testing.T, bin string, env []string, args ...string) cliResult {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = env
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("run: %v", err)
		}
		code = ee.ExitCode()
	}
	return cliResult{stdout: stdout.String(), stderr: stderr.String(), code: code}
}

func envWithHome(home string) []string {
	out := make([]string, 0, len(os.Environ())+2)
	for _, e := range os.Environ() {
		if strings.HasPrefix(e, "HOME=") || strings.HasPrefix(e, "USERPROFILE=") {
			continue
		}
		out = append(out, e)
	}
	return append(out, "HOME="+home, "USERPROFILE="+home)
}
