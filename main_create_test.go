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
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/adamdecaf/trustprune/pkg/certutil"
)

func TestCreateCLI(t *testing.T) {
	bin := cliBinary(t)
	src := readTestFile(t, filepath.Join("testdata", "lots.crt"))
	certs, err := certutil.Decode(src)
	if err != nil || len(certs) < 2 {
		t.Fatalf("lots.crt: len=%d err=%v", len(certs), err)
	}
	keepFP := certutil.GetHexSHA256Fingerprint(*certs[0])

	t.Run("help", func(t *testing.T) {
		home := t.TempDir()
		res := runCLI(t, bin, home, "create", "--help")
		if res.code != 0 {
			t.Fatalf("code=%d stdout=%s stderr=%s", res.code, res.stdout, res.stderr)
		}
		for _, needle := range []string{
			"trustprune create --file allowlist.yaml",
			"trustprune create --file allowlist.yaml --out ca-bundle.pem",
			"--app certifi --store /path/to/cacert.pem",
			"--app openssl --file allowlist.yaml --bundle",
			"default: pem",
			"options: pem",
			"mode 0644",
			"without changing the store",
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
		if !strings.Contains(res.stderr, "pem") {
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

	t.Run("stray args", func(t *testing.T) {
		home, bundle, before := certifiBundle(t, src)
		al := writeKeepFirstAllowlist(t, src)
		res := runCLI(t, bin, home, "create", "--app", "certifi", "--store", bundle, "--file", al, "extra")
		assertStrayRejected(t, res, "extra")
		assertSameBytes(t, bundle, before)
		assertNoBackupRoot(t, home)
	})
}
