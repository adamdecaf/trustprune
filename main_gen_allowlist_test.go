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
	"strings"
	"testing"
)

func TestCLIGenAllowlistFlags(t *testing.T) {
	bin := cliBinary(t)
	home := t.TempDir()
	out := filepath.Join(home, "allowlist.yaml")

	t.Run("help lists --hosts and --presets", func(t *testing.T) {
		res := runCLI(t, bin, home, "gen-allowlist", "--help")
		if res.code != 0 {
			t.Fatalf("code=%d stdout=%s stderr=%s", res.code, res.stdout, res.stderr)
		}
		body := res.stdout + res.stderr
		if !strings.Contains(body, "--hosts") {
			t.Fatalf("help missing --hosts:\n%s", body)
		}
		if !strings.Contains(body, "--presets") {
			t.Fatalf("help missing --presets:\n%s", body)
		}
		if !strings.Contains(body, "--no-presets") {
			t.Fatalf("help missing --no-presets:\n%s", body)
		}
	})

	t.Run("unknown preset is exit 2", func(t *testing.T) {
		res := runCLI(t, bin, home, "gen-allowlist", "--out", out, "--presets", "nope")
		assertUsageError(t, res, "unknown preset")
		assertNoAllowlist(t, out)
	})

	t.Run("hosts bad scheme is exit 2", func(t *testing.T) {
		res := runCLI(t, bin, home, "gen-allowlist", "--out", out, "--hosts", "http://example.com")
		assertUsageError(t, res, "scheme")
		assertNoAllowlist(t, out)
	})

	t.Run("hosts invalid value is exit 2", func(t *testing.T) {
		res := runCLI(t, bin, home, "gen-allowlist", "--out", out, "--hosts", "not a host")
		assertUsageError(t, res, "invalid host")
		assertNoAllowlist(t, out)
	})

	t.Run("presets with no-presets is exit 2", func(t *testing.T) {
		res := runCLI(t, bin, home, "gen-allowlist", "--out", out, "--presets", "linux", "--no-presets")
		assertUsageError(t, res, "--presets")
		if !strings.Contains(res.stderr, "--no-presets") {
			t.Fatalf("stderr=%q", res.stderr)
		}
		assertNoAllowlist(t, out)
	})

	t.Run("missing --out is exit 2", func(t *testing.T) {
		res := runCLI(t, bin, home, "gen-allowlist", "--hosts", "example.com")
		assertUsageError(t, res, "required flag --out not set")
	})

	t.Run("--out alone prints help and exits 0", func(t *testing.T) {
		res := runCLI(t, bin, home, "gen-allowlist", "--out", out)
		if res.code != 0 {
			t.Fatalf("code=%d stdout=%s stderr=%s", res.code, res.stdout, res.stderr)
		}
		if !strings.Contains(res.stdout, "trustprune gen-allowlist") {
			t.Fatalf("expected help, stdout=%q stderr=%q", res.stdout, res.stderr)
		}
		assertNoAllowlist(t, out)
	})

	t.Run("--out --no-presets prints help and exits 0", func(t *testing.T) {
		res := runCLI(t, bin, home, "gen-allowlist", "--out", out, "--no-presets")
		if res.code != 0 {
			t.Fatalf("code=%d stdout=%s stderr=%s", res.code, res.stdout, res.stderr)
		}
		if !strings.Contains(res.stdout, "trustprune gen-allowlist") {
			t.Fatalf("expected help, stdout=%q stderr=%q", res.stdout, res.stderr)
		}
		assertNoAllowlist(t, out)
	})

	t.Run("stray args rejected before any write", func(t *testing.T) {
		res := runCLI(t, bin, home, "gen-allowlist", "--out", out, "--hosts", "example.com", "extra")
		assertStrayRejected(t, res, "extra")
		assertNoAllowlist(t, out)
	})

	t.Run("unknown preset does not truncate TRACE", func(t *testing.T) {
		const sentinel = "preserve-me\n"
		tracePath := writeTestFile(t, "trace.out", []byte(sentinel))
		res := runCLIWithEnv(t, bin, envWithTRACE(t.TempDir(), tracePath), "gen-allowlist", "--out", out, "--presets", "nope")
		if res.code != 2 {
			t.Fatalf("code=%d stdout=%q stderr=%q", res.code, res.stdout, res.stderr)
		}
		assertSameBytes(t, tracePath, []byte(sentinel))
	})
}

func assertNoAllowlist(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("gen-allowlist wrote %s: %v", path, err)
	}
}
