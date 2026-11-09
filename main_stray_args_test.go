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

func TestStrayArgsRejectedBeforeWrite(t *testing.T) {
	bin := cliBinary(t)
	example := readTestFile(t, filepath.Join("testdata", "example.crt"))
	local := readTestFile(t, filepath.Join("testdata", "localcert.pem"))
	both := append(append([]byte{}, example...), local...)

	t.Run("add", func(t *testing.T) {
		home, bundle, before := certifiBundle(t, both)
		cert := writeTestFile(t, "cert.pem", example)
		res := runCLI(t, bin, home, "add", "-app", "certifi", "-store", bundle, "-file", cert, "extra", "-dry-run")
		assertStrayRejected(t, res, "extra")
		assertSameBytes(t, bundle, before)
	})

	t.Run("add glob", func(t *testing.T) {
		home, bundle, before := certifiBundle(t, both)
		cert := writeTestFile(t, "cert.pem", example)
		res := runCLI(t, bin, home, "add", "-app", "certifi", "-store", bundle, "-file", cert, "a.pem", "b.pem", "-dry-run")
		assertStrayRejected(t, res, "a.pem")
		if !strings.Contains(res.stdout, "b.pem") || !strings.Contains(res.stdout, "-dry-run") {
			t.Fatalf("stdout should list every unparsed arg:\n%s", res.stdout)
		}
		assertSameBytes(t, bundle, before)
	})

	t.Run("backup", func(t *testing.T) {
		home, bundle, before := certifiBundle(t, both)
		res := runCLI(t, bin, home, "backup", "-app", "certifi", "-store", bundle, "extra", "-dry-run")
		assertStrayRejected(t, res, "extra")
		assertSameBytes(t, bundle, before)
		assertNoBackupRoot(t, home)
	})

	t.Run("restore", func(t *testing.T) {
		home, bundle, before := certifiBundle(t, local)
		// A different PEM so a real restore would change the live bundle.
		seedCertifiBackup(t, home, bundle, example)
		res := runCLI(t, bin, home, "restore", "-app", "certifi", "-store", bundle, "extra", "-dry-run")
		assertStrayRejected(t, res, "extra")
		assertSameBytes(t, bundle, before)
	})

	t.Run("allowlist", func(t *testing.T) {
		home, bundle, before := certifiBundle(t, both)
		seedCertifiBackup(t, home, bundle, both)
		al := writeKeepFirstAllowlist(t, example)
		res := runCLI(t, bin, home, "allowlist", "-app", "certifi", "-store", bundle, "-file", al, "extra", "-dry-run")
		assertStrayRejected(t, res, "extra")
		assertSameBytes(t, bundle, before)
	})

	t.Run("whitelist", func(t *testing.T) {
		home, bundle, before := certifiBundle(t, both)
		seedCertifiBackup(t, home, bundle, both)
		al := writeKeepFirstAllowlist(t, example)
		res := runCLI(t, bin, home, "whitelist", "-app", "certifi", "-store", bundle, "-file", al, "extra", "-dry-run")
		assertStrayRejected(t, res, "extra")
		assertSameBytes(t, bundle, before)
	})

	t.Run("list", func(t *testing.T) {
		home := t.TempDir()
		res := runCLI(t, bin, home, "list", "x", "-count")
		assertStrayRejected(t, res, "x")
		if !strings.Contains(res.stdout, "-count") {
			t.Fatalf("-count should be reported as unparsed, stdout=%s", res.stdout)
		}
	})

	t.Run("list uppercase", func(t *testing.T) {
		home := t.TempDir()
		res := runCLI(t, bin, home, "LIST", "x", "-count")
		assertStrayRejected(t, res, "x")
	})

	t.Run("help after positional is not parsed", func(t *testing.T) {
		res := runCLI(t, bin, t.TempDir(), "list", "extra", "-help")
		assertStrayRejected(t, res, "-help")
	})

	t.Run("parsed help still prints usage", func(t *testing.T) {
		res := runCLI(t, bin, t.TempDir(), "list", "-help", "extra")
		if res.code == 2 || strings.Contains(res.stdout, "unexpected argument") {
			t.Fatalf("parsed -help should still print usage, code=%d stdout=%q", res.code, res.stdout)
		}
		if !strings.Contains(res.stdout, "Usage: trustprune list") {
			t.Fatalf("stdout=%q stderr=%q", res.stdout, res.stderr)
		}
	})

	t.Run("apps", func(t *testing.T) {
		res := runCLI(t, bin, t.TempDir(), "apps", "extra")
		assertStrayRejected(t, res, "extra")
	})

	t.Run("version", func(t *testing.T) {
		res := runCLI(t, bin, t.TempDir(), "version", "extra")
		assertStrayRejected(t, res, "extra")
		if strings.Contains(res.stdout, "(Go:") {
			t.Fatalf("version ran before reject:\n%s", res.stdout)
		}
	})

	t.Run("gen-allowlist", func(t *testing.T) {
		home := t.TempDir()
		out := filepath.Join(home, "out.yaml")
		res := runCLI(t, bin, home, "gen-allowlist", "-file", filepath.Join("testdata", "file-with-urls"), "-out", out, "extra", "-dry-run")
		assertStrayRejected(t, res, "extra")
		if _, err := os.Stat(out); !os.IsNotExist(err) {
			t.Fatalf("gen-allowlist wrote %s: %v", out, err)
		}
	})

	t.Run("gen-whitelist", func(t *testing.T) {
		res := runCLI(t, bin, t.TempDir(), "gen-whitelist", "extra")
		assertStrayRejected(t, res, "extra")
	})
}

// TestTraceNotTruncatedOnStrayArgs is the regression for opening TRACE
// (os.Create truncates) before rejectUnexpectedArgs. A stray positional
// must leave an existing trace file alone. Accepted help still opens it.
func TestTraceNotTruncatedOnStrayArgs(t *testing.T) {
	bin := cliBinary(t)
	const sentinel = "preserve-me\n"

	t.Run("stray positional", func(t *testing.T) {
		tracePath := writeTestFile(t, "trace.out", []byte(sentinel))
		res := runCLIWithEnv(t, bin, envWithTRACE(t.TempDir(), tracePath), "list", "x", "-count")
		assertStrayRejected(t, res, "x")
		assertSameBytes(t, tracePath, []byte(sentinel))
	})

	t.Run("list -help writes TRACE", func(t *testing.T) {
		tracePath := writeTestFile(t, "trace.out", []byte(sentinel))
		res := runCLIWithEnv(t, bin, envWithTRACE(t.TempDir(), tracePath), "list", "-help")
		if res.code == 2 || strings.Contains(res.stdout, "unexpected argument") {
			t.Fatalf("parsed -help should still print usage, code=%d stdout=%q stderr=%q", res.code, res.stdout, res.stderr)
		}
		if !strings.Contains(res.stdout, "Usage: trustprune list") {
			t.Fatalf("stdout=%q stderr=%q", res.stdout, res.stderr)
		}
		after := readTestFile(t, tracePath)
		if len(after) == 0 || string(after) == sentinel {
			t.Fatalf("TRACE file not written on accepted list -help (%d bytes)", len(after))
		}
	})

	t.Run("top-level -h writes and stops TRACE", func(t *testing.T) {
		tracePath := writeTestFile(t, "trace.out", []byte(sentinel))
		res := runCLIWithEnv(t, bin, envWithTRACE(t.TempDir(), tracePath), "-h")
		if res.code != 0 {
			t.Fatalf("code=%d stdout=%q stderr=%q", res.code, res.stdout, res.stderr)
		}
		if !strings.Contains(res.stdout, "Usage of trustprune") {
			t.Fatalf("stdout=%q stderr=%q", res.stdout, res.stderr)
		}
		if strings.Contains(res.stdout, "ERROR: stopping trace") || strings.Contains(res.stderr, "ERROR: stopping trace") {
			t.Fatalf("trace stop failed: stdout=%q stderr=%q", res.stdout, res.stderr)
		}
		after := readTestFile(t, tracePath)
		if len(after) == 0 || string(after) == sentinel {
			t.Fatalf("TRACE file not written on accepted -h (%d bytes)", len(after))
		}
	})
}

func envWithTRACE(home, tracePath string) []string {
	base := envWithHome(home)
	out := make([]string, 0, len(base)+1)
	for _, e := range base {
		if strings.HasPrefix(e, "TRACE=") {
			continue
		}
		out = append(out, e)
	}
	return append(out, "TRACE="+tracePath)
}

func TestConnectPositionalStillAccepted(t *testing.T) {
	bin := cliBinary(t)
	home := t.TempDir()

	t.Run("positional url", func(t *testing.T) {
		// http is rejected by parseConnectUrl before any dial.
		res := runCLI(t, bin, home, "connect", "http://example.com")
		if strings.Contains(res.stdout, "unexpected argument") {
			t.Fatalf("positional URL rejected: code=%d stdout=%q stderr=%q", res.code, res.stdout, res.stderr)
		}
		if res.code == 0 || !strings.Contains(res.stdout+res.stderr, "non-secure") {
			t.Fatalf("code=%d stdout=%q stderr=%q", res.code, res.stdout, res.stderr)
		}
	})

	t.Run("extra positional stays unknown arguments", func(t *testing.T) {
		res := runCLI(t, bin, home, "connect", "http://example.com", "extra")
		if res.code == 2 || strings.Contains(res.stdout, "unexpected argument") {
			t.Fatalf("connect should keep its own error, code=%d stdout=%q stderr=%q", res.code, res.stdout, res.stderr)
		}
		if res.code == 0 || !strings.Contains(res.stdout, "unknown arguments") {
			t.Fatalf("code=%d stdout=%q stderr=%q", res.code, res.stdout, res.stderr)
		}
	})
}

func assertStrayRejected(t *testing.T, res cliResult, arg string) {
	t.Helper()
	if res.code != 2 {
		t.Fatalf("code=%d\nstdout=%s\nstderr=%s", res.code, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stdout, "ERROR: unexpected argument") {
		t.Fatalf("stdout=%q stderr=%q", res.stdout, res.stderr)
	}
	if !strings.Contains(res.stdout, "flags must come before any non-flag arguments") || !strings.Contains(res.stdout, "shell glob") {
		t.Fatalf("missing hint:\n%s", res.stdout)
	}
	if arg != "" && !strings.Contains(res.stdout, arg) {
		t.Fatalf("stdout missing %q:\n%s", arg, res.stdout)
	}
}

func certifiBundle(t *testing.T, pem []byte) (home, bundle string, before []byte) {
	t.Helper()
	home = t.TempDir()
	bundle = writeTestFile(t, "cacert.pem", pem)
	before = readTestFile(t, bundle)
	return home, bundle, before
}

func writeTestFile(t *testing.T, name string, body []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func readTestFile(t *testing.T, path string) []byte {
	t.Helper()
	// #nosec G304 -- test fixture or temp path
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func assertSameBytes(t *testing.T, path string, before []byte) {
	t.Helper()
	after := readTestFile(t, path)
	if string(after) != string(before) {
		t.Fatalf("file changed: %s (%d -> %d bytes)", path, len(before), len(after))
	}
}

func assertNoBackupRoot(t *testing.T, home string) {
	t.Helper()
	root := trustpruneBackupRoot(home)
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("backup root %s: %v", root, err)
	}
}

// trustpruneBackupRoot matches store.primaryBackupParent. Tests cannot call it.
func trustpruneBackupRoot(home string) string {
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(home, "Library", "trustprune")
	default:
		return filepath.Join(home, ".trustprune")
	}
}

func seedCertifiBackup(t *testing.T, home, bundle string, pem []byte) {
	t.Helper()
	dir := filepath.Join(trustpruneBackupRoot(home), "certifi", "1700000000")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cacert.pem"), pem, 0o644); err != nil {
		t.Fatal(err)
	}
	body := canonicalTestPath(bundle) + "\n"
	if err := os.WriteFile(filepath.Join(dir, "source"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func canonicalTestPath(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return filepath.Clean(path)
	}
	abs = filepath.Clean(abs)
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil || resolved == "" {
		return abs
	}
	return resolved
}

func writeKeepFirstAllowlist(t *testing.T, pem []byte) string {
	t.Helper()
	certs, err := certutil.Decode(pem)
	if err != nil || len(certs) == 0 {
		t.Fatalf("decode allowlist cert: %d %v", len(certs), err)
	}
	fp := certutil.GetHexSHA256Fingerprint(*certs[0])
	body := "fingerprints:\n  - \"" + fp + "\"\n"
	return writeTestFile(t, "allowlist.yaml", []byte(body))
}
